// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <iostream>
#include "Config.hpp"
#include "Node.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace bytecoin;

static const bool multicore = true;

Node::DownloaderV3::DownloaderV3(Node *node, BlockChainState &block_chain)
    : m_node(node)
    , m_block_chain(block_chain)
    , m_chain_timer(std::bind(&DownloaderV3::on_chain_timer, this))
    , m_download_timer(std::bind(&DownloaderV3::on_download_timer, this))
    , log_request_timestamp(std::chrono::steady_clock::now())
    , log_response_timestamp(std::chrono::steady_clock::now()) {
	if (multicore) {
		auto th_count = std::max<size_t>(2, std::thread::hardware_concurrency() / 2);
		// we use more energy but have the same speed when using hyperthreading
		//		std::cout << "Starting multicore POW checker using " << th_count << "/" <<
		// std::thread::hardware_concurrency()
		//		          << " cpus" << std::endl;
		for (size_t i = 0; i != th_count; ++i)
			threads.emplace_back(&DownloaderV3::thread_run, this);
		main_loop = platform::EventLoop::current();
	}
	m_download_timer.once(SYNC_TIMEOUT / 8);  // just several ticks per SYNC_TIMEOUT
}

Node::DownloaderV3::~DownloaderV3() {
	{
		std::unique_lock<std::mutex> lock(mu);
		quit = true;
		have_work.notify_all();
	}
	for (auto &&th : threads)
		th.join();
}

// std::set<std::pair<Height, Hash>> Node::DownloaderV3::fill_can_download(Hash hash)const{
//
//}

void Node::DownloaderV3::add_work(std::tuple<Hash, bool, RawBlock> &&wo) {
	std::unique_lock<std::mutex> lock(mu);
	work.push_back(std::move(wo));
	have_work.notify_all();
}

void Node::DownloaderV3::thread_run() {
	crypto::CryptoNightContext hash_crypto_context;
	while (true) {
		std::tuple<Hash, bool, RawBlock> wo;
		{
			std::unique_lock<std::mutex> lock(mu);
			if (quit)
				return;
			if (work.empty()) {
				have_work.wait(lock);
				continue;
			}
			wo = std::move(work.front());
			work.pop_front();
		}
		PreparedBlock result(std::move(std::get<2>(wo)),
		    m_node->m_block_chain.get_currency(),
		    std::get<1>(wo) ? &hash_crypto_context : nullptr);
		{
			std::unique_lock<std::mutex> lock(mu);
			prepared_blocks[std::get<0>(wo)] = std::move(result);
			main_loop->wake();  // so we start processing on_idle
		}
	}
}

uint32_t Node::DownloaderV3::get_known_block_count(uint32_t my) const {
	for (auto &&gc : m_good_clients)
		my = std::max(my, gc.first->get_other_top_block_desc().height);
	return my;
}

void Node::DownloaderV3::on_connect(P2PProtocolBytecoinNew *who) {
	if (who->is_incoming())  // Never sync from incoming
		return;
	m_node->m_log(logging::TRACE) << "DownloaderV3::on_connect " << who->get_address() << std::endl;
	invariant(m_good_clients.insert(std::make_pair(who, 0)).second, "");
	// compare height, not hashes. This syncs most good transactions between short splits
	if (who->get_other_top_block_desc().height == m_block_chain.get_tip_height()) {
		m_node->m_log(logging::TRACE) << "DownloaderV3::on_connect sync_transactions to " << who->get_address()
		                              << " our pool size="
		                              << m_node->m_block_chain.get_memory_state_transactions().size() << std::endl;
		m_node->sync_transactions(who);
		// If we at same height, sync tx now, otherwise will sync after we reach same height
	}
	//	who->can_download_blocks = m_block_chain.fill_can_download(who->get_other_top_block_desc().hash);
	advance_download();
}

void Node::DownloaderV3::on_disconnect(P2PProtocolBytecoinNew *who) {
	if (who->is_incoming())
		return;
	if (m_good_clients.count(who) == 0)  // Remove only if we have it added
		return;
	m_node->m_log(logging::TRACE) << "DownloaderV3::on_disconnect " << who->get_address() << std::endl;
	invariant(total_downloading_blocks >= m_good_clients[who], "total_downloading_blocks mismatch in disconnect");
	total_downloading_blocks -= m_good_clients[who];
	m_good_clients.erase(who);
	for (auto lit = m_who_downloaded_block.begin(); lit != m_who_downloaded_block.end();)
		if (*lit == who)
			lit = m_who_downloaded_block.erase(lit);
		else
			++lit;
	for (auto &&dc : m_download_chain) {
		if (dc.status == DownloadCell::DOWNLOADING && dc.downloading_client == who)
			dc.downloading_client = nullptr;
	}
	if (m_find_diff_client && m_find_diff_client == who) {
		m_chain_timer.cancel();
		m_find_diff_client = nullptr;
		m_node->m_log(logging::TRACE) << "DownloaderV3::on_disconnect find_diff_client reset to 0" << std::endl;
	}
	if (m_sync_headers_client && m_sync_headers_client == who) {
		m_chain_timer.cancel();
		m_sync_headers_client = nullptr;
		m_node->m_log(logging::TRACE) << "DownloaderV3::on_disconnect sync_headers_client reset to 0" << std::endl;
	}
	advance_download();
}

void Node::DownloaderV3::on_chain_timer() {
	if (m_find_diff_client) {
		m_node->m_log(logging::TRACE) << "DownloaderV3::on_chain_timer find_diff_client disconnect" << std::endl;
		m_find_diff_client->disconnect(std::string());
		return;
	}
	if (m_sync_headers_client) {
		m_node->m_log(logging::TRACE) << "DownloaderV3::on_chain_timer m_sync_headers_client disconnect" << std::endl;
		m_sync_headers_client->disconnect(std::string());
		return;
	}
}

void Node::DownloaderV3::on_msg_find_diff(P2PProtocolBytecoinNew *who, np::FindDiff::Response &&resp) {
	m_chain_timer.cancel();
	if (resp.sparse_chain.size() > np::FindDiff::Response::MAX_SPARSE_CHAIN_LENGTH)
		return who->disconnect("MAX_SPARSE_CHAIN_LENGTH violation");
	if (who != m_find_diff_client)
		return who->disconnect("Stray FindDiff Response");
	api::BlockHeader desired_header;
	api::BlockHeader have_header;
	if (resp.sparse_chain.size() < 2)
		return who->disconnect("FindDiff sparse_chain length < 2");
	if (resp.sparse_chain.at(0).hash != m_find_diff_bid)
		return who->disconnect("FindDiff sparse_chain does not start with desired_bid");
	if (m_node->m_block_chain.read_header(resp.sparse_chain.at(0).hash, &desired_header)) {
		m_node->m_log(logging::INFO) << "DownloaderV3::on_msg_find_diff already have desired_bid from "
		                             << m_sync_headers_client->get_address() << " m_find_diff_bid=" << m_find_diff_bid
		                             << " remote height=" << m_sync_headers_client->get_other_top_block_desc().height
		                             << " our height=" << m_block_chain.get_tip_height() << std::endl;
		// While we were searching for diff, we got the desired header already
		m_find_diff_client = nullptr;
		advance_chain();
		return;
	}
	SWCheckpoint desired_sw = resp.sparse_chain.at(0);
	resp.sparse_chain.erase(resp.sparse_chain.begin());
	if (!m_node->m_block_chain.read_header(resp.sparse_chain.back().hash, &have_header))
		return who->disconnect("FindDiff sparse_chain does not contain any bid we have");
	SWCheckpoint have_sw = resp.sparse_chain.back();
	resp.sparse_chain.pop_back();
	while (!resp.sparse_chain.empty() &&
	       !m_node->m_block_chain.read_header(resp.sparse_chain.at(0).hash, &desired_header)) {
		desired_sw = resp.sparse_chain.at(0);
		resp.sparse_chain.erase(resp.sparse_chain.begin());
	}
	while (
	    !resp.sparse_chain.empty() && m_node->m_block_chain.read_header(resp.sparse_chain.back().hash, &have_header)) {
		have_sw = resp.sparse_chain.back();
		resp.sparse_chain.pop_back();
	}
	if (!resp.sparse_chain.empty())
		return who->disconnect("FindDiff sparse_chain with wrong order");
	if (desired_sw.height == have_sw.height + 1) {  // Found!
		m_sync_headers_client              = m_find_diff_client;
		m_find_diff_client                 = nullptr;
		m_sync_headers_previous_block_hash = have_sw.hash;
		np::SyncHeaders::Request fd;
		fd.previous_hash = m_sync_headers_previous_block_hash;
		fd.max_count     = np::SyncHeaders::Request::GOOD_COUNT;
		BinaryArray msg  = seria::to_binary_kv(fd);
		m_find_diff_client->send(P2PProtocolBytecoinNew::create_header(np::SyncHeaders::Request::ID, msg.size()));
		m_find_diff_client->send(std::move(msg));
		m_node->m_log(logging::INFO) << "DownloaderV3::advance_chain SyncHeaders::Request from "
		                             << m_sync_headers_client->get_address()
		                             << " remote height=" << m_sync_headers_client->get_other_top_block_desc().height
		                             << " our height=" << m_block_chain.get_tip_height() << std::endl;
		m_chain_timer.once(SYNC_TIMEOUT);
		return;
	}
	m_find_diff_iteration += 1;
	np::FindDiff::Request fd;
	fd.gap_start.push_back(have_sw.hash);
	fd.desired_bid  = m_find_diff_bid;
	BinaryArray msg = seria::to_binary_kv(fd);
	m_find_diff_client->send(P2PProtocolBytecoinNew::create_header(np::FindDiff::Request::ID, msg.size()));
	m_find_diff_client->send(std::move(msg));
	m_node->m_log(logging::INFO) << "DownloaderV3::advance_chain next FindDiff::Request from "
	                             << m_find_diff_client->get_address()
	                             << " remote height=" << m_find_diff_client->get_other_top_block_desc().height
	                             << " our height=" << m_block_chain.get_tip_height() << std::endl;
	m_chain_timer.once(SYNC_TIMEOUT);
}
void Node::DownloaderV3::on_msg_sync_headers(P2PProtocolBytecoinNew *who, np::SyncHeaders::Response &&resp) {
	m_chain_timer.cancel();
	if (resp.binary_headers.size() > np::SyncHeaders::Request::GOOD_COUNT)
		return who->disconnect("SyncHeaders binary_headers too much headers returned");
	if (resp.binary_headers.size() == 0) {  // Peer switched chain
		m_node->m_log(logging::INFO) << "DownloaderV3::on_msg_sync_headers peer switched chains "
		                             << m_sync_headers_client->get_address()
		                             << " m_sync_headers_previous_block_hash=" << m_sync_headers_previous_block_hash
		                             << " remote height=" << m_sync_headers_client->get_other_top_block_desc().height
		                             << " our height=" << m_block_chain.get_tip_height() << std::endl;
		m_sync_headers_client = nullptr;
		advance_chain();
		return;
	}
	for (const auto &bh : resp.binary_headers) {
		BlockTemplate block_header;
		seria::from_binary(block_header, bh);
		api::BlockHeader info;
		//		if (m_block_chain.add_header(block_header, &info) == BroadcastAction::BAN)
		//			return who->disconnect("SyncHeaders Response header banned");
		if (info.previous_block_hash != m_sync_headers_previous_block_hash)
			return who->disconnect("SyncHeaders Response binary_headers do not form chain with requested start");
		m_sync_headers_previous_block_hash = info.previous_block_hash;
	}
	// TODO - increase probability if reply takes too long
	const size_t barrier = crypto::rand<size_t>() % (np::SyncHeaders::Request::GOOD_COUNT * 110 / 100);
	const bool finished  = m_sync_headers_previous_block_hash == m_sync_headers_client->get_other_top_block_desc().hash;
	if (resp.binary_headers.size() <= barrier || finished) {
		m_node->m_log(logging::INFO) << "DownloaderV3::on_msg_sync_headers probability switch "
		                             << m_sync_headers_client->get_address() << " count=" << resp.binary_headers.size()
		                             << " barrier=" << barrier << " finished=" << int(finished)
		                             << " remote height=" << m_sync_headers_client->get_other_top_block_desc().height
		                             << " our height=" << m_block_chain.get_tip_height() << std::endl;
		m_sync_headers_client = nullptr;
		advance_chain();
		return;
	}
	np::SyncHeaders::Request fd;
	fd.previous_hash = m_sync_headers_previous_block_hash;
	fd.max_count     = np::SyncHeaders::Request::GOOD_COUNT;
	BinaryArray msg  = seria::to_binary_kv(fd);
	m_find_diff_client->send(P2PProtocolBytecoinNew::create_header(np::SyncHeaders::Request::ID, msg.size()));
	m_find_diff_client->send(std::move(msg));
	m_node->m_log(logging::INFO) << "DownloaderV3::advance_chain next SyncHeaders::Request from "
	                             << m_sync_headers_client->get_address()
	                             << " remote height=" << m_sync_headers_client->get_other_top_block_desc().height
	                             << " our height=" << m_block_chain.get_tip_height() << std::endl;
	m_chain_timer.once(SYNC_TIMEOUT);
}
void Node::DownloaderV3::on_msg_get_transactions(P2PProtocolBytecoinNew *who, np::GetTransactions::Response &&resp) {}

/*void Node::DownloaderV3::on_msg_notify_request_chain(P2PProtocolBytecoin *who,
    const NOTIFY_RESPONSE_CHAIN_ENTRY::request &req) {
    if (m_chain_client != who || !m_chain_request_sent)
        return;  // TODO - who just sent us chain we did not ask, ban
    m_chain_request_sent = false;
    m_chain_timer.cancel();
    m_node->m_log(logging::INFO) << "Downloader received chain from " << who->get_address()
                                 << " start_height=" << req.start_height << " length=" << req.m_block_ids.size()
                                 << std::endl;
    m_chain_start_height = req.start_height;
    chain_source         = m_chain_client->get_address();
    m_chain.assign(req.m_block_ids.begin(), req.m_block_ids.end());
    //	Hash last_downloaded_block = m_chain.empty() ? Hash{} : m_chain.back();
    std::set<Hash> downloading_bids;
    for (auto &&dc : m_download_chain)
        downloading_bids.insert(dc.bid);
    while (!m_chain.empty() &&
           (m_node->m_block_chain.has_block(m_chain.front()) || downloading_bids.count(m_chain.front()) != 0)) {
        m_chain.pop_front();
        m_chain_start_height += 1;
    }  // We stop removing as soon as we find new block, because wrong order might prevent us from applying blocks
    if (req.m_block_ids.size() != m_chain.size() + 1) {
        m_node->m_log(logging::INFO) << "Downloader truncated chain length=" << m_chain.size() << std::endl;
    }
    if (req.m_block_ids.empty()){ // Most likely peer is 3.2.0
        const auto now = m_node->m_p2p.get_local_time();
        m_node->m_log(logging::INFO) << "Downloader truncated chain to zero, delaying connect to " << who->get_address()
<< std::endl;
        m_node->m_peer_db.delay_connection_attempt(who->get_address(), now);
        who->disconnect(std::string());  // Will recursively call advance_chain again
    }
    advance_download();
}*/

static const size_t GOOD_LAG = 5;  // lagging by 5 blocks is ok for us

void Node::DownloaderV3::advance_chain() {
	if (m_find_diff_client || m_sync_headers_client)
		return;  // TODO - if number of headers we are preparing > some const
	std::vector<P2PProtocolBytecoinNew *> lagging_clients;
	std::vector<P2PProtocolBytecoinNew *> worth_clients;
	const auto now = m_node->m_p2p.get_local_time();
	for (auto &&who : m_good_clients) {
		if (who.first->get_other_top_block_desc().height + GOOD_LAG < m_node->m_block_chain.get_tip_height())
			lagging_clients.push_back(who.first);
		api::BlockHeader info;
		if (!m_node->m_block_chain.read_header(who.first->get_other_top_block_desc().hash, &info))
			worth_clients.push_back(who.first);
	}
	if (lagging_clients.size() > m_node->m_config.p2p_max_outgoing_connections / 4) {
		auto who = lagging_clients.front();
		m_node->m_peer_db.delay_connection_attempt(who->get_address(), now);
		m_node->m_log(logging::INFO) << "DownloaderV3 disconnecting lagging client " << who->get_address() << std::endl;
		who->disconnect(std::string());  // Will recursively call advance_chain again
		return;
	}
	if (worth_clients.empty())
		return;  // We hope to get more connections soon
	m_find_diff_client    = worth_clients.at(crypto::rand<size_t>() % worth_clients.size());
	m_find_diff_iteration = 0;
	m_find_diff_bid       = m_find_diff_client->get_other_top_block_desc().hash;
	np::FindDiff::Request fd;
	fd.gap_start    = m_node->m_block_chain.get_sparse_chain();
	fd.desired_bid  = m_find_diff_bid;
	BinaryArray msg = seria::to_binary_kv(fd);
	m_find_diff_client->send(P2PProtocolBytecoinNew::create_header(np::FindDiff::Request::ID, msg.size()));
	m_find_diff_client->send(std::move(msg));
	m_node->m_log(logging::INFO) << "DownloaderV3::advance_chain FindDiff::Request from "
	                             << m_find_diff_client->get_address()
	                             << " remote height=" << m_find_diff_client->get_other_top_block_desc().height
	                             << " our height=" << m_block_chain.get_tip_height() << std::endl;
	m_chain_timer.once(SYNC_TIMEOUT);
}

void Node::DownloaderV3::start_download(DownloadCell &dc, P2PProtocolBytecoinNew *who) {
	auto idea_now         = std::chrono::steady_clock::now();
	dc.downloading_client = who;
	dc.block_source       = who->get_address();
	dc.request_time       = idea_now;
	m_good_clients[dc.downloading_client] += 1;
	total_downloading_blocks += 1;
	NOTIFY_REQUEST_GET_OBJECTS::request msg;
	msg.blocks.push_back(dc.bid);
	if (std::chrono::duration_cast<std::chrono::milliseconds>(idea_now - log_request_timestamp).count() > 1000) {
		log_request_timestamp = idea_now;
		std::cout << "Requesting block " << dc.expected_height << " from " << dc.downloading_client->get_address()
		          << std::endl;
	}
	m_node->m_log(logging::TRACE) << "DownloaderV3::advance_download requesting block " << dc.expected_height
	                              << " hash=" << dc.bid << " from " << dc.downloading_client->get_address()
	                              << std::endl;
	BinaryArray raw_msg =
	    LevinProtocol::send_message(NOTIFY_REQUEST_GET_OBJECTS::ID, LevinProtocol::encode(msg), false);
	dc.downloading_client->send(std::move(raw_msg));
}

void Node::DownloaderV3::stop_download(DownloadCell &dc, bool success) {
	if (dc.status != DownloadCell::DOWNLOADING || !dc.downloading_client)
		return;
	auto git = m_good_clients.find(dc.downloading_client);
	invariant(git != m_good_clients.end() && git->second != 0 && total_downloading_blocks != 0,
	    "DownloadCell reference to good client not found");
	git->second -= 1;
	total_downloading_blocks -= 1;
	if (success) {
		dc.status = DownloadCell::DOWNLOADED;
		m_who_downloaded_block.push_back(dc.downloading_client);
	}
	dc.downloading_client = nullptr;
}

/*void Node::DownloaderV3::on_msg_notify_request_objects(P2PProtocolBytecoin *who,
    const NOTIFY_RESPONSE_GET_OBJECTS::request &req) {
    for (auto &&rb : req.blocks) {
        Hash bid;
        try {
            BlockTemplate bheader;
            seria::from_binary(bheader, rb.block);
            bid = bytecoin::get_block_hash(bheader);
        } catch (const std::exception &ex) {
            m_node->m_log(logging::INFO) << "Exception " << common::what(ex) << " while parsing returned block, banning
"
                                         << who->get_address() << std::endl;
            who->disconnect(std::string());
            break;
        }
        bool cell_found = false;
        for (auto &&dc : m_download_chain) {
            if (dc.status != DownloadCell::DOWNLOADING || dc.downloading_client != who || dc.bid != bid)
                continue;  // downloaded or downloading
            stop_download(dc, true);
            dc.rb.block        = rb.block;         // TODO - std::move
            dc.rb.transactions = rb.transactions;  // TODO - std::move
            auto now           = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - log_response_timestamp).count() > 1000) {
                log_response_timestamp = now;
                std::cout << "Received block with height=" << dc.expected_height
                          << " (queue=" << total_downloading_blocks << ") from " << who->get_address() << std::endl;
            }
            m_node->m_log(logging::TRACE)
                << "Downloader received block with height=" << dc.expected_height << " hash=" << dc.bid
                << " (queue=" << total_downloading_blocks << ") from " << who->get_address() << std::endl;
            cell_found = true;
            if (multicore) {
                dc.status = DownloadCell::PREPARING;
                add_work(std::tuple<Hash, bool, RawBlock>(dc.bid,
                    !m_node->m_block_chain.get_currency().is_in_sw_checkpoint_zone(dc.expected_height),
                    std::move(dc.rb)));
            } else {
                dc.pb     = PreparedBlock(std::move(dc.rb), m_node->m_block_chain.get_currency(), nullptr);
                dc.status = DownloadCell::PREPARED;
            }
            break;
        }
        if (!cell_found) {
            m_node->m_log(logging::INFO) << "Downloader received stray block from " << who->get_address() << std::endl;
            //			who->disconnect(std::string());
            //			break;
        }
    }
    for (auto &&bid : req.missed_ids) {
        for (size_t dit_counter = 0; dit_counter != m_download_chain.size(); ++dit_counter) {
            auto & dit = m_download_chain.at(dit_counter);
            if (dit.status != DownloadCell::DOWNLOADING || dit.downloading_client != who || dit.bid != bid)
                continue;  // downloaded or downloading
            stop_download(dit, false);
            if (!m_chain_client || m_chain_client == who) {
                m_node->m_log(logging::INFO)
                    << "Downloader cannot download block from any connected client, cleaning chain" << std::endl;
                while (m_download_chain.size() > dit_counter) {
                    stop_download(m_download_chain.back(), false);
                    m_download_chain.pop_back();
                }
                m_chain.clear();
                advance_download();
                return;
            }
            start_download(dit, m_chain_client);
        }
    }
    advance_download();
}*/

bool Node::DownloaderV3::on_idle() {
	int added_counter = 0;
	if (multicore) {
		std::unique_lock<std::mutex> lock(mu);
		for (auto &&pb : prepared_blocks) {
			for (auto &&dc : m_download_chain)
				if (dc.status == DownloadCell::PREPARING && dc.bid == pb.first) {
					dc.pb     = std::move(pb.second);
					dc.status = DownloadCell::PREPARED;
					break;
				}
		}
		prepared_blocks.clear();
	}
	auto idea_start = std::chrono::high_resolution_clock::now();
	while (!m_download_chain.empty() && m_download_chain.front().status == DownloadCell::PREPARED) {
		DownloadCell dc = std::move(m_download_chain.front());
		m_download_chain.pop_front();
		api::BlockHeader info;
		auto action = m_block_chain.add_block(
		    dc.pb, &info, common::ip_address_and_port_to_string(dc.block_source.ip, dc.block_source.port));
		if (action == BroadcastAction::BAN) {
			m_node->m_log(logging::INFO) << "Downloader DownloadCell BAN height=" << dc.expected_height
			                             << " wb=" << dc.bid << std::endl;
			// TODO - ban client who gave us chain
			//			continue;
		}
		//		if (action == BroadcastAction::NOTHING)
		//			std::cout << "BroadcastAction::NOTHING height=" << info.height << " cd=" <<
		// info.cumulative_difficulty.lo
		//			          << std::endl;
		if (action == BroadcastAction::BROADCAST_ALL) {
			//			std::cout << "BroadcastAction::BROADCAST_ALL height=" << info.height
			//			          << " cd=" << info.cumulative_difficulty.lo << std::endl;
			if (m_download_chain.empty()) {
				// We do not want to broadcast too often during download
				m_node->m_log(logging::INFO) << "Added last (from batch) downloaded block height=" << info.height
				                             << " bid=" << info.hash << std::endl;
				COMMAND_TIMED_SYNC::request req;
				req.payload_data =
				    CORE_SYNC_DATA{m_node->m_block_chain.get_tip_height(), m_node->m_block_chain.get_tip_bid()};
				BinaryArray raw_msg =
				    LevinProtocol::send_message(COMMAND_TIMED_SYNC::ID, LevinProtocol::encode(req), true);
				m_node->broadcast(
				    nullptr, raw_msg);  // nullptr - we can not always know which connection was block source
				//				m_node->broadcast_new(nullptr, raw_msg); // TODO nullptr - we can not always know which
				// connection was block source
			}
		}
		added_counter += 1;
		auto idea_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		    std::chrono::high_resolution_clock::now() - idea_start);
		if (idea_ms.count() > 100)
			break;
	}
	if (added_counter) {
		m_node->advance_long_poll();
		advance_download();
		if (m_download_chain.empty())
			for (auto &&who : m_good_clients) {
				if (who.first->get_other_top_block_desc().height == m_node->m_block_chain.get_tip_height()) {
					m_node->m_log(logging::TRACE)
					    << "DownloaderV3::on_idle sync_transactions to " << who.first->get_address()
					    << " our pool size=" << m_node->m_block_chain.get_memory_state_transactions().size()
					    << std::endl;
					m_node->sync_transactions(who.first);
					break;  // TODO - sync with all nodes
				}
			}
	}

	return !m_download_chain.empty() && m_download_chain.front().status == DownloadCell::PREPARED;
}

void Node::DownloaderV3::on_download_timer() {
	m_download_timer.once(SYNC_TIMEOUT / 8);  // just several ticks per SYNC_TIMEOUT
	auto idea_now = std::chrono::steady_clock::now();
	if (!m_download_chain.empty() && m_download_chain.front().status == DownloadCell::DOWNLOADING &&
	    m_download_chain.front().downloading_client && m_download_chain.front().protect_from_disconnect &&
	    std::chrono::duration_cast<std::chrono::seconds>(idea_now - m_download_chain.front().request_time).count() >
	        SYNC_TIMEOUT) {
		auto who = m_download_chain.front().downloading_client;
		m_node->m_peer_db.delay_connection_attempt(who->get_address(), m_node->m_p2p.get_local_time());
		m_node->m_log(logging::INFO) << "Downloader disconnecting protected slacker " << who->get_address()
		                             << std::endl;
		who->disconnect(std::string());
	}
}

void Node::DownloaderV3::advance_download() {
	/*	if (m_node->m_block_chain_reader1 || m_node->m_block_chain_reader2 ||
	        m_block_chain.get_tip_height() < m_block_chain.internal_import_known_height())
	        return;
	    const size_t TOTAL_DOWNLOAD_BLOCKS = 400;   // TODO - dynamic count
	    const size_t TOTAL_DOWNLOAD_WINDOW = 2000;  // TODO - dynamic count
	    while (m_download_chain.size() < TOTAL_DOWNLOAD_WINDOW && !m_chain.empty()) {
	        m_download_chain.push_back(DownloadCell());
	        m_download_chain.back().bid             = m_chain.front();
	        m_download_chain.back().expected_height = m_chain_start_height;
	        m_download_chain.back().bid_source      = chain_source;
	        m_chain.pop_front();
	        m_chain_start_height += 1;
	    }
	    advance_chain();

	    while (m_who_downloaded_block.size() > TOTAL_DOWNLOAD_BLOCKS)
	        m_who_downloaded_block.pop_front();
	    std::map<P2PProtocolBytecoin *, size_t> who_downloaded_counter;
	    for (auto lit = m_who_downloaded_block.begin(); lit != m_who_downloaded_block.end(); ++lit)
	        who_downloaded_counter[*lit] += 1;
	    auto idea_now = std::chrono::steady_clock::now();
	    for (size_t dit_counter = 0; dit_counter != m_download_chain.size(); ++dit_counter) {
	        auto & dit = m_download_chain.at(dit_counter);
	        if (dit.status != DownloadCell::DOWNLOADING || dit.downloading_client)
	            continue;  // downloaded or downloading
	        if (total_downloading_blocks >= TOTAL_DOWNLOAD_BLOCKS)
	            break;
	        P2PProtocolBytecoin *ready_client = nullptr;
	        size_t ready_counter            = std::numeric_limits<size_t>::max();
	        size_t ready_speed              = 1;
	        for (auto &&who : m_good_clients) {
	            size_t speed =
	                    std::max<size_t>(1, std::min<size_t>(TOTAL_DOWNLOAD_BLOCKS / 4,
	   who_downloaded_counter[who.first]));
	            // We clamp speed so that if even 1 downloaded all blocks, we will give
	            // small % of blocks to other peers
	            if (who.second * ready_speed < ready_counter * speed &&
	                who.first->get_last_received_sync_data().current_height >= dit.expected_height) {
	                ready_client  = who.first;
	                ready_counter = who.second;
	                ready_speed   = speed;
	            }
	        }
	        if (!ready_client && m_chain_client)
	            ready_client = m_chain_client;
	        if (!ready_client){ // Cannot download chain from any client
	            m_node->m_log(logging::INFO) << "DownloaderV3::advance_download cannot download blocks from any
	   connected client, cleaning chain" << std::endl;
	            while (m_download_chain.size() > dit_counter) {
	                stop_download(m_download_chain.back(), false);
	                m_download_chain.pop_back();
	            }
	            m_chain.clear();
	            advance_chain();
	            return;
	        }
	        start_download(dit, ready_client);
	    }
	    const bool bad_timeout =
	        !m_download_chain.empty() && m_download_chain.front().status == DownloadCell::DOWNLOADING &&
	        m_download_chain.front().downloading_client && !m_download_chain.front().protect_from_disconnect &&
	        std::chrono::duration_cast<std::chrono::seconds>(idea_now - m_download_chain.front().request_time).count() >
	            2 * SYNC_TIMEOUT;
	    const bool bad_relatively_slow =
	        total_downloading_blocks < TOTAL_DOWNLOAD_BLOCKS && m_download_chain.size() >= TOTAL_DOWNLOAD_WINDOW &&
	        m_good_clients.size() > 1 && m_download_chain.front().status == DownloadCell::DOWNLOADING &&
	        m_download_chain.front().downloading_client && !m_download_chain.front().protect_from_disconnect;
	    if (bad_relatively_slow || bad_timeout) {
	        auto who = m_download_chain.front().downloading_client;
	        for (auto &&dc : m_download_chain)
	            if (dc.downloading_client == who)
	                dc.protect_from_disconnect = true;
	        m_node->m_peer_db.delay_connection_attempt(who->get_address(), m_node->m_p2p.get_local_time());
	        m_node->m_log(logging::INFO) << "DownloaderV3::advance_download disconnecting slacker " <<
	   who->get_address()
	                                     << std::endl;
	        who->disconnect(std::string());
	    }*/
}
