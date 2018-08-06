// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <iostream>
#include "Config.hpp"
#include "Node.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace bytecoin;

static const bool multicore = true;

Node::DownloaderV11::DownloaderV11(Node *node, BlockChainState &block_chain)
    : m_node(node)
    , m_block_chain(block_chain)
    , m_chain_timer(std::bind(&DownloaderV11::on_chain_timer, this))
    , m_download_timer(std::bind(&DownloaderV11::on_download_timer, this))
    , log_request_timestamp(std::chrono::steady_clock::now())
    , log_response_timestamp(std::chrono::steady_clock::now()) {
	if (multicore) {
		auto th_count = std::max<size_t>(2, std::thread::hardware_concurrency() / 2);
		// we use more energy but have the same speed when using hyperthreading
		//		std::cout << "Starting multicore POW checker using " << th_count << "/" <<
		// std::thread::hardware_concurrency()
		//		          << " cpus" << std::endl;
		for (size_t i = 0; i != th_count; ++i)
			threads.emplace_back(&DownloaderV11::thread_run, this);
		main_loop = platform::EventLoop::current();
	}
	m_download_timer.once(SYNC_TIMEOUT / 8);  // just several ticks per SYNC_TIMEOUT
}

Node::DownloaderV11::~DownloaderV11() {
	{
		std::unique_lock<std::mutex> lock(mu);
		quit = true;
		have_work.notify_all();
	}
	for (auto &&th : threads)
		th.join();
}

void Node::DownloaderV11::add_work(std::tuple<Hash, bool, RawBlock> &&wo) {
	std::unique_lock<std::mutex> lock(mu);
	work.push_back(std::move(wo));
	have_work.notify_all();
}

void Node::DownloaderV11::thread_run() {
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
		PreparedBlock result(std::move(std::get<2>(wo)), std::get<1>(wo) ? &hash_crypto_context : nullptr);
		{
			std::unique_lock<std::mutex> lock(mu);
			prepared_blocks[std::get<0>(wo)] = std::move(result);
			main_loop->wake();  // so we start processing on_idle
		}
	}
}

uint32_t Node::DownloaderV11::get_known_block_count(uint32_t my) const {
	for (auto &&gc : m_good_clients)
		my = std::max(my, gc.first->get_last_received_sync_data().current_height);
	return my;
}

void Node::DownloaderV11::on_connect(P2PClientBytecoin *who) {
	if (who->is_incoming())  // Never sync from incoming
		return;
	m_node->m_log(logging::TRACE) << "DownloaderV11::on_connect " << who->get_address() << std::endl;
	if (who->get_version() == 1) {
		m_good_clients.insert(std::make_pair(who, 0));
		if (who->get_last_received_sync_data().current_height == m_block_chain.get_tip_height()) {
			m_node->m_log(logging::TRACE)
			    << "DownloaderV11::on_connect sync_transactions to " << who->get_address()
			    << " our pool size=" << m_node->m_block_chain.get_memory_state_transactions().size() << std::endl;
			m_node->sync_transactions(who);
			// If we at same height, sync tx now, otherwise will sync after we reach same height
		}
		advance_download();
	}
}

void Node::DownloaderV11::on_disconnect(P2PClientBytecoin *who) {
	if (who->is_incoming())
		return;
	m_node->m_log(logging::TRACE) << "DownloaderV11::on_disconnect " << who->get_address() << std::endl;
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
	if (m_chain_client && m_chain_client == who) {
		m_chain_timer.cancel();
		m_chain_client = nullptr;
		m_chain_request_sent = false;
		m_node->m_log(logging::TRACE) << "DownloaderV11::on_disconnect m_chain_client reset to 0" << std::endl;
	}
	advance_download();
}

void Node::DownloaderV11::on_chain_timer() {
	if (m_chain_client) {
		m_node->m_log(logging::TRACE) << "DownloaderV11::on_chain_timer" << std::endl;
		m_chain_client->disconnect(std::string());
	}
}

void Node::DownloaderV11::on_msg_notify_request_chain(P2PClientBytecoin *who,
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
	advance_download();
}

static const size_t GOOD_LAG = 5;  // lagging by 5 blocks is ok for us

void Node::DownloaderV11::advance_chain() {
	if (!m_chain.empty() || !m_download_chain.empty() || m_chain_request_sent)
		return;
	m_chain_client = nullptr;
	std::vector<P2PClientBytecoin *> lagging_clients;
	std::vector<P2PClientBytecoin *> worth_clients;
	const auto now = m_node->m_p2p.get_local_time();
	for (auto &&who : m_good_clients) {
		if (who.first->get_last_received_sync_data().current_height + GOOD_LAG < m_node->m_block_chain.get_tip_height())
			lagging_clients.push_back(who.first);
		api::BlockHeader info;
		if (!m_node->m_block_chain.read_header(who.first->get_last_received_sync_data().top_id, &info))
			worth_clients.push_back(who.first);
	}
	if (lagging_clients.size() > m_node->m_config.p2p_default_connections_count / 4) {
		auto who = lagging_clients.front();
		m_node->m_peer_db.delay_connection_attempt(who->get_address(), now);
		m_node->m_log(logging::INFO) << "Downloader disconnecting lagging client " << who->get_address() << std::endl;
		who->disconnect(std::string());  // Will recursively call advance_chain again
		return;
	}
	if (worth_clients.empty())
		return;  // We hope to get more connections soon
	m_chain_client       = worth_clients.at(crypto::rand<size_t>() % worth_clients.size());
	m_chain_request_sent = true;
	NOTIFY_REQUEST_CHAIN::request msg;
	msg.block_ids = m_block_chain.get_sparse_chain();

	m_node->m_log(logging::INFO) << "DownloaderV11::advance_chain Requesting chain from "
	                             << m_chain_client->get_address()
	                             << " remote height=" << m_chain_client->get_last_received_sync_data().current_height
	                             << " our height=" << m_block_chain.get_tip_height() << std::endl;
	BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_REQUEST_CHAIN::ID, LevinProtocol::encode(msg), false);
	m_chain_client->send(std::move(raw_msg));
	m_chain_timer.once(SYNC_TIMEOUT);
}

void Node::DownloaderV11::start_download(DownloadCell &dc, P2PClientBytecoin *who) {
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
	m_node->m_log(logging::TRACE) << "DownloaderV11::advance_download requesting block " << dc.expected_height
	                              << " hash=" << dc.bid << " from " << dc.downloading_client->get_address()
	                              << std::endl;
	BinaryArray raw_msg =
	    LevinProtocol::send_message(NOTIFY_REQUEST_GET_OBJECTS::ID, LevinProtocol::encode(msg), false);
	dc.downloading_client->send(std::move(raw_msg));
}

void Node::DownloaderV11::stop_download(DownloadCell &dc, bool success) {
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

void Node::DownloaderV11::on_msg_notify_request_objects(P2PClientBytecoin *who,
    const NOTIFY_RESPONSE_GET_OBJECTS::request &req) {
	for (auto &&rb : req.blocks) {
		Hash bid;
		try {
			BlockTemplate bheader;
			seria::from_binary(bheader, rb.block);
			bid = bytecoin::get_block_hash(bheader);
		} catch (const std::exception &ex) {
			m_node->m_log(logging::INFO) << "Exception " << ex.what() << " while parsing returned block, banning "
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
				dc.pb     = PreparedBlock(std::move(dc.rb), nullptr);
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
}

bool Node::DownloaderV11::on_idle() {
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
				COMMAND_TIMED_SYNC::request req;
				req.payload_data =
				    CORE_SYNC_DATA{m_node->m_block_chain.get_tip_height(), m_node->m_block_chain.get_tip_bid()};
				BinaryArray raw_msg =
				    LevinProtocol::send_message(COMMAND_TIMED_SYNC::ID, LevinProtocol::encode(req), true);
				m_node->m_p2p.broadcast(
				    nullptr, raw_msg);  // nullptr - we can not always know which connection was block source
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
				if (who.first->get_last_received_sync_data().current_height == m_node->m_block_chain.get_tip_height()) {
					m_node->m_log(logging::TRACE)
					    << "DownloaderV11::on_idle sync_transactions to " << who.first->get_address()
					    << " our pool size=" << m_node->m_block_chain.get_memory_state_transactions().size()
					    << std::endl;
					m_node->sync_transactions(who.first);
					break;  // TODO - sync with all nodes
				}
			}
	}

	return !m_download_chain.empty() && m_download_chain.front().status == DownloadCell::PREPARED;
}

void Node::DownloaderV11::on_download_timer() {
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

void Node::DownloaderV11::advance_download() {
	if (m_node->m_block_chain_reader1 || m_node->m_block_chain_reader2 ||
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
	std::map<P2PClientBytecoin *, size_t> who_downloaded_counter;
	for (auto lit = m_who_downloaded_block.begin(); lit != m_who_downloaded_block.end(); ++lit)
		who_downloaded_counter[*lit] += 1;
	auto idea_now = std::chrono::steady_clock::now();
	for (size_t dit_counter = 0; dit_counter != m_download_chain.size(); ++dit_counter) {
		auto & dit = m_download_chain.at(dit_counter);
		if (dit.status != DownloadCell::DOWNLOADING || dit.downloading_client)
			continue;  // downloaded or downloading
		if (total_downloading_blocks >= TOTAL_DOWNLOAD_BLOCKS)
			break;
		P2PClientBytecoin *ready_client = nullptr;
		size_t ready_counter            = std::numeric_limits<size_t>::max();
		size_t ready_speed              = 1;
		for (auto &&who : m_good_clients) {
			size_t speed =
			    std::max<size_t>(1, std::min<size_t>(TOTAL_DOWNLOAD_BLOCKS / 4, who_downloaded_counter[who.first]));
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
		if (!ready_client) {  // Cannot download chain from any client
			m_node->m_log(logging::INFO)
			    << "DownloaderV11::advance_download cannot download blocks from any connected client, cleaning chain"
			    << std::endl;
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
		m_node->m_log(logging::INFO) << "DownloaderV11::advance_download disconnecting slacker " << who->get_address()
		                             << std::endl;
		who->disconnect(std::string());
	}
}
