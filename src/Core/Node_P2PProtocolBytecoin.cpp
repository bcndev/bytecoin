// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <iostream>
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "Node.hpp"
#include "TransactionExtra.hpp"
#include "common/JsonValue.hpp"
#include "p2p/PeerDB.hpp"
#include "platform/PathTools.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"
#include "version.hpp"

using namespace cn;

static bool greater_fee_per_byte(const TransactionDesc &a, const TransactionDesc &b) {
	invariant(a.size != 0 && b.size != 0, "");
	const auto afb = a.fee / a.size;
	const auto bfb = b.fee / b.size;
	return std::tie(afb, a.hash) > std::tie(bfb, b.hash);
}

Node::P2PProtocolBytecoin::P2PProtocolBytecoin(Node *node, P2PClient *client)
    : P2PProtocolBasic(node->m_config, node->m_p2p.get_unique_number(), client)
    , m_node(node)
    , m_chain_timer(std::bind(&P2PProtocolBytecoin::on_chain_timer, this))
    , m_download_timer(std::bind(&P2PProtocolBytecoin::on_download_timer, this))
    , m_syncpool_timer(std::bind(&P2PProtocolBytecoin::on_syncpool_timer, this))
    , m_download_transactions_timer(std::bind(&P2PProtocolBytecoin::on_download_transactions_timer, this)) {}

Node::P2PProtocolBytecoin::~P2PProtocolBytecoin() = default;

CoreSyncData Node::P2PProtocolBytecoin::get_my_sync_data() const {
	CoreSyncData sync_data;
	sync_data.current_height = m_node->m_block_chain.get_tip_height();
	sync_data.top_id         = m_node->m_block_chain.get_tip_bid();
	return sync_data;
}

std::vector<NetworkAddress> Node::P2PProtocolBytecoin::get_peers_to_share() const {
	return m_node->m_peer_db->get_peerlist_to_p2p(
	    get_address(), m_node->m_p2p.get_local_time(), config.p2p_default_peers_in_handshake);
}

std::vector<PeerlistEntryLegacy> Node::P2PProtocolBytecoin::get_legacy_peers_to_share() const {
	return m_node->m_peer_db->get_peerlist_to_p2p_legacy(
	    get_address(), m_node->m_p2p.get_local_time(), config.p2p_default_peers_in_handshake);
}

void Node::P2PProtocolBytecoin::on_first_message_after_handshake() {
	// if we set just seen on handshake, we will keep connecting to seed nodes forever
	m_node->m_peer_db->set_peer_just_seen(get_peer_unique_number(), get_address(), m_node->m_p2p.get_local_time());
}

void Node::P2PProtocolBytecoin::on_chain_timer() {
	invariant(m_chain_request_sent, "");
	m_node->m_log(logging::TRACE) << "on_chain_timer, disconnecting " << get_address();
	disconnect(std::string{});
}

void Node::P2PProtocolBytecoin::on_download_timer() {
	invariant(m_downloading_block_count != 0, "");
	m_node->m_log(logging::TRACE) << "on_download_timer, disconnecting " << get_address();
	disconnect(std::string{});
}

void Node::P2PProtocolBytecoin::on_syncpool_timer() {
	invariant(m_syncpool_request_sent, "");
	m_node->m_log(logging::TRACE) << "on_download_transactions_timer, disconnecting " << get_address();
	disconnect(std::string{});
}
void Node::P2PProtocolBytecoin::on_download_transactions_timer() {
	invariant(m_downloading_transaction_count != 0, "");
	m_node->m_log(logging::TRACE) << "on_download_transactions_timer, disconnecting " << get_address();
	disconnect(std::string{});
}

void Node::P2PProtocolBytecoin::advance_chain() {
	if (is_incoming() || !m_chain.empty() || m_chain_request_sent)
		return;
	api::BlockHeader info;
	if (m_node->m_block_chain.get_header(get_peer_sync_data().top_id, &info)) {
		if (info.height + m_node->m_config.p2p_outgoing_peer_max_lag < m_node->m_block_chain.get_tip_height()) {
			m_node->m_log(logging::INFO) << "Disconnecting and delay connecting lagging client " << get_address();
			const auto now = m_node->m_p2p.get_local_time();
			m_node->m_peer_db->delay_connection_attempt(get_address(), now);
			disconnect(std::string{});
		}
		// We have peer's top block in our blockchain, nop.
		return;
	}
	m_chain_request_sent = true;
	p2p::GetChain::Request msg;
	if (m_previous_chain_hash != Hash{}) {
		// TODO - turn m_next_chain_hash into sparse chain
		msg.block_ids.push_back(m_previous_chain_hash);
		msg.block_ids.push_back(m_node->m_block_chain.get_genesis_bid());
	} else {
		msg.block_ids = m_node->m_block_chain.get_sparse_chain(p2p::GetChain::Response::MAX_BLOCK_IDS * 4 / 5);
		// Fix for very large blockchain with last checkpoint far in the past
		if (msg.block_ids.size() > p2p::GetChain::Request::MAX_BLOCK_IDS)
			msg.block_ids.erase(
			    msg.block_ids.begin() + p2p::GetChain::Request::MAX_BLOCK_IDS - 1, msg.block_ids.end() - 1);
	}

	m_chain_timer.once(m_node->m_config.download_chain_timeout);
	m_node->m_log(logging::INFO) << "advance_chain Requesting chain from " << get_address()
	                             << " remote height=" << get_peer_sync_data().current_height
	                             << " our height=" << m_node->m_block_chain.get_tip_height();
	BinaryArray raw_msg = LevinProtocol::send(msg);
	send(std::move(raw_msg));
}

void Node::P2PProtocolBytecoin::advance_blocks() {
	// Remove already added to the block chain
	while (!m_chain.empty() && m_node->m_block_chain.has_header(m_chain.front()->first) &&
	       m_chain.front()->second.who_downloading != this) {
		m_previous_chain_hash = m_chain.front()->first;
		m_chain_start_height += 1;
		m_node->remove_chain_block(m_chain.front());
		m_chain.pop_front();
	}
	if (m_downloading_block_count >= m_node->m_config.max_downloading_blocks_from_each_peer)
		return;
	size_t we_downloading = 0;
	std::vector<Hash> request_block_ids;
	for (size_t i = 0; i < std::min(m_chain.size(), m_node->m_config.download_window) &&
	                   we_downloading < m_node->m_config.max_downloading_blocks_from_each_peer;
	     ++i) {
		auto cit = m_chain.at(i);
		if (cit->second.who_downloading || cit->second.preparing) {
			we_downloading += (cit->second.who_downloading == this) ? 1 : 0;
			continue;
		}
		we_downloading += 1;
		cit->second.who_downloading = this;
		cit->second.expected_height = static_cast<Height>(m_chain_start_height + i);
		m_downloading_block_count += 1;
		request_block_ids.push_back(cit->first);
		const auto now = std::chrono::steady_clock::now();
		if (std::chrono::duration_cast<std::chrono::milliseconds>(now - m_node->log_request_timestamp).count() > 1000) {
			m_node->log_request_timestamp = now;
			std::cout << "Requesting block " << m_chain_start_height + i << " from " << get_address() << std::endl;
		}
		m_node->m_log(logging::TRACE) << "advance_download requesting block " << m_chain_start_height + i
		                              << " hash=" << cit->first << " from " << get_address();
	}
	if (!request_block_ids.empty())
		m_download_timer.once(m_node->m_config.download_block_timeout);
	for (const auto &bid : request_block_ids) {
		p2p::GetObjects::Request msg;
		msg.blocks.push_back(bid);
		send(LevinProtocol::send(msg));
	}
}

void Node::P2PProtocolBytecoin::advance_transactions() {
	if (get_peer_sync_data().top_id != m_node->m_block_chain.get_tip_bid())
		return;
	if (!m_syncpool_request_sent) {
		p2p::SyncPool::Request msg;
		msg.from     = syncpool_start;
		msg.to.first = m_node->m_block_chain.minimum_pool_fee_per_byte(true, &msg.to.second);
		if (msg.from <= msg.to)
			return;
		m_syncpool_request_sent = true;
		m_syncpool_timer.once(m_node->m_config.sync_pool_timeout);
		m_node->m_log(logging::TRACE) << "Sending SyncPool to " << get_address()
		                              << " with fee_per_byte=" << msg.from.first << " hash=" << msg.from.second;
		send(LevinProtocol::send(msg));
		return;
	}
}

bool Node::P2PProtocolBytecoin::on_transaction_descs(const std::vector<TransactionDesc> &descs) {
	const auto &pool   = m_node->m_block_chain.get_memory_state_transactions();
	Amount minimum_fee = m_node->m_block_chain.minimum_pool_fee_per_byte(true);
	//	Amount previous_fee_per_byte = std::numeric_limits<Amount>::max();
	//	Hash previous_hash;
	// TODO - check that descs are in limits set at request
	std::vector<TransactionDesc> request_transaction_descs;
	for (const auto &desc : descs) {
		if (desc.size == 0) {
			disconnect("SyncPool desc size == 0");
			return false;
		}
		Amount fee_per_byte = desc.fee / desc.size;
		//		TODO - uncomment when no 3.4.0 version is running in the wild
		//		if (fee_per_byte > previous_fee_per_byte ||
		//		    (fee_per_byte == previous_fee_per_byte && desc.hash >= previous_hash)) {
		//			disconnect("SyncPool descs not sorted");
		//			return false;
		//		}
		//		previous_hash         = desc.hash;
		//		previous_fee_per_byte = fee_per_byte;
		if (fee_per_byte < minimum_fee)
			continue;
		if (!m_node->m_block_chain.in_chain(desc.newest_referenced_block))
			continue;
		if (pool.count(desc.hash) != 0 || m_node->m_block_chain.has_transaction(desc.hash))
			continue;
		if (m_transaction_descs.count(desc.hash) != 0)
			continue;  // Already have
		if (m_node->downloading_transactions.count(desc.hash) != 0)
			continue;  // Already downloading
		request_transaction_descs.push_back(desc);
	}
	//	TODO - remove sort when no 3.4.0 version is running in the wild
	std::sort(request_transaction_descs.begin(), request_transaction_descs.end(), greater_fee_per_byte);
	if (!request_transaction_descs.empty())
		m_download_transactions_timer.once(m_node->m_config.download_transaction_timeout);
	m_downloading_transaction_count += request_transaction_descs.size();
	for (const auto &desc : request_transaction_descs) {
		invariant(m_transaction_descs.insert(std::make_pair(desc.hash, desc)).second, "");
		invariant(m_node->downloading_transactions.insert(std::make_pair(desc.hash, this)).second, "");
		p2p::GetObjects::Request msg;
		msg.txs.push_back(desc.hash);
		send(LevinProtocol::send(msg));
	}
	return true;
}

void Node::P2PProtocolBytecoin::transaction_download_finished(const Hash &tid, bool success) {
	auto tit = m_transaction_descs.find(tid);
	if (tit == m_transaction_descs.end())
		return;
	if (success) {
		tit = m_transaction_descs.erase(tit);
		return;
	}
	if (!m_node->downloading_transactions.insert(std::make_pair(tid, this)).second)
		return;  // Someone already started downloading it
	m_downloading_transaction_count += 1;
	m_download_transactions_timer.once(m_node->m_config.download_transaction_timeout);
	p2p::GetObjects::Request msg;
	msg.txs.push_back(tid);
	send(LevinProtocol::send(msg));
}

bool Node::P2PProtocolBytecoin::on_idle(std::chrono::steady_clock::time_point idle_start) {
	size_t added_counter                                 = 0;
	boost::variant<ConsensusError, PreparedBlock> result = ConsensusError{""};
	while (!m_chain.empty() && m_node->m_pow_checker.get_prepared_block(m_chain.front()->first, &result)) {
		auto cit = m_chain.front();
		m_node->m_log(logging::TRACE) << "on_idle prepared block " << cit->second.expected_height
		                              << " hash=" << cit->first << " from " << get_address();
		if (const ConsensusError *err = boost::get<ConsensusError>(&result)) {
			m_node->m_log(logging::INFO) << "on_idle prepared block consensus error what=" << err->what();
			disconnect(std::string{"on_idle prepared what="} + err->what());
			return false;
		}
		const PreparedBlock &pb = boost::get<PreparedBlock>(result);
		invariant(pb.bid == cit->first, "");
		invariant(cit->second.who_downloading == nullptr, "");
		m_previous_chain_hash = cit->first;
		m_chain_start_height += 1;
		m_chain.pop_front();
		const Height expected_height = cit->second.expected_height;
		cit->second.preparing        = false;
		m_node->remove_chain_block(cit);

		api::BlockHeader info;
		bool add_block_result = false;
		try {
			add_block_result = m_node->m_block_chain.add_block(pb, &info, false, get_address().to_string());
		} catch (const std::exception &ex) {
			auto what = common::what(ex);
			m_node->m_log(logging::INFO) << "on_idle add_block BAN expected height=" << expected_height
			                             << " actual height=" << info.height << " wb=" << pb.bid << " what=" << what;
			disconnect("on_idle add_block BAN what=" + what);
			return false;
		}
		for (auto who : m_node->m_broadcast_protocols)
			who->advance_transactions();
		if (expected_height != info.height) {  // TODO - BAN
			m_node->m_log(logging::INFO) << "on_idle add_block lied about height, expected height " << expected_height
			                             << " actual height=" << info.height << " wb=" << pb.bid;
		}
		if (add_block_result) {
			if (m_chain.empty() ||
			    m_node->m_block_chain.get_tip_height() % m_node->m_config.download_broadcast_every_n_blocks == 0) {
				// We do not want to broadcast too often during download
				m_node->m_log(logging::INFO)
				    << "Added last (from batch) downloaded block height=" << info.height << " bid=" << info.hash;
				p2p::TimedSync::Notify req;
				req.payload_data =
				    CoreSyncData{m_node->m_block_chain.get_tip_height(), m_node->m_block_chain.get_tip_bid()};
				BinaryArray raw_msg = LevinProtocol::send(req);
				m_node->broadcast(
				    nullptr, raw_msg);  // nullptr - we can not always know which connection was block source
			}
		}
		added_counter += 1;
		auto idea_ms =
		    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - idle_start);
		if (idea_ms.count() > int(1000 * m_node->m_config.max_on_idle_time))
			break;
	}
	return !m_chain.empty() && m_node->m_pow_checker.has_prepared_block(m_chain.front()->first);
}

void Node::P2PProtocolBytecoin::after_handshake() {
	m_node->m_p2p.peers_updated();
	m_node->m_broadcast_protocols.insert(this);
	m_node->advance_long_poll();

	auto signed_checkpoints = m_node->m_block_chain.get_latest_checkpoints();
	for (const auto &sck : signed_checkpoints) {
		p2p::Checkpoint::Notify msg(sck);
		BinaryArray raw_msg = LevinProtocol::send(msg);
		send(std::move(raw_msg));
	}
	advance_transactions();  // We can be on the same height already, will sync pools then
	advance_chain();
}

void Node::P2PProtocolBytecoin::on_msg_handshake(p2p::Handshake::Request &&req) {
	m_node->m_peer_db->add_incoming_peer(get_address(), m_node->m_p2p.get_local_time());
	after_handshake();
}

void Node::P2PProtocolBytecoin::on_msg_handshake(p2p::Handshake::Response &&req) {
	m_node->m_peer_db->merge_peerlist_from_p2p(get_address(), req.local_peerlist, m_node->m_p2p.get_local_time());
	m_node->m_peer_db->merge_peerlist_from_p2p(get_address(), req.peerlist, m_node->m_p2p.get_local_time());
	after_handshake();
}

void Node::P2PProtocolBytecoin::on_msg_notify_request_chain(p2p::GetChain::Request &&req) {
	if (req.block_ids.size() > p2p::GetChain::Request::MAX_BLOCK_IDS)
		return disconnect("GetChainRequest too many block_ids");
	p2p::GetChain::Response msg;
	msg.m_block_ids = m_node->m_block_chain.get_sync_headers_chain(
	    req.block_ids, &msg.start_height, p2p::GetChain::Response::MAX_BLOCK_IDS);

	BinaryArray raw_msg = LevinProtocol::send(msg);
	send(std::move(raw_msg));
}

void Node::P2PProtocolBytecoin::on_msg_notify_request_chain(p2p::GetChain::Response &&req) {
	if (req.m_block_ids.size() > p2p::GetChain::Response::MAX_BLOCK_IDS)
		return disconnect("GetChainResponse too many block_ids");
	if (!m_chain_request_sent)
		return disconnect("GetChainResponse stray chain");
	if (req.m_block_ids.empty())  // TODO - add delay to advance_chain
		return disconnect("GetChainResponse chain");
	invariant(m_chain.empty(), "");
	m_chain_request_sent = false;
	m_chain_timer.cancel();
	m_node->m_log(logging::INFO) << "received chain from " << get_address() << " start_height=" << req.start_height
	                             << " length=" << req.m_block_ids.size();
	api::BlockHeader info;
	if (!m_node->m_block_chain.get_header(req.m_block_ids.front(), &info))
		return disconnect("Chain does not start with hash we have");
	m_chain_start_height = info.height;
	// TODO - prevent wrong order
	for (const auto &bid : req.m_block_ids) {
		if (m_node->m_block_chain.has_header(bid)) {
			m_chain_start_height += 1;
			m_previous_chain_hash = bid;
			continue;
		}
		m_chain.push_back(m_node->chain_blocks.insert(std::make_pair(bid, DownloadInfo{})).first);
		m_chain.back()->second.chain_counter += 1;
	}
	if (req.m_block_ids.size() != m_chain.size() + 1) {
		m_node->m_log(logging::INFO) << "truncated chain length=" << m_chain.size();
	}
	if (m_chain.empty()) {
		// TODO - add delay to advance_chain
		m_node->m_log(logging::INFO) << "truncated chain to zero from " << get_address();
		advance_chain();
		return;
	}
	advance_blocks();
}

void Node::P2PProtocolBytecoin::on_msg_notify_request_objects(p2p::GetObjects::Request &&req) {
	if (req.txs.size() + req.blocks.size() != 1)
		return disconnect("Must be 1 block or 1 transaction in GetObjectsRequest");
	p2p::GetObjects::Response msg;
	for (const auto &bid : req.blocks) {
		RawBlock raw_block;
		if (m_node->m_block_chain.get_block(bid, &raw_block)) {
			msg.blocks.push_back(std::move(raw_block));
			continue;
		}
		msg.missed_ids.push_back(bid);
	}
	for (const auto &tid : req.txs) {
		const auto &pool = m_node->m_block_chain.get_memory_state_transactions();
		auto tit         = pool.find(tid);
		if (tit != pool.end()) {
			msg.txs.push_back(tit->second.binary_tx);
			continue;
		}
		BinaryArray binary_tx;
		size_t index_in_block = 0;
		Height block_height   = 0;
		Hash block_hash;
		if (m_node->m_block_chain.get_transaction(tid, &binary_tx, &block_height, &block_hash, &index_in_block)) {
			msg.txs.push_back(std::move(binary_tx));
			continue;
		}
		msg.missed_ids.push_back(tid);
	}
	send(LevinProtocol::send(msg));
}

void Node::P2PProtocolBytecoin::on_msg_notify_request_objects(p2p::GetObjects::Response &&req) {
	if (req.blocks.size() + req.txs.size() + req.missed_ids.size() != 1)
		return disconnect("Too much objects in GetObjectsResponse");
	for (auto &&rb : req.blocks) {  // 0 or 1
		Hash bid;
		try {
			BlockTemplate bheader;
			seria::from_binary(bheader, rb.block);
			auto body_proxy = get_body_proxy_from_template(bheader);
			bid             = cn::get_block_hash(bheader, body_proxy);
		} catch (const std::exception &ex) {
			m_node->m_log(logging::INFO) << "Exception " << common::what(ex)
			                             << " while parsing returned block, banning " << get_address();
			disconnect("Bad Block Returned");
			return;
		}
		auto cit = m_node->chain_blocks.find(bid);
		if (cit == m_node->chain_blocks.end() || cit->second.who_downloading != this) {
			m_node->m_log(logging::INFO) << "GetObjectsResponse received stray block from " << get_address();
			disconnect("Stray Block Returned");
			return;
		}
		cit->second.who_downloading = nullptr;
		cit->second.preparing       = true;
		invariant(m_downloading_block_count > 0, "");
		m_downloading_block_count -= 1;
		m_node->m_log(logging::TRACE) << "GetObjectsResponse received block " << cit->second.expected_height
		                              << " hash=" << cit->first << " from " << get_address();
		bool check_pow = m_node->m_config.paranoid_checks ||
		                 !m_node->m_block_chain.get_currency().is_in_hard_checkpoint_zone(cit->second.expected_height);
		m_node->m_pow_checker.add_block(bid, check_pow, std::move(rb));
	}
	p2p::RelayTransactions::Notify msg_v4;
	for (const auto &btx : req.txs) {  // 0 or 1
		Transaction tx;
		try {
			seria::from_binary(tx, btx);
		} catch (const std::exception &ex) {
			return disconnect("Invalid transaction binary format " + common::what(ex));
		}
		const Hash tid = get_transaction_hash(tx);
		auto cit       = m_node->downloading_transactions.find(tid);
		if (cit == m_node->downloading_transactions.end() || cit->second != this) {
			m_node->m_log(logging::INFO) << "GetObjectsResponse received stray transaction from " << get_address();
			return disconnect("Stray Transaction Returned");
		}
		auto tit = m_transaction_descs.find(tid);
		invariant(tit != m_transaction_descs.end(), "");
		if (tit->second.size != btx.size())
			return disconnect("Lied about transcation size");
		Amount my_fee = get_tx_fee(tx);
		if (tit->second.fee != my_fee)
			return disconnect("Lied about transcation fee");
		if (m_node->m_block_chain.in_chain(tit->second.newest_referenced_block)) {
			Height newest_referenced_height = 0;
			if (!m_node->m_block_chain.get_largest_referenced_height(tx, &newest_referenced_height) ||
			    !m_node->m_block_chain.in_chain(newest_referenced_height, tit->second.newest_referenced_block))
				return disconnect("Lied about newest_referenced_block");
			try {
				if (m_node->m_block_chain.add_transaction(tid, tx, btx, true, get_address().to_string())) {
					TransactionDesc desc;
					desc.hash                    = tid;
					desc.size                    = btx.size();
					desc.fee                     = my_fee;
					desc.newest_referenced_block = tit->second.newest_referenced_block;
					if (desc.size != 0)  // Should always be true, but will exit process if not, so we double-check
						msg_v4.transaction_descs.push_back(desc);
				}
			} catch (const ConsensusErrorOutputDoesNotExist &ex) {
				// We are safe to ban for bad output reference, because we have newest referenced block
				return disconnect("NOTIFY_NEW_TRANSACTIONS add_transaction BAN what=" + common::what(ex));
			} catch (const ConsensusErrorBadOutputOrSignature &ex) {
				// We are safe to ban for bad signatures, because we have newest referenced block
				return disconnect("NOTIFY_NEW_TRANSACTIONS add_transaction BAN what=" + common::what(ex));
			} catch (const ConsensusErrorOutputSpent &) {
				// Not a ban reason
			} catch (const std::exception &ex) {
				return disconnect("NOTIFY_NEW_TRANSACTIONS add_transaction BAN what=" + common::what(ex));
			}
		}
		cit = m_node->downloading_transactions.erase(cit);
		tit = m_transaction_descs.erase(tit);
		invariant(m_downloading_transaction_count > 0, "");
		m_downloading_transaction_count -= 1;
		for (auto who : m_node->m_broadcast_protocols)
			if (who != this)
				who->transaction_download_finished(tid, true);
	}
	for (auto &&tid : req.missed_ids) {  // Here should be only transactions, we ask only block peer always has
		auto cit = m_node->downloading_transactions.find(tid);
		if (cit == m_node->downloading_transactions.end() || cit->second != this) {
			m_node->m_log(logging::INFO) << "GetObjectsResponse received stray missed_id from " << get_address();
			return disconnect("Stray Transaction Returned");
		}
		auto tit = m_transaction_descs.find(tid);
		invariant(tit != m_transaction_descs.end(), "");
		cit = m_node->downloading_transactions.erase(cit);
		tit = m_transaction_descs.erase(tit);
		invariant(m_downloading_transaction_count > 0, "");
		m_downloading_transaction_count -= 1;
		for (auto who : m_node->m_broadcast_protocols)
			if (who != this)
				who->transaction_download_finished(tid, false);
	}
	if (m_downloading_block_count != 0)
		m_download_timer.once(m_node->m_config.download_block_timeout);
	else
		m_download_timer.cancel();
	if (m_downloading_transaction_count != 0)
		m_download_transactions_timer.once(m_node->m_config.download_transaction_timeout);
	else
		m_download_transactions_timer.cancel();
	if (!msg_v4.transaction_descs.empty()) {
		// Contains exactly 1 transaction
		BinaryArray raw_msg_v4 = LevinProtocol::send(msg_v4);

		m_node->broadcast(this, raw_msg_v4);
		m_node->advance_long_poll();
	}
	if (!req.blocks.empty())
		advance_blocks();
}

void Node::P2PProtocolBytecoin::on_disconnect(const std::string &ban_reason) {
	m_node->m_broadcast_protocols.erase(this);

	m_chain_request_sent = false;
	m_chain_timer.cancel();

	for (const auto &cit : m_chain) {
		if (cit->second.who_downloading == this) {
			m_downloading_block_count -= 1;
			cit->second.who_downloading = nullptr;
		}
		m_node->remove_chain_block(cit);
	}
	m_chain.clear();
	m_download_timer.cancel();
	invariant(m_downloading_block_count == 0, "");

	m_syncpool_request_sent = false;
	m_syncpool_timer.cancel();
	for (auto const &cit : m_transaction_descs) {
		auto tit = m_node->downloading_transactions.find(cit.first);
		if (tit->second == this) {
			tit = m_node->downloading_transactions.erase(tit);
			m_downloading_transaction_count -= 1;
		}
		for (auto who : m_node->m_broadcast_protocols)
			who->transaction_download_finished(cit.first, false);
	}
	m_transaction_descs.clear();
	m_download_transactions_timer.cancel();
	invariant(m_downloading_transaction_count == 0, "");

	P2PProtocolBasic::on_disconnect(ban_reason);
	m_node->advance_long_poll();
}

void Node::P2PProtocolBytecoin::on_msg_notify_request_tx_pool(p2p::SyncPool::Request &&req) {
	if (req.from <= req.to)
		return disconnect("SyncPool request from <= to");
	p2p::SyncPool::Response msg;
	msg.transaction_descs = m_node->m_block_chain.sync_pool(req.from, req.to, p2p::SyncPool::Response::MAX_DESC_COUNT);
	send(LevinProtocol::send(msg));
}

void Node::P2PProtocolBytecoin::on_msg_notify_request_tx_pool(p2p::SyncPool::Response &&req) {
	m_syncpool_timer.cancel();
	m_syncpool_request_sent = false;
	if (req.transaction_descs.size() > p2p::SyncPool::Response::MAX_DESC_COUNT)
		return disconnect("SyncPool too much descs");
	if (!on_transaction_descs(req.transaction_descs))
		return;  // Disconnected
	if (req.transaction_descs.empty())
		syncpool_start = {0, Hash{}};
	else {
		// Divisions by zero here is impossible due to checks in on_transaction_descs
		Amount first_fee_per_byte = req.transaction_descs.front().fee / req.transaction_descs.front().size;
		if (std::make_pair(first_fee_per_byte, req.transaction_descs.front().hash) >= syncpool_start)
			return disconnect("SyncPool wrong chunk");
		Amount last_fee_per_byte = req.transaction_descs.back().fee / req.transaction_descs.back().size;
		syncpool_start           = std::make_pair(last_fee_per_byte, req.transaction_descs.back().hash);
	}
	advance_transactions();
}

void Node::P2PProtocolBytecoin::on_msg_timed_sync(p2p::TimedSync::Notify &&req) { advance_chain(); }

void Node::P2PProtocolBytecoin::on_msg_notify_new_block(p2p::RelayBlock::Notify &&req) {
	if (!req.b.transactions.empty())
		return disconnect("RelayBlock only header is allowed");
	if (m_node->m_block_chain.has_header(req.top_id))
		return;
	BlockTemplate header;
	seria::from_binary(header, req.b.block);
	const auto &pool = m_node->m_block_chain.get_memory_state_transactions();
	for (const auto &tid : header.transaction_hashes) {
		auto tit = pool.find(tid);
		if (tit != pool.end()) {
			req.b.transactions.push_back(tit->second.binary_tx);
			continue;
		}
		BinaryArray binary_tx;
		size_t index_in_block = 0;
		Height block_height   = 0;
		Hash block_hash;
		if (m_node->m_block_chain.get_transaction(tid, &binary_tx, &block_height, &block_hash, &index_in_block)) {
			req.b.transactions.push_back(std::move(binary_tx));
			continue;
		}
		// We cannot reassemble block from transactions, will download it normally
		set_peer_sync_data(CoreSyncData{req.current_blockchain_height, req.top_id});
		advance_chain();
		return;
	}
	// We reassembled full block, can now broadcast it to V1 or V4 clients
	PreparedBlock pb{RawBlock(req.b), m_node->m_block_chain.get_currency(), nullptr};
	if (req.top_id != pb.bid)
		return disconnect("RelayBlock lied about top_id");
	api::BlockHeader info;
	// We'll catch consensus error automatically in common handler
	if (m_node->m_block_chain.add_block(pb, &info, false, get_address().to_string())) {
		if (req.current_blockchain_height != info.height)
			return disconnect("RelayBlock lied about current_blockchain_height");
		set_peer_sync_data(CoreSyncData{info.height, pb.bid});
		p2p::RelayBlock::Notify req_v4;
		req_v4.b.block                   = req.b.block;
		req_v4.top_id                    = info.hash;
		req_v4.current_blockchain_height = info.height;

		BinaryArray raw_msg_v4 = LevinProtocol::send(req_v4);
		// TODO - broadcast to only those who do not have it
		m_node->broadcast(this, raw_msg_v4);
		m_node->advance_long_poll();
	} else {
		set_peer_sync_data(CoreSyncData{req.current_blockchain_height, pb.bid});
	}
}

void Node::P2PProtocolBytecoin::on_msg_notify_new_transactions(p2p::RelayTransactions::Notify &&req) {
	if (req.transaction_descs.size() > p2p::RelayTransactions::Notify::MAX_DESC_COUNT)
		return disconnect("RelayTransactions too much descs");
	on_transaction_descs(req.transaction_descs);
}

void Node::P2PProtocolBytecoin::on_msg_notify_checkpoint(p2p::Checkpoint::Notify &&req) {
	if (!m_node->m_block_chain.add_checkpoint(req, get_address().to_string()))
		return;
	m_node->m_log(logging::INFO) << "p2p::Checkpoint::Notify height=" << req.height << " hash=" << req.hash
	                             << " key_id=" << req.key_id << " counter=" << req.counter;
	BinaryArray raw_msg = LevinProtocol::send(req);
	m_node->broadcast(nullptr, raw_msg);  // nullptr, not this - so a sender sees "reflection" of message
	// TODO - investigate reason for TimedSync broadcast here
	p2p::TimedSync::Notify ts_req;
	ts_req.payload_data = CoreSyncData{m_node->m_block_chain.get_tip_height(), m_node->m_block_chain.get_tip_bid()};
	raw_msg             = LevinProtocol::send(ts_req);
	m_node->broadcast(nullptr, raw_msg);
	m_node->advance_long_poll();
}

#if bytecoin_ALLOW_DEBUG_COMMANDS

void Node::P2PProtocolBytecoin::on_msg_stat_info(p2p::GetStatInfo::Request &&req) {
	if (!m_node->check_trust(req.tr))
		return disconnect(std::string{});
	p2p::GetStatInfo::Response msg = m_node->create_statistics_response(api::cnd::GetStatistics::Request{true, true});
	while (true) {
		BinaryArray raw_msg = LevinProtocol::send(msg);
		if (raw_msg.size() <= p2p::GetStatInfo::Response::MAX_SIZE) {
			send(std::move(raw_msg));
			break;
		}
		if (msg.peer_list_white.size() >= msg.peer_list_gray.size() &&
		    msg.peer_list_white.size() >= msg.connected_peers.size()) {
			msg.peer_list_white.resize(msg.peer_list_white.size() / 2);
			continue;
		}
		if (msg.peer_list_gray.size() >= msg.peer_list_white.size() &&
		    msg.peer_list_gray.size() >= msg.connected_peers.size()) {
			msg.peer_list_gray.resize(msg.peer_list_gray.size() / 2);
			continue;
		}
		msg.connected_peers.resize(msg.connected_peers.size() / 2);
	}
}

#endif
