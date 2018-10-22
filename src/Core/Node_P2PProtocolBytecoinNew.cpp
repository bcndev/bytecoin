// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <boost/algorithm/string.hpp>
#include <iostream>
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "Node.hpp"
#include "TransactionExtra.hpp"
#include "common/JsonValue.hpp"
#include "platform/PathTools.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"
#include "version.hpp"

using namespace bytecoin;

void Node::P2PProtocolBytecoinNew::on_download_timer() { disconnect(std::string()); }

np::TopBlockDesc Node::P2PProtocolBytecoinNew::get_top_block_desc() const {
	np::TopBlockDesc result;
	result.cd     = m_node->m_block_chain.get_tip_cumulative_difficulty();
	result.height = m_node->m_block_chain.get_tip_height();
	result.hash   = m_node->m_block_chain.get_tip_bid();
	return result;
}

std::vector<NetworkAddress> Node::P2PProtocolBytecoinNew::get_peers_to_share() const {
	auto result = m_node->m_peer_db.get_peerlist_to_p2p(
	    get_address(), m_node->m_p2p.get_local_time(), m_node->m_config.p2p_default_peers_in_handshake);
	return result;
}

void Node::P2PProtocolBytecoinNew::on_first_message_after_handshake() {
	// if we set just seen on handshake, we will keep connecting to seed nodes forever
	m_node->m_peer_db.set_peer_just_seen(get_other_peer_desc().peer_id, get_address(), m_node->m_p2p.get_local_time());
}

void Node::P2PProtocolBytecoinNew::on_disconnect(const std::string &ban_reason) {
	m_node->broadcast_protocols_new.erase(this);
	m_node->m_downloader_v3.on_disconnect(this);

	P2PProtocolNew::on_disconnect(ban_reason);
	m_node->advance_long_poll();
}

void Node::P2PProtocolBytecoinNew::on_msg_bytes(size_t, size_t) {  // downloaded. uploaded
	                                                               //	P2PProtocolNew::on_msg_bytes(, );
}
void Node::P2PProtocolBytecoinNew::after_handshake() {
	m_node->m_p2p.peers_updated();
	m_node->broadcast_protocols_new.insert(this);
	m_node->advance_long_poll();

	auto signed_checkpoints = m_node->m_block_chain.get_latest_checkpoints();
	for (const auto &sck : signed_checkpoints) {
		BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_CHECKPOINT::ID, LevinProtocol::encode(sck), false);
		send(std::move(raw_msg));
	}
	m_node->m_downloader_v3.on_connect(this);  // Can destroy this...
}

void Node::P2PProtocolBytecoinNew::on_msg_handshake(np::Handshake::Request &&req) {
	m_node->m_peer_db.add_incoming_peer(get_address(), m_node->m_p2p.get_local_time());
	after_handshake();
}
void Node::P2PProtocolBytecoinNew::on_msg_handshake(np::Handshake::Response &&req) {
	m_node->m_peer_db.merge_peerlist_from_p2p(get_address(), req.peerlist, m_node->m_p2p.get_local_time());
	after_handshake();
}
void Node::P2PProtocolBytecoinNew::on_msg_find_diff(np::FindDiff::Request &&req) {
	np::FindDiff::Response fd;
	if (req.gap_start.size() > np::FindDiff::Request::MAX_GAP_START_LENGTH || req.gap_start.size() == 0)
		return disconnect("FindDiff.Request.gap_start.size violation");
	for (Hash gap : req.gap_start) {
		fd.sparse_chain = m_node->m_block_chain.get_sparse_chain(gap, req.desired_bid);
		if (fd.sparse_chain.empty())
			continue;
		BinaryArray msg = seria::to_binary_kv(fd);
		send(create_header(np::FindDiff::Response::ID, msg.size()));
		send(std::move(msg));
	}
	disconnect("FindDiff Request protocol violation - no hash from req.gap_start found in blockchain");
}
void Node::P2PProtocolBytecoinNew::on_msg_find_diff(np::FindDiff::Response &&resp) {
	m_node->m_downloader_v3.on_msg_find_diff(this, std::move(resp));
}
void Node::P2PProtocolBytecoinNew::on_msg_sync_headers(np::SyncHeaders::Request &&req) {
	if (req.max_count > np::SyncHeaders::Request::MAX_COUNT)
		return disconnect("SyncHeaders.Request.max_count violation");
	api::BlockHeader previous_header;
	if (!m_node->m_block_chain.read_header(req.previous_hash, &previous_header))
		return disconnect("SyncHeaders.Request.previous_hash block not found");
	np::SyncHeaders::Response res;
	if (m_node->m_block_chain.in_chain(previous_header.height, previous_header.hash)) {
		for (Height ha = previous_header.height + 1; ha < m_node->m_block_chain.get_tip_height(); ++ha) {
			if (res.binary_headers.size() >= req.max_count)
				break;
			Hash bid;
			invariant(m_node->m_block_chain.read_chain(ha, &bid), "");
			RawBlock rb;
			invariant(m_node->m_block_chain.read_block(bid, &rb), "SyncHeaders.Request block not found");
			res.binary_headers.push_back(rb.block);
		}
	}
	BinaryArray msg = seria::to_binary_kv(res);
	send(create_header(np::SyncHeaders::Response::ID, msg.size()));
	send(std::move(msg));
}
void Node::P2PProtocolBytecoinNew::on_msg_sync_headers(np::SyncHeaders::Response &&resp) {
	m_node->m_downloader_v3.on_msg_sync_headers(this, std::move(resp));
}
void Node::P2PProtocolBytecoinNew::on_msg_get_transactions(np::GetTransactions::Request &&req) {
	if (req.transaction_hashes.size() > np::GetTransactions::Request::MAX_TRANSACTION_HASHES)
		return disconnect("MAX_TRANSACTION_HASHES");
	np::GetTransactions::Response fd;
	fd.top_block_desc = get_top_block_desc();
	if (req.transaction_hashes.empty()) {
		RawBlock rb;
		if (m_node->m_block_chain.read_block(req.block_hash, &rb)) {
			fd.transactions = std::move(rb.transactions);
		}
	} else {
		fd.transactions.reserve(req.transaction_hashes.size());
		for (auto &&tid : req.transaction_hashes) {
			BinaryArray binary_tx;
			Height block_height = 0;
			Hash block_hash;
			size_t index_in_block = 0;
			if (m_node->m_block_chain.read_transaction(tid, &binary_tx, &block_height, &block_hash, &index_in_block)) {
				fd.transactions.push_back(std::move(binary_tx));
			}
		}
	}
	BinaryArray msg = seria::to_binary_kv(fd);
	send(create_header(np::GetTransactions::Response::ID, msg.size()));
	send(std::move(msg));
}
void Node::P2PProtocolBytecoinNew::on_msg_get_transactions(np::GetTransactions::Response &&resp) {
	m_node->m_downloader_v3.on_msg_get_transactions(this, std::move(resp));
}
void Node::P2PProtocolBytecoinNew::on_msg_get_pool_hashes(np::GetPoolHashes::Request &&req) {}
void Node::P2PProtocolBytecoinNew::on_msg_get_pool_hashes(np::GetPoolHashes::Response &&resp) {}
void Node::P2PProtocolBytecoinNew::on_msg_relay_block_header(np::RelayBlockHeader &&req) {}
void Node::P2PProtocolBytecoinNew::on_msg_relay_transaction_desc(np::RelayTransactionDescs &&req) {}

#if bytecoin_ALLOW_DEBUG_COMMANDS
void Node::P2PProtocolBytecoinNew::on_msg_get_peer_statistics(np::GetPeerStatistics::Request &&req) {
	if (!m_node->check_trust(req.tr))
		return disconnect(std::string());
	np::GetPeerStatistics::Response res;
	res             = m_node->create_statistics_response();
	BinaryArray msg = seria::to_binary_kv(res);
	send(create_header(np::GetPeerStatistics::Response::ID, msg.size()));
	send(std::move(msg));
}
#endif
