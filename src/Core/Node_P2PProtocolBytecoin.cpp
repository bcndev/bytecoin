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

Node::P2PProtocolBytecoin::~P2PProtocolBytecoin() {
	//	std::cout << "~P2PProtocolBytecoin this=" << std::hex << (size_t)this << std::dec << std::endl;
}

void Node::P2PProtocolBytecoin::on_msg_bytes(size_t, size_t) {  // downloaded. uploaded
	//    node->peers.on_peer_bytes(get_address(), downloaded, uploaded,
	//    node->p2p.get_local_time());
}

CORE_SYNC_DATA
Node::P2PProtocolBytecoin::get_sync_data() const {
	CORE_SYNC_DATA sync_data;
	sync_data.current_height = m_node->m_block_chain.get_tip_height();
	sync_data.top_id         = m_node->m_block_chain.get_tip_bid();
	return sync_data;
}

std::vector<PeerlistEntryLegacy> Node::P2PProtocolBytecoin::get_peers_to_share() const {
	auto result = m_node->m_peer_db.get_peerlist_to_p2p_legacy(
	    get_address(), m_node->m_p2p.get_local_time(), config.p2p_default_peers_in_handshake);
	return result;
}

void Node::P2PProtocolBytecoin::on_first_message_after_handshake() {
	// if we set just seen on handshake, we will keep connecting to seed nodes
	// forever
	m_node->m_peer_db.set_peer_just_seen(
	    get_last_received_unique_number(), get_address(), m_node->m_p2p.get_local_time());
}

void Node::P2PProtocolBytecoin::on_immediate_protocol_switch(unsigned char first_byte) {
#if bytecoin_NEWP2P
	// We ignore first_byte for now, because we have only 1 new protocol
	get_client()->set_protocol(std::make_unique<P2PProtocolBytecoinNew>(m_node, get_client()));
#endif
}

void Node::P2PProtocolBytecoin::after_handshake() {
	m_node->m_p2p.peers_updated();
	m_node->broadcast_protocols.insert(this);
	m_node->advance_long_poll();

	auto signed_checkpoints = m_node->m_block_chain.get_latest_checkpoints();
	for (const auto &sck : signed_checkpoints) {
		BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_CHECKPOINT::ID, LevinProtocol::encode(sck), false);
		send(std::move(raw_msg));
	}
	m_node->m_downloader.on_connect(this);  // Can destroy this...
}

void Node::P2PProtocolBytecoin::on_msg_handshake(COMMAND_HANDSHAKE::request &&req) {
#if bytecoin_NEWP2P
	if (get_version() == P2PProtocolVersion::V3_NEW && P2PProtocolVersion::V3_NEW == P2PProtocolVersion::CURRENT) {
		get_client()->set_protocol(std::make_unique<P2PProtocolBytecoinNew>(m_node, get_client()));
		return;
	}
#endif
	m_node->m_peer_db.add_incoming_peer(get_address(), m_node->m_p2p.get_local_time());
	after_handshake();
}

void Node::P2PProtocolBytecoin::on_msg_handshake(COMMAND_HANDSHAKE::response &&req) {
#if bytecoin_NEWP2P
	if (get_version() == P2PProtocolVersion::V3_NEW && P2PProtocolVersion::V3_NEW == P2PProtocolVersion::CURRENT) {
		get_client()->set_protocol(std::make_unique<P2PProtocolBytecoinNew>(m_node, get_client()));
		return;
	}
#endif
	m_node->m_peer_db.merge_peerlist_from_p2p(get_address(), req.local_peerlist, m_node->m_p2p.get_local_time());
	after_handshake();
}

void Node::P2PProtocolBytecoin::on_msg_notify_request_chain(NOTIFY_REQUEST_CHAIN::request &&req) {
	NOTIFY_RESPONSE_CHAIN_ENTRY::request msg;
	msg.m_block_ids = m_node->m_block_chain.get_sync_headers_chain(
	    req.block_ids, &msg.start_height, config.p2p_block_ids_sync_default_count);
	msg.total_height = m_node->m_block_chain.get_tip_height() + 1;

	BinaryArray raw_msg =
	    LevinProtocol::send_message(NOTIFY_RESPONSE_CHAIN_ENTRY::ID, LevinProtocol::encode(msg), false);
	send(std::move(raw_msg));
}

void Node::P2PProtocolBytecoin::on_msg_notify_request_chain(NOTIFY_RESPONSE_CHAIN_ENTRY::request &&req) {
	m_node->m_downloader.on_msg_notify_request_chain(this, req);
}

void Node::P2PProtocolBytecoin::on_msg_notify_request_objects(NOTIFY_REQUEST_GET_OBJECTS::request &&req) {
	NOTIFY_RESPONSE_GET_OBJECTS::request msg;
	msg.current_blockchain_height = m_node->m_block_chain.get_tip_height() + 1;
	for (auto &&bh : req.blocks) {
		RawBlock raw_block;
		if (m_node->m_block_chain.read_block(bh, &raw_block)) {
			msg.blocks.push_back(RawBlockLegacy{raw_block.block, raw_block.transactions});
		} else
			msg.missed_ids.push_back(bh);
	}
	if (!req.txs.empty()) {
		// TODO - remove after we are sure transactions are never asked
		throw std::runtime_error(
		    "Transactions asked in NOTIFY_REQUEST_GET_OBJECTS by " + common::ip_address_to_string(get_address().ip));
	}
	BinaryArray raw_msg =
	    LevinProtocol::send_message(NOTIFY_RESPONSE_GET_OBJECTS::ID, LevinProtocol::encode(msg), false);
	send(std::move(raw_msg));
}

void Node::P2PProtocolBytecoin::on_msg_notify_request_objects(NOTIFY_RESPONSE_GET_OBJECTS::request &&req) {
	m_node->m_downloader.on_msg_notify_request_objects(this, req);
}

void Node::P2PProtocolBytecoin::on_disconnect(const std::string &ban_reason) {
	m_node->broadcast_protocols.erase(this);
	m_node->m_downloader.on_disconnect(this);

	P2PProtocolBasic::on_disconnect(ban_reason);
	m_node->advance_long_poll();
}

void Node::P2PProtocolBytecoin::on_msg_notify_request_tx_pool(NOTIFY_REQUEST_TX_POOL::request &&req) {
	NOTIFY_NEW_TRANSACTIONS::request msg;
	auto mytxs = m_node->m_block_chain.get_memory_state_transactions();
	msg.txs.reserve(mytxs.size());
	std::sort(req.txs.begin(), req.txs.end());  // Should have been sorted on wire,
	                                            // checked here, but alas, legacy
	for (auto &&tx : mytxs) {
		auto it = std::lower_bound(req.txs.begin(), req.txs.end(), tx.first);
		if (it != req.txs.end() && *it == tx.first)
			continue;
		msg.txs.push_back(tx.second.binary_tx);
	}
	m_node->m_log(logging::TRACE) << "on_msg_notify_request_tx_pool from " << get_address()
	                              << " peer sent=" << req.txs.size() << " we are relaying=" << msg.txs.size()
	                              << std::endl;
	if (msg.txs.empty())
		return;
	BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_NEW_TRANSACTIONS::ID, LevinProtocol::encode(msg), false);
	send(std::move(raw_msg));
}

void Node::P2PProtocolBytecoin::on_msg_timed_sync(COMMAND_TIMED_SYNC::request &&req) {
	m_node->m_downloader.advance_download();
}
void Node::P2PProtocolBytecoin::on_msg_timed_sync(COMMAND_TIMED_SYNC::response &&req) {
	m_node->m_downloader.advance_download();
}

void Node::P2PProtocolBytecoin::on_msg_notify_new_block(NOTIFY_NEW_BLOCK::request &&req) {
	RawBlock raw_block{req.b.block, req.b.transactions};
	PreparedBlock pb(std::move(raw_block), m_node->m_block_chain.get_currency(), nullptr);
	api::BlockHeader info;
	auto action = m_node->m_block_chain.add_block(pb, &info, get_address().to_string());
	switch (action) {
	case BroadcastAction::BAN:
		disconnect("NOTIFY_NEW_BLOCK add_block BAN");
		return;
	case BroadcastAction::BROADCAST_ALL: {
		req.hop += 1;
		BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_NEW_BLOCK::ID, LevinProtocol::encode(req), false);
		m_node->broadcast(this, raw_msg);
		m_node->broadcast_new(nullptr, pb.raw_block.block);
		m_node->advance_long_poll();
		break;
	}
	case BroadcastAction::NOTHING:
		break;
	}
	set_last_received_sync_data(CORE_SYNC_DATA{req.current_blockchain_height - 1, pb.bid});
	// -1 is in legacy protocol
	m_node->m_downloader.advance_download();
}

void Node::P2PProtocolBytecoin::on_msg_notify_new_transactions(NOTIFY_NEW_TRANSACTIONS::request &&req) {
	if (m_node->m_block_chain_reader1 || m_node->m_block_chain_reader2 ||
	    m_node->m_block_chain.get_tip_height() < m_node->m_block_chain.internal_import_known_height())
		return;  // We cannot check tx while downloading anyway
	NOTIFY_NEW_TRANSACTIONS::request msg;
	Hash any_tid;
	for (auto &&raw_tx : req.txs) {
		Transaction tx;
		try {
			seria::from_binary(tx, raw_tx);
		} catch (const std::exception &ex) {
			disconnect("NOTIFY_NEW_TRANSACTIONS add_transaction BAN from_binary failed " + common::what(ex));
			return;
		}
		const Hash tid         = get_transaction_hash(tx);
		any_tid                = tid;
		Height conflict_height = 0;
		auto action            = m_node->m_block_chain.add_transaction(
		    tid, tx, raw_tx, m_node->m_p2p.get_local_time(), &conflict_height, get_address().to_string());
		switch (action) {
		case AddTransactionResult::BAN:
			disconnect("NOTIFY_NEW_TRANSACTIONS add_transaction BAN");
			return;
		case AddTransactionResult::BROADCAST_ALL:
			msg.txs.push_back(raw_tx);
			break;
		case AddTransactionResult::ALREADY_IN_POOL:
		case AddTransactionResult::INCREASE_FEE:
		case AddTransactionResult::FAILED_TO_REDO:
		case AddTransactionResult::OUTPUT_ALREADY_SPENT:
			break;
		}
	}
	m_node->m_log(logging::TRACE) << "on_msg_notify_new_transactions from " << get_address()
	                              << " got=" << req.txs.size() << " relaying=" << msg.txs.size()
	                              << (req.txs.size() > 1 ? " notify_tx_reply (?) " : " ")
	                              << (any_tid == Hash{} ? "" : common::pod_to_hex(any_tid)) << std::endl;
	if (msg.txs.empty())
		return;
	BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_NEW_TRANSACTIONS::ID, LevinProtocol::encode(msg), false);
	m_node->broadcast(this, raw_msg);
	//	m_node->broadcast_new(nullptr, ); // TODO - broadcast
	m_node->advance_long_poll();
}

void Node::P2PProtocolBytecoin::on_msg_notify_checkpoint(NOTIFY_CHECKPOINT::request &&req) {
	if (!m_node->m_block_chain.add_checkpoint(req, get_address().to_string()))
		return;
	m_node->m_log(logging::INFO) << "NOTIFY_CHECKPOINT::request height=" << req.height << " hash=" << req.hash
	                             << " key_id=" << req.key_id << " counter=" << req.counter << std::endl;
	BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_CHECKPOINT::ID, LevinProtocol::encode(req), false);
	m_node->broadcast(nullptr, raw_msg);  // nullptr, not this - so a sender sees "reflection" of message
	//    m_node->broadcast_new(nullptr, raw_msg); // nullptr, not this - so a sender sees "reflection" of message
	COMMAND_TIMED_SYNC::request ts_req;
	ts_req.payload_data = CORE_SYNC_DATA{m_node->m_block_chain.get_tip_height(), m_node->m_block_chain.get_tip_bid()};
	raw_msg             = LevinProtocol::send_message(COMMAND_TIMED_SYNC::ID, LevinProtocol::encode(ts_req), true);
	m_node->broadcast(nullptr, raw_msg);
	//    m_node->broadcast_new(nullptr, raw_msg); // ?
	m_node->advance_long_poll();
}

#if bytecoin_ALLOW_DEBUG_COMMANDS
void Node::P2PProtocolBytecoin::on_msg_network_state(COMMAND_REQUEST_NETWORK_STATE::request &&req) {
	if (!m_node->check_trust(req.tr)) {
		disconnect(std::string());
		return;
	}
	COMMAND_REQUEST_NETWORK_STATE::response msg;
	msg.local_time = m_node->m_p2p.get_local_time();
	msg.my_id      = get_unique_number();
	for (auto &&cc : m_node->m_downloader.get_good_clients()) {
		connection_entry item;
		item.is_income = cc.first->is_incoming();
		item.id        = cc.first->get_unique_number();
		item.adr.port  = cc.first->get_address().port;
		item.adr.ip    = ip_address_to_legacy(cc.first->get_address().ip);
		msg.connections_list.push_back(item);
	}
	BinaryArray raw_msg = LevinProtocol::send_reply(COMMAND_REQUEST_NETWORK_STATE::ID, LevinProtocol::encode(msg), 0);
	send(std::move(raw_msg));
}

void Node::P2PProtocolBytecoin::on_msg_stat_info(COMMAND_REQUEST_STAT_INFO::request &&req) {
	if (!m_node->check_trust(req.tr)) {
		disconnect(std::string());
		return;
	}
	COMMAND_REQUEST_STAT_INFO::response msg;
	for (auto &&pb : m_node->broadcast_protocols)
		if (pb->is_incoming())
			msg.incoming_connections_count += 1;
		else
			msg.connections_count += 1;
	for (auto &&pb : m_node->broadcast_protocols_new)
		if (pb->is_incoming())
			msg.incoming_connections_count += 1;
		else
			msg.connections_count += 1;
	msg.connections_count += msg.incoming_connections_count;
	msg.version         = app_version();
	msg.os_version      = platform::get_os_version_string();
	msg.payload_info    = CoreStatistics{};
	BinaryArray raw_msg = LevinProtocol::send_reply(COMMAND_REQUEST_STAT_INFO::ID, LevinProtocol::encode(msg), 0);
	send(std::move(raw_msg));
}

#endif
