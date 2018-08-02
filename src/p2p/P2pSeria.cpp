// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "CryptoNoteProtocolDefinitions.hpp"
#include "P2pProtocolDefinitions.hpp"
#include "P2pProtocolTypes.hpp"
#include "crypto/hash.hpp"
#include "seria/BinaryOutputStream.hpp"

crypto::Hash bytecoin::proof_of_trust::get_hash() const {
	std::string s;
	s.append(reinterpret_cast<const char *>(&peer_id), sizeof(peer_id));
	s.append(reinterpret_cast<const char *>(&time), sizeof(time));
	return crypto::cn_fast_hash(s.data(), s.size());
}

namespace seria {
template<typename T>
typename std::enable_if<std::is_standard_layout<T>::value>::type serialize_as_binary(
    std::vector<T> &value, common::StringView name, seria::ISeria &serializer) {
	serializer.object_key(name);
	std::string blob;
	if (serializer.is_input()) {
		serializer(blob);
		value.resize(blob.size() / sizeof(T));
		if (blob.size()) {
			memcpy(&value[0], blob.data(), blob.size());
		}
	} else {
		if (!value.empty()) {
			blob.assign(reinterpret_cast<const char *>(&value[0]), value.size() * sizeof(T));
		}
		serializer(blob);
	}
}

// P2pProtocolTypes
void ser(bytecoin::UUID &v, seria::ISeria &s) { s.binary(&v, sizeof(v)); }

void ser_members(bytecoin::PeerlistEntry &v, seria::ISeria &s) {
	seria_kv("adr", v.adr, s);
	seria_kv("id", v.id, s);
	seria_kv("last_seen", v.last_seen, s);
	//	uint64_t last_seen_64 = v.last_seen;
	//	seria_kv("last_seen", last_seen_64, s);
	//	if (s.is_input())
	//		v.last_seen = static_cast<uint32_t>(last_seen_64);
	//	seria_kv("reserved", v.reserved, s);
}

void ser_members(bytecoin::NetworkAddress &v, seria::ISeria &s) {
	seria_kv("ip", v.ip, s);
	seria_kv("port", v.port, s);
}

void ser_members(bytecoin::connection_entry &v, seria::ISeria &s) {
	seria_kv("adr", v.adr, s);
	seria_kv("id", v.id, s);
	seria_kv("is_income", v.is_income, s);
}

void ser_members(bytecoin::CoreStatistics &v, seria::ISeria &s) {
	seria::seria_kv("tx_pool_size", v.tx_pool_size, s);
	seria::seria_kv("blockchain_height", v.blockchain_height, s);
	seria::seria_kv("mining_speed", v.mining_speed, s);
	seria::seria_kv("alternative_blocks", v.alternative_blocks, s);
	seria::seria_kv("top_block_id_str", v.top_block_id_str, s);
}

// P2pProtocolDefinitions
void ser_members(bytecoin::network_config &v, seria::ISeria &s) {
	seria_kv("connections_count", v.connections_count, s);
	seria_kv("handshake_interval", v.handshake_interval, s);
	seria_kv("packet_max_size", v.packet_max_size, s);
	seria_kv("config_id", v.config_id, s);
}

void ser_members(bytecoin::basic_node_data &v, seria::ISeria &s) {
	seria_kv("network_id", v.network_id, s);
	if (s.is_input()) {
		v.version = 0;
	}
	seria_kv("version", v.version, s);
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("local_time", v.local_time, s);
	seria_kv("my_port", v.my_port, s);
}

void ser_members(bytecoin::CORE_SYNC_DATA &v, seria::ISeria &s) {
	if (s.is_input()) {
		uint32_t on_wire = 0;
		s.object_key("current_height");
		s(on_wire);
		v.current_height = on_wire - 1;
	} else {
		uint32_t on_wire = v.current_height + 1;
		s.object_key("current_height");
		s(on_wire);
	}
	seria_kv("top_id", v.top_id, s);
}

void ser_members(bytecoin::COMMAND_HANDSHAKE::request &v, seria::ISeria &s) {
	seria_kv("node_data", v.node_data, s);
	seria_kv("payload_data", v.payload_data, s);
}

void ser_members(bytecoin::COMMAND_HANDSHAKE::response &v, seria::ISeria &s) {
	seria_kv("node_data", v.node_data, s);
	seria_kv("payload_data", v.payload_data, s);
	serialize_as_binary(v.local_peerlist, "local_peerlist", s);
}

void ser_members(bytecoin::COMMAND_TIMED_SYNC::request &v, seria::ISeria &s) {
	seria_kv("payload_data", v.payload_data, s);
}

void ser_members(bytecoin::COMMAND_TIMED_SYNC::response &v, seria::ISeria &s) {
	seria_kv("local_time", v.local_time, s);
	seria_kv("payload_data", v.payload_data, s);
	serialize_as_binary(v.local_peerlist, "local_peerlist", s);
}

void ser_members(bytecoin::COMMAND_PING::request &v, seria::ISeria &s) {}

void ser_members(bytecoin::COMMAND_PING::response &v, seria::ISeria &s) {
	seria_kv("status", v.status, s);
	seria_kv("peer_id", v.peer_id, s);
}

#if bytecoin_ALLOW_DEBUG_COMMANDS
void ser_members(bytecoin::proof_of_trust &v, seria::ISeria &s) {
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("time", v.time, s);
	seria_kv("sign", v.sign, s);
}

void ser_members(bytecoin::COMMAND_REQUEST_STAT_INFO::request &v, seria::ISeria &s) { seria_kv("tr", v.tr, s); }

void ser_members(bytecoin::COMMAND_REQUEST_STAT_INFO::response &v, seria::ISeria &s) {
	seria_kv("version", v.version, s);
	seria_kv("os_version", v.os_version, s);
	seria_kv("connections_count", v.connections_count, s);
	seria_kv("incoming_connections_count", v.incoming_connections_count, s);
	seria_kv("payload_info", v.payload_info, s);
}

void ser_members(bytecoin::COMMAND_REQUEST_NETWORK_STATE::request &v, seria::ISeria &s) { seria_kv("tr", v.tr, s); }

void ser_members(bytecoin::COMMAND_REQUEST_NETWORK_STATE::response &v, seria::ISeria &s) {
	serialize_as_binary(v.local_peerlist_white, "local_peerlist_white", s);
	serialize_as_binary(v.local_peerlist_gray, "local_peerlist_gray", s);
	serialize_as_binary(v.connections_list, "connections_list", s);
	seria_kv("my_id", v.my_id, s);
	seria_kv("local_time", v.local_time, s);
}
#endif

// CryptoNoteProtocolDefinitions
void ser_members(bytecoin::RawBlockLegacy &v, seria::ISeria &s) {
	std::string other_block;
	std::vector<std::string> other_transactions;
	if (s.is_input()) {
		seria::seria_kv("block", other_block, s);
		seria::seria_kv("txs", other_transactions, s);
		v.block.reserve(other_block.size());
		v.transactions.reserve(other_transactions.size());
		std::copy(other_block.begin(), other_block.end(), std::back_inserter(v.block));
		std::transform(other_transactions.begin(), other_transactions.end(), std::back_inserter(v.transactions),
		    [](const std::string &s) { return bytecoin::BinaryArray(s.data(), s.data() + s.size()); });
	} else {
		other_block.reserve(v.block.size());
		other_transactions.reserve(v.transactions.size());
		std::copy(v.block.begin(), v.block.end(), std::back_inserter(other_block));
		std::transform(v.transactions.begin(), v.transactions.end(), std::back_inserter(other_transactions),
		    [](bytecoin::BinaryArray &s) { return std::string(s.begin(), s.end()); });
		seria::seria_kv("block", other_block, s);
		seria::seria_kv("txs", other_transactions, s);
	}
}

void ser_members(bytecoin::NOTIFY_NEW_BLOCK::request &v, seria::ISeria &s) {
	seria_kv("b", v.b, s);
	seria_kv("current_blockchain_height", v.current_blockchain_height, s);
	seria_kv("hop", v.hop, s);
}

void ser_members(bytecoin::NOTIFY_NEW_TRANSACTIONS::request &v, seria::ISeria &s) {
	std::vector<std::string> transactions;
	if (s.is_input()) {
		seria::seria_kv("txs", transactions, s);
		v.txs.reserve(transactions.size());
		std::transform(transactions.begin(), transactions.end(), std::back_inserter(v.txs),
		    [](const std::string &s) { return bytecoin::BinaryArray(s.data(), s.data() + s.size()); });
	} else {
		transactions.reserve(v.txs.size());
		std::transform(v.txs.begin(), v.txs.end(), std::back_inserter(transactions),
		    [](const bytecoin::BinaryArray &s) { return std::string(s.begin(), s.end()); });
		seria::seria_kv("txs", transactions, s);
	}
}

void ser_members(bytecoin::NOTIFY_REQUEST_GET_OBJECTS::request &v, seria::ISeria &s) {
	serialize_as_binary(v.txs, "txs", s);
	serialize_as_binary(v.blocks, "blocks", s);
}

void ser_members(bytecoin::NOTIFY_RESPONSE_GET_OBJECTS::request &v, seria::ISeria &s) {
	seria_kv("txs", v.txs, s);
	seria_kv("blocks", v.blocks, s);
	serialize_as_binary(v.missed_ids, "missed_ids", s);
	seria_kv("current_blockchain_height", v.current_blockchain_height, s);
}

void ser_members(bytecoin::NOTIFY_REQUEST_CHAIN::request &v, seria::ISeria &s) {
	serialize_as_binary(v.block_ids, "block_ids", s);
}

void ser_members(bytecoin::NOTIFY_RESPONSE_CHAIN_ENTRY::request &v, seria::ISeria &s) {
	seria_kv("start_height", v.start_height, s);
	seria_kv("total_height", v.total_height, s);
	serialize_as_binary(v.m_block_ids, "m_block_ids", s);
}

void ser_members(bytecoin::NOTIFY_REQUEST_TX_POOL::request &v, seria::ISeria &s) {
	serialize_as_binary(v.txs, "txs", s);
}
}
