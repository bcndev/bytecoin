// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "P2pProtocolDefinitions.hpp"
#include "P2pProtocolTypes.hpp"
#include "common/Varint.hpp"
#include "crypto/hash.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/JsonOutputStream.hpp"

using namespace cn;

#if bytecoin_ALLOW_DEBUG_COMMANDS
Hash p2p::ProofOfTrust::get_hash() const {
	//	std::string s;
	//  time was uint64_t here, adjust if seriously need this legacy peice of code
	//	s.append(reinterpret_cast<const char *>(&peer_id), sizeof(peer_id));
	//	s.append(reinterpret_cast<const char *>(&time), sizeof(time));
	//	Hash old_hash = crypto::cn_fast_hash(s.data(), s.size());
	BinaryArray ba = seria::to_binary(*this);
	// We simplified proof of trust definition, because most likely
	// trusted key is lost and to update it software update is required anyway
	return crypto::cn_fast_hash(ba.data(), ba.size());
}
#endif

namespace seria {

// TODO - Endianness
template<typename T>
typename std::enable_if<std::is_standard_layout<T>::value>::type serialize_as_binary(
    std::vector<T> &value, common::StringView name, seria::ISeria &serializer) {
	serializer.object_key(name);
	std::string blob;
	if (serializer.is_input()) {
		ser(blob, serializer);
		value.resize(blob.size() / sizeof(T));
		if (!blob.empty())
			memcpy(&value[0], blob.data(), blob.size());
	} else {
		if (!value.empty())
			blob.assign(reinterpret_cast<const char *>(&value[0]), value.size() * sizeof(T));
		ser(blob, serializer);
	}
}

// P2pProtocolTypes
bool ser(UUID &v, seria::ISeria &s) { return s.binary(&v, sizeof(v)); }

void ser_members(PeerlistEntryLegacy &v, seria::ISeria &s) {
	seria_kv("adr", v.adr, s);
	seria_kv("id", v.id, s);
	seria_kv("last_seen", v.last_seen, s);
	//	uint64_t last_seen_64 = v.last_seen;
	//	seria_kv("last_seen", last_seen_64, s);
	//	if (s.is_input())
	//		v.last_seen = static_cast<uint32_t>(last_seen_64);
	//	seria_kv("reserved", v.reserved, s);
}

void ser_members(NetworkAddressLegacy &v, seria::ISeria &s) {
	seria_kv("ip", v.ip, s);
	seria_kv("port", v.port, s);
}

// void ser_members(connection_entry &v, seria::ISeria &s) {
//	seria_kv("adr", v.adr, s);
//	seria_kv("id", v.id, s);
//	seria_kv("is_income", v.is_income, s);
//}

// void ser_members(CoreStatistics &v, seria::ISeria &s) {
//	seria::seria_kv("tx_pool_size", v.tx_pool_size, s);
//	seria::seria_kv("blockchain_height", v.blockchain_height, s);
//	seria::seria_kv("mining_speed", v.mining_speed, s);
//	seria::seria_kv("alternative_blocks", v.alternative_blocks, s);
//	seria::seria_kv("top_block_id_str", v.top_block_id_str, s);
//}
void ser_members(CoreStatistics &v, seria::ISeria &s) {
	seria_kv("version", v.version, s);
	seria_kv("platform", v.platform, s);
	seria_kv("net", v.net, s);
	seria_kv("genesis_block_hash", v.genesis_block_hash, s);
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("start_time", v.start_time, s);
	seria_kv("checkpoints", v.checkpoints, s);
	seria_kv("transaction_pool_count", v.transaction_pool_count, s);
	seria_kv("transaction_pool_size", v.transaction_pool_size, s);
	seria_kv("transaction_pool_max_size", v.transaction_pool_max_size, s);
	seria_kv("transaction_pool_lowest_fee_per_byte", v.transaction_pool_lowest_fee_per_byte, s);
	seria_kv("upgrade_decided_height", v.upgrade_decided_height, s);
	seria_kv("upgrade_votes_in_top_block", v.upgrade_votes_in_top_block, s);
	seria_kv("peer_list_white", v.peer_list_white, s);
	seria_kv("peer_list_gray", v.peer_list_gray, s);
	seria_kv("connected_peers", v.connected_peers, s);
	seria_kv("node_database_size", v.node_database_size, s);
}

void ser_members(BasicNodeData &v, seria::ISeria &s) {
	seria_kv("network_id", v.network_id, s);
	seria_kv("version", v.version, s);
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("local_time", v.local_time, s);
	seria_kv("my_port", v.my_port, s);
}

void ser_kv_plus1(common::StringView name, Height &v, seria::ISeria &s) {
	if (s.is_input()) {
		Height on_wire = 0;
		s.object_key(name);
		ser(on_wire, s);
		v = on_wire - 1;
	} else {
		uint32_t on_wire = v + 1;
		s.object_key(name);
		ser(on_wire, s);
	}
}
void ser_members(CoreSyncData &v, seria::ISeria &s) {
	ser_kv_plus1("current_height", v.current_height, s);
	seria_kv("top_id", v.top_id, s);
}

void ser_members(p2p::Handshake::Request &v, seria::ISeria &s) {
	seria_kv("node_data", v.node_data, s);
	seria_kv("payload_data", v.payload_data, s);
}

void ser_members(p2p::Handshake::Response &v, seria::ISeria &s) {
	seria_kv("node_data", v.node_data, s);
	seria_kv("payload_data", v.payload_data, s);
	serialize_as_binary(v.local_peerlist, "local_peerlist", s);
}

void ser_members(p2p::TimedSync::Request &v, seria::ISeria &s) { seria_kv("payload_data", v.payload_data, s); }

void ser_members(p2p::TimedSync::Response &v, seria::ISeria &s) {
	seria_kv("local_time", v.local_time, s);
	seria_kv("payload_data", v.payload_data, s);
	serialize_as_binary(v.local_peerlist, "local_peerlist", s);
}

void ser_members(p2p::PingLegacy::Request &v, seria::ISeria &s) {}

void ser_members(p2p::PingLegacy::Response &v, seria::ISeria &s) {
	seria_kv("status", v.status, s);
	seria_kv("peer_id", v.peer_id, s);
}

#if bytecoin_ALLOW_DEBUG_COMMANDS
void ser_members(p2p::ProofOfTrust &v, seria::ISeria &s) {
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("time", v.time, s);
	seria_kv("sign", v.sign, s);
}

void ser_members(p2p::GetStatInfo::Request &v, seria::ISeria &s) {
	seria_kv("tr", v.tr, s);
	seria_kv("need_peer_lists", v.need_peer_lists, s);
}

/*void ser_members(p2p::GetStatInfo::Response &v, seria::ISeria &s) {
    seria_kv("version", v.version, s);
    seria_kv("os_version", v.os_version, s);
    seria_kv("connections_count", v.connections_count, s);  // "*s_count" will be removed together with legacy P2P
    seria_kv("incoming_connections_count", v.incoming_connections_count,
        s);  // "*s_count" will be removed together with legacy P2P
    seria_kv("payload_info", v.payload_info, s);
}

void ser_members(COMMAND_REQUEST_NETWORK_STATE::Request &v, seria::ISeria &s) { seria_kv("tr", v.tr, s); }

void ser_members(COMMAND_REQUEST_NETWORK_STATE::Response &v, seria::ISeria &s) {
    serialize_as_binary(v.local_peerlist_white, "local_peerlist_white", s);
    serialize_as_binary(v.local_peerlist_gray, "local_peerlist_gray", s);
    serialize_as_binary(v.connections_list, "connections_list", s);
    seria_kv("my_id", v.my_id, s);
    seria_kv("local_time", v.local_time, s);
}*/
#endif

void ser_members(p2p::RelayBlock::Notify &v, seria::ISeria &s) {
	seria_kv("b", v.b, s);
	ser_kv_plus1("current_blockchain_height", v.current_blockchain_height, s);
	if (s.is_input() || v.top_id != Hash{})  // TODO - remove after 3.4 fork, this is workaround of bug in 3.2
		seria_kv("top_id", v.top_id, s);
	seria_kv("hop", v.hop, s);
}

void ser_members(p2p::RelayTransactions::Notify &v, seria::ISeria &s) {
	seria::seria_kv("txs", v.txs, s);
	if (s.is_input() | !v.transaction_descs.empty())  // TODO - remove after 3.4 fork
		seria::seria_kv("transaction_descs", v.transaction_descs, s);
}

void ser_members(p2p::GetObjectsRequest::Notify &v, seria::ISeria &s) {
	serialize_as_binary(v.txs, "txs", s);
	serialize_as_binary(v.blocks, "blocks", s);
}

void ser_members(p2p::GetObjectsResponse::Notify &v, seria::ISeria &s) {
	seria_kv("txs", v.txs, s);
	seria_kv("blocks", v.blocks, s);
	serialize_as_binary(v.missed_ids, "missed_ids", s);
	ser_kv_plus1("current_blockchain_height", v.current_blockchain_height, s);
}

void ser_members(p2p::GetChainRequest::Notify &v, seria::ISeria &s) {
	serialize_as_binary(v.block_ids, "block_ids", s);
}

void ser_members(p2p::GetChainResponse::Notify &v, seria::ISeria &s) {
	seria_kv("start_height", v.start_height, s);
	ser_kv_plus1("total_height", v.total_height, s);
	serialize_as_binary(v.m_block_ids, "m_block_ids", s);
}

void ser_members(p2p::SyncPool::Notify &v, seria::ISeria &s) { serialize_as_binary(v.txs, "txs", s); }
void ser_members(p2p::SyncPool::Request &v, seria::ISeria &s) {
	seria_kv("from_fee_per_byte", v.from.first, s);
	seria_kv("from_hash", v.from.second, s);
	seria_kv("to_fee_per_byte", v.to.first, s);
	seria_kv("to_hash", v.to.second, s);
}
void ser_members(p2p::SyncPool::Response &v, seria::ISeria &s) {
	seria_kv("transaction_descs", v.transaction_descs, s);
}

bool ser(NetworkAddress &v, seria::ISeria &s) {
	if (dynamic_cast<seria::JsonOutputStream *>(&s)) {
		std::string str = common::ip_address_and_port_to_string(v.ip, v.port);
		return ser(str, s);
	}
	if (dynamic_cast<seria::JsonInputStream *>(&s)) {
		std::string str;
		if (!ser(str, s))
			return false;
		common::parse_ip_address_and_port(str, &v.ip, &v.port);
		return true;
	}
	bool result = s.begin_object();
	seria_kv("ip", v.ip, s);
	seria_kv("port", v.port, s);
	s.end_object();
	return result;
}
void ser_members(PeerlistEntry &v, seria::ISeria &s) {
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("last_seen", v.last_seen, s);
	seria_kv("address", v.address, s);
	seria_kv("ban_until", v.ban_until, s);
	seria_kv("ban_reason", v.ban_reason, s);
}
void ser_members(ConnectionDesc &v, seria::ISeria &s) {
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("address", v.address, s);
	seria_kv("is_incoming", v.is_incoming, s);
	seria_kv("p2p_version", v.p2p_version, s);
	seria_kv("top_block_desc", v.top_block_desc, s);
}
void ser_members(TopBlockDesc &v, seria::ISeria &s) {
	seria_kv("hash", v.hash, s);
	seria_kv("height", v.height, s);
	seria_kv("cumulative_difficulty", v.cd.lo, s);
	seria_kv_optional("cumulative_difficulty_hi", v.cd.hi, s);
}
void ser_members(TransactionDesc &v, seria::ISeria &s) {
	seria_kv("hash", v.hash, s);
	seria_kv("fee", v.fee, s);
	seria_kv("size", v.size, s);
	seria_kv("nrb", v.newest_referenced_block, s);
}
}  // namespace seria
