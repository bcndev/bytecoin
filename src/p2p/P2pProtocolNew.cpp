// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "P2pProtocolNew.hpp"
#include "crypto/hash.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/JsonInputStream.hpp"
#include "seria/JsonOutputStream.hpp"

using namespace bytecoin;

#if bytecoin_ALLOW_DEBUG_COMMANDS
Hash np::ProofOfTrust::get_hash() const {
	BinaryArray ba = seria::to_binary(*this);
	return crypto::cn_fast_hash(ba.data(), ba.size());
}
#endif

std::string NetworkAddress::to_string() const { return common::ip_address_and_port_to_string(ip, port); }

namespace seria {

void ser(NetworkAddress &v, seria::ISeria &s) {
	if (dynamic_cast<seria::JsonOutputStream *>(&s)) {
		std::string str = common::ip_address_and_port_to_string(v.ip, v.port);
		ser(str, s);
	} else if (dynamic_cast<seria::JsonInputStream *>(&s)) {
		std::string str;
		ser(str, s);
		if (!common::parse_ip_address_and_port(str, &v.ip, &v.port))
			throw std::runtime_error("Failed to parse ip address and port from " + str);
	} else {
		s.begin_object();
		seria_kv("ip", v.ip, s);
		seria_kv("port", v.port, s);
		s.end_object();
	}
}
void ser_members(PeerlistEntry &v, seria::ISeria &s) {
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("last_seen", v.last_seen, s);
	seria_kv("address", v.address, s);
	seria_kv("ban_until", v.ban_until, s);
	seria_kv("ban_reason", v.ban_reason, s);
}
void ser_members(np::ConnectionDesc &v, seria::ISeria &s) {
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("address", v.address, s);
	seria_kv("is_incoming", v.is_incoming, s);
	seria_kv("p2p_version", v.p2p_version, s);
	seria_kv("top_block_desc", v.top_block_desc, s);
}
void ser_members(np::PeerDesc &v, seria::ISeria &s) {
	seria_kv("p2p_version", v.p2p_version, s);
	seria_kv("genesis_block_hash", v.genesis_block_hash, s);
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("local_time", v.local_time, s);
	seria_kv("p2p_external_port", v.p2p_external_port, s);
}
void ser_members(np::TopBlockDesc &v, seria::ISeria &s) {
	seria_kv("hash", v.hash, s);
	seria_kv("height", v.height, s);
	seria_kv("cumulative_difficulty", v.cd.lo, s);
	seria_kv_optional("cumulative_difficulty_hi", v.cd.hi, s);
}
void ser_members(np::TransactionDesc &v, seria::ISeria &s) {
	seria_kv("hash", v.hash, s);
	seria_kv("fee", v.fee, s);
	seria_kv("size", v.size, s);
	seria_kv("nrb", v.newest_referenced_block, s);
}
void ser_members(np::Handshake::Request &v, seria::ISeria &s) {
	seria_kv("peer_desc", v.peer_desc, s);
	seria_kv("top_block_desc", v.top_block_desc, s);
}
void ser_members(np::Handshake::Response &v, seria::ISeria &s) {
	seria_kv("peer_desc", v.peer_desc, s);
	seria_kv("top_block_desc", v.top_block_desc, s);
	seria_kv("peerlist", v.peerlist, s);
}
void ser_members(np::FindDiff::Request &v, seria::ISeria &s) {
	seria_kv("gap_start", v.gap_start, s);
	seria_kv("desired_bid", v.desired_bid, s);
}
void ser_members(np::FindDiff::Response &v, seria::ISeria &s) { seria_kv("sparse_chain", v.sparse_chain, s); }
void ser_members(np::SyncHeaders::Request &v, seria::ISeria &s) {
	seria_kv("previous_hash", v.previous_hash, s);
	seria_kv("max_count", v.max_count, s);
}
void ser_members(np::SyncHeaders::Response &v, seria::ISeria &s) { seria_kv("binary_headers", v.binary_headers, s); }
void ser_members(np::GetTransactions::Request &v, seria::ISeria &s) {
	seria_kv("transaction_hashes", v.transaction_hashes, s);
	seria_kv("block_hash", v.block_hash, s);
}
void ser_members(np::GetTransactions::Response &v, seria::ISeria &s) {
	seria_kv("top_block_desc", v.top_block_desc, s);
	seria_kv("transactions", v.transactions, s);
}
void ser_members(np::GetPoolHashes::Request &v, seria::ISeria &s) {
	seria_kv("min_fee_per_byte", v.min_fee_per_byte, s);
	seria_kv("start_fee_per_byte", v.start_fee_per_byte, s);
	seria_kv("start_hash", v.start_hash, s);
	seria_kv("max_total_size", v.max_total_size, s);
	seria_kv("max_total_count", v.max_total_count, s);
}
void ser_members(np::GetPoolHashes::Response &v, seria::ISeria &s) {
	seria_kv("top_block_desc", v.top_block_desc, s);
	seria_kv("transaction_descs", v.transaction_descs, s);
}
void ser_members(np::RelayBlockHeader &v, seria::ISeria &s) {
	seria_kv("top_block_desc", v.top_block_desc, s);
	seria_kv("binary_header", v.binary_header, s);
}

void ser_members(np::RelayTransactionDescs &v, seria::ISeria &s) {
	seria_kv("top_block_desc", v.top_block_desc, s);
	seria_kv("transaction_descs", v.transaction_descs, s);
}
#if bytecoin_ALLOW_DEBUG_COMMANDS
void ser_members(np::ProofOfTrust &v, seria::ISeria &s) {
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("time", v.time, s);
	seria_kv("sign", v.sign, s);
}
void ser_members(np::GetPeerStatistics::Request &v, seria::ISeria &s) { seria_kv("tr", v.tr, s); }
void ser_members(np::GetPeerStatistics::Response &v, seria::ISeria &s) {
	seria_kv("version", v.version, s);
	seria_kv("platform", v.platform, s);
	seria_kv("net", v.net, s);
	seria_kv("genesis_block_hash", v.genesis_block_hash, s);
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("start_time", v.start_time, s);
	seria_kv("checkpoints", v.checkpoints, s);
	seria_kv("transaction_pool_size", v.transaction_pool_size, s);
	seria_kv("transaction_pool_max_size", v.transaction_pool_max_size, s);
	seria_kv("transaction_pool_lowest_fee_per_byte", v.transaction_pool_lowest_fee_per_byte, s);
	seria_kv("upgrade_decided_height", v.upgrade_decided_height, s);
	seria_kv("upgrade_votes_in_top_block", v.upgrade_votes_in_top_block, s);
	seria_kv("peer_list_white", v.peer_list_white, s);
	seria_kv("peer_list_gray", v.peer_list_gray, s);
	seria_kv("connections", v.connections, s);
}
#endif
}
