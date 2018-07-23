// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "P2pProtocolNew.hpp"

namespace seria {

void ser_members(bytecoin::np::NetworkAddress &v, seria::ISeria &s) {
	seria_kv("version", v.version, s);
	seria_kv("port", v.port, s);
	s.object_key("ip");
	s.binary(v.ip.data(), v.ip.size());  // if not correct for version during save, will throw on load
}
void ser_members(bytecoin::np::PeerlistEntry &v, seria::ISeria &s) {
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("last_seen", v.last_seen, s);
	seria_kv("address", v.address, s);
}
void ser_members(bytecoin::np::ConnectionDesc &v, seria::ISeria &s) {
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("address", v.address, s);
	seria_kv("is_incoming", v.is_incoming, s);
}
void ser_members(bytecoin::np::PeerDesc &v, seria::ISeria &s) {
	seria_kv("p2p_version", v.p2p_version, s);
	seria_kv("genesis_block_hash", v.genesis_block_hash, s);
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("local_time", v.local_time, s);
	seria_kv("my_external_port", v.my_external_port, s);
}
void ser_members(bytecoin::np::TopBlockDesc &v, seria::ISeria &s) {
	seria_kv("top_bid", v.top_bid, s);
	seria_kv("cumulative_difficulty", v.cd.lo, s);
	seria_kv("cumulative_difficulty_hi", v.cd.hi, s);
}
void ser_members(bytecoin::np::TransactionDesc &v, seria::ISeria &s) {
	seria_kv("hash", v.hash, s);
	seria_kv("fee", v.fee, s);
	seria_kv("size", v.size, s);
	seria_kv("newest_referenced_block", v.newest_referenced_block, s);
}
void ser_members(bytecoin::np::Handshake::Request &v, seria::ISeria &s) {
	seria_kv("peer_desc", v.peer_desc, s);
	seria_kv("top_block_desc", v.top_block_desc, s);
}
void ser_members(bytecoin::np::Handshake::Response &v, seria::ISeria &s) {
	seria_kv("peer_desc", v.peer_desc, s);
	seria_kv("top_block_desc", v.top_block_desc, s);
	seria_kv("peerlist", v.peerlist, s);
}
void ser_members(bytecoin::np::FindDiff::Request &v, seria::ISeria &s) {
	seria_kv("gap_start", v.gap_start, s);
	seria_kv("gap_end", v.gap_end, s);
}
void ser_members(bytecoin::np::FindDiff::Response &v, seria::ISeria &s) {
	seria_kv("top_block_desc", v.top_block_desc, s);
	seria_kv("sparse_chain", v.sparse_chain, s);
}
void ser_members(bytecoin::np::RelayTransactionDescs &v, seria::ISeria &s) {
	seria_kv("top_block_desc", v.top_block_desc, s);
	seria_kv("transaction_descs", v.transaction_descs, s);
}
}
