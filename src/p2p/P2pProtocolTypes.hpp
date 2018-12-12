// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "Core/Difficulty.hpp"
#include "CryptoNote.hpp"
#include "common/Ipv4Address.hpp"
#include "common/StringTools.hpp"
#include "crypto/generic-ops.hpp"
#include "seria/ISeria.hpp"

namespace cn {

using common::NetworkAddress;

typedef uint64_t PeerIdType;

enum P2PProtocolVersion : uint8_t { NO_HANDSHAKE_YET = 0, V1 = 1, AMETHYST = 4 };
// V4 adds several fields/messages and sets strict rules, violating would be BAN.

#pragma pack(push, 1)
struct UUID {
	uint8_t data[16];  // TODO - return {} initializer when Google updates NDK compiler
};

struct NetworkAddressLegacy {
	uint32_t ip   = 0;
	uint32_t port = 0;
};

struct PeerlistEntryLegacy {
	NetworkAddressLegacy adr;
	PeerIdType id      = 0;
	uint32_t last_seen = 0;  // coincides with Timestamp
	uint32_t reserved  = 0;  // High part of former 64-bit last_seen
};

// struct connection_entry {
//	NetworkAddressLegacy adr;
//	PeerIdType id  = 0;
//	bool is_income = false;
//};
#pragma pack(pop)

struct BasicNodeData {
	UUID network_id{};
	uint8_t version      = 0;
	Timestamp local_time = 0;
	uint16_t my_port     = 0;  // p2p external port.
	PeerIdType peer_id   = 0;
};

struct CoreSyncData {
	Height current_height = 0;  // crazy, but this one is top block + 1 instead of top block
	// We conform to legacy by sending incremented field on wire
	Hash top_id;
};

struct TransactionDesc {
	enum { MAX_KV_SIZE = 128 };
	Hash hash;
	Amount fee  = 0;
	size_t size = 0;
	Hash newest_referenced_block;  // serialized as "nrb" for space reasons in packets
};

struct TopBlockDesc {
	Hash hash;
	Height height           = 0;
	CumulativeDifficulty cd = 0;
};

struct PeerlistEntry {
	PeerIdType peer_id  = 0;
	Timestamp last_seen = 0;
	NetworkAddress address;
	Timestamp ban_until = 0;
	std::string ban_reason;
};

struct ConnectionDesc {
	PeerIdType peer_id = 0;
	NetworkAddress address;
	bool is_incoming    = false;
	uint8_t p2p_version = 0;
	TopBlockDesc top_block_desc;
};

struct CoreStatistics {
	std::string version;
	std::string platform;
	Timestamp start_time = 0;  // Unix timestamp UTC
	std::string net;
	Hash genesis_block_hash;  // To be sure about which coin :)

	PeerIdType peer_id = 0;  // For p2p
	std::vector<PeerlistEntry> peer_list_white;
	std::vector<PeerlistEntry> peer_list_gray;
	std::vector<ConnectionDesc> connected_peers;

	std::vector<SignedCheckpoint> checkpoints;
	size_t transaction_pool_count               = 0;
	size_t transaction_pool_size                = 0;
	size_t transaction_pool_max_size            = 0;
	Amount transaction_pool_lowest_fee_per_byte = 0;
	Height upgrade_decided_height               = 0;
	Height upgrade_votes_in_top_block           = 0;
};

// inline bool operator<(const NetworkAddressLegacy &a, const NetworkAddressLegacy &b) {
//	return std::tie(a.ip, a.port) < std::tie(b.ip, b.port);
//}

// inline bool operator==(const NetworkAddressLegacy &a, const NetworkAddressLegacy &b) {
//	return a.ip == b.ip && a.port == b.port;
//}

CRYPTO_MAKE_COMPARABLE(UUID, std::memcmp)
}  // namespace cn

namespace seria {
void ser(cn::UUID &v, seria::ISeria &s);
void ser_members(cn::BasicNodeData &v, seria::ISeria &s);
void ser_members(cn::CoreSyncData &v, seria::ISeria &s);
void ser_members(cn::TransactionDesc &v, seria::ISeria &s);
void ser_members(cn::PeerlistEntryLegacy &v, seria::ISeria &s);
void ser_members(cn::NetworkAddressLegacy &v, seria::ISeria &s);
void ser_members(cn::CoreStatistics &v, seria::ISeria &s);
void ser(cn::NetworkAddress &v, seria::ISeria &s);
void ser_members(cn::PeerlistEntry &v, seria::ISeria &s);
void ser_members(cn::ConnectionDesc &v, seria::ISeria &s);
void ser_members(cn::TopBlockDesc &v, seria::ISeria &s);
}  // namespace seria
