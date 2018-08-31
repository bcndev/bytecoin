// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <string.h>
#include <tuple>
#include "Core/Difficulty.hpp"
#include "CryptoNote.hpp"
#include "common/Ipv4Address.hpp"
#include "common/StringTools.hpp"
#include "crypto/generic-ops.hpp"
#include "seria/ISeria.hpp"

namespace bytecoin {

typedef uint64_t PeerIdType;

enum P2PProtocolVersion : uint8_t { V0 = 0, V1 = 1, V3_NEW = 3, CURRENT = V1 };

struct NetworkAddress {
	BinaryArray ip;  // 4 or 16 bytes, depending on version
	uint16_t port = 0;

	std::string to_string() const;
};

inline bool operator<(const NetworkAddress &a, const NetworkAddress &b) {
	return std::tie(a.ip, a.port) < std::tie(b.ip, b.port);
}

inline bool operator==(const NetworkAddress &a, const NetworkAddress &b) { return a.ip == b.ip && a.port == b.port; }

inline std::ostream &operator<<(std::ostream &s, const NetworkAddress &na) { return s << na.to_string(); }

struct PeerlistEntry {
	PeerIdType peer_id  = 0;
	Timestamp last_seen = 0;
	NetworkAddress address;
	Timestamp ban_until = 0;
	std::string ban_reason;
};

namespace np {  // new protocol

#pragma pack(push, 1)
struct Header {
	enum : uint64_t { MAGIC = 0x02E85C0A89412FC1 };  // New bender's nightmare
	enum {
		MAGIC_FIRST_BYTE = MAGIC & 0xFF,
		MAX_PACKET_SIZE  = 100000000  // Remove after per-command limits implemented
	};
	uint64_t magic     = 0;
	uint32_t body_size = 0;
	uint32_t command   = 0;
};
#pragma pack(pop)

struct TopBlockDesc {
	Hash hash;
	Height height           = 0;
	CumulativeDifficulty cd = 0;
};

struct ConnectionDesc {
	PeerIdType peer_id = 0;
	NetworkAddress address;
	bool is_incoming    = false;
	uint8_t p2p_version = 0;
	TopBlockDesc top_block_desc;
};

struct PeerDesc {
	uint8_t p2p_version = 0;
	Hash genesis_block_hash;
	PeerIdType peer_id         = 0;
	Timestamp local_time       = 0;
	uint16_t p2p_external_port = 0;
};

struct TransactionDesc {
	Hash hash;
	Amount fee    = 0;
	uint32_t size = 0;
	Hash newest_referenced_block;  // serialized as "nrb" for space reasons in packets
};

struct Handshake {
	struct Request {
		enum { ID = 101 };

		PeerDesc peer_desc;
		TopBlockDesc top_block_desc;
	};

	struct Response {
		enum { ID = 102, GOOD_PEER_LIST_LENGTH = 100, MAX_PEER_LIST_LENGTH = 5000 };

		PeerDesc peer_desc;
		TopBlockDesc top_block_desc;
		std::vector<NetworkAddress> peerlist;
	};
};

struct FindDiff {
	struct Request {
		enum { ID = 201, MAX_GAP_START_LENGTH = 100 };

		std::vector<Hash> gap_start;
		Hash desired_bid;
	};

	struct Response {
		enum { ID = 202, MAX_SPARSE_CHAIN_LENGTH = 100 };

		std::vector<SWCheckpoint> sparse_chain;
	};
};

struct SyncHeaders {
	struct Request {
		enum { ID = 301, GOOD_COUNT = 500, MAX_COUNT = 4000 };

		Hash previous_hash;
		uint32_t max_count = 0;
	};

	struct Response {
		enum { ID = 302 };

		std::vector<BinaryArray> binary_headers;
	};
};

struct GetTransactions {
	struct Request {
		enum { ID = 401, MAX_TRANSACTION_HASHES = 10000 };

		std::vector<Hash> transaction_hashes;
		Hash block_hash;  // If hashes empty, will send all transactions from block
	};

	struct Response {
		enum { ID = 402 };

		TopBlockDesc top_block_desc;
		std::vector<BinaryArray> transactions;
	};
};

struct GetPoolHashes {
	struct Request {
		enum { ID = 501, MAX_TOTAL_SIZE = 10000000, MAX_TOTAL_COUNT = 20000 };

		Amount min_fee_per_byte;
		Amount start_fee_per_byte;
		Hash start_hash;
		uint32_t max_total_size  = 0;
		uint32_t max_total_count = 0;
	};

	struct Response {
		enum { ID = 502 };

		TopBlockDesc top_block_desc;
		std::vector<TransactionDesc> transaction_descs;
	};
};

struct RelayBlockHeader {
	enum { ID = 600 };

	TopBlockDesc top_block_desc;
	BinaryArray binary_header;
};

struct RelayTransactionDescs {
	enum { ID = 700, MAX_TRANSACION_DESCS_LENGTH = 100 };

	TopBlockDesc top_block_desc;
	std::vector<TransactionDesc> transaction_descs;
};

#if bytecoin_ALLOW_DEBUG_COMMANDS

struct ProofOfTrust {
	PeerIdType peer_id = 0;
	Timestamp time     = 0;
	crypto::Signature sign;

	Hash get_hash() const;
};

struct GetPeerStatistics {
	struct Request {
		enum { ID = 801 };

		ProofOfTrust tr;
	};

	struct Response {
		enum { ID = 802 };

		std::string version;
		std::string platform;
		Timestamp start_time = 0;  // Unix timestamp UTC
		std::string net;
		Hash genesis_block_hash;  // To be sure about which coin :)

		uint64_t peer_id = 0;  // For p2p
		std::vector<PeerlistEntry> peer_list_white;
		std::vector<PeerlistEntry> peer_list_gray;
		std::vector<np::ConnectionDesc> connections;

		std::vector<SignedCheckpoint> checkpoints;
		uint64_t transaction_pool_size              = 0;
		uint64_t transaction_pool_max_size          = 0;
		Amount transaction_pool_lowest_fee_per_byte = 0;
		Height upgrade_decided_height               = 0;
		Height upgrade_votes_in_top_block           = 0;
	};
};

#endif
}
}

namespace seria {
void ser(bytecoin::NetworkAddress &v, seria::ISeria &s);
void ser_members(bytecoin::PeerlistEntry &v, seria::ISeria &s);
void ser_members(bytecoin::np::ConnectionDesc &v, seria::ISeria &s);
void ser_members(bytecoin::np::PeerDesc &v, seria::ISeria &s);
void ser_members(bytecoin::np::TopBlockDesc &v, seria::ISeria &s);
void ser_members(bytecoin::np::TransactionDesc &v, seria::ISeria &s);
void ser_members(bytecoin::np::Handshake::Request &v, seria::ISeria &s);
void ser_members(bytecoin::np::Handshake::Response &v, seria::ISeria &s);
void ser_members(bytecoin::np::FindDiff::Request &v, seria::ISeria &s);
void ser_members(bytecoin::np::FindDiff::Response &v, seria::ISeria &s);
void ser_members(bytecoin::np::SyncHeaders::Request &v, seria::ISeria &s);
void ser_members(bytecoin::np::SyncHeaders::Response &v, seria::ISeria &s);
void ser_members(bytecoin::np::GetTransactions::Request &v, seria::ISeria &s);
void ser_members(bytecoin::np::GetTransactions::Response &v, seria::ISeria &s);
void ser_members(bytecoin::np::GetPoolHashes::Request &v, seria::ISeria &s);
void ser_members(bytecoin::np::GetPoolHashes::Response &v, seria::ISeria &s);
void ser_members(bytecoin::np::RelayBlockHeader &v, seria::ISeria &s);
void ser_members(bytecoin::np::RelayTransactionDescs &v, seria::ISeria &s);
#if bytecoin_ALLOW_DEBUG_COMMANDS
void ser_members(bytecoin::np::ProofOfTrust &v, seria::ISeria &s);
void ser_members(bytecoin::np::GetPeerStatistics::Request &v, seria::ISeria &s);
void ser_members(bytecoin::np::GetPeerStatistics::Response &v, seria::ISeria &s);
#endif
}
