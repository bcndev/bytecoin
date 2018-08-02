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

namespace np {  // new protocol

typedef uint64_t PeerIdType;

enum P2PProtocolVersion : uint8_t { V0 = 0, V1 = 1, EXPERIMENTAL = 2 };

#pragma pack(push, 1)
struct Header {
	enum : uint64_t { MAGIC = 0x02E85C0A89412FC1 };  // New bender's nightmare
	enum {
		MAX_PACKET_SIZE = 100000000  // Remove after per-command limits implemented
	};
	uint64_t magic     = 0;
	uint32_t body_size = 0;
	uint32_t command   = 0;
};
#pragma pack(pop)

struct NetworkAddress {
	uint8_t version = 0;  // 4, 6
	uint16_t port   = 0;
	BinaryArray ip;  // 4 or 16 bytes, depending on version
};

struct PeerlistEntry {
	PeerIdType peer_id  = 0;
	Timestamp last_seen = 0;  // coincides with Timestamp
	NetworkAddress address;
};

struct ConnectionDesc {
	PeerIdType peer_id = 0;
	NetworkAddress address;
	bool is_incoming = false;
};

struct PeerDesc {
	uint8_t p2p_version = 0;
	Hash genesis_block_hash;
	PeerIdType peer_id        = 0;
	Timestamp local_time      = 0;
	uint16_t my_external_port = 0;
};

struct TopBlockDesc {
	crypto::Hash top_bid;
	CumulativeDifficulty cd = 0;
};

struct TransactionDesc {
	Hash hash;
	Amount fee    = 0;
	uint32_t size = 0;
	Hash newest_referenced_block;
};

struct Handshake {
	struct Request {
		enum { ID = 101 };

		PeerDesc peer_desc;
		TopBlockDesc top_block_desc;
	};

	struct Response {
		enum { ID = 102, MAX_PEER_LIST_LENGTH = 5000 };

		PeerDesc peer_desc;
		TopBlockDesc top_block_desc;
		std::vector<NetworkAddress> peerlist;
	};
};

struct FindDiff {
	struct Request {
		enum { ID = 201 };

		Hash gap_start;
		Hash gap_end;
	};

	struct Response {
		enum { ID = 202, MAX_SPARSE_CHAIN_LENGTH = 100 };

		TopBlockDesc top_block_desc;
		std::vector<Hash> sparse_chain;
	};
};

struct SyncHeaders {
	struct Request {
		enum { ID = 301, GOOD_COUNT = 500, MAX_COUNT = 4000 };

		Hash start_hash;
		uint32_t max_count = 0;
	};

	struct Response {
		enum { ID = 302 };

		TopBlockDesc top_block_desc;
		std::vector<BlockTemplate> headers;
	};
};

struct GetTransactions {
	struct Request {
		enum { ID = 401 };

		std::vector<Hash> hashes;
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
		enum { ID = 501 };

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

struct RelayHeader {
	enum { ID = 600 };

	TopBlockDesc top_block_desc;
	BlockTemplate header;
};

struct RelayTransactionDescs {
	enum { ID = 700, MAX_TRANSACION_DESCS_LENGTH = 100 };

	TopBlockDesc top_block_desc;
	std::vector<TransactionDesc> transaction_descs;
};

#if bytecoin_ALLOW_DEBUG_COMMANDS

struct proof_of_trust {
	PeerIdType peer_id = 0;
	Timestamp time     = 0;
	crypto::Signature sign;

	//	crypto::Hash get_hash() const;
};

struct GetPeerStatistics {
	struct Request {
		enum { ID = 801 };

		proof_of_trust tr;
	};

	struct Response {
		enum { ID = 802 };

		std::string version;   // bytecoind version
		std::string platform;  // Windows, Linux, Darwin, etc.
		std::vector<PeerlistEntry> peer_list_white;
		std::vector<PeerlistEntry> peer_list_ban;
		std::vector<PeerlistEntry> peer_list_gray;
		std::vector<ConnectionDesc> connections;
		std::string stats;  // json
	};
};

#endif

inline bool operator<(const NetworkAddress &a, const NetworkAddress &b) {
	return std::tie(a.version, a.ip, a.port) < std::tie(b.version, b.ip, b.port);
}

inline bool operator==(const NetworkAddress &a, const NetworkAddress &b) {
	return a.version == b.version && a.ip == b.ip && a.port == b.port;
}

// inline std::ostream &operator<<(std::ostream &s, const NetworkAddress &na) {
//	return s << common::ip_address_and_port_to_string(na.ip, na.port);
//} TODO - implement for both ipv4 and ipv6
}
}

namespace seria {
void ser_members(bytecoin::np::NetworkAddress &v, seria::ISeria &s);
void ser_members(bytecoin::np::PeerlistEntry &v, seria::ISeria &s);
void ser_members(bytecoin::np::ConnectionDesc &v, seria::ISeria &s);
void ser_members(bytecoin::np::PeerDesc &v, seria::ISeria &s);
void ser_members(bytecoin::np::TopBlockDesc &v, seria::ISeria &s);
void ser_members(bytecoin::np::TransactionDesc &v, seria::ISeria &s);
void ser_members(bytecoin::np::Handshake::Request &v, seria::ISeria &s);
void ser_members(bytecoin::np::Handshake::Response &v, seria::ISeria &s);
void ser_members(bytecoin::np::FindDiff::Request &v, seria::ISeria &s);
void ser_members(bytecoin::np::FindDiff::Response &v, seria::ISeria &s);
void ser_members(bytecoin::np::RelayTransactionDescs &v, seria::ISeria &s);
}
