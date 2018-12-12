// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "CryptoNote.hpp"
#include "CryptoNoteConfig.hpp"
#include "LevinProtocol.hpp"
#include "P2pProtocolTypes.hpp"

#include "crypto/crypto.hpp"

namespace cn { namespace p2p {

enum { P2P_COMMANDS_POOL_BASE = 1000 };

// Values below are part of P2P consensus
constexpr size_t LEVIN_DEFAULT_MAX_PACKET_SIZE = 100 * 1000 * 1000;  // Used only in V2
constexpr size_t UNKNOWN_COMMAND_MAX_SIZE      = 100 * 1000;         // Used only in V4

struct Handshake {
	struct Request {
		enum { ID = P2P_COMMANDS_POOL_BASE + 1, TYPE = LevinProtocol::REQUEST, MAX_SIZE = 1024 };
		BasicNodeData node_data;
		CoreSyncData payload_data;
	};

	struct Response {
		enum {
			ID             = P2P_COMMANDS_POOL_BASE + 1,
			TYPE           = LevinProtocol::RESPONSE,
			MAX_PEER_COUNT = 500,
			MAX_SIZE       = 1024 + MAX_PEER_COUNT * sizeof(PeerlistEntryLegacy)
		};
		BasicNodeData node_data;
		CoreSyncData payload_data;
		std::vector<PeerlistEntryLegacy> local_peerlist;
	};
};

struct TimedSync {
	struct Request {
		enum { ID = P2P_COMMANDS_POOL_BASE + 2, TYPE = LevinProtocol::REQUEST, MAX_SIZE = 1024 };
		CoreSyncData payload_data;
	};

	struct Response {
		enum {
			ID             = P2P_COMMANDS_POOL_BASE + 2,
			TYPE           = LevinProtocol::RESPONSE,
			MAX_PEER_COUNT = 50,
			MAX_SIZE       = 1024 + MAX_PEER_COUNT * sizeof(PeerlistEntryLegacy)
		};
		Timestamp local_time = 0;
		CoreSyncData payload_data;
		std::vector<PeerlistEntryLegacy> local_peerlist;
	};
};

struct PingLegacy {  // Legacy, only answered, never sent
	//	  Used to make "callback" connection, to be sure that opponent node
	//	  have accessible connection point. Only other nodes can add peer to peerlist,
	//	  and ONLY in case when peer has accepted connection and answered to ping.
	static std::string status_ok() { return "OK"; }

	struct Request {
		enum { ID = P2P_COMMANDS_POOL_BASE + 3, TYPE = LevinProtocol::REQUEST, MAX_SIZE = 1024 };
	};

	struct Response {
		enum { ID = P2P_COMMANDS_POOL_BASE + 3, TYPE = LevinProtocol::RESPONSE, MAX_SIZE = 1024 };
		std::string status;
		PeerIdType peer_id = 0;
	};
};

enum { BC_COMMANDS_POOL_BASE = 2000 };

struct RelayBlock {
	struct Notify {
		enum {
			ID       = BC_COMMANDS_POOL_BASE + 1,
			TYPE     = LevinProtocol::NOTIFY,
			MAX_SIZE = 4096 + parameters::MAX_HEADER_SIZE + parameters::BLOCK_CAPACITY_VOTE_MAX / 8
		};
		// BlockTemplate contains transaction id per block transaction, we estimate min transaction size as 8 * 32 bytes
		RawBlock b;                            // In V4, transactions must be empty (Relay header)
		Hash top_id;                           // Always hash of b, only in V4
		Height current_blockchain_height = 0;  // Always height of b. This is also height + 1 on wire.
		uint32_t hop                     = 0;  // we always set it to 1, because it can be used to track block sources
	};
};

struct RelayTransactions {
	struct Notify {
		enum {
			ID             = BC_COMMANDS_POOL_BASE + 2,
			TYPE           = LevinProtocol::NOTIFY,
			MAX_DESC_COUNT = 1000,
			MAX_SIZE       = 1024 + MAX_DESC_COUNT * TransactionDesc::MAX_KV_SIZE
		};
		std::vector<BinaryArray> txs;                    // In protocol V1
		std::vector<TransactionDesc> transaction_descs;  // In protocol V4
	};
};

struct GetObjectsRequest {
	struct Notify {
		enum { ID = BC_COMMANDS_POOL_BASE + 3, TYPE = LevinProtocol::NOTIFY, MAX_SIZE = 1024 };
		std::vector<Hash> txs;  // Always ignored in protocol V1
		std::vector<Hash> blocks;
		// In protocol V4, either txs or blocks must contain exactly 1 hash, otherwise ban
	};
};

struct GetObjectsResponse {
	struct Notify {
		enum {
			ID       = BC_COMMANDS_POOL_BASE + 4,
			TYPE     = LevinProtocol::NOTIFY,
			MAX_SIZE = 4096 + parameters::MAX_HEADER_SIZE + parameters::BLOCK_CAPACITY_VOTE_MAX
		};
		// In protocol V4, when requested multiple objects, we always return single block or
		// transaction per message. In addition up to MAX_OBJECT_COUNT can be returned in missed_ids
		std::vector<BinaryArray> txs;  // Always empty in protocol V1
		std::vector<RawBlock> blocks;
		std::vector<Hash> missed_ids;
		Height current_blockchain_height = 0;  // This is also height + 1 on wire. We set it but never use it
	};
};

struct GetChainRequest {
	struct Notify {
		enum {
			ID            = BC_COMMANDS_POOL_BASE + 6,
			TYPE          = LevinProtocol::NOTIFY,
			MAX_BLOCK_IDS = 200,
			MAX_SIZE      = 1024 + MAX_BLOCK_IDS * sizeof(Hash)
		};
		std::vector<Hash> block_ids;  // sparse chain, last hash is always genesis block
	};
};

struct GetChainResponse {
	struct Notify {
		enum {
			ID            = BC_COMMANDS_POOL_BASE + 7,
			TYPE          = LevinProtocol::NOTIFY,
			MAX_BLOCK_IDS = 10000,
			MAX_SIZE      = 1024 + MAX_BLOCK_IDS * sizeof(Hash)
		};
		Height start_height = 0;  // height of first block_id
		Height total_height = 0;  // this is also +1 on wire. We set it but never use it
		std::vector<Hash> m_block_ids;
	};
};

struct SyncPool {
	struct Notify {  // In protocol V1
		enum { ID = BC_COMMANDS_POOL_BASE + 8, TYPE = LevinProtocol::NOTIFY, MAX_SIZE = 0 };
		std::vector<Hash> txs;
	};
	struct Request {  // In protocol V4
		enum { ID = BC_COMMANDS_POOL_BASE + 8, TYPE = LevinProtocol::REQUEST, MAX_SIZE = 1024 };
		std::pair<Amount, Hash> from;
		std::pair<Amount, Hash> to;
		// Should return sorted descs starting with but not equal to start_* pair, and up but not equal to min_* pair
	};
	struct Response {  // In protocol V4
		enum {
			ID             = BC_COMMANDS_POOL_BASE + 8,
			TYPE           = LevinProtocol::RESPONSE,
			MAX_DESC_COUNT = 1000,
			MAX_SIZE       = 1024 + MAX_DESC_COUNT * TransactionDesc::MAX_KV_SIZE
		};
		std::vector<TransactionDesc> transaction_descs;
	};
};
struct Checkpoint {
	struct Notify : public SignedCheckpoint {
		enum { ID = BC_COMMANDS_POOL_BASE + 10, TYPE = LevinProtocol::NOTIFY, MAX_SIZE = 1024 };
		Notify() = default;
		explicit Notify(const SignedCheckpoint &c) : SignedCheckpoint(c) {}
	};
};

#if bytecoin_ALLOW_DEBUG_COMMANDS
// These commands are considered as insecure, and made in debug purposes for a limited lifetime.
// Anyone who feel unsafe with this commands can disable the bytecoin_ALLOW_DEBUG_COMMANDS macro in CryptoNote.hpp
// We significantly changed debug commands

struct ProofOfTrust {
	PeerIdType peer_id = 0;
	Timestamp time     = 0;
	crypto::Signature sign;

	Hash get_hash() const;
};

struct GetStatInfo {
	struct Request {
		enum { ID = P2P_COMMANDS_POOL_BASE + 4, TYPE = LevinProtocol::REQUEST, MAX_SIZE = 1024 };
		ProofOfTrust tr;
		bool need_peer_lists = false;
	};

	struct Response : public CoreStatistics {
		enum { ID = P2P_COMMANDS_POOL_BASE + 4, TYPE = LevinProtocol::RESPONSE, MAX_SIZE = 10 * 1024 * 1024 };  // TODO
		Response() = default;
		Response(const CoreStatistics &c) : CoreStatistics(c) {}  // implicit
	};
};

// struct COMMAND_REQUEST_NETWORK_STATE { // Remains for historic purposes
//	enum { ID = P2P_COMMANDS_POOL_BASE + 5 };
//	struct Request {
//		ProofOfTrust tr;
//	};
//	struct Response {
//		std::vector<PeerlistEntryLegacy> local_peerlist_white;
//		std::vector<PeerlistEntryLegacy> local_peerlist_gray;
//		std::vector<connection_entry> connections_list;
//		PeerIdType my_id    = 0;
//		uint64_t local_time = 0;
//	};
//};
// struct COMMAND_REQUEST_PEER_ID { // Remains for historic purposes
//	enum { ID = P2P_COMMANDS_POOL_BASE + 6 };
//	struct Request {};
//	struct Response {
//		PeerIdType my_id = 0;
//	};
//};

#endif
}}  // namespace cn::p2p
namespace seria {
void ser_members(cn::p2p::Handshake::Request &v, seria::ISeria &s);
void ser_members(cn::p2p::Handshake::Response &v, seria::ISeria &s);
void ser_members(cn::p2p::TimedSync::Request &v, seria::ISeria &s);
void ser_members(cn::p2p::TimedSync::Response &v, seria::ISeria &s);
void ser_members(cn::p2p::PingLegacy::Request &v, seria::ISeria &s);
void ser_members(cn::p2p::PingLegacy::Response &v, seria::ISeria &s);
void ser_members(cn::p2p::RelayBlock::Notify &v, seria::ISeria &s);
void ser_members(cn::p2p::RelayTransactions::Notify &v, seria::ISeria &s);
void ser_members(cn::p2p::GetObjectsRequest::Notify &v, seria::ISeria &s);
void ser_members(cn::p2p::GetObjectsResponse::Notify &v, seria::ISeria &s);
void ser_members(cn::p2p::GetChainRequest::Notify &v, seria::ISeria &s);
void ser_members(cn::p2p::GetChainResponse::Notify &v, seria::ISeria &s);
void ser_members(cn::p2p::SyncPool::Notify &v, seria::ISeria &s);
void ser_members(cn::p2p::SyncPool::Request &v, seria::ISeria &s);
void ser_members(cn::p2p::SyncPool::Response &v, seria::ISeria &s);
inline void ser_members(cn::p2p::Checkpoint::Notify &v, seria::ISeria &s) {
	ser_members(static_cast<cn::SignedCheckpoint &>(v), s);
}
#if bytecoin_ALLOW_DEBUG_COMMANDS
void ser_members(cn::p2p::ProofOfTrust &v, seria::ISeria &s);
void ser_members(cn::p2p::GetStatInfo::Request &v, seria::ISeria &s);
inline void ser_members(cn::p2p::GetStatInfo::Response &v, seria::ISeria &s) {
	ser_members(static_cast<cn::CoreStatistics &>(v), s);
}
#endif
}  // namespace seria
