// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "Core/CryptoNoteTools.hpp"
#include "CryptoNote.hpp"
#include "CryptoNoteConfig.hpp"
#include "LevinProtocol.hpp"
#include "P2pProtocolTypes.hpp"

#include "crypto/crypto.hpp"

namespace cn { namespace p2p {

enum { P2P_COMMANDS_POOL_BASE = 1000 };

// Values below are part of P2P consensus
constexpr size_t UNKNOWN_COMMAND_MAX_SIZE = 100 * 1024;

struct Handshake {
	struct Request {
		enum { ID = P2P_COMMANDS_POOL_BASE + 1, TYPE = LevinProtocol::REQUEST, MAX_SIZE = 1024 };
		BasicNodeData node_data;
		CoreSyncData payload_data;
	};

	struct Response {
		enum {
			ID                  = P2P_COMMANDS_POOL_BASE + 1,
			TYPE                = LevinProtocol::RESPONSE,
			MAX_PEER_COUNT      = 500,
			MAX_SEND_PEER_COUNT = 200,
			MAX_SIZE            = 1024 + MAX_PEER_COUNT * sizeof(PeerlistEntryLegacy)  // Update in V5
		};
		BasicNodeData node_data;
		CoreSyncData payload_data;
		std::vector<PeerlistEntryLegacy> local_peerlist;  // Remove in V5
		std::vector<NetworkAddress> peerlist;
	};
};

struct TimedSync {   // TODO - rename to TopBlockUpdated
	struct Notify {  // has type request for historic purposes
		enum { ID = P2P_COMMANDS_POOL_BASE + 2, TYPE = LevinProtocol::REQUEST, MAX_SIZE = 1024 };
		CoreSyncData payload_data;
	};

	struct Response {  // Remove in V5
		enum {
			ID             = P2P_COMMANDS_POOL_BASE + 2,
			TYPE           = LevinProtocol::RESPONSE,
			MAX_PEER_COUNT = 50,
			MAX_SIZE       = 1024 + MAX_PEER_COUNT * sizeof(PeerlistEntryLegacy)
		};
		CoreSyncData payload_data;
		// TODO - we sent peer list here in V1-V4, hence non-trivial MAX_SIZE
	};
};

enum { BC_COMMANDS_POOL_BASE = 2000 };

struct RelayBlock {
	struct Notify {
		enum {
			ID       = BC_COMMANDS_POOL_BASE + 1,
			TYPE     = LevinProtocol::NOTIFY,
			MAX_SIZE = 4096 + parameters::MAX_HEADER_SIZE +
			           parameters::BLOCK_CAPACITY_VOTE_MAX * sizeof(Hash) / MIN_NONCOINBASE_TRANSACTION_SIZE
		};
		// MAX_SIZE is like this because BlockTemplate contains transaction id per block transaction
		RawBlock b;                            // In V4, transactions must be empty (Relay header)
		Hash top_id;                           // Always hash of b, only in V4
		Height current_blockchain_height = 0;  // Always height of b. This is also height + 1 on wire.
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
		std::vector<TransactionDesc> transaction_descs;  // In protocol V4
	};
};

struct GetObjects {
	// Request and Response have NOTIFY type for historic purposes
	struct Request {
		enum { ID = BC_COMMANDS_POOL_BASE + 3, TYPE = LevinProtocol::NOTIFY, MAX_SIZE = 1024 };
		std::vector<Hash> txs;
		std::vector<Hash> blocks;
		// In protocol V4, either txs or blocks must contain exactly 1 hash, otherwise ban
	};
	struct Response {
		enum {
			ID       = BC_COMMANDS_POOL_BASE + 4,
			TYPE     = LevinProtocol::NOTIFY,
			MAX_SIZE = 4096 + parameters::MAX_HEADER_SIZE + parameters::BLOCK_CAPACITY_VOTE_MAX +
			           parameters::BLOCK_CAPACITY_VOTE_MAX * sizeof(Hash) / MIN_NONCOINBASE_TRANSACTION_SIZE
		};
		// MAX_SIZE is like this because BlockTemplate contains transaction id per block transaction
		// In protocol V4, we request only single object, so get exactly 1 object (or missed id) back
		std::vector<BinaryArray> txs;
		std::vector<RawBlock> blocks;
		std::vector<Hash> missed_ids;
	};
};

struct GetChain {
	// Request and Response have NOTIFY type for historic purposes
	struct Request {
		enum {
			ID            = BC_COMMANDS_POOL_BASE + 6,
			TYPE          = LevinProtocol::NOTIFY,
			MAX_BLOCK_IDS = 200,
			MAX_SIZE      = 1024 + MAX_BLOCK_IDS * sizeof(Hash)
		};
		std::vector<Hash> block_ids;  // sparse chain, last hash is always genesis block
	};
	struct Response {
		enum {
			ID            = BC_COMMANDS_POOL_BASE + 7,
			TYPE          = LevinProtocol::NOTIFY,
			MAX_BLOCK_IDS = 10000,
			MAX_SIZE      = 1024 + MAX_BLOCK_IDS * sizeof(Hash)
		};
		// TODO remove start_height in V5, m_block_ids must always
		// start from the block we have, so we always know start_height
		Height start_height = 0;  // height of first block_id
		std::vector<Hash> m_block_ids;
	};
};

struct SyncPool {
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
		enum { ID = P2P_COMMANDS_POOL_BASE + 4, TYPE = LevinProtocol::RESPONSE, MAX_SIZE = 1 * 1024 * 1024 };
		Response() = default;
		Response(const CoreStatistics &c) : CoreStatistics(c) {}  // implicit
	};
};

#endif
}}  // namespace cn::p2p
namespace seria {
void ser_members(cn::p2p::Handshake::Request &v, seria::ISeria &s);
void ser_members(cn::p2p::Handshake::Response &v, seria::ISeria &s);
void ser_members(cn::p2p::TimedSync::Notify &v, seria::ISeria &s);
void ser_members(cn::p2p::TimedSync::Response &v, seria::ISeria &s);
void ser_members(cn::p2p::RelayBlock::Notify &v, seria::ISeria &s);
void ser_members(cn::p2p::RelayTransactions::Notify &v, seria::ISeria &s);
void ser_members(cn::p2p::GetObjects::Request &v, seria::ISeria &s);
void ser_members(cn::p2p::GetObjects::Response &v, seria::ISeria &s);
void ser_members(cn::p2p::GetChain::Request &v, seria::ISeria &s);
void ser_members(cn::p2p::GetChain::Response &v, seria::ISeria &s);
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
