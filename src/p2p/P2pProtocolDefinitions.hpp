// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include "CryptoNote.hpp"
#include "P2pProtocolTypes.hpp"

#include "crypto/crypto.hpp"

namespace byterub {

struct network_config {
	uint32_t connections_count       = 0;
	uint32_t connection_timeout      = 0;
	uint32_t ping_connection_timeout = 0;
	uint32_t handshake_interval      = 0;
	uint32_t packet_max_size         = 0;
	uint32_t config_id               = 0;
	uint32_t send_peerlist_sz        = 0;
};

enum P2PProtocolVersion : uint8_t { V0 = 0, V1 = 1, CURRENT = V1 };

struct basic_node_data {
	UUID network_id;
	uint8_t version     = 0;
	uint64_t local_time = 0;
	uint32_t my_port    = 0;
	PeerIdType peer_id  = 0;
};

struct CORE_SYNC_DATA {
	uint32_t current_height = 0;  // crazy, but this one is top block + 1 instead of top block
	// We conform to legacy by sending incremented field on wire
	crypto::Hash top_id;
};

enum { P2P_COMMANDS_POOL_BASE = 1000 };

struct COMMAND_HANDSHAKE {
	enum { ID = P2P_COMMANDS_POOL_BASE + 1 };

	struct request {
		basic_node_data node_data;
		CORE_SYNC_DATA payload_data;
	};

	struct response {
		basic_node_data node_data;
		CORE_SYNC_DATA payload_data;
		std::vector<PeerlistEntry> local_peerlist;
	};
};

struct COMMAND_TIMED_SYNC {
	enum { ID = P2P_COMMANDS_POOL_BASE + 2 };

	struct request {
		CORE_SYNC_DATA payload_data;
	};

	struct response {
		uint64_t local_time = 0;
		CORE_SYNC_DATA payload_data;
		std::vector<PeerlistEntry> local_peerlist;
	};
};

struct COMMAND_PING {
	//	  Used to make "callback" connection, to be sure that opponent node
	//	  have accessible connection point. Only other nodes can add peer to peerlist,
	//	  and ONLY in case when peer has accepted connection and answered to ping.
	enum { ID = P2P_COMMANDS_POOL_BASE + 3 };

	static std::string status_ok() { return "OK"; }

	struct request {};

	struct response {
		std::string status;
		PeerIdType peer_id = 0;
	};
};

#ifdef ALLOW_DEBUG_COMMANDS
// These commands are considered as insecure, and made in debug purposes for a limited lifetime.
// Anyone who feel unsafe with this commands can disable the ALLOW_GET_STAT_COMMAND macro.

struct proof_of_trust {
	PeerIdType peer_id = 0;
	uint64_t time      = 0;
	crypto::Signature sign;

	crypto::Hash get_hash() const;
};

struct CoreStatistics {  // TODO - convert to json blob
	uint64_t transactionPoolSize   = 0;
	uint64_t blockchainHeight      = 0;
	uint64_t miningSpeed           = 0;
	uint64_t alternativeBlockCount = 0;
	std::string topBlockHashString;
};

struct COMMAND_REQUEST_STAT_INFO {
	enum { ID = P2P_COMMANDS_POOL_BASE + 4 };

	struct request {
		proof_of_trust tr;
	};

	struct response {
		std::string version;
		std::string os_version;
		uint64_t connections_count          = 0;
		uint64_t incoming_connections_count = 0;
		CoreStatistics payload_info;
	};
};

struct COMMAND_REQUEST_NETWORK_STATE {
	enum { ID = P2P_COMMANDS_POOL_BASE + 5 };

	struct request {
		proof_of_trust tr;
	};

	struct response {
		std::vector<PeerlistEntry> local_peerlist_white;
		std::vector<PeerlistEntry> local_peerlist_gray;
		std::vector<connection_entry> connections_list;
		PeerIdType my_id    = 0;
		uint64_t local_time = 0;
	};
};

struct COMMAND_REQUEST_PEER_ID  // TODO - remove this message in next hard fork, peer_id is sent on handshake and in
                                // lots of other messages
{
	enum { ID = P2P_COMMANDS_POOL_BASE + 6 };

	struct request {};

	struct response {
		PeerIdType my_id = 0;
	};
};

#endif
}
namespace seria {
void ser_members(byterub::network_config &v, seria::ISeria &s);
void ser_members(byterub::basic_node_data &v, seria::ISeria &s);
void ser_members(byterub::CORE_SYNC_DATA &v, seria::ISeria &s);
void ser_members(byterub::COMMAND_HANDSHAKE::request &v, seria::ISeria &s);
void ser_members(byterub::COMMAND_HANDSHAKE::response &v, seria::ISeria &s);
void ser_members(byterub::COMMAND_TIMED_SYNC::request &v, seria::ISeria &s);
void ser_members(byterub::COMMAND_TIMED_SYNC::response &v, seria::ISeria &s);
void ser_members(byterub::COMMAND_PING::request &v, seria::ISeria &s);
void ser_members(byterub::COMMAND_PING::response &v, seria::ISeria &s);
#ifdef ALLOW_DEBUG_COMMANDS
void ser_members(byterub::proof_of_trust &v, seria::ISeria &s);
void ser_members(byterub::COMMAND_REQUEST_STAT_INFO::request &v, seria::ISeria &s);
void ser_members(byterub::COMMAND_REQUEST_STAT_INFO::response &v, seria::ISeria &s);
void ser_members(byterub::COMMAND_REQUEST_NETWORK_STATE::request &v, seria::ISeria &s);
void ser_members(byterub::COMMAND_REQUEST_NETWORK_STATE::response &v, seria::ISeria &s);
#endif
}
