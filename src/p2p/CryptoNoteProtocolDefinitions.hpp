// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <list>
#include "CryptoNote.hpp"

namespace bytecoin {

enum { BC_COMMANDS_POOL_BASE = 2000 };

//just to keep backward compatibility with BlockCompleteEntry serialization
struct RawBlockLegacy {
	BinaryArray block;
	std::vector<BinaryArray> transactions;
};

struct NOTIFY_NEW_BLOCK {
	enum { ID = BC_COMMANDS_POOL_BASE + 1 };
	struct request {
		RawBlockLegacy b;
		uint32_t current_blockchain_height = 0; // TODO - check if this is also +1
		uint32_t hop = 0;
	};
};

struct NOTIFY_NEW_TRANSACTIONS {
	enum { ID = BC_COMMANDS_POOL_BASE + 2 };
	struct request {
		std::vector<BinaryArray> txs;
	};
};

struct NOTIFY_REQUEST_GET_OBJECTS {
	enum { ID = BC_COMMANDS_POOL_BASE + 3 };
	struct request {
		std::vector<crypto::Hash> txs;
		std::vector<crypto::Hash> blocks;
	};
};

struct NOTIFY_RESPONSE_GET_OBJECTS {
	enum { ID = BC_COMMANDS_POOL_BASE + 4 };
	struct request {
		std::vector<std::string> txs;
		std::vector<RawBlockLegacy> blocks;
		std::vector<crypto::Hash> missed_ids;
		uint32_t current_blockchain_height = 0;  // top block height + 1
	};
};

struct NOTIFY_REQUEST_CHAIN {
	enum { ID = BC_COMMANDS_POOL_BASE + 6 };

	struct request {
		std::vector<crypto::Hash> block_ids; // IDs of the first 10 blocks are sequential, next goes with pow(2,n) offset, like 2, 4, 8, 16, 32, 64 and so on, and the last one is always genesis block
	};
};

struct NOTIFY_RESPONSE_CHAIN_ENTRY {
	enum { ID = BC_COMMANDS_POOL_BASE + 7 };
	struct request {
		uint32_t start_height = 0; // height of first block_id
		uint32_t total_height = 0; // top block height + 1
		std::vector<crypto::Hash> m_block_ids;
	};
};

struct NOTIFY_REQUEST_TX_POOL {
	enum { ID = BC_COMMANDS_POOL_BASE + 8 };
	struct request {
		std::vector<crypto::Hash> txs;
	};
};

}

namespace seria {
void serMembers(bytecoin::RawBlockLegacy &v, seria::ISeria &s);
void serMembers(bytecoin::NOTIFY_NEW_BLOCK::request &v, seria::ISeria &s);
void serMembers(bytecoin::NOTIFY_NEW_TRANSACTIONS::request &v, seria::ISeria &s);
void serMembers(bytecoin::NOTIFY_REQUEST_GET_OBJECTS::request &v, seria::ISeria &s);
void serMembers(bytecoin::NOTIFY_RESPONSE_GET_OBJECTS::request &v, seria::ISeria &s);
void serMembers(bytecoin::NOTIFY_REQUEST_CHAIN::request &v, seria::ISeria &s);
void serMembers(bytecoin::NOTIFY_RESPONSE_CHAIN_ENTRY::request &v, seria::ISeria &s);
void serMembers(bytecoin::NOTIFY_REQUEST_TX_POOL::request &v, seria::ISeria &s);
}
