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

#include <cstdint>
#include <string>
#include <vector>
#include "common/CommandLine.hpp"
#include "CryptoNote.hpp"
#include "p2p/P2pProtocolTypes.hpp"

namespace bytecoin {

class Config {  // Consensus does not depend on those parameters
public:
	explicit Config(common::CommandLine & cmd);

	bool is_testnet;
	Timestamp locked_tx_allowed_delta_seconds;
	Height locked_tx_allowed_delta_blocks;

	Timestamp mempool_tx_live_time;
	//  Timestamp mempoolTxFromAltBlockLiveTime;
	//  size_t numberOfPeriodsToForgetTxDeletedFromPool;

	std::string blocks_file_name;
	std::string block_indexes_file_name;

	std::string crypto_note_name;
	UUID network_id;

	uint16_t p2p_bind_port;
	uint16_t p2p_external_port;
	std::string p2p_bind_ip;

	uint16_t bytecoind_bind_port;
	std::string bytecoind_bind_ip;
	uint16_t bytecoind_remote_port;
	std::string bytecoind_remote_ip;

	uint16_t walletd_bind_port;
	std::string walletd_bind_ip;

	size_t p2p_local_white_list_limit;
	size_t p2p_local_gray_list_limit;
	size_t p2p_default_peers_in_handshake;
	size_t p2p_default_connections_count;
	bool p2p_allow_local_ip;
	size_t p2p_whitelist_connections_percent;

	size_t p2p_block_ids_sync_default_count;
	size_t p2p_blocks_sync_default_count;
	size_t rpc_get_blocks_fast_max_count;

	std::vector<NetworkAddress> exclusive_nodes;
	std::vector<NetworkAddress> seed_nodes;
	std::vector<NetworkAddress> priority_nodes;  // Those nodes have reconnect and ban periods greatly reduced

	PublicKey trusted_public_key{};

	std::string coin_directory;

	std::string get_coin_directory(const std::string &subdir = std::string(), bool create = true) const;
};

}  // namespace bytecoin
