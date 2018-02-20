// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include <boost/optional.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include "CryptoNote.hpp"
#include "common/CommandLine.hpp"
#include "p2p/P2pProtocolTypes.hpp"

namespace bytecoin {

class Config {  // Consensus does not depend on those parameters
public:
	explicit Config(common::CommandLine &cmd);

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

	std::string ssl_certificate_pem_file;
	boost::optional<std::string> ssl_certificate_password;
	std::string bytecoind_authorization;
	uint16_t bytecoind_bind_port;
	std::string bytecoind_bind_ip;
	uint16_t bytecoind_remote_port;
	std::string bytecoind_remote_ip;

	std::string walletd_authorization;
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
