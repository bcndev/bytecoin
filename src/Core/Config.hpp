// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <boost/optional.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include "CryptoNote.hpp"
#include "p2p/P2pProtocolTypes.hpp"

namespace common {
class CommandLine;
}

namespace cn {

class Config {  // Consensus does not depend on those parameters
public:
	class DataFolderError : public std::runtime_error {
	public:
		using std::runtime_error::runtime_error;
	};
	class ConfigError : public std::runtime_error {
	public:
		using std::runtime_error::runtime_error;
	};

	explicit Config(common::CommandLine &cmd);
	static std::string prepare_usage(const std::string &usage);  // replaces defaults

	std::string net;
	bool is_archive;

	std::string blocks_file_name;
	std::string block_indexes_file_name;

	std::string crypto_note_name;
	UUID network_id;
	bool allow_empty_network_id = false;

	uint16_t p2p_bind_port;
	uint16_t p2p_external_port;
	std::string p2p_bind_ip;
	std::string multicast_address;
	uint16_t multicast_port;
	float multicast_period;
	bool secrets_via_api;
	bool use_multicast() const;

	std::string bytecoind_authorization;
	std::string bytecoind_authorization_private;
	uint16_t bytecoind_bind_port;
	std::string bytecoind_bind_ip;
	uint16_t bytecoind_remote_port = 0;
	std::string bytecoind_remote_ip;

	size_t max_pool_size              = 4 * 1000 * 1000;
	size_t max_undo_transactions_size = 200 * 1000 * 1000;
	// During very large reorganization, only last transaction within limit will be redone

	// a bit different commit periods to make most commits not simultaneous
	Timestamp db_commit_period_wallet_cache = 291;
	Timestamp db_commit_period_blockchain   = 311;
	Timestamp db_commit_period_peers        = 60;
	size_t db_commit_every_n_blocks         = 50000;
	// This affects DB transaction size. TODO - sum size of blocks instead

	std::string walletd_authorization;
	uint16_t walletd_bind_port;
	std::string walletd_bind_ip;

	size_t p2p_local_white_list_limit        = 1000;
	size_t p2p_local_gray_list_limit         = 5000;
	size_t p2p_default_peers_in_handshake    = 250;
	size_t p2p_max_outgoing_connections      = 8;
	size_t p2p_max_incoming_connections      = 100;
	size_t p2p_whitelist_connections_percent = 70;

	Timestamp p2p_ban_period                = 60 * 15;
	Timestamp p2p_reconnect_period          = 60 * 5;
	Timestamp p2p_reconnect_period_seed     = 86400;
	Timestamp p2p_reconnect_period_priority = 30;
	float p2p_no_internet_reconnect_delay   = 0.5f;
	// When we fail to connect to any peer after lots of attempts

	float p2p_network_unreachable_delay = 10.0f;
	// When connect() fails immediately several times in a row

	Timestamp p2p_no_incoming_handshake_disconnect_timeout = 30;
	Timestamp p2p_no_incoming_message_disconnect_timeout   = 60 * 6;
	Timestamp p2p_no_outgoing_message_ping_timeout         = 60 * 4;

	size_t rpc_sync_blocks_max_count;

	Height p2p_outgoing_peer_max_lag = 5;
	// if peer we are connected to is/starts lagging by 5 blocks or more, we will
	// disconnect and delay connect it, in hope to find better peers

	size_t max_downloading_blocks_from_each_peer = 100;
	size_t download_window                       = 2000;
	float download_block_timeout                 = 30.0f;
	float download_transaction_timeout           = 30.0f;
	float download_chain_timeout                 = 30.0f;
	float sync_pool_timeout                      = 30.0f;
	float max_on_idle_time                       = 0.1f;  // seconds
	size_t download_broadcast_every_n_blocks     = 10000;
	// During download, we send time sync commands periodically to inform other that
	// they can now download more blocks from us

	Timestamp wallet_sync_timestamp_granularity = 86400 * 30;
	// Sending exact timestamp of wallet to public node allows tracking
	size_t wallet_sync_request_max_size      = 1024 * 1024;
	size_t wallet_sync_preparator_queue_size = 10 * 1024 * 1024;

	std::vector<NetworkAddress> seed_nodes;
	std::vector<NetworkAddress> priority_nodes;
	bool exclusive_nodes = false;  // if true, will connect to priority_nodes only
	bool paranoid_checks = false;  // Check every byte of blockchain, even before last checkpoint
	PublicKey trusted_public_key{};

	std::string data_folder;

	std::string get_data_folder() const { return data_folder; }  // suppress creation of dir itself
	std::string get_data_folder(const std::string &subdir) const;

	Height payment_queue_confirmations;
};

}  // namespace cn
