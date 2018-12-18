// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Config.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <iostream>
#include "CryptoNoteConfig.hpp"
#include "common/Base64.hpp"
#include "common/CommandLine.hpp"
#include "p2p/P2pProtocolDefinitions.hpp"
#include "platform/PathTools.hpp"
#include "platform/Time.hpp"
#include "rpc_api.hpp"

using namespace common;
using namespace cn;
using namespace parameters;

static void parse_peer_and_add_to_container(const std::string &str, std::vector<NetworkAddress> &container) {
	NetworkAddress na{};
	if (!common::parse_ip_address_and_port(str, &na.ip, &na.port))
		throw std::runtime_error("Wrong address format " + str + ", should be ip:port");
	container.push_back(na);
}

static std::string get_net(common::CommandLine &cmd) {
	std::string net;
	if (const char *pa = cmd.get("--net")) {
		net = pa;
		if (net == "main" || net == "stage" || net == "test")
			return net;
		throw std::runtime_error("Wrong net value " + net + ", should be 'test', 'stage', or 'main'");
	}
	if (cmd.get_bool("--testnet", "use --net=test instead"))
		return "test";
	return "main";
}

Config::Config(common::CommandLine &cmd)
    : net(get_net(cmd))
    , is_archive(cmd.get_bool("--archive"))
    , blocks_file_name(BLOCKS_FILENAME)
    , block_indexes_file_name(BLOCKINDEXES_FILENAME)
    , crypto_note_name(CRYPTONOTE_NAME)
    , network_id(BYTECOIN_NETWORK)
    , p2p_bind_port(P2P_DEFAULT_PORT)
    , p2p_external_port(P2P_DEFAULT_PORT)
    , p2p_bind_ip("0.0.0.0")
    , multicast_address("239.195.17.131")
    , multicast_port(P2P_DEFAULT_PORT)
    , multicast_period(net == "main" ? 0 : 60.0f)  // No multicast in main net due to anonymity
    , secrets_via_api(cmd.get_bool("--secrets-via-api"))
    , bytecoind_bind_port(RPC_DEFAULT_PORT)
    , bytecoind_bind_ip("127.0.0.1")  // Less attack vectors from outside for ordinary uses
    , bytecoind_remote_ip("127.0.0.1")
    , walletd_bind_port(WALLET_RPC_DEFAULT_PORT)
    , walletd_bind_ip("127.0.0.1")  // Connection to wallet allows spending
    , rpc_sync_blocks_max_count(api::cnd::SyncBlocks::Request::MAX_COUNT)
    , paranoid_checks(cmd.get_bool("--paranoid-checks"))
    , trusted_public_key(P2P_STAT_TRUSTED_PUBLIC_KEY)
    , payment_queue_confirmations(720) {
	if (net == "test") {
		network_id.data[0] += 1;
		p2p_bind_port += 1000;
		p2p_external_port += 1000;
		bytecoind_bind_port += 1000;
		walletd_bind_port += 1000;
		multicast_port += 1000;
		if (const char *pa = cmd.get("--time-multiplier"))
			platform::set_time_multiplier_for_tests(boost::lexical_cast<int>(pa));
		payment_queue_confirmations = 30;
	}
	if (net == "stage") {
		network_id.data[0] += 2;
		p2p_bind_port += 2000;
		p2p_external_port += 2000;
		bytecoind_bind_port += 2000;
		walletd_bind_port += 2000;
		multicast_port += 2000;
	}
	if (const char *pa = cmd.get("--p2p-bind-address")) {
		if (!common::parse_ip_address_and_port(pa, &p2p_bind_ip, &p2p_bind_port))
			throw std::runtime_error("Wrong address format " + std::string(pa) + ", should be ip:port");
		p2p_external_port = p2p_bind_port;
	}
	if (const char *pa = cmd.get("--p2p-external-port"))
		p2p_external_port = boost::lexical_cast<uint16_t>(pa);
	if (const char *pa = cmd.get("--walletd-bind-address")) {
		if (!common::parse_ip_address_and_port(pa, &walletd_bind_ip, &walletd_bind_port))
			throw std::runtime_error("Wrong address format " + std::string(pa) + ", should be ip:port");
	}
	if (const char *pa = cmd.get("--" CRYPTONOTE_NAME "d-authorization")) {
		bytecoind_authorization         = common::base64::encode(BinaryArray(pa, pa + strlen(pa)));
		bytecoind_authorization_private = bytecoind_authorization;
	}
	if (const char *pa = cmd.get("--" CRYPTONOTE_NAME "d-authorization-private")) {
		bytecoind_authorization_private = common::base64::encode(BinaryArray(pa, pa + strlen(pa)));
	}
	if (const char *pa = cmd.get("--" CRYPTONOTE_NAME "d-bind-address")) {
		if (!common::parse_ip_address_and_port(pa, &bytecoind_bind_ip, &bytecoind_bind_port))
			throw std::runtime_error("Wrong address format " + std::string(pa) + ", should be ip:port");
	}
	if (const char *pa = cmd.get("--" CRYPTONOTE_NAME "d-remote-address")) {
		std::string addr         = pa;
		const std::string prefix = "https://";
		if (addr.find(prefix) == 0) {
#if !platform_USE_SSL
			throw std::runtime_error("Using https in --" CRYPTONOTE_NAME
			                         "d-remote-address impossible - this binary is built without OpenSSL");
#endif
			std::string sip;
			std::string sport;
			if (!split_string(addr.substr(prefix.size()), ":", sip, sport))
				throw std::runtime_error(
				    "Wrong address format " + addr + ", should be <ip>:<port> or https://<host>:<port>");
			bytecoind_remote_port = boost::lexical_cast<uint16_t>(sport);
			bytecoind_remote_ip   = prefix + sip;
		} else {
			const std::string prefix2 = "http://";
			if (addr.find(prefix2) == 0)
				addr = addr.substr(prefix2.size());
			if (!common::parse_ip_address_and_port(addr, &bytecoind_remote_ip, &bytecoind_remote_port))
				throw std::runtime_error("Wrong address format " + addr + ", should be ip:port");
		}
	}
	cmd.get_bool("--allow-local-ip", "Local IPs are automatically allowed for peers from the same private network");
	for (auto &&pa : cmd.get_array("--seed-node-address"))
		parse_peer_and_add_to_container(pa, seed_nodes);
	for (auto &&pa : cmd.get_array("--seed-node", "Use --seed-node-address instead"))
		parse_peer_and_add_to_container(pa, seed_nodes);
	for (auto &&pa : cmd.get_array("--priority-node-address"))
		parse_peer_and_add_to_container(pa, priority_nodes);
	for (auto &&pa : cmd.get_array("--add-priority-node", "Use --priority-node-address instead"))
		parse_peer_and_add_to_container(pa, priority_nodes);
	std::vector<NetworkAddress> exclusive_nodes_list;
	for (auto &&pa : cmd.get_array("--exclusive-node-address"))
		parse_peer_and_add_to_container(pa, exclusive_nodes_list);
	for (auto &&pa : cmd.get_array("--add-exclusive-node", "Use --exclusive-node-address instead"))
		parse_peer_and_add_to_container(pa, exclusive_nodes_list);
	if (!priority_nodes.empty() && !exclusive_nodes_list.empty())
		throw std::runtime_error("Priority nodes and exclusive nodes cannot be used together");
	if (!exclusive_nodes_list.empty()) {
		exclusive_nodes = true;
		priority_nodes  = exclusive_nodes_list;
	}
	if (seed_nodes.empty() && net != "test")
		for (auto &&sn : net == "stage" ? SEED_NODES_STAGENET : SEED_NODES) {
			NetworkAddress addr;
			if (!common::parse_ip_address_and_port(sn, &addr.ip, &addr.port))
				continue;
			seed_nodes.push_back(addr);
		}
	std::sort(seed_nodes.begin(), seed_nodes.end());
	std::sort(priority_nodes.begin(), priority_nodes.end());

	data_folder = platform::get_app_data_folder(CRYPTONOTE_NAME);
	if (net != "main")
		data_folder += "_" + net + "net";
	if (const char *pa = cmd.get("--data-folder")) {
		data_folder = platform::normalize_folder(pa);
		if (!platform::folder_exists(data_folder))
			throw std::runtime_error("Data folder must exist " + data_folder);
	} else {
		if (!platform::create_folders_if_necessary(data_folder))  // Create only in default place
			throw std::runtime_error("Failed to create data folder " + data_folder);
	}
}

std::string Config::prepare_usage(const std::string &usage) {
	std::string result = usage;
	boost::replace_all(result, "bytecoin", CRYPTONOTE_NAME);
	boost::replace_all(result, "blocks.bin", BLOCKS_FILENAME);
	boost::replace_all(result, "blockindexes.bin", BLOCKINDEXES_FILENAME);
	boost::replace_all(result, "8080", common::to_string(P2P_DEFAULT_PORT));
	boost::replace_all(result, "8081", common::to_string(RPC_DEFAULT_PORT));
	boost::replace_all(result, "8070", common::to_string(WALLET_RPC_DEFAULT_PORT));
	return result;
}

std::string Config::get_data_folder(const std::string &subdir) const {
	std::string folder = data_folder;
	// This code is called just several times at startup, so no caching
	folder += "/" + subdir;
	if (!platform::create_folder_if_necessary(folder))
		throw std::runtime_error("Failed to create coin folder " + folder);
	return folder;
}
