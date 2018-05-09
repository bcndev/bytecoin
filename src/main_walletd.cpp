// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <boost/algorithm/string.hpp>
#include <common/Base64.hpp>
#include <future>
#include "Core/Config.hpp"
#include "Core/Node.hpp"
#include "Core/WalletNode.hpp"
#include "common/CommandLine.hpp"
#include "common/ConsoleTools.hpp"
#include "logging/LoggerManager.hpp"
#include "platform/ExclusiveLock.hpp"
#include "platform/Network.hpp"
#include "platform/PathTools.hpp"
#include "version.hpp"

using namespace bytecoin;

static const char USAGE[] =
    R"(walletd )" bytecoin_VERSION_STRING R"(.

Usage:
  walletd [options] --wallet-file=<file> | --export-blocks=<directory>
  walletd --help | -h
  walletd --version | -v

Options:
  --wallet-file=<file>                 Path to wallet file to open.
  --wallet-password=<password>         DEPRECATED AND NOT RECOMMENDED (as entailing security risk). Use given string as password and not read it from stdin.
  --create-wallet                      Create wallet file with new random keys. Must be used with --wallet-file option.
  --import-keys                        Create wallet file with imported keys read as a line from stdin. Must be used with --create-wallet.
  --set-password                       Read new password as a line from stdin (twice) and reencrypt wallet file.
  --export-view-only=<file>            Export view-only version of wallet file with the same password, then exit.
  --export-keys                        Export wallet keys to stdout, then exit.
  --testnet                            Configure for testnet.
  --walletd-bind-address=<ip:port>     Interface and port for walletd RPC [default: 127.0.0.1:8070].
  --data-folder=<full-path>            Folder for wallet cache, blockchain, logs and peer DB [default: )" platform_DEFAULT_DATA_FOLDER_PATH_PREFIX
    R"(bytecoin].
  --bytecoind-remote-address=<ip:port> Connect to remote bytecoind and suppress running built-in bytecoind.
  --bytecoind-authorization=<usr:pass> HTTP authorization for RCP.

Options for built-in bytecoind (run when no --bytecoind-remote-address specified):
  --allow-local-ip                     Allow local ip add to peer list, mostly in debug purposes.
  --p2p-bind-address=<ip:port>         Interface and port for P2P network protocol [default: 0.0.0.0:8080].
  --p2p-external-port=<port>           External port for P2P network protocol, if port forwarding used with NAT [default: 8080].
  --bytecoind-bind-address=<ip:port>   Interface and port for bytecoind RPC [default: 127.0.0.1:8081].
  --seed-node-address=<ip:port>        Specify list (one or more) of nodes to start connecting to.
  --priority-node-address=<ip:port>    Specify list (one or more) of nodes to connect to and attempt to keep the connection open.
  --exclusive-node-address=<ip:port>   Specify list (one or more) of nodes to connect to only. All other nodes including seed nodes will be ignored.)";

static const bool separate_thread_for_bytecoind = true;

int main(int argc, const char *argv[]) try {
	common::console::UnicodeConsoleSetup console_setup;
	auto idea_start = std::chrono::high_resolution_clock::now();
	common::CommandLine cmd(argc, argv);
	std::string wallet_file, password, new_password, export_view_only, import_keys_value;
	const bool set_password  = cmd.get_bool("--set-password");
	bool ask_password        = true;
	const bool export_keys   = cmd.get_bool("--export-keys");
	const bool create_wallet = cmd.get_bool("--create-wallet");
	const bool import_keys   = create_wallet && cmd.get_bool("--import-keys");
	if (const char *pa = cmd.get("--wallet-file"))
		wallet_file = pa;
	if (const char *pa = cmd.get("--export-view-only"))
		export_view_only = pa;
	if (const char *pa = cmd.get("--wallet-password")) {
		password     = pa;
		ask_password = false;
	}
	if (!ask_password && create_wallet) {
		std::cout << "When generating wallet, you cannot use --wallet-password. Wallet password will be read from stdin"
		          << std::endl;
		return api::WALLETD_WRONG_ARGS;
	}

	bytecoin::Config config(cmd);
	bytecoin::Currency currency(config.is_testnet);

	if (cmd.should_quit(USAGE, bytecoin::app_version()))
		return api::WALLETD_WRONG_ARGS;
	logging::LoggerManager logManagerNode;
	logManagerNode.configure_default(config.get_data_folder("logs"), "bytecoind-");

	if (wallet_file.empty()) {
		std::cout << "--wallet-file=<file> argument is mandatory" << std::endl;
		return api::WALLETD_WRONG_ARGS;
	}
	if (create_wallet && import_keys && import_keys_value.empty()) {
		std::cout << "Enter imported keys as hex bytes (05AB6F... etc.): " << std::flush;
		if (!std::getline(std::cin, import_keys_value)) {
			std::cout << "Unexpected end of stdin" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		boost::algorithm::trim(import_keys_value);
		if (import_keys_value.empty()) {
			std::cout << "Imported keys should not be empty" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
	}
	if (!create_wallet && ask_password) {
		std::cout << "Enter current wallet password: " << std::flush;
		if (!std::getline(std::cin, password)) {
			std::cout << "Unexpected end of stdin" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		boost::algorithm::trim(password);
	}
	if (create_wallet || set_password) {
		std::cout << "Enter new wallet password: " << std::flush;
		if (!std::getline(std::cin, new_password)) {
			std::cout << "Unexpected end of stdin" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		boost::algorithm::trim(new_password);
		std::cout << "Repeat new wallet password:" << std::flush;
		std::string new_password2;
		if (!std::getline(std::cin, new_password2)) {
			std::cout << "Unexpected end of stdin" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		boost::algorithm::trim(new_password2);
		if (new_password != new_password2) {
			std::cout << "New passwords do not match" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
	}
	const std::string coinFolder = config.get_data_folder();
	//	if (wallet_file.empty() && !generate_wallet) // No args can be provided when debugging with MSVC
	//		wallet_file = "C:\\Users\\user\\test.wallet";

	std::unique_ptr<platform::ExclusiveLock> walletcache_lock;
	std::unique_ptr<Wallet> wallet;
	try {
		wallet = std::make_unique<Wallet>(
		    wallet_file, create_wallet ? new_password : password, create_wallet, import_keys_value);
	} catch (const common::StreamError &ex) {
		std::cout << ex.what() << std::endl;
		return api::WALLET_FILE_READ_ERROR;
	} catch (const Wallet::Exception &ex) {
		std::cout << ex.what() << std::endl;
		return ex.return_code;
	}
	try {
		if (set_password)
			wallet->set_password(new_password);
		if (!export_view_only.empty()) {
			wallet->export_view_only(export_view_only);
			return 0;
		}
		if (export_keys) {
			std::cout << common::to_hex(wallet->export_keys()) << std::endl;
			return 0;
		}
	} catch (const common::StreamError &ex) {
		std::cout << ex.what() << std::endl;
		return api::WALLET_FILE_WRITE_ERROR;
	} catch (const Wallet::Exception &ex) {
		std::cout << ex.what() << std::endl;
		return ex.return_code;
	}
	std::unique_ptr<platform::ExclusiveLock> blockchain_lock;
	try {
		if (!config.bytecoind_remote_port)
			blockchain_lock = std::make_unique<platform::ExclusiveLock>(coinFolder, "bytecoind.lock");
	} catch (const platform::ExclusiveLock::FailedToLock &ex) {
		std::cout << "Bytecoind already running - " << ex.what() << std::endl;
		return api::BYTECOIND_ALREADY_RUNNING;
	}
	try {
		walletcache_lock = std::make_unique<platform::ExclusiveLock>(
		    config.get_data_folder("wallet_cache"), wallet->get_cache_name() + ".lock");
	} catch (const platform::ExclusiveLock::FailedToLock &ex) {
		std::cout << "Wallet with the same viewkey is in use - " << ex.what() << std::endl;
		return api::WALLET_WITH_THE_SAME_VIEWKEY_IN_USE;
	}
	if (!ask_password) {
		common::console::set_text_color(common::console::BrightRed);
		std::cout << "Password on command line is a security risk. Use echo <pwd> | ./walletd" << std::endl;
		common::console::set_text_color(common::console::Default);
	}
	std::cout << "Enter HTTP authorization <user>:<password> for walletd RPC: " << std::flush;
	std::string auth;
	if (!std::getline(std::cin, auth)) {
		std::cout << "Unexpected end of stdin" << std::endl;
		return api::WALLETD_WRONG_ARGS;
	}
	boost::algorithm::trim(auth);
	config.walletd_authorization = common::base64::encode(BinaryArray(auth.data(), auth.data() + auth.size()));
	if (config.walletd_authorization.empty()) {
		common::console::set_text_color(common::console::BrightRed);
		std::cout << "No authorization for RPC is a security risk. Use username with a strong password" << std::endl;
		common::console::set_text_color(common::console::Default);
	} else {
		if (auth.find(":") == std::string::npos) {
			std::cout << "HTTP authorization must be in the format <user>:<password>" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
	}
	logging::LoggerManager logManagerWalletNode;
	logManagerWalletNode.configure_default(config.get_data_folder("logs"), "walletd-");

	WalletState wallet_state(*wallet, logManagerWalletNode, config, currency);
	boost::asio::io_service io;
	platform::EventLoop run_loop(io);

	std::unique_ptr<BlockChainState> block_chain;
	std::unique_ptr<Node> node;

	std::promise<void> prm;
	std::thread bytecoind_thread;
	if (!config.bytecoind_remote_port) {
		try {
			if (separate_thread_for_bytecoind) {
				bytecoind_thread = std::thread([&prm, &logManagerNode, &config, &currency] {
					boost::asio::io_service io;
					platform::EventLoop separate_run_loop(io);

					std::unique_ptr<BlockChainState> separate_block_chain;
					std::unique_ptr<Node> separate_node;
					try {
						separate_block_chain = std::make_unique<BlockChainState>(logManagerNode, config, currency);
						separate_node        = std::make_unique<Node>(logManagerNode, config, *separate_block_chain);
						prm.set_value();
					} catch (...) {
						prm.set_exception(std::current_exception());
						return;
					}
					while (!io.stopped()) {
						if (separate_node->on_idle())  // We load blockchain there
							io.poll();
						else
							io.run_one();
					}
				});
				std::future<void> fut = prm.get_future();
				fut.get();  // propagates thread exception from here
			} else {
				block_chain = std::make_unique<BlockChainState>(logManagerNode, config, currency);
				node        = std::make_unique<Node>(logManagerNode, config, *block_chain);
			}
		} catch (const boost::system::system_error &ex) {
			std::cout << ex.what() << std::endl;
			if (bytecoind_thread.joinable())
				bytecoind_thread.join();  // otherwise terminate will be called in ~thread
			return api::BYTECOIND_BIND_PORT_IN_USE;
		}
	}

	std::unique_ptr<WalletNode> wallet_node;
	try {
		wallet_node = std::make_unique<WalletNode>(nullptr, logManagerWalletNode, config, wallet_state);
	} catch (const boost::system::system_error &ex) {
		std::cout << ex.what() << std::endl;
		return api::WALLETD_BIND_PORT_IN_USE;
	}

	auto idea_ms =
	    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - idea_start);
	std::cout << "walletd started seconds=" << double(idea_ms.count()) / 1000 << std::endl;

	while (!io.stopped()) {
		if (node && node->on_idle())  // We load blockchain there
			io.poll();
		else
			io.run_one();
	}
	return 0;
} catch (const std::exception &ex) {  // On Windows what() is not printed if thrown from main
	std::cout << "Exception in main() - " << ex.what() << std::endl;
	throw;
}
