// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include <boost/algorithm/string.hpp>
#include <future>
#include "Core/Config.hpp"
#include "Core/Node.hpp"
#include "Core/WalletNode.hpp"
#include "common/CommandLine.hpp"
#include "common/ConsoleTools.hpp"
#include "logging/LoggerManager.hpp"
#include "platform/ExclusiveLock.hpp"
#include "platform/Network.hpp"
#include "version.hpp"

using namespace byterub;

static const char USAGE[] =
    R"(walletd.

Usage:
  walletd [options] --wallet-file=<file> | --export-blocks=<directory>
  walletd --help | -h
  walletd --version | -v

Options:
  --wallet-file=<file>                 Path to wallet file to open.
  --wallet-password=<password>         DEPRECATED. Password to decrypt wallet file. If not specified, will read as a line from stdin.
  --generate-wallet                    Create wallet file with new random keys. Must be used with --wallet-file option.
  --import-keys=<hexbytes>             DEPRECATED. Create wallet file with specified imported keys. Must be used with --generate-wallet.
  --import-keys                        Create wallet file with imported keys read as a line from stdin. Must be used with --generate-wallet.
  --set-password=<password>            DEPRECATED. Reencrypt wallet file with the new password.
  --set-password                       Read new password as a line from stdin (twice) and reencrypt wallet file.
  --export-view-only=<file>            Export view-only version of wallet file with the same password, then exit.

  --testnet                            Configure for testnet.
  --walletd-bind-address=<ip:port>     Interface and port for walletd RPC [default: 127.0.0.1:8070].
  --walletd-authorization=<auth>       DEPRECATED. HTTP Basic Authorization header (base64 of login:password)

  --byterubd-remote-address=<ip:port> Connect to remote byterubd and suppress running built-in byterubd.
  --byterubd-authorization=<auth>     HTTP Basic Authorization header (base64 of login:password)

Options for built-in byterubd (run when no --byterubd-remote-address specified):
  --allow-local-ip                     Allow local ip add to peer list, mostly in debug purposes.
  --hide-my-port                       DEPRECATED. Do not announce yourself as peer list candidate. Use --p2p-external-port=0 instead.
  --p2p-bind-address=<ip:port>         Interface and port for P2P network protocol [default: 0.0.0.0:8080].
  --p2p-external-port=<port>           External port for P2P network protocol, if port forwarding used with NAT [default: 8080].
  --byterubd-bind-address=<ip:port>   Interface and port for byterubd RPC [default: 0.0.0.0:8081].
  --seed-node-address=<ip:port>        Specify list (one or more) of nodes to start connecting to.
  --priority-node-address=<ip:port>    Specify list (one or more) of nodes to connect to and attempt to keep the connection open.
  --exclusive-node-address=<ip:port>   Specify list (one or more) of nodes to connect to only. All other nodes including seed nodes will be ignored.
)";

static const bool separate_thread_for_byterubd = true;

int main(int argc, const char *argv[]) try {
	common::console::UnicodeConsoleSetup console_setup;
	auto idea_start = std::chrono::high_resolution_clock::now();
	common::CommandLine cmd(argc, argv);
	std::string wallet_file, password, new_password, export_view_only, import_keys_value;
	bool set_password         = false;
	bool password_in_args     = true;
	bool new_password_in_args = true;
	bool import_keys          = false;
	bool generate_wallet      = false;
	if (const char *pa = cmd.get("--wallet-file"))
		wallet_file = pa;
	if (const char *pa = cmd.get("--container-file", "Use --wallet-file instead"))
		wallet_file = pa;
	if (cmd.get_bool("--generate-wallet"))
		generate_wallet = true;
	if (cmd.get_bool("--generate-container", "Use --generate-wallet instead"))
		generate_wallet = true;
	if (const char *pa = cmd.get("--export-view-only"))
		export_view_only = pa;
	if (const char *pa = cmd.get("--wallet-password")) {
		password = pa;
		if (generate_wallet) {
			std::cout << "When generating wallet, use --set-password=<pass> argument for password" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
	} else if (const char *pa = cmd.get("--container-password", "Use --wallet-password instead")) {
		password = pa;
		if (generate_wallet) {
			std::cout << "When generating wallet, use --set-password=<pass> argument for password" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
	} else
		password_in_args = false;
	if (cmd.get_type("--set-password") == typeid(bool)) {
		cmd.get_bool("--set-password");  // mark option as used
		new_password_in_args = false;
		set_password         = true;
	} else if (const char *pa = cmd.get("--set-password")) {
		new_password = pa;
		set_password = true;
	} else
		new_password_in_args = false;
	if (generate_wallet) {
		if (cmd.get_type("--import-keys") == typeid(bool)) {
			cmd.get_bool("--import-keys");  // mark option as used
			import_keys = true;
		} else if (const char *pa = cmd.get("--import-keys")) {
			import_keys       = true;
			import_keys_value = pa;
			if (import_keys_value.empty()) {
				std::cout << "--import-keys=<hexbytes> should not be empty. Use --import-keys without value to enter "
				             "keys from stdin"
				          << std::endl;
				return api::WALLETD_WRONG_ARGS;
			}
		}
	}
	byterub::Config config(cmd);
	byterub::Currency currency(config.is_testnet);

	if (cmd.should_quit(USAGE, byterub::app_version()))
		return 0;
	logging::LoggerManager logManagerNode;
	logManagerNode.configure_default(config.get_coin_directory("logs"), "byterubd-");

	if (wallet_file.empty()) {
		std::cout << "--wallet-file=<file> argument is mandatory" << std::endl;
		return api::WALLETD_WRONG_ARGS;
	}
	if (generate_wallet && import_keys && import_keys_value.empty()) {
		std::cout << "Enter imported keys as hex bytes (05AB6F... etc.): " << std::flush;
		std::getline(std::cin, import_keys_value);
		boost::algorithm::trim(import_keys_value);
		if (import_keys_value.empty()) {
			std::cout << "Imported keys should not be empty" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
	}
	if (!generate_wallet && !password_in_args) {
		std::cout << "Enter current wallet password: " << std::flush;
		std::getline(std::cin, password);
		boost::algorithm::trim(password);
	}
	if ((generate_wallet || set_password) && !new_password_in_args) {
		std::cout << "Enter new wallet password: " << std::flush;
		std::getline(std::cin, new_password);
		boost::algorithm::trim(new_password);
		std::cout << "Repeat new wallet password:" << std::flush;
		std::string new_password2;
		std::getline(std::cin, new_password2);
		boost::algorithm::trim(new_password2);
		if (new_password != new_password2) {
			std::cout << "New passwords do not match" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
	}
	const std::string coinFolder = config.get_coin_directory();
	//	if (wallet_file.empty() && !generate_wallet) // No args can be provided when debugging with MSVC
	//		wallet_file = "C:\\Users\\user\\test.wallet";

	std::unique_ptr<platform::ExclusiveLock> blockchain_lock;
	std::unique_ptr<platform::ExclusiveLock> walletcache_lock;
	std::unique_ptr<Wallet> wallet;
	try {
		if (!config.byterubd_remote_port)
			blockchain_lock = std::make_unique<platform::ExclusiveLock>(coinFolder, "byterubd.lock");
	} catch (const platform::ExclusiveLock::FailedToLock &ex) {
		std::cout << ex.what() << std::endl;
		return api::BYTERUBD_ALREADY_RUNNING;
	}
	try {
		wallet = std::make_unique<Wallet>(
		    wallet_file, generate_wallet ? new_password : password, generate_wallet, import_keys_value);
		walletcache_lock = std::make_unique<platform::ExclusiveLock>(
		    config.get_coin_directory("wallet_cache"), wallet->get_cache_name() + ".lock");
	} catch (const std::ios_base::failure &ex) {
		std::cout << ex.what() << std::endl;
		return api::WALLET_FILE_READ_ERROR;
	} catch (const platform::ExclusiveLock::FailedToLock &ex) {
		std::cout << ex.what() << std::endl;
		return api::WALLET_WITH_THE_SAME_VIEWKEY_IN_USE;
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
	} catch (const std::ios_base::failure &ex) {
		std::cout << ex.what() << std::endl;
		return api::WALLET_FILE_WRITE_ERROR;
	} catch (const Wallet::Exception &ex) {
		std::cout << ex.what() << std::endl;
		return ex.return_code;
	}
	logging::LoggerManager logManagerWalletNode;
	logManagerWalletNode.configure_default(config.get_coin_directory("logs"), "walletd-");

	WalletState wallet_state(*wallet, logManagerWalletNode, config, currency);
	boost::asio::io_service io;
	platform::EventLoop run_loop(io);

	std::unique_ptr<BlockChainState> block_chain;
	std::unique_ptr<Node> node;

	std::promise<void> prm;
	std::thread byterubd_thread;
	if (!config.byterubd_remote_port) {
		try {
			if (separate_thread_for_byterubd) {
				byterubd_thread = std::thread([&prm, &logManagerNode, &config, &currency] {
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
				fut.wait();  // propagates thread exception from here
			} else {
				block_chain = std::make_unique<BlockChainState>(logManagerNode, config, currency);
				node        = std::make_unique<Node>(logManagerNode, config, *block_chain);
			}
		} catch (const boost::system::system_error &ex) {
			std::cout << ex.what() << std::endl;
			if (byterubd_thread.joinable())
				byterubd_thread.join();  // otherwise terminate will be called in ~thread
			return api::BYTERUBD_BIND_PORT_IN_USE;
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
} catch (const std::exception & ex) { // On Windows what() is not printed if thrown from main
	std::cout << "Exception in main() - " << ex.what() << std::endl;
	throw;
}
