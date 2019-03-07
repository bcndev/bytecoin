// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <boost/algorithm/string.hpp>
#include <future>
#include <random>
#include "Core/Config.hpp"
#include "Core/Node.hpp"
#include "Core/WalletNode.hpp"
#include "common/BIPs.hpp"
#include "common/Base64.hpp"
#include "common/CommandLine.hpp"
#include "common/ConsoleTools.hpp"
#include "logging/LoggerManager.hpp"
#include "platform/ExclusiveLock.hpp"
#include "platform/Network.hpp"
#include "platform/PathTools.hpp"
#include "platform/Time.hpp"
#include "version.hpp"

using namespace cn;

static const char USAGE[] = R"(walletd )" bytecoin_VERSION_STRING R"(.

Usage:
  walletd [options] --wallet-file=<file>
  walletd --help | -h
  walletd --version | -v

Options:
  --wallet-file=<file-path>             Path to wallet file to open.
  --import-keys                         Create wallet file with imported keys read as a line from stdin. Must be used with --wallet-type=legacy.
  --create-wallet                       Create wallet file with existing BIP39 mnemonic read as a line from stdin.
  --creation-timestamp=<t>              When creating wallet file, set wallet creation timestamp to <t> (now is possible value) [default: 0]. Must be used with --create-wallet option.
  --address-count=<c>                   When creating wallet file, immediately generate <c> addresses [default: 1].
  --wallet-type=<type>                  Used with --create-mnemonic, possible values are 'amethyst', 'legacy', 'hardware' [default: 'amethyst']
  --create-mnemonic                     Create a new random BIP39 mnemonic, then exit.
  --mnemonic-strength=<bits>            Used with --create-mnemonic, [default: 256].
  --secrets-via-api                     Specify to allow getting secrets using 'get_wallet_info' json RPC method (off by default for security reasons).
  --set-password                        Read new password as a line from stdin (twice) and re-encrypt wallet file, then exit.
  --launch-after-command                Instead of exiting, continue launching after --create-wallet, --set-password commands and --import-view-key
  --export-view-only=<file-path>        Export view-only version of wallet file, then exit. Add --set-password to export with different password.
  --view-outgoing-addresses             Used only with --export-view-only=<> and HD wallet. if set, exported view-only wallet will be able to see destination addresses in tracked transactions.
  --export-keys                         Export unencrypted wallet keys to stdout, then exit. (Only for legacy wallets)
  --export-mnemonic                     Export mnemonic to stdout, then exit. (Only for deterministic wallets)
  --import-view-key                     Import view key from hardware wallet into wallet file, greatly increasing blockchain scan speed (Only for hardware wallets).
  --walletd-bind-address=<ip:port>      IP and port for walletd RPC API [default: 127.0.0.1:8070].
  --data-folder=<folder-path>           Folder for wallet cache, blockchain, logs and peer DB [default: )" platform_DEFAULT_DATA_FOLDER_PATH_PREFIX
                            R"(bytecoin].
  --bytecoind-remote-address=<ip:port>  Connect to remote bytecoind and suppress running built-in bytecoind.
                                        Set this option to https://<host:port> instead, to connect to remote bytecoind via https
  --bytecoind-authorization=<user:pass> HTTP basic authentication credentials for RPC API.
  --backup-wallet-data=<folder-path>    Perform hot backup of wallet file, history, payment queue and wallet cache into specified empty folder, then exit.
                                        Add --set-password to set different password for backed-up wallet file.
  --net=<main|stage|test>               Configure for mainnet or testnet [default: main].

Options for built-in bytecoind (run when no --bytecoind-remote-address specified):
DEPRECATED AND NOT RECOMMENDED as entailing security risk. Please always run bytecoind as a separate process.
  --p2p-bind-address=<ip:port>          IP and port for P2P network protocol [default: 0.0.0.0:8080].
  --p2p-external-port=<port>            External port for P2P network protocol, if port forwarding used with NAT [default: 8080].
  --bytecoind-bind-address=<ip:port>    IP and port for bytecoind RPC [default: 127.0.0.1:8081].
  --seed-node-address=<ip:port>         Specify list (one or more) of nodes to start connecting to.
  --priority-node-address=<ip:port>     Specify list (one or more) of nodes to connect to and attempt to keep the connection open.
  --exclusive-node-address=<ip:port>    Specify list (one or more) of nodes to connect to only. All other nodes including seed nodes will be ignored.)";

static const bool separate_thread_for_bytecoind = true;

int main(int argc, const char *argv[]) try {
	common::console::UnicodeConsoleSetup console_setup;
	auto idea_start = std::chrono::high_resolution_clock::now();

	//	Visual Studio does not support passing cmake args in IDE
	//	const char *argv2[] = {"walletd", "--create-wallet", "--wallet-type=hardware", "--wallet-file=test.wallet"};
	//	const char argc2    = sizeof(argv2) / sizeof(*argv2);
	//  common::CommandLine cmd(argc2, argv2);

	common::CommandLine cmd(argc, argv);

	if (cmd.get_bool("--create-mnemonic")) {
		size_t bits = 256;
		if (const char *pa = cmd.get("--mnemonic-strength"))
			bits = boost::lexical_cast<size_t>(pa);
		if (cmd.should_quit(Config::prepare_usage(USAGE).c_str(), cn::app_version())) {
			std::cout
			    << "--create-mnemonic must be used with no other options or with --mnemonic-strength=<bits> option"
			    << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		try {
			std::cout << cn::Bip32Key::create_random_bip39_mnemonic(bits) << std::endl;
		} catch (const Bip32Key::Exception &e) {
			std::cerr << "Invalid mnemonic parameters. " << e.what() << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		return 0;
	}
	if (cmd.get_bool("--check-mnemonic")) {  // Undocumented, used by GUI for now
		if (cmd.should_quit(Config::prepare_usage(USAGE).c_str(), cn::app_version())) {
			std::cout << "--check-mnemonic cannot be used with other options" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		std::string mnemonic;
		if (!console_setup.getline(mnemonic)) {
			std::cout << "Unexpected end of stdin" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		try {
			mnemonic = cn::Bip32Key::check_bip39_mnemonic(mnemonic);
		} catch (const Bip32Key::Exception &ex) {
			std::cout << "Mnemonic invalid - " << common::what(ex) << std::endl;
			return api::WALLETD_MNEMONIC_CRC;
		}
		return 0;
	}
	// All other scenarios require wallet file
	std::string wallet_file;
	if (const char *pa = cmd.get("--wallet-file"))
		wallet_file = pa;
	if (wallet_file.empty()) {
		if (int r = cmd.should_quit(Config::prepare_usage(USAGE).c_str(), cn::app_version()))
			return r == 1 ? 0 : api::WALLETD_WRONG_ARGS;
		std::cout << "--wallet-file=<file> argument is mandatory" << std::endl;
		return api::WALLETD_WRONG_ARGS;
	}
	boost::optional<std::string> password;
	boost::optional<std::string> walletd_http_auth;
	if (const char *pa = cmd.get("--wallet-password")) {  // Undocumented, used for debugging
		password = pa;
		common::console::set_text_color(common::console::BrightRed);
		std::cout << "Password on command line is a security risk. Use 'echo <pwd> | ./walletd' or 'cat secrets.txt | "
		             "./walletd'"
		          << std::endl;
		common::console::set_text_color(common::console::Default);
	}
	if (const char *pa = cmd.get("--walletd-http-auth"))  // Undocumented, used for debugging
		walletd_http_auth = pa;
	const bool create_wallet   = cmd.get_bool("--create-wallet");
	const bool set_password    = cmd.get_bool("--set-password");
	const bool import_view_key = cmd.get_bool("--import-view-key");
	const bool export_keys     = cmd.get_bool("--export-keys");
	const bool export_mnemonic = cmd.get_bool("--export-mnemonic");
	std::string export_view_only;
	if (const char *pa = cmd.get("--export-view-only"))
		export_view_only = pa;
	std::string backup_wallet_data;
	if (const char *pa = cmd.get("--backup-wallet", "Deprecated, use --backup-wallet-data"))
		backup_wallet_data = pa;
	if (const char *pa = cmd.get("--backup-wallet-data"))
		backup_wallet_data = platform::normalize_folder(pa);

	// TODO check that only 1 of those commands used
	// create_wallet export_keys | export_view_only | backup_wallet_data
	// set_password can be used by itself or with export_view_only | backup_wallet_data

	const bool import_keys             = cmd.get_bool("--import-keys");
	const bool view_outgoing_addresses = cmd.get_bool("--view-outgoing-addresses");
	if (view_outgoing_addresses && export_view_only.empty()) {
		std::cout << "--view-outgoing-addresses can only be used with --export-view-only" << std::endl;
		return api::WALLETD_WRONG_ARGS;
	}
	const bool launch_after_command = cmd.get_bool("--launch-after-command");  // undocumented, used by GUI
	if (launch_after_command && !(create_wallet || set_password || import_view_key)) {
		std::cout << "--launch-after-command can only be used with commands" << std::endl;
		return api::WALLETD_WRONG_ARGS;
	}
	std::string wallet_type = "amethyst";
	if (const char *pa = cmd.get("--wallet-type")) {
		if (!create_wallet) {
			std::cout << "--wallet-type can only be used with --create-wallet" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		wallet_type = pa;
		if (wallet_type != "amethyst" && wallet_type != "legacy" && wallet_type != "hardware") {
			std::cout << "--wallet-type= value can be 'amethyst', 'legacy' or 'hardware'" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
	}
	if (import_keys && (!create_wallet || wallet_type != "legacy")) {
		std::cout << "--import-keys can only be used with --create-wallet --wallet-type=legacy" << std::endl;
		return api::WALLETD_WRONG_ARGS;
	}
	Timestamp creation_timestamp = 0;
	if (const char *pa = cmd.get("--creation-timestamp")) {
		if (!create_wallet) {
			std::cout << "--creation-timestamp can only be used when creating wallet" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		creation_timestamp =
		    std::string(pa) == "now" ? platform::now_unix_timestamp() : boost::lexical_cast<Timestamp>(pa);
	}
	size_t address_count = 0;
	if (const char *pa = cmd.get("--address-count")) {
		if (!create_wallet || wallet_type == "legacy") {
			std::cout << "--address-count cannot be used with --wallet-type=legacy" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		address_count = boost::lexical_cast<size_t>(pa);
	}

	Config config(cmd);
	Currency currency(config.net);

	if (const char *pa = cmd.get("--emulate-hardware-wallet"))  // Undocumented, used by devs
		hardware::HardwareWallet::debug_set_mnemonic(pa);

	if (int r = cmd.should_quit(Config::prepare_usage(USAGE).c_str(), cn::app_version()))
		return r == 1 ? 0 : api::WALLETD_WRONG_ARGS;

	std::string import_keys_value;
	if (import_keys) {
		std::cout << "Enter imported keys as hex bytes (05AB6F... etc.): " << std::flush;
		if (!console_setup.getline(import_keys_value)) {
			std::cout << "Unexpected end of stdin" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		std::cout << std::endl;
		boost::algorithm::trim(import_keys_value);
		if (import_keys_value.empty()) {
			std::cout << "Imported keys should not be empty" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
	}

	std::string mnemonic, mnemonic_password;
	if (create_wallet && wallet_type == "amethyst") {
		std::cout << "Enter BIP39 mnemonic: " << std::flush;
		if (!console_setup.getline(mnemonic)) {
			std::cout << "Unexpected end of stdin" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		try {
			mnemonic = cn::Bip32Key::check_bip39_mnemonic(mnemonic);
		} catch (const Bip32Key::Exception &ex) {
			std::cout << "Mnemonic invalid - " << common::what(ex) << std::endl;
			return api::WALLETD_MNEMONIC_CRC;
		}
		std::cout << "Enter BIP39 mnemonic password (empty recommended): " << std::flush;
		if (!console_setup.getline(mnemonic_password)) {
			std::cout << "Unexpected end of stdin" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		std::cout << std::endl;
		boost::algorithm::trim(mnemonic_password);
	}

	if (!create_wallet && !password) {
		std::cout << "Enter current wallet file password: " << std::flush;
		password = std::string();
		if (!console_setup.getline(password.get(), true)) {
			std::cout << "Unexpected end of stdin" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		std::cout << std::endl;
		boost::algorithm::trim(password.get());
	}
	std::string new_password;
	if ((create_wallet && wallet_type != "hardware") || set_password) {
		std::cout << "Enter new wallet file password: " << std::flush;
		if (!console_setup.getline(new_password, true)) {
			std::cout << "Unexpected end of stdin" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		std::cout << std::endl;
		boost::algorithm::trim(new_password);
		std::cout << "Repeat new wallet file password:" << std::flush;
		std::string new_password2;
		if (!console_setup.getline(new_password2, true)) {
			std::cout << "Unexpected end of stdin" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		std::cout << std::endl;
		boost::algorithm::trim(new_password2);
		if (new_password != new_password2) {
			std::cout << "New passwords do not match" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
	}

	const std::string coin_folder = config.get_data_folder();
	//	if (wallet_file.empty() && !generate_wallet) // No args can be provided when debugging with MSVC
	//		wallet_file = "C:\\Users\\user\\test.wallet";

	logging::LoggerManager logManagerWalletNode;
	logManagerWalletNode.configure_default(config.get_data_folder("logs"), "walletd-", cn::app_version());

	if (!config.bytecoind_remote_port && !create_wallet && !set_password && !import_view_key && !export_keys &&
	    !export_mnemonic && export_view_only.empty() && backup_wallet_data.empty()) {
		common::console::set_text_color(common::console::BrightRed);
		std::cout << "Warning: inproc " CRYPTONOTE_NAME "d is deprecated and will be removed soon." << std::endl;
		std::cout << "  Please run bytecoind separately, then specify --remote-" CRYPTONOTE_NAME
		             "d-address=<ip>:<port> argument to walletd"
		          << std::endl;
		std::cout << "  This is important to prevent " CRYPTONOTE_NAME
		             "d P2P attack vectors from reaching walletd address space where wallet keys reside"
		          << std::endl;
		common::console::set_text_color(common::console::Default);
	}
	boost::asio::io_service io;
	platform::EventLoop run_loop(io);  // must be before Wallet (trezor uses io)

	std::unique_ptr<Wallet> wallet;
	try {
		if (create_wallet && wallet_type == "hardware") {
			wallet = std::make_unique<WalletHD>(currency, logManagerWalletNode, wallet_file, new_password, mnemonic,
			    creation_timestamp, mnemonic_password, true);
			wallet->create_look_ahead_records(address_count);
		} else if (create_wallet && wallet_type == "amethyst") {
			wallet = std::make_unique<WalletHD>(currency, logManagerWalletNode, wallet_file, new_password, mnemonic,
			    creation_timestamp, mnemonic_password, false);
			wallet->create_look_ahead_records(address_count);
		} else if (create_wallet && wallet_type == "legacy") {
			wallet = std::make_unique<WalletContainerStorage>(
			    currency, logManagerWalletNode, wallet_file, new_password, import_keys_value, creation_timestamp);
		} else {
			const bool readonly =
			    !backup_wallet_data.empty() || !export_view_only.empty() || export_keys || export_mnemonic;
			const bool is_sqlite = WalletHD::is_sqlite(wallet_file);
			if (is_sqlite)
				wallet =
				    std::make_unique<WalletHD>(currency, logManagerWalletNode, wallet_file, password.get(), readonly);
			else
				wallet = std::make_unique<WalletContainerStorage>(
				    currency, logManagerWalletNode, wallet_file, password.get());
		}
	} catch (const common::StreamError &ex) {
		std::cout << common::what(ex) << std::endl;
		return api::WALLET_FILE_READ_ERROR;
	} catch (const Wallet::Exception &ex) {
		std::cout << common::what(ex) << std::endl;
		return ex.return_code;
	}
	if (create_wallet) {
		std::cout << "Successfully created wallet with first address "
		          << currency.account_address_as_string(wallet->get_first_address()) << std::endl;
	}
	if (import_view_key) {
		if (!wallet->get_hw()) {
			std::cout << "--import-view-key can be used only with hardware wallet" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		if (wallet->get_view_secret_key() != SecretKey{}) {
			std::cout << "Wallet file already contains view key, please remove --import-view-key argument" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		wallet->import_view_key();
	}
	if ((create_wallet || import_view_key) && !launch_after_command) {
		return 0;
	}
	std::cout << "Opened wallet with first address " << currency.account_address_as_string(wallet->get_first_address())
	          << std::endl;
	try {
		if (!backup_wallet_data.empty()) {
			const std::string name      = platform::get_filename_without_folder(wallet_file);
			const std::string dst_name  = backup_wallet_data + "/" + name;
			const std::string dst_cache = backup_wallet_data + "/wallet_cache/" + wallet->get_cache_name();
			if (!platform::create_folder_if_necessary(backup_wallet_data + "/wallet_cache")) {
				std::cout << "Could not create folder for backup " << (backup_wallet_data + "/wallet_cache")
				          << std::endl;
				return 1;
			}
			if (!platform::create_folder_if_necessary(dst_cache)) {
				std::cout << "Could not create folder for backup " << dst_cache << std::endl;
				return 1;
			}
			std::cout << "Backing up wallet file to " << dst_name << std::endl;
			wallet->backup(dst_name, set_password ? new_password : password.get());
			common::console::set_text_color(common::console::BrightRed);
			std::cout
			    << "There will be no progress printed for 1-20 minutes, depending on wallet size and computer speed."
			    << std::endl;
			common::console::set_text_color(common::console::Default);

			std::cout << "Starting wallet cache backup to " << dst_cache << std::endl;
			try {
				platform::DB::backup_db(coin_folder + "/wallet_cache/" + wallet->get_cache_name(), dst_cache);
			} catch (const std::exception &) {
				std::cout
				    << "Common error 'Failed to open database' usually means that wallet cache for this wallet file not found. Either walletd never started sync with this wallet file or was launched with different --data-folder"
				    << std::endl;
				throw;
			}
			std::cout << "Backing of wallet data finished successfully" << std::endl;
			return 0;
		}
		if (!export_view_only.empty()) {
			if (wallet->is_view_only()) {
				std::cout << "Cannot export as view-only, wallet file is already view-only" << std::endl;
				return api::WALLETD_WRONG_ARGS;
			}
			wallet->export_wallet(
			    export_view_only, set_password ? new_password : password.get(), true, view_outgoing_addresses);
			std::cout << "Successfully exported view-only copy of the wallet" << std::endl;
			return 0;
		}
		if (export_keys) {
			if (wallet->is_amethyst())
				throw Wallet::Exception(api::WALLETD_WRONG_ARGS, "You can only export keys from a legacy wallet");
			if (wallet->get_actual_records_count() != 1)
				throw Wallet::Exception(api::WALLETD_EXPORTKEYS_MORETHANONE,
				    "You can only export keys from a legacy wallet if it is containing 1 address, otherwise just back it up");
			std::cout << wallet->export_keys() << std::endl;  // exports mnemonic for HD wallet
			return 0;
		}
		if (export_mnemonic) {
			if (!wallet->is_amethyst())
				throw Wallet::Exception(
				    api::WALLETD_WRONG_ARGS, "You can only export mnemonic from a deterministic wallet");
			std::cout << wallet->export_keys() << std::endl;  // exports mnemonic for HD wallet
			return 0;
		}
		if (set_password) {
			wallet->set_password(new_password);
			std::cout << "Successfully set new password" << std::endl;
			if (!launch_after_command)
				return 0;
		}
	} catch (const common::StreamError &ex) {
		std::cout << common::what(ex) << std::endl;
		return api::WALLET_FILE_WRITE_ERROR;
	} catch (const Wallet::Exception &ex) {
		std::cout << common::what(ex) << std::endl;
		return ex.return_code;
	} catch (const std::exception &ex) {
		std::cout << common::what(ex) << std::endl;
		return 1;
	}
	if (!walletd_http_auth) {
		std::cout << "Enter HTTP authorization <user>:<password> for walletd RPC: " << std::flush;
		walletd_http_auth = std::string();
		if (!console_setup.getline(walletd_http_auth.get(), true)) {
			std::cout << "Unexpected end of stdin" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
		std::cout << std::endl;
	}
	boost::algorithm::trim(walletd_http_auth.get());
	config.walletd_authorization = common::base64::encode(common::as_binary_array(walletd_http_auth.get()));
	if (config.walletd_authorization.empty()) {
		common::console::set_text_color(common::console::BrightRed);
		std::cout << "No authorization for RPC is a security risk. Use username with a strong password" << std::endl;
		common::console::set_text_color(common::console::Default);
	} else {
		if (walletd_http_auth.get().find(":") == std::string::npos) {
			std::cout << "HTTP authorization must be in the format <user>:<password>" << std::endl;
			return api::WALLETD_WRONG_ARGS;
		}
	}
	std::unique_ptr<platform::ExclusiveLock> blockchain_lock;
	try {
		if (!config.bytecoind_remote_port)
			blockchain_lock = std::make_unique<platform::ExclusiveLock>(coin_folder, CRYPTONOTE_NAME "d.lock");
	} catch (const platform::ExclusiveLock::FailedToLock &ex) {
		std::cout << "Bytecoind already running - " << common::what(ex) << std::endl;
		return api::BYTECOIND_ALREADY_RUNNING;
	}
	std::unique_ptr<platform::ExclusiveLock> walletcache_lock;
	try {
		std::cout << "Using wallet cache folder " << config.get_data_folder("wallet_cache") << "/"
		          << wallet->get_cache_name() << std::endl;
		walletcache_lock = std::make_unique<platform::ExclusiveLock>(
		    config.get_data_folder("wallet_cache"), wallet->get_cache_name() + ".lock");
	} catch (const platform::ExclusiveLock::FailedToLock &ex) {
		std::cout << "Wallet with the same first address is in use - " << common::what(ex) << std::endl;
		return api::WALLET_WITH_SAME_KEYS_IN_USE;
	}
	WalletState wallet_state(*wallet, logManagerWalletNode, config, currency);
	//	wallet_state.test_undo_blocks();
	//	return 0;

	std::unique_ptr<BlockChainState> block_chain;
	std::unique_ptr<Node> node;

	logging::LoggerManager logManagerNode;
	logManagerNode.configure_default(config.get_data_folder("logs"), CRYPTONOTE_NAME "d-", cn::app_version());

	std::unique_ptr<WalletNode> wallet_node;
	try {
		wallet_node = std::make_unique<WalletNode>(nullptr, logManagerWalletNode, config, wallet_state);
	} catch (const platform::TCPAcceptor::AddressInUse &ex) {
		std::cout << common::what(ex) << std::endl;
		return api::WALLETD_BIND_PORT_IN_USE;  // We should return before we create bytecoind thread, otherwise
		                                       // terminate
	}
	std::promise<void> prm;
	std::thread bytecoind_thread;
	if (!config.bytecoind_remote_port) {
		try {
			if (separate_thread_for_bytecoind) {
				bytecoind_thread      = std::thread([&prm, &logManagerNode, &config, &currency] {
                    boost::asio::io_service io;
                    platform::EventLoop separate_run_loop(io);

                    std::unique_ptr<BlockChainState> separate_block_chain;
                    std::unique_ptr<Node> separate_node;
                    try {
                        separate_block_chain =
                            std::make_unique<BlockChainState>(logManagerNode, config, currency, false);
                        separate_node = std::make_unique<Node>(logManagerNode, config, *separate_block_chain);
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
				block_chain = std::make_unique<BlockChainState>(logManagerNode, config, currency, false);
				node        = std::make_unique<Node>(logManagerNode, config, *block_chain);
			}
		} catch (const platform::TCPAcceptor::AddressInUse &ex) {
			std::cout << common::what(ex) << std::endl;
			if (bytecoind_thread.joinable())
				bytecoind_thread.join();  // otherwise terminate will be called in ~thread
			return api::BYTECOIND_BIND_PORT_IN_USE;
		} catch (const BlockChainState::Exception &ex) {
			std::cout << common::what(ex) << std::endl;
			if (bytecoind_thread.joinable())
				bytecoind_thread.join();  // otherwise terminate will be called in ~thread
			return api::BYTECOIND_DATABASE_FORMAT_TOO_NEW;
		} catch (const std::exception &ex) {  // On Windows what() is not printed if thrown from main
			std::cout << "Uncaught Exception in main() - " << common::what(ex) << std::endl;
			// TODO - check that ..joinable()..join().. code from above does not apply also
			throw;
		}
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
	std::cout << "Uncaught Exception in main() - " << common::what(ex) << std::endl;
	throw;
}
