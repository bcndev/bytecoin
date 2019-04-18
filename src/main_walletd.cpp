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
  walletd --create-mnemonic [--mnemonic-strength=<bits>]
  walletd --help | -h
  walletd --version | -v

Creating wallets:
  --create-wallet                       Create wallet file with existing BIP39 mnemonic read as a line from stdin.
  --wallet-type=<type>                  Possible values are 'amethyst', 'legacy', 'hardware' [default: 'amethyst']
  --creation-timestamp=<t>              Set wallet creation timestamp (unix timestamp or 'now') [default: 0].
  --address-count=<c>                   Immediately generate number of addresses [default: 1].
  --import-keys                         Import keys read as a line from stdin (only for 'legacy' wallet type).

Modifying wallets:
  --set-password                        Read new password as a line from stdin (twice) and re-encrypt wallet file, then exit.
                                        Can be used with --export-view-only or --backup-wallet-data to set destination wallet password.
  --export-view-only=<file-path>        Export view-only version of wallet file, then exit.
  --view-outgoing-addresses             Used only with --export-view-only and 'amethyst' wallet. Exported view-only wallet
                                        will be able to see destination addresses in tracked transactions.
  --export-keys                         Export unencrypted wallet keys to stdout, then exit. (Only for 'legacy' wallets)
  --export-mnemonic                     Export mnemonic to stdout, then exit. (Only for 'amethyst' wallets)
  --import-view-key                     Import view key from hardware wallet into wallet file, greatly increasing blockchain scan speed.
  --backup-wallet-data=<folder-path>    Hot backup of wallet file, history, payment queue and cache into specified empty folder, then exit.

Running with selected wallet:
  --secrets-via-api                     Allow getting secrets using 'get_wallet_info' json RPC method.
  --launch-after-command                Continue launching after --create-wallet, --set-password and --import-view-key
  --walletd-bind-address=<ip:port>      IP and port for walletd RPC API [default: 127.0.0.1:8070].
  --data-folder=<folder-path>           Folder for wallet cache, blockchain, logs and peer DB [default: %appdata%/bytecoin].
  --bytecoind-remote-address=<ip:port>  Connect to remote bytecoind and suppress running built-in bytecoind.
                                        Set this option to https://<host:port> instead, to connect to remote bytecoind via https
  --bytecoind-authorization=<user:pass> HTTP basic authentication credentials for RPC API.
  --net=<main|stage|test>               Configure for mainnet or testnet [default: main].

Options for BIP39 mnemonic creation
  --create-mnemonic                     Create a new random BIP39 mnemonic, then exit.
  --mnemonic-strength=<bits>            Used with --create-mnemonic, [default: 256].

Options for built-in bytecoind (run when no --bytecoind-remote-address specified):
DEPRECATED AND NOT RECOMMENDED as entailing security risk. Please always run bytecoind as a separate process.
  --p2p-bind-address=<ip:port>          IP and port for P2P network protocol [default: 0.0.0.0:8080].
  --p2p-external-port=<port>            External port for P2P network protocol, if port forwarding used with NAT [default: 8080].
  --bytecoind-bind-address=<ip:port>    IP and port for bytecoind RPC [default: 127.0.0.1:8081].
  --seed-node-address=<ip:port>         Specify list (one or more) of nodes to start connecting to.
  --priority-node-address=<ip:port>     Specify list (one or more) of nodes to connect to and attempt to keep the connection open.
  --exclusive-node-address=<ip:port>    Specify list (one or more) of nodes to connect to only. All other nodes including seed nodes will be ignored.)";

static const bool separate_thread_for_bytecoind = true;

// All launch scenarios

// *Creating mnemonic
//  --create-mnemonic                     Create a new random BIP39 mnemonic, then exit.
//  --mnemonic-strength=<bits>            Used with --create-mnemonic, [default: 256].
//  always exit

// *Checking mnemonic (undocumented)
// --check-mnemonic
//  always exit

// *All other options below require
// --wallet-file=<file-path>             Path to wallet file to open.
// Config options are also read here

//  *Export wallet
//  --export-view-only=<file-path>        Export view-only version of wallet file, then exit...
//  --view-outgoing-addresses             Used only with --export-view-only=<> and HD wallet. if set...
//  --set-password, Asks password 2x always exit
//  Asks password/Opens wallet
//  always exit

//  *Export keys/mnemonic
//  --export-keys                         Export unencrypted wallet keys to stdout, then exit. (Only for legacy wallets)
//  --export-mnemonic                     Export mnemonic to stdout, then exit. (Only for deterministic wallets)
//  Asks password/Opens wallet
//  always exit

//  *Backup wallet
//  --backup-wallet-data=<folder-path>    Perform hot backup of wallet file...
//  Asks password/Opens wallet
//  if --set-password, Asks password 2x
//  always exit

// Creating wallet
//  --create-wallet                       Create wallet file with existing BIP39 mnemonic read as a line from stdin.
//  --wallet-type=<type>                  Used with --create-wallet...
//  --import-keys                         Create wallet file with imported keys...
//  --creation-timestamp=<t>              When creating wallet file, set wallet creation timestamp...
//  --address-count=<c>                   When creating wallet file, immediately generate <c> addresses [default: 1].
//  --import-view-key                     Import view key from hardware wallet into wallet file...
//  Asks password 2x
//  --launch-after-command

//  If no other command used, sets password and/or imports view key are command
//  --import-view-key                     Import view key from hardware wallet...
//  --set-password                        Read new password...
//  (Asks password 2x if --set-password set)
//  --launch-after-command

// Config options
//  --net=<main|stage|test>               Configure for mainnet or testnet [default: main].
//  --secrets-via-api                     Specify to allow...
//  --walletd-bind-address=<ip:port>      IP and port for walletd RPC API [default: 127.0.0.1:8070].
//  --data-folder=<folder-path>           Folder for wallet cache, blockchain, logs and peer DB
//  --bytecoind-remote-address=<ip:port>  Connect to remote bytecoind...
//  --bytecoind-authorization=<user:pass> HTTP basic authentication credentials for RPC API.

void wrong_args(const std::string &msg) { throw Wallet::Exception(api::WALLETD_WRONG_ARGS, msg); }

void warning(const std::string &msg) {
	common::console::set_text_color(common::console::BrightRed);
	std::cout << msg << std::endl;
	common::console::set_text_color(common::console::Default);
}

std::string getline(common::console::UnicodeConsoleSetup &console_setup, const bool hide_input = false) {
	std::string result;
	if (!console_setup.getline(result, hide_input))
		wrong_args("Unexpected end of stdin.");
	return result;
}

std::string prompt_for_string(const std::string &prompt,
    common::console::UnicodeConsoleSetup &console_setup,
    const bool hide_input = false) {
	std::cout << prompt << ": " << std::flush;
	auto result = getline(console_setup, hide_input);
	if (hide_input)
		std::cout << std::endl;
	return boost::algorithm::trim_copy(result);
}

template<class T>
T safe_lexical_cast(const std::string &str, const std::string &option, const std::string &range) {
	try {
		return common::integer_cast<T>(str);
	} catch (const std::exception &) {
		wrong_args("Command line option " + option + " has wrong value '" + str + "', should be " + range);
	}
	return T{};
}

int create_mnemonic(common::console::UnicodeConsoleSetup &console_setup, common::CommandLine &cmd) {
	size_t bits = 256;
	if (const char *pa = cmd.get("--mnemonic-strength"))
		bits = safe_lexical_cast<size_t>(pa, "--mnemonic-strength", "number in range 128..256");
	if (cmd.show_errors("cannot be used with --create-mnemonic"))
		wrong_args(
		    "Command line option --create-mnemonic must be used with no other options or with --mnemonic-strength=<bits> option");
	std::cout << cn::Bip32Key::create_random_bip39_mnemonic(bits) << std::endl;
	return 0;
}

int check_mnemonic(common::console::UnicodeConsoleSetup &console_setup, common::CommandLine &cmd) {
	if (cmd.show_errors("cannot be used with --check-mnemonic"))
		wrong_args("Command line option --check-mnemonic cannot be used with other options");
	std::string mnemonic = getline(console_setup);
	mnemonic             = cn::Bip32Key::check_bip39_mnemonic(mnemonic);
	return 0;
}

boost::optional<std::string> read_wallet_password(common::CommandLine &cmd) {
	boost::optional<std::string> password;
	if (const char *pa = cmd.get("--wallet-password")) {  // Undocumented, used for debugging
		password = std::string(pa);
		warning(
		    "Password on command line is a security risk. Use 'echo <pwd> | ./walletd' or 'cat secrets.txt | "
		    "./walletd'");
	}
	return password;
}

std::string read_non_empty(const char *option, common::CommandLine &cmd) {
	std::string result;
	if (const char *pa = cmd.get(option)) {
		result = pa;
		if (result.empty())
			wrong_args("Command line option " + std::string(option) + " cannot be empty string");
	}
	return result;
}

std::unique_ptr<Wallet> open_wallet(const Currency &currency, logging::ILogger &log, const std::string &wallet_file,
    boost::optional<std::string> *password, bool readonly, common::console::UnicodeConsoleSetup &console_setup) {
	if (!*password)
		*password = prompt_for_string("Enter current wallet file password", console_setup, true);
	const bool is_sqlite = WalletHD::is_sqlite(wallet_file);
	std::unique_ptr<Wallet> wallet;
	if (is_sqlite)
		wallet = std::make_unique<WalletHD>(currency, log, wallet_file, password->get(), readonly);
	else
		wallet = std::make_unique<WalletContainerStorage>(currency, log, wallet_file, password->get());
	std::cout << "Opened wallet with first address " << currency.account_address_as_string(wallet->get_first_address())
	          << std::endl;
	return wallet;
}

std::string ask_new_password(
    bool set_password, const std::string &password, common::console::UnicodeConsoleSetup &console_setup) {
	if (!set_password)
		return password;
	std::string new_password  = prompt_for_string("Enter new wallet file password", console_setup, true);
	std::string new_password2 = prompt_for_string("Repeat new wallet file password", console_setup, true);
	if (new_password != new_password2)
		wrong_args("New passwords do not match");
	return new_password;
}

std::unique_ptr<Wallet> create_wallet(const Currency &currency, logging::ILogger &log, const std::string &wallet_file,
    common::CommandLine &cmd, common::console::UnicodeConsoleSetup &console_setup) {
	std::string wallet_type = "amethyst";
	if (const char *pa = cmd.get("--wallet-type")) {
		wallet_type = pa;
		if (wallet_type != "amethyst" && wallet_type != "legacy" && wallet_type != "hardware")
			wrong_args("Command line option --wallet-type has wrong value '" + wallet_type +
			           "', should be 'amethyst', 'legacy' or 'hardware'");
	}
	const bool import_keys = cmd.get_bool("--import-keys");
	if (import_keys && wallet_type != "legacy")
		wrong_args("Command line option --import-keys can only be used with --wallet-type=legacy");
	size_t address_count = 0;
	if (const char *pa = cmd.get("--address-count")) {
		if (wallet_type == "legacy")
			wrong_args("Command line option --address-count cannot be used with --wallet-type=legacy");
		address_count = safe_lexical_cast<uint32_t>(pa, "--address-count", "number in range 0..4294967295");
	}
	const bool import_view_key = cmd.get_bool("--import-view-key");
	if (import_view_key && wallet_type != "hardware")
		wrong_args("Command line option --import-view-key can only be used with --wallet-type=hardware");

	Timestamp creation_timestamp = 0;
	if (const char *pa = cmd.get("--creation-timestamp")) {
		creation_timestamp = std::string(pa) == "now" ? platform::now_unix_timestamp()
		                                              : safe_lexical_cast<Timestamp>(pa, "--creation-timestamp",
		                                                    "number in range 0..4294967295 or 'now'");
	}
	if (cmd.show_errors("cannot be used with --create-wallet"))
		return std::unique_ptr<Wallet>{};
	std::string import_keys_value;
	if (import_keys) {
		import_keys_value = prompt_for_string("Enter imported keys as hex bytes (05AB6F... etc.)", console_setup);
		if (import_keys_value.empty())
			wrong_args("Imported keys should not be empty");
	}
	std::string mnemonic, mnemonic_password;
	if (wallet_type == "amethyst") {
		mnemonic          = prompt_for_string("Enter BIP39 mnemonic", console_setup);
		mnemonic          = cn::Bip32Key::check_bip39_mnemonic(mnemonic);
		mnemonic_password = prompt_for_string("Enter BIP39 mnemonic password (empty recommended)", console_setup);
	}
	std::string new_password = ask_new_password(true, std::string(), console_setup);
	std::unique_ptr<Wallet> wallet;
	if (wallet_type == "hardware") {
		wallet = std::make_unique<WalletHD>(
		    currency, log, wallet_file, new_password, mnemonic, creation_timestamp, mnemonic_password, true);
		wallet->create_look_ahead_records(address_count);
		if (import_view_key) {
			wallet->import_view_key();
			std::cout << "Successfully imported view key" << std::endl;
		}
	} else if (wallet_type == "amethyst") {
		wallet = std::make_unique<WalletHD>(
		    currency, log, wallet_file, new_password, mnemonic, creation_timestamp, mnemonic_password, false);
		wallet->create_look_ahead_records(address_count);
	} else if (wallet_type == "legacy") {
		wallet = std::make_unique<WalletContainerStorage>(
		    currency, log, wallet_file, new_password, import_keys_value, creation_timestamp);
	}
	std::cout << "Successfully created wallet with first address "
	          << currency.account_address_as_string(wallet->get_first_address()) << std::endl;
	return wallet;
}

int main(int argc, const char *argv[]) try {
	common::console::UnicodeConsoleSetup console_setup;
	auto idea_start = std::chrono::high_resolution_clock::now();

	//	Visual Studio does not support passing cmake args in IDE
	//	const char *argv2[] = {"walletd", "--create-wallet", "--wallet-type=hardware", "--wallet-file=test.wallet"};
	//	const char argc2    = sizeof(argv2) / sizeof(*argv2);
	//  common::CommandLine cmd(argc2, argv2);

	common::CommandLine cmd(argc, argv);
	if (cmd.show_help(Config::prepare_usage(USAGE).c_str(), cn::app_version()))
		return 0;
	if (cmd.get_bool("--create-mnemonic"))
		return create_mnemonic(console_setup, cmd);
	if (cmd.get_bool("--check-mnemonic"))  // Undocumented, used by GUI for now
		return check_mnemonic(console_setup, cmd);

	Config config(cmd);
	Currency currency(config.net);
	const std::string coin_folder = config.get_data_folder();
	if (const char *pa = cmd.get("--emulate-hardware-wallet"))  // Undocumented, used by devs
		hardware::Proxy::debug_set_mnemonic(pa);

	// --wallet-password and --walletd-http-auth are insecure but important for testing
	boost::optional<std::string> walletd_http_auth;
	if (const char *pa = cmd.get("--walletd-http-auth"))  // Undocumented, used for debugging
		walletd_http_auth = boost::algorithm::trim_copy(std::string(pa));

	logging::LoggerManager logManagerWalletNode;
	logManagerWalletNode.configure_default(config.get_data_folder("logs"), "walletd-", cn::app_version());

	boost::asio::io_service io;
	platform::EventLoop run_loop(io);  // must be before Wallet creation (trezor uses io)

	std::unique_ptr<Wallet> wallet;
	const std::string wallet_file = read_non_empty("--wallet-file", cmd);
	if (wallet_file.empty())
		wrong_args("Command line option --wallet-file=<file> is mandatory");

	if (cmd.get_bool("--create-wallet")) {
		const bool launch_after_command = cmd.get_bool("--launch-after-command");
		wallet = create_wallet(currency, logManagerWalletNode, wallet_file, cmd, console_setup);
		if (!wallet)
			return api::WALLETD_WRONG_ARGS;
		if (!launch_after_command)
			return 0;
	} else {
		boost::optional<std::string> password = read_wallet_password(cmd);
		const std::string export_view_only    = read_non_empty("--export-view-only", cmd);
		if (!export_view_only.empty()) {
			const bool set_password            = cmd.get_bool("--set-password");
			const bool view_outgoing_addresses = cmd.get_bool("--view-outgoing-addresses");
			if (cmd.show_errors("cannot be used with --export-view-only"))
				return api::WALLETD_WRONG_ARGS;
			wallet = open_wallet(currency, logManagerWalletNode, wallet_file, &password, true, console_setup);
			if (wallet->is_view_only())
				wrong_args("Cannot export as view-only, wallet file is already view-only");
			std::string new_password = ask_new_password(set_password, password.get(), console_setup);
			wallet->export_wallet(export_view_only, new_password, true, view_outgoing_addresses);
			std::cout << "Successfully exported view-only copy of the wallet" << std::endl;
			return 0;
		}
		if (cmd.get_bool("--export-keys")) {
			if (cmd.show_errors("cannot be used with --export-keys"))
				return api::WALLETD_WRONG_ARGS;
			wallet = open_wallet(currency, logManagerWalletNode, wallet_file, &password, true, console_setup);
			if (wallet->is_amethyst())
				wrong_args("You can only export keys from a legacy wallet");
			if (wallet->get_actual_records_count() != 1)
				throw Wallet::Exception(api::WALLETD_EXPORTKEYS_MORETHANONE,
				    "You can only export keys from a legacy wallet if it is containing 1 address, otherwise just back it up");
			std::cout << wallet->export_keys() << std::endl;  // exports mnemonic for HD wallet
			return 0;
		}
		if (cmd.get_bool("--export-mnemonic")) {
			if (cmd.show_errors("cannot be used with --export-mnemonic"))
				return api::WALLETD_WRONG_ARGS;
			wallet = open_wallet(currency, logManagerWalletNode, wallet_file, &password, true, console_setup);
			if (!wallet->is_amethyst())
				wrong_args("You can only export mnemonic from a deterministic wallet");
			std::cout << wallet->export_keys() << std::endl;  // exports mnemonic for HD wallet
			return 0;
		}
		if (cmd.get("--backup-wallet"))
			wrong_args("--backup-wallet option is removed, use --backup-wallet-data");
		const std::string backup_wallet_data = read_non_empty("--backup-wallet-data", cmd);
		if (!backup_wallet_data.empty()) {
			const bool set_password = cmd.get_bool("--set-password");
			if (cmd.show_errors("cannot be used with --backup-wallet-data"))
				return api::WALLETD_WRONG_ARGS;
			wallet = open_wallet(currency, logManagerWalletNode, wallet_file, &password, true, console_setup);
			std::string new_password    = ask_new_password(set_password, password.get(), console_setup);
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
			wallet->backup(dst_name, new_password);
			warning("There will be no progress printed for 1-20 minutes, depending on wallet size and computer speed.");

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
		// Normal launch, import_view_key and set_password are commands
		const bool import_view_key      = cmd.get_bool("--import-view-key");
		const bool set_password         = cmd.get_bool("--set-password");
		const bool launch_after_command = cmd.get_bool("--launch-after-command");
		if (launch_after_command && !(set_password || import_view_key))
			wrong_args(
			    "Command line option --launch-after-command can only be used with --create-wallet, --set-password, --import-view-key");
		if (cmd.show_errors("cannot be used when opening wallet"))
			return api::WALLETD_WRONG_ARGS;
		wallet = open_wallet(currency, logManagerWalletNode, wallet_file, &password, false, console_setup);
		std::string new_password = ask_new_password(set_password, password.get(), console_setup);
		if (import_view_key) {
			if (!wallet->get_hw())
				wrong_args("Command line option --import-view-key can be used only with hardware wallet");
			if (wallet->get_view_secret_key() != SecretKey{}) {
				warning("Wallet file already contains view key, ignoring --import-view-key argument");
			} else {
				wallet->import_view_key();
				std::cout << "Successfully imported view key" << std::endl;
			}
		}
		if (set_password) {
			wallet->set_password(new_password);
			std::cout << "Successfully set new password" << std::endl;
		}
		if (!launch_after_command && (set_password || import_view_key))
			return 0;
	}
	// Launching here
	if (!config.bytecoind_remote_port) {
		warning("Warning: inproc " CRYPTONOTE_NAME "d is deprecated and will be removed soon.");
		warning("  Please run " CRYPTONOTE_NAME "d separately, then specify --remote-" CRYPTONOTE_NAME
		        "d-address=<ip>:<port> argument to walletd");
		warning("  This is important to prevent " CRYPTONOTE_NAME
		        "d P2P attack vectors from reaching walletd address space where wallet keys reside");
	}
	if (!walletd_http_auth)
		walletd_http_auth =
		    prompt_for_string("Enter HTTP authorization <user>:<password> for walletd RPC", console_setup);
	config.walletd_authorization = common::base64::encode(common::as_binary_array(walletd_http_auth.get()));
	if (config.walletd_authorization.empty()) {
		warning("No authorization for RPC is a security risk. Use username with a strong password");
	} else {
		if (walletd_http_auth.get().find(":") == std::string::npos)
			wrong_args("HTTP authorization must be in the format <user>:<password>");
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

	auto wallet_node = std::make_unique<WalletNode>(nullptr, logManagerWalletNode, config, wallet_state);

	// Carefull, throwing after we create bytecoind thread will terminate immediately
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
		if ((node && node->on_idle()) || wallet_node->on_idle())  // We load blockchain there
			io.poll();
		else
			io.run_one();
	}
	return 0;
} catch (const cn::Config::DataFolderError &ex) {
	std::cout << common::what(ex) << std::endl;
	return api::BYTECOIND_DATAFOLDER_ERROR;
} catch (const platform::TCPAcceptor::AddressInUse &ex) {
	std::cout << common::what(ex) << std::endl;
	return api::WALLETD_BIND_PORT_IN_USE;
} catch (const cn::Config::ConfigError &ex) {
	std::cout << common::what(ex) << std::endl;
	return api::WALLETD_WRONG_ARGS;
} catch (const Bip32Key::Exception &ex) {
	std::cout << "Mnemonic invalid - " << common::what(ex) << std::endl;
	return api::WALLETD_MNEMONIC_CRC;
} catch (const common::StreamError &ex) {
	std::cout << common::what(ex) << std::endl;
	return api::WALLET_FILE_WRITE_ERROR;
} catch (const platform::sqlite::Error &ex) {
	std::cout << common::what(ex) << std::endl;
	return api::WALLET_FILE_WRITE_ERROR;
} catch (const Wallet::Exception &ex) {
	std::cout << common::what(ex) << std::endl;
	return ex.return_code;
} catch (const std::exception &ex) {  // On Windows what() is not printed if thrown from main
	std::cout << "Uncaught Exception in main() - " << common::what(ex) << std::endl;
	throw;
}
