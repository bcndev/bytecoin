// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletNodeExt.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "TransactionExtra.hpp"
#include "WalletHDsqlite.hpp"
#include "WalletLegacy.hpp"
#include "common/BIPs.hpp"
#include "common/Math.hpp"
#include "http/Server.hpp"
#include "platform/Time.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

using namespace cn;

WalletNodeExt::~WalletNodeExt() = default;  // we have unique_ptr to incomplete type

void WalletNodeExt::close_wallet() {
	m_wallet_sync.reset();
	wallet_state.reset();
	wallet_state_db.reset();
	wallet.reset();
#ifdef __EMSCRIPTEN__
	wallet_file_op.reset();
#else
	walletcache_lock.reset();
#endif

	m_command_request.reset();

	for (auto lit = m_long_poll_http_clients.begin(); lit != m_long_poll_http_clients.end();) {
		LongPollClient cli = std::move(*lit);
		lit                = m_long_poll_http_clients.erase(lit);
		// We erase first, because on some platforms on_api_http_disconnect will be called
		// synchronously in Server::write, and will also attempt to erase from m_long_poll_http_clients
		http::ResponseBody last_http_response;
		last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
		last_http_response.r.status             = 200;
		last_http_response.r.http_version_major = cli.original_request.r.http_version_major;
		last_http_response.r.http_version_minor = cli.original_request.r.http_version_minor;
		last_http_response.r.keep_alive         = cli.original_request.r.keep_alive;
		last_http_response.set_body(json_rpc::create_error_response_body(
		    json_rpc::Error(json_rpc::INVALID_REQUEST, "Wallet closed"), cli.original_json_request));
		http::Server::write(cli.original_who, std::move(last_http_response));
	}

	for (auto lit = m_waiting_command_requests.begin(); lit != m_waiting_command_requests.end();) {
		WaitingClient cli = std::move(*lit);
		lit               = m_waiting_command_requests.erase(lit);
		if (!cli.original_who)
			continue;
		// We erase first, because on some platforms on_api_http_disconnect will be called
		// synchronously in Server::write, and will also attempt to erase from m_long_poll_http_clients
		http::ResponseBody last_http_response;
		last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
		last_http_response.r.status             = 200;
		last_http_response.r.http_version_major = cli.original_request.r.http_version_major;
		last_http_response.r.http_version_minor = cli.original_request.r.http_version_minor;
		last_http_response.r.keep_alive         = cli.original_request.r.keep_alive;
		last_http_response.set_body(json_rpc::create_error_response_body(
		    json_rpc::Error(json_rpc::INVALID_REQUEST, "Wallet closed"), cli.original_json_request));
		http::Server::write(cli.original_who, std::move(last_http_response));
	}
}

void WalletNodeExt::on_api_http_disconnect(http::Client *who) {
	WalletNode::on_api_http_disconnect(who);
	if (ext_who == who)
		ext_who = nullptr;
}

void WalletNodeExt::open_wallet_cache(const http::RequestBody &raw_request, const json_rpc::Request &raw_js_request) {
#ifdef __EMSCRIPTEN__
	if (!wallet) {
		if (ext_who) {
			http::ResponseBody last_http_response(raw_request.r);
			last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
			last_http_response.r.status = 200;
			last_http_response.set_body(json_rpc::create_error_response_body(
			    json_rpc::Error(api::WALLET_FILE_WRITE_ERROR, "Cannot read wallet file"), raw_js_request));
			http::Server::write(ext_who, std::move(last_http_response));
		}
		return;
	}
	std::string cache_name = wallet->get_cache_name() + Wallet::net_append(m_currency.net);
	wallet_state_db        = std::make_unique<WalletState::DB>(platform::O_OPEN_ALWAYS, cache_name, [=]() {
        try {
            std::cout << "on_ext_create_wallet callback" << std::endl;
            wallet_state =
                std::make_unique<WalletState>(*wallet, m_log.get_logger(), m_config, m_currency, *wallet_state_db);
            m_wallet_sync =
                std::make_unique<WalletSync>(m_log.get_logger(), *wallet_state, [this]() { advance_long_poll(); });
            std::cout << "on_ext_create_wallet finish" << std::endl;
            if (ext_who) {
                api::walletd::ExtCreateWallet::Response response;
                response.wallet_file = wallet->get_cache_name() + ".wallet.memory";
                http::ResponseBody last_http_response(raw_request.r);
                last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
                last_http_response.r.status = 200;
                last_http_response.set_body(json_rpc::create_response_body(response, raw_js_request));
                http::Server::write(ext_who, std::move(last_http_response));
            }
        } catch (const std::exception &ex) {
            if (ext_who) {
                http::ResponseBody last_http_response(raw_request.r);
                last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
                last_http_response.r.status = 200;
                last_http_response.set_body(json_rpc::create_error_response_body(
                    json_rpc::Error(json_rpc::INTERNAL_ERROR, common::what(ex)), raw_js_request));
                http::Server::write(ext_who, std::move(last_http_response));
            }
        }
    });
#endif
}

bool WalletNodeExt::on_ext_create_wallet(http::Client *who, http::RequestBody &&raw_request,
    json_rpc::Request &&raw_js_request, api::walletd::ExtCreateWallet::Request &&request,
    api::walletd::ExtCreateWallet::Response &response) {
	close_wallet();
#ifdef __EMSCRIPTEN__
	std::cout << "on_ext_create_wallet start" << std::endl;
	auto wallet_hd = std::make_unique<WalletHDJson>(
	    m_currency, m_log.get_logger(), request.mnemonic, request.creation_timestamp, request.mnemonic_password);
	wallet_hd->create_look_ahead_records(request.address_count);
	auto json_data = wallet_hd->save_json_data();
	wallet         = std::move(wallet_hd);
	wallet_file_op = std::make_unique<platform::AsyncIndexDBOperation>(wallet->get_cache_name() + ".wallet.memory",
	    json_data.data(), json_data.size(), [=]() { std::cout << "on_ext_create_wallet wallet saved" << std::endl; });
	ext_who        = who;
	open_wallet_cache(raw_request, raw_js_request);
	return false;
#else
	response.wallet_file = request.wallet_file;
	try {
		if (request.wallet_type == "hardware") {
			wallet = std::make_unique<WalletHDsqlite>(m_currency, m_log.get_logger(), request.wallet_file,
			    request.wallet_password, request.mnemonic, request.creation_timestamp, request.mnemonic_password, true);
			wallet->create_look_ahead_records(request.address_count);
			if (request.import_view_key) {
				wallet->import_view_key();
				std::cout << "Successfully imported view key" << std::endl;
			}
		} else if (request.wallet_type == "amethyst") {
			wallet = std::make_unique<WalletHDsqlite>(m_currency, m_log.get_logger(), request.wallet_file,
			    request.wallet_password, request.mnemonic, request.creation_timestamp, request.mnemonic_password,
			    false);
			wallet->create_look_ahead_records(request.address_count);
		} else if (request.wallet_type == "legacy") {
			wallet = std::make_unique<WalletLegacy>(m_currency, m_log.get_logger(), request.wallet_file,
			    request.wallet_password, request.import_keys, request.creation_timestamp);
		}
		m_log(logging::INFO) << "Successfully created wallet with first address "
		                     << m_currency.account_address_as_string(wallet->get_first_address());
		m_log(logging::INFO) << "Using wallet cache folder " << m_config.get_data_folder("wallet_cache") << "/"
		                     << wallet->get_cache_name();
		walletcache_lock = std::make_unique<platform::ExclusiveLock>(
		    m_config.get_data_folder("wallet_cache"), wallet->get_cache_name() + ".lock");
		wallet_state_db = std::make_unique<WalletState::DB>(
		    platform::O_OPEN_ALWAYS, m_config.get_data_folder("wallet_cache") + "/" + wallet->get_cache_name());
		wallet_state =
		    std::make_unique<WalletState>(*wallet, m_log.get_logger(), m_config, m_currency, *wallet_state_db);
		m_wallet_sync =
		    std::make_unique<WalletSync>(m_log.get_logger(), *wallet_state, [this]() { advance_long_poll(); });
	} catch (const platform::ExclusiveLock::FailedToLock &ex) {
		m_log(logging::INFO) << "Wallet with the same first address is in use - " << common::what(ex);
		throw json_rpc::Error(
		    api::WALLET_WITH_SAME_KEYS_IN_USE, "Wallet with the same first address is in use" + common::what(ex));
	} catch (const Bip32Key::Exception &ex) {
		m_log(logging::INFO) << "Mnemonic invalid - " << common::what(ex);
		throw json_rpc::Error(api::WALLETD_MNEMONIC_CRC, "Mnemonic invalid - " + common::what(ex));
	} catch (const common::StreamError &ex) {
		m_log(logging::INFO) << common::what(ex);
		throw json_rpc::Error(api::WALLET_FILE_WRITE_ERROR, common::what(ex));
	} catch (const platform::sqlite::Error &ex) {
		m_log(logging::INFO) << common::what(ex);
		throw json_rpc::Error(api::WALLET_FILE_WRITE_ERROR, common::what(ex));
	} catch (const Wallet::Exception &ex) {
		m_log(logging::INFO) << common::what(ex);
		throw json_rpc::Error(ex.return_code, common::what(ex));
	}
	return true;
#endif
}

bool WalletNodeExt::on_ext_open_wallet(http::Client *who, http::RequestBody &&raw_request,
    json_rpc::Request &&raw_js_request, api::walletd::ExtOpenWallet::Request &&request,
    api::walletd::ExtOpenWallet::Response &) {
	close_wallet();
#ifdef __EMSCRIPTEN__
	std::cout << "on_ext_open_wallet start" << std::endl;
	ext_who = who;
	wallet_file_op =
	    std::make_unique<platform::AsyncIndexDBOperation>(request.wallet_file, [=](const char *data, size_t size) {
		    std::cout << "on_ext_open_wallet wallet loaded size=" << size << std::endl;
		    if (data) {
			    std::string json_data(data, size);
			    wallet = std::make_unique<WalletHDJson>(m_currency, m_log.get_logger(), json_data);
		    }
		    open_wallet_cache(raw_request, raw_js_request);
	    });
	return false;
#else
	try {
		const bool is_sqlite = WalletHDsqlite::is_sqlite(request.wallet_file);
		if (is_sqlite)
			wallet = std::make_unique<WalletHDsqlite>(
			    m_currency, m_log.get_logger(), request.wallet_file, request.wallet_password, false);
		else
			wallet = std::make_unique<WalletLegacy>(
			    m_currency, m_log.get_logger(), request.wallet_file, request.wallet_password);
		m_log(logging::INFO) << "Opened wallet with first address "
		                     << m_currency.account_address_as_string(wallet->get_first_address());
		m_log(logging::INFO) << "Using wallet cache folder " << m_config.get_data_folder("wallet_cache") << "/"
		                     << wallet->get_cache_name();
		walletcache_lock = std::make_unique<platform::ExclusiveLock>(
		    m_config.get_data_folder("wallet_cache"), wallet->get_cache_name() + ".lock");
		wallet_state_db = std::make_unique<WalletState::DB>(
		    platform::O_OPEN_ALWAYS, m_config.get_data_folder("wallet_cache") + "/" + wallet->get_cache_name());
		wallet_state =
		    std::make_unique<WalletState>(*wallet, m_log.get_logger(), m_config, m_currency, *wallet_state_db);
		m_wallet_sync =
		    std::make_unique<WalletSync>(m_log.get_logger(), *wallet_state, [this]() { advance_long_poll(); });
	} catch (const platform::ExclusiveLock::FailedToLock &ex) {
		m_log(logging::INFO) << "Wallet with the same first address is in use - " << common::what(ex);
		throw json_rpc::Error(
		    api::WALLET_WITH_SAME_KEYS_IN_USE, "Wallet with the same first address is in use" + common::what(ex));
	} catch (const Bip32Key::Exception &ex) {
		m_log(logging::INFO) << "Mnemonic invalid - " << common::what(ex);
		throw json_rpc::Error(api::WALLETD_MNEMONIC_CRC, "Mnemonic invalid - " + common::what(ex));
	} catch (const common::StreamError &ex) {
		m_log(logging::INFO) << common::what(ex);
		throw json_rpc::Error(api::WALLET_FILE_WRITE_ERROR, common::what(ex));
	} catch (const platform::sqlite::Error &ex) {
		m_log(logging::INFO) << common::what(ex);
		throw json_rpc::Error(api::WALLET_FILE_WRITE_ERROR, common::what(ex));
	} catch (const Wallet::Exception &ex) {
		m_log(logging::INFO) << common::what(ex);
		throw json_rpc::Error(ex.return_code, common::what(ex));
	}
	return true;
#endif
}

bool WalletNodeExt::on_ext_set_password(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::walletd::ExtSetPassword::Request &&request, api::walletd::ExtSetPassword::Response &) {
	check_wallet_open();
	wallet->set_password(request.wallet_password);
	m_log(logging::INFO) << "Successfully set new password";
	return true;
}

bool WalletNodeExt::on_ext_close_wallet(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::walletd::ExtCloseWallet::Request &&, api::walletd::ExtCloseWallet::Response &) {
	check_wallet_open();
	close_wallet();
	m_log(logging::INFO) << "Closed wallet";
	return true;
}
