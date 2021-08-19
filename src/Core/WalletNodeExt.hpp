// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "WalletNode.hpp"
#ifdef __EMSCRIPTEN__
#include "platform/IndexDB.hpp"
#else
#include "platform/ExclusiveLock.hpp"
#endif

namespace cn {

class WalletNodeExt : public WalletNode {
public:
	explicit WalletNodeExt(const Config &config, const Currency &currency, logging::ILogger &log)
	    : WalletNode(config, currency, log) {}
	~WalletNodeExt() override;

	bool on_ext_create_wallet(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::ExtCreateWallet::Request &&, api::walletd::ExtCreateWallet::Response &) override;
	bool on_ext_open_wallet(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::ExtOpenWallet::Request &&, api::walletd::ExtOpenWallet::Response &) override;
	bool on_ext_set_password(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::ExtSetPassword::Request &&, api::walletd::ExtSetPassword::Response &) override;
	bool on_ext_close_wallet(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::ExtCloseWallet::Request &&, api::walletd::ExtCloseWallet::Response &) override;

protected:
	void on_api_http_disconnect(http::Client *) override;

private:
#ifdef __EMSCRIPTEN__
	std::unique_ptr<platform::AsyncIndexDBOperation> wallet_file_op;
#else
	std::unique_ptr<platform::ExclusiveLock> walletcache_lock;
#endif
	std::unique_ptr<Wallet> wallet;
	std::unique_ptr<WalletState::DB> wallet_state_db;
	std::unique_ptr<WalletState> wallet_state;

	http::Client *ext_who = nullptr;

	void open_wallet_cache(const http::RequestBody &raw_request, const json_rpc::Request &raw_js_request);
	void close_wallet();
};

}  // namespace cn
