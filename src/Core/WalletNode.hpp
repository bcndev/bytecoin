// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "WalletSync.hpp"

namespace http {
class Server;
class Client;
}  // namespace http
namespace platform {
class ExclusiveLock;
}  // namespace platform
namespace cn {
class Node;

class WalletNode {
public:
	explicit WalletNode(logging::ILogger &, WalletState &);
	explicit WalletNode(const Config &config, const Currency &currency, logging::ILogger &);
	virtual ~WalletNode();

	typedef std::function<bool(WalletNode *, http::Client *, http::RequestBody &&, json_rpc::Request &&, std::string &)>
	    JSONRPCHandlerFunction;

	bool on_get_status(http::Client *, http::RequestBody &&, json_rpc::Request &&, api::walletd::GetStatus::Request &&,
	    api::walletd::GetStatus::Response &);
	bool on_get_addresses(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::GetAddresses::Request &&, api::walletd::GetAddresses::Response &);
	bool on_get_wallet_info(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::GetWalletInfo::Request &&, api::walletd::GetWalletInfo::Response &);
	bool on_get_wallet_records(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::GetWalletRecords::Request &&, api::walletd::GetWalletRecords::Response &);
	bool on_set_label(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::SetAddressLabel::Request &&, api::walletd::SetAddressLabel::Response &);
	bool on_create_addresses(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::CreateAddresses::Request &&, api::walletd::CreateAddresses::Response &);
	bool on_get_view_key(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::GetViewKeyPair::Request &&, api::walletd::GetViewKeyPair::Response &);
	bool on_get_unspent(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::GetUnspents::Request &&, api::walletd::GetUnspents::Response &);
	bool on_get_balance(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::GetBalance::Request &&, api::walletd::GetBalance::Response &);
	bool on_get_transfers(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::GetTransfers::Request &&, api::walletd::GetTransfers::Response &);
	bool on_create_transaction(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::CreateTransaction::Request &&, api::walletd::CreateTransaction::Response &);
	bool on_create_sendproof(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::CreateSendproof::Request &&, api::walletd::CreateSendproof::Response &);
	bool on_send_transaction(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::SendTransaction::Request &&,
	    api::cnd::SendTransaction::Response &);  // We lock spent outputs until next pool sync
	bool on_get_transaction(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::GetTransaction::Request &&, api::walletd::GetTransaction::Response &);

	virtual bool on_ext_create_wallet(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::ExtCreateWallet::Request &&, api::walletd::ExtCreateWallet::Response &);
	virtual bool on_ext_open_wallet(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::ExtOpenWallet::Request &&, api::walletd::ExtOpenWallet::Response &);
	virtual bool on_ext_set_password(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::ExtSetPassword::Request &&, api::walletd::ExtSetPassword::Response &);
	virtual bool on_ext_close_wallet(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::walletd::ExtCloseWallet::Request &&, api::walletd::ExtCloseWallet::Response &);

	typedef std::unordered_map<std::string, JSONRPCHandlerFunction> HandlersMap;
	static const HandlersMap m_jsonrpc_handlers;

protected:
	logging::LoggerRef m_log;
	const Config &m_config;
	const Currency &m_currency;

	std::unique_ptr<http::Server> m_api;

	std::unique_ptr<WalletSync> m_wallet_sync;

	struct WaitingClient {
		http::Client *original_who = nullptr;
		http::RequestBody request;
		http::RequestBody original_request;
		json_rpc::Request original_json_request;
		std::function<void(const WaitingClient &wc, http::ResponseBody &&resp)> fun;
		std::function<void(const WaitingClient &wc, std::string)> err_fun;
	};
	std::deque<WaitingClient> m_waiting_command_requests;
	http::Agent m_commands_agent;
	std::unique_ptr<http::Request> m_command_request;

	void add_waiting_command(http::Client *who, http::RequestBody &&original_request,
	    json_rpc::Request &&original_json_request, http::RequestBody &&request,
	    std::function<void(const WaitingClient &wc, http::ResponseBody &&resp)> &&fun,
	    std::function<void(const WaitingClient &wc, std::string)> &&err_fun);
	void send_next_waiting_command();
	void process_waiting_command_response(http::ResponseBody &&resp);
	void process_waiting_command_error(std::string err);

	struct LongPollClient {
		http::Client *original_who = nullptr;
		http::RequestBody original_request;
		json_rpc::Request original_json_request;
		api::walletd::GetStatus::Request original_get_status;
	};
	std::list<LongPollClient> m_long_poll_http_clients;
	void advance_long_poll();

	api::walletd::GetStatus::Response create_status_response() const;

	bool on_api_http_request(http::Client *, http::RequestBody &&, http::ResponseBody &);
	virtual void on_api_http_disconnect(http::Client *);

	bool on_json_rpc(http::Client *, http::RequestBody &&, http::ResponseBody &, bool &method_found);
	void check_address_in_wallet_or_throw(const std::string &addr) const;

	WalletState &get_wallet_state() { return m_wallet_sync->get_wallet_state(); }
	const WalletState &get_wallet_state() const { return m_wallet_sync->get_wallet_state(); }

	void check_wallet_open();
};

}  // namespace cn
