// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "WalletSync.hpp"

namespace http {
class Server;
class Client;
}  // namespace http
namespace cn {
class Node;

class WalletNode : public WalletSync {
public:
	explicit WalletNode(Node *inproc_node, logging::ILogger &, const Config &, WalletState &);
	~WalletNode();

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

	typedef std::unordered_map<std::string, JSONRPCHandlerFunction> HandlersMap;
	static const HandlersMap m_jsonrpc_handlers;

private:
	Node *m_inproc_node;

	std::unique_ptr<http::Server> m_api;

	struct WaitingClient {
		http::Client *original_who = nullptr;
		http::RequestBody request;
		http::RequestBody original_request;
		common::JsonValue original_jsonrpc_id;
		std::function<void(const WaitingClient &wc, http::ResponseBody &&resp)> fun;
		std::function<void(const WaitingClient &wc, std::string)> err_fun;
	};
	std::deque<WaitingClient> m_waiting_command_requests;
	void add_waiting_command(http::Client *who, http::RequestBody &&original_request,
	    const common::JsonValue &original_rpc_id, http::RequestBody &&request,
	    std::function<void(const WaitingClient &wc, http::ResponseBody &&resp)> &&fun,
	    std::function<void(const WaitingClient &wc, std::string)> &&err_fun);
	void send_next_waiting_command();
	void process_waiting_command_response(http::ResponseBody &&resp);
	void process_waiting_command_error(std::string err);

	struct LongPollClient {
		http::Client *original_who = nullptr;
		http::RequestBody original_request;
		common::JsonValue original_jsonrpc_id;
		api::walletd::GetStatus::Request original_get_status;
	};
	std::list<LongPollClient> m_long_poll_http_clients;
	void advance_long_poll();

	api::walletd::GetStatus::Response create_status_response() const;

	bool on_api_http_request(http::Client *, http::RequestBody &&, http::ResponseBody &);
	void on_api_http_disconnect(http::Client *);

	bool on_json_rpc(http::Client *, http::RequestBody &&, http::ResponseBody &, bool &method_found);
	void check_address_in_wallet_or_throw(const std::string &addr) const;
};

}  // namespace cn
