// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "Node.hpp"
#include "WalletSync.hpp"
#include "http/Server.hpp"

namespace bytecoin {

class WalletNode : public WalletSync {
public:
	explicit WalletNode(Node *inproc_node, logging::ILogger &, const Config &, WalletState &);

	typedef std::function<bool(
	    WalletNode *, http::Client *, http::RequestData &&, json_rpc::Request &&, json_rpc::Response &)>
	    JSONRPCHandlerFunction;

	// New protocol (json_rpc3)
	bool handle_get_status3(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::walletd::GetStatus::Request &&, api::walletd::GetStatus::Response &);
	bool handle_get_addresses3(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::walletd::GetAddresses::Request &&, api::walletd::GetAddresses::Response &);
	bool handle_create_address_list3(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::walletd::CreateAddresses::Request &&, api::walletd::CreateAddresses::Response &);
	bool handle_get_view_key3(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::walletd::GetViewKeyPair::Request &&, api::walletd::GetViewKeyPair::Response &);
	bool handle_get_unspent3(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::walletd::GetUnspents::Request &&, api::walletd::GetUnspents::Response &);
	bool handle_get_balance3(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::walletd::GetBalance::Request &&, api::walletd::GetBalance::Response &);
	bool handle_get_transfers3(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::walletd::GetTransfers::Request &&, api::walletd::GetTransfers::Response &);
	bool handle_create_transaction3(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::walletd::CreateTransaction::Request &&, api::walletd::CreateTransaction::Response &);
	bool handle_create_sendproof3(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::walletd::CreateSendProof::Request &&, api::walletd::CreateSendProof::Response &);
	bool handle_send_transaction3(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::SendTransaction::Request &&,
	    api::bytecoind::SendTransaction::Response &);  // We lock spent outputs until next pool sync
	bool handle_get_transaction3(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::walletd::GetTransaction::Request &&, api::walletd::GetTransaction::Response &);

private:
	Node *m_inproc_node;

	std::unique_ptr<http::Server> m_api;

	struct WaitingClient {
		http::Client *original_who = nullptr;
		http::RequestData request;
		http::RequestData original_request;
		json_rpc::OptionalJsonValue original_jsonrpc_id;
		std::function<void(const WaitingClient &wc, http::ResponseData &&resp)> fun;
		std::function<void(const WaitingClient &wc, std::string)> err_fun;
	};
	std::deque<WaitingClient> m_waiting_command_requests;
	void add_waiting_command(http::Client *who, http::RequestData &&original_request,
	    const json_rpc::OptionalJsonValue &original_rpc_id, http::RequestData &&request,
	    std::function<void(const WaitingClient &wc, http::ResponseData &&resp)> fun,
	    std::function<void(const WaitingClient &wc, std::string)> err_fun);
	void send_next_waiting_command();
	void process_waiting_command_response(http::ResponseData &&resp);
	void process_waiting_command_error(std::string err);

	struct LongPollClient {
		http::Client *original_who = nullptr;
		http::RequestData original_request;
		json_rpc::OptionalJsonValue original_jsonrpc_id;
		bytecoin::api::walletd::GetStatus::Request original_get_status;
	};
	std::list<LongPollClient> m_long_poll_http_clients;
	void advance_long_poll();

	typedef std::unordered_map<std::string, JSONRPCHandlerFunction> HandlersMap;
	static const HandlersMap m_jsonrpc3_handlers;

	api::walletd::GetStatus::Response create_status_response3() const;

	bool on_api_http_request(http::Client *, http::RequestData &&, http::ResponseData &);
	void on_api_http_disconnect(http::Client *);

	bool process_json_rpc_request(
	    const HandlersMap &, http::Client *, http::RequestData &&, http::ResponseData &, bool &method_found);
	void check_address_in_wallet_or_throw(const std::string &addr) const;
};

}  // namespace bytecoin
