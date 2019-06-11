// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletNode.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "TransactionExtra.hpp"
#include "common/Math.hpp"
#include "http/Server.hpp"
#include "platform/Time.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

#ifndef __EMSCRIPTEN__
#include "Node.hpp"
#endif

using namespace cn;

const WalletNode::HandlersMap WalletNode::m_jsonrpc_handlers = {
    {api::walletd::GetStatus::method(), json_rpc::make_member_method(&WalletNode::on_get_status)},
    {api::walletd::GetAddresses::method(), json_rpc::make_member_method(&WalletNode::on_get_addresses)},
    {api::walletd::GetWalletInfo::method(), json_rpc::make_member_method(&WalletNode::on_get_wallet_info)},
    {api::walletd::GetWalletRecords::method(), json_rpc::make_member_method(&WalletNode::on_get_wallet_records)},
    {api::walletd::SetAddressLabel::method(), json_rpc::make_member_method(&WalletNode::on_set_label)},
    {api::walletd::CreateAddresses::method(), json_rpc::make_member_method(&WalletNode::on_create_addresses)},
    {api::walletd::GetViewKeyPair::method(), json_rpc::make_member_method(&WalletNode::on_get_view_key)},
    {api::walletd::GetBalance::method(), json_rpc::make_member_method(&WalletNode::on_get_balance)},
    {api::walletd::GetUnspents::method(), json_rpc::make_member_method(&WalletNode::on_get_unspent)},
    {api::walletd::GetTransfers::method(), json_rpc::make_member_method(&WalletNode::on_get_transfers)},
    {api::walletd::CreateTransaction::method(), json_rpc::make_member_method(&WalletNode::on_create_transaction)},
    {api::walletd::SendTransaction::method(), json_rpc::make_member_method(&WalletNode::on_send_transaction)},
    {api::walletd::CreateSendproof::method(), json_rpc::make_member_method(&WalletNode::on_create_sendproof)},
    {api::walletd::GetTransaction::method(), json_rpc::make_member_method(&WalletNode::on_get_transaction)}};

WalletNode::WalletNode(Node *inproc_node, logging::ILogger &log, const Config &config, WalletState &wallet_state)
    : WalletSync(log, config, wallet_state, std::bind(&WalletNode::advance_long_poll, this))
    , m_inproc_node(inproc_node) {
	if (!config.walletd_bind_ip.empty() && config.walletd_bind_port != 0)
		m_api = std::make_unique<http::Server>(config.walletd_bind_ip, config.walletd_bind_port,
		    std::bind(&WalletNode::on_api_http_request, this, _1, _2, _3),
		    std::bind(&WalletNode::on_api_http_disconnect, this, _1));
}

WalletNode::~WalletNode() {}  // we have unique_ptr to incomplete type

bool WalletNode::on_api_http_request(http::Client *who, http::RequestBody &&request, http::ResponseBody &response) {
	response.r.add_headers_nocache();
	bool method_found = false;
	if (request.r.uri == api::walletd::url()) {
		bool result = on_json_rpc(who, std::move(request), response, method_found);
		if (method_found)
			return result;
	}
#ifndef __EMSCRIPTEN__
	if (m_inproc_node)
		return m_inproc_node->on_json_rpc(who, std::move(request), response);
#endif
	m_log(logging::INFO) << "http_request node tunneling url=" << request.r.uri
	                     << " start of body=" << request.body.substr(0, 200);
	http::RequestBody original_request;
	original_request.r            = request.r;
	request.r.http_version_major  = 1;
	request.r.http_version_minor  = 1;
	request.r.keep_alive          = true;
	request.r.basic_authorization = m_config.bytecoind_authorization;
	add_waiting_command(who, std::move(original_request), common::JsonValue(nullptr), std::move(request),
	    [](const WaitingClient &wc, http::ResponseBody &&send_response) mutable {
		    send_response.r.http_version_major = wc.original_request.r.http_version_major;
		    send_response.r.http_version_minor = wc.original_request.r.http_version_minor;
		    send_response.r.keep_alive         = wc.original_request.r.keep_alive;
		    // bytecoind never sends connection-close, so we are safe to retain all headers
		    http::Server::write(wc.original_who, std::move(send_response));
	    },
	    [](const WaitingClient &wc, std::string err) {
		    http::ResponseBody send_response;
		    send_response.r.http_version_major = wc.original_request.r.http_version_major;
		    send_response.r.http_version_minor = wc.original_request.r.http_version_minor;
		    send_response.r.keep_alive         = wc.original_request.r.keep_alive;
		    send_response.r.status             = 504;  // TODO -test this code path
		    http::Server::write(wc.original_who, std::move(send_response));
	    });
	return false;
}

void WalletNode::on_api_http_disconnect(http::Client *who) {
	for (auto &&wc : m_waiting_command_requests) {
		if (wc.original_who == who)
			wc.original_who = nullptr;
	}
	for (auto lit = m_long_poll_http_clients.begin(); lit != m_long_poll_http_clients.end();)
		if (lit->original_who == who)
			lit = m_long_poll_http_clients.erase(lit);
		else
			++lit;
}

bool WalletNode::on_json_rpc(
    http::Client *who, http::RequestBody &&request, http::ResponseBody &response, bool &method_found) {
	method_found = false;
	response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});

	common::JsonValue jid(nullptr);

	try {
		json_rpc::Request json_req(request.body);
		jid = json_req.get_id().get();

		auto it = m_jsonrpc_handlers.find(json_req.get_method());
		if (it == m_jsonrpc_handlers.end()) {
			return false;
		}
		method_found = true;
		if (!m_config.walletd_authorization.empty() &&
		    request.r.basic_authorization != m_config.walletd_authorization) {
			response.r.headers.push_back({"WWW-Authenticate", "Basic realm=\"Wallet\", charset=\"UTF-8\""});
			response.r.status = 401;
			return true;
		}
		std::string response_body;
		if (!it->second(this, who, std::move(request), std::move(json_req), response_body))
			return false;
		response.set_body(std::move(response_body));
	} catch (const json_rpc::Error &err) {
		response.set_body(json_rpc::create_error_response_body(err, jid));
	} catch (const std::exception &e) {
		json_rpc::Error json_err(json_rpc::INTERNAL_ERROR, common::what(e));
		response.set_body(json_rpc::create_error_response_body(json_err, jid));
	}
	response.r.status = 200;
	return true;
}

// New protocol

api::walletd::GetStatus::Response WalletNode::create_status_response() const {
	api::walletd::GetStatus::Response response = m_last_node_status;
	response.top_block_height                  = m_wallet_state.get_tip_height();
	response.top_block_hash                    = m_wallet_state.get_tip().hash;
	response.top_block_timestamp               = m_wallet_state.get_tip().timestamp;
	response.top_block_timestamp_median        = m_wallet_state.get_tip().timestamp_median;
	response.top_block_difficulty              = m_wallet_state.get_tip().difficulty;
	response.top_block_cumulative_difficulty   = m_wallet_state.get_tip().cumulative_difficulty;
	response.transaction_pool_version          = m_wallet_state.get_tx_pool_version();
	response.lower_level_error                 = m_sync_error;
	// TODO - pass lower level error
	return response;
}

bool WalletNode::on_get_status(http::Client *who, http::RequestBody &&raw_request, json_rpc::Request &&raw_js_request,
    api::walletd::GetStatus::Request &&request, api::walletd::GetStatus::Response &response) {
	response = create_status_response();
	if (!response.ready_for_longpoll(request)) {
		//		m_log(logging::INFO) << "on_get_status will long poll, json="
		// << raw_request.body;
		LongPollClient lpc;
		lpc.original_who        = who;
		lpc.original_request    = raw_request;
		lpc.original_jsonrpc_id = raw_js_request.get_id().get();
		lpc.original_get_status = request;
		m_long_poll_http_clients.push_back(lpc);
		return false;
	}
	return true;
}

bool WalletNode::on_get_addresses(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::walletd::GetAddresses::Request &&request, api::walletd::GetAddresses::Response &response) {
	const Wallet &wa             = m_wallet_state.get_wallet();
	response.total_address_count = wa.get_actual_records_count();
	response.addresses.reserve(response.total_address_count);
	if (request.need_secret_spend_keys) {
		if (!m_config.secrets_via_api)
			throw json_rpc::Error(json_rpc::INVALID_PARAMS,
			    "To allow getting secrets via API, walletd must be launched with '--secrets-via-api' argument.");
		response.secret_spend_keys.reserve(response.total_address_count);
	}
	for (size_t i = request.from_address; i < response.total_address_count; ++i) {
		if (response.addresses.size() >= request.max_count)
			break;
		WalletRecord rec;
		AccountAddress addr;
		wa.get_record(i, &rec, &addr);
		response.addresses.push_back(m_wallet_state.get_currency().account_address_as_string(addr));
		if (request.need_secret_spend_keys)
			response.secret_spend_keys.push_back(rec.spend_secret_key);
	}
	return true;
}

bool WalletNode::on_get_wallet_info(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::walletd::GetWalletInfo::Request &&request, api::walletd::GetWalletInfo::Response &response) {
	const Wallet &wa                     = m_wallet_state.get_wallet();
	response.view_only                   = wa.is_view_only();
	response.wallet_type                 = wa.get_hw() ? "hardware" : wa.is_amethyst() ? "amethyst" : "legacy";
	response.can_view_outgoing_addresses = wa.can_view_outgoing_addresses();
	response.has_view_secret_key         = wa.get_view_secret_key() != SecretKey{};
	response.total_address_count         = wa.get_actual_records_count();
	response.wallet_creation_timestamp   = wa.get_oldest_timestamp();
	response.first_address = m_wallet_state.get_currency().account_address_as_string(wa.get_first_address());
	response.net           = m_config.net;
	if (request.need_secrets) {
		if (!m_config.secrets_via_api)
			throw json_rpc::Error(json_rpc::INVALID_PARAMS,
			    "To allow getting secrets via API, walletd must be launched with '--secrets-via-api' argument.");
		if (wa.is_amethyst())
			response.mnemonic = m_wallet_state.get_wallet().export_keys();
		else
			response.import_keys = m_wallet_state.get_wallet().export_keys();
		response.secret_view_key = wa.get_view_secret_key();
		response.public_view_key = wa.get_view_public_key();
	}
	return true;
}

bool WalletNode::on_get_wallet_records(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::walletd::GetWalletRecords::Request &&request, api::walletd::GetWalletRecords::Response &response) {
	const Wallet &wa = m_wallet_state.get_wallet();
	if (request.create) {
		if (!wa.is_amethyst())
			throw json_rpc::Error(
			    json_rpc::INVALID_PARAMS, "wallet is not deterministic, impossible to create addresses by index");
		if (request.count == std::numeric_limits<size_t>::max())
			throw json_rpc::Error(json_rpc::INVALID_PARAMS, "If 'create' set to true, you must also set 'max_count'");
		if (request.count > std::numeric_limits<size_t>::max() - request.index)
			throw json_rpc::Error(json_rpc::INVALID_PARAMS, "You asked to create too many addresses.");
		m_wallet_state.create_addresses(request.index + request.count);
	}
	response.total_count = wa.get_actual_records_count();
	response.records.reserve(response.total_count);
	for (size_t i = request.index; i < response.total_count; ++i) {
		if (response.records.size() >= request.count)
			break;
		WalletRecord record;
		AccountAddress addr;
		wa.get_record(i, &record, &addr);
		api::walletd::GetWalletRecords::Record wr;
		wr.index   = i;
		wr.address = m_wallet_state.get_currency().account_address_as_string(addr);
		wr.label   = wa.get_label(wr.address);
		if (request.need_secrets) {
			wr.public_spend_key = record.spend_public_key;
			wr.secret_spend_key = record.spend_secret_key;
		}
		response.records.push_back(std::move(wr));
	}
	return true;
}

bool WalletNode::on_set_label(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::walletd::SetAddressLabel::Request &&request, api::walletd::SetAddressLabel::Response &) {
	check_address_in_wallet_or_throw(request.address);
	m_wallet_state.get_wallet().set_label(request.address, request.label);
	return true;
}

bool WalletNode::on_get_view_key(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::walletd::GetViewKeyPair::Request &&, api::walletd::GetViewKeyPair::Response &response) {
	if (!m_config.secrets_via_api)
		throw json_rpc::Error(json_rpc::INVALID_PARAMS,
		    "To allow getting secrets via API, walletd must be launched with '--secrets-via-api' argument.");
	response.public_view_key = m_wallet_state.get_wallet().get_view_public_key();
	response.secret_view_key = m_wallet_state.get_wallet().get_view_secret_key();
	response.import_keys     = m_wallet_state.get_wallet().export_keys();
	return true;
}

bool WalletNode::on_create_addresses(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::walletd::CreateAddresses::Request &&request, api::walletd::CreateAddresses::Response &response) {
	//	if (m_wallet_state.get_wallet().is_view_only())
	//		throw json_rpc::Error(json_rpc::INVALID_PARAMS, "wallet is view-only, impossible to create addresses");
	if (request.secret_spend_keys.empty())
		return true;
	std::vector<AccountAddress> addresses;
	auto records = m_wallet_state.generate_new_addresses(
	    request.secret_spend_keys, request.creation_timestamp, platform::now_unix_timestamp(), &addresses);
	response.addresses.reserve(records.size());
	response.secret_spend_keys.reserve(records.size());
	for (size_t i = 0; i != records.size(); ++i) {
		//		AccountAddress addr = m_wallet_state.get_wallet().record_to_address(rec);
		response.addresses.push_back(m_wallet_state.get_currency().account_address_as_string(addresses.at(i)));
		response.secret_spend_keys.push_back(records.at(i).spend_secret_key);
	}
	return true;
}

void WalletNode::check_address_in_wallet_or_throw(const std::string &addr) const {
	if (addr.empty())
		return;
	AccountAddress address;
	if (!m_wallet_state.get_currency().parse_account_address_string(addr, &address))
		throw api::ErrorAddress(api::ErrorAddress::ADDRESS_FAILED_TO_PARSE, "Failed to parse address", addr);
	if (!m_wallet_state.get_wallet().is_our_address(address))
		throw api::ErrorAddress(api::ErrorAddress::ADDRESS_NOT_IN_WALLET, "Address not in wallet", addr);
}

bool WalletNode::on_get_balance(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::walletd::GetBalance::Request &&request, api::walletd::GetBalance::Response &response) {
	check_address_in_wallet_or_throw(request.address);
	Height height_or_depth = api::ErrorWrongHeight::fix_height_or_depth(
	    request.height_or_depth, m_wallet_state.get_tip_height(), false, false, 128);
	response = m_wallet_state.get_balance(request.address, height_or_depth);
	return true;
}

bool WalletNode::on_get_unspent(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::walletd::GetUnspents::Request &&request, api::walletd::GetUnspents::Response &response) {
	check_address_in_wallet_or_throw(request.address);
	Height height_or_depth = api::ErrorWrongHeight::fix_height_or_depth(
	    request.height_or_depth, m_wallet_state.get_tip_height(), false, false, 128);
	Amount total_amount = 0;
	m_wallet_state.api_add_unspent(&response.spendable, &total_amount, request.address, height_or_depth);
	response.locked_or_unconfirmed =
	    m_wallet_state.api_get_locked_or_unconfirmed_unspent(request.address, height_or_depth);
	return true;
}

bool WalletNode::on_get_transfers(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::walletd::GetTransfers::Request &&request, api::walletd::GetTransfers::Response &response) {
	check_address_in_wallet_or_throw(request.address);
	if (request.from_height > request.to_height)
		throw json_rpc::Error(api::walletd::GetTransfers::INVALID_PARAMS,
		    "from_height should be <= to_height, actual request.from_height=" + common::to_string(request.from_height) +
		        ", request.to_height=" + common::to_string(request.to_height));
	if (request.from_height > m_wallet_state.get_tip_height())
		throw api::ErrorWrongHeight("from_height cannot exceed top block height, actual request.from_height=",
		    request.from_height, m_wallet_state.get_tip_height());
	response.next_from_height = request.from_height;
	response.next_to_height   = request.to_height;
	// GetTransfers API is documented to accept (from..to] range,
	// but code works with traditional [from..to) range
	// This is design error in API. We now have to do clumsy recalculations for iteration.
	if (request.from_height != std::numeric_limits<Height>::max())
		request.from_height += 1;
	if (request.to_height != std::numeric_limits<Height>::max())
		request.to_height += 1;
	//	auto legacy_from_height = request.from_height;
	//	auto legacy_to_height   = request.to_height;
	response.blocks = m_wallet_state.api_get_transfers(
	    request.address, &request.from_height, &request.to_height, request.forward, request.desired_transaction_count);
	for (const auto &b : response.blocks)  // We repeat information for legacy clients
		response.unlocked_transfers.insert(
		    response.unlocked_transfers.end(), b.unlocked_transfers.begin(), b.unlocked_transfers.end());
	//	{
	//		// TODO - remove cheching legacy and current results
	//		auto legacy_unlocked_transfers =
	//				m_wallet_state.api_get_unlocked_transfers_legacy(request.address, request.from_height,
	// request.to_height); 		std::map<std::pair<std::string, Hash>, Amount> unl;
	// std::map<std::pair<std::string, Hash>, Amount> unl2; 		for (const auto &tr : legacy_unlocked_transfers)
	// unl[std::make_pair(tr.address, tr.transaction_hash)] += tr.amount; 		auto legacy_blocks =
	// m_wallet_state.api_get_transfers(request.address,
	//&legacy_from_height, &legacy_to_height, 		    request.forward, request.desired_transaction_count);
	//		invariant(response.blocks.size() == legacy_blocks.size(), "");
	//		for (size_t i = 0; i != response.blocks.size(); ++i) {
	//			invariant(response.blocks.at(i).header.hash == legacy_blocks.at(i).header.hash, "");
	//			invariant(response.blocks.at(i).transactions.size() == legacy_blocks.at(i).transactions.size(), "");
	//			for (size_t j = 0; j != response.blocks.at(i).transactions.size(); ++j)
	//				invariant(
	//				    response.blocks.at(i).transactions.at(j).hash == legacy_blocks.at(i).transactions.at(j).hash,
	//""); 			for (const auto &tr : response.blocks.at(i).unlocked_transfers)
	// unl2[std::make_pair(tr.address, tr.transaction_hash)] += tr.amount;
	//		}
	//		invariant(unl == unl2, "");
	//	}
	if (request.from_height <= m_wallet_state.get_tip_height() + 1 &&
	    request.to_height > m_wallet_state.get_tip_height() + 1) {
		api::Block pool_block = m_wallet_state.api_get_pool_as_history(request.address);
		if (!pool_block.transactions.empty()) {
			if (request.forward)
				response.blocks.push_back(pool_block);
			else
				response.blocks.insert(response.blocks.begin(), pool_block);
		}
	}
	if (request.forward) {
		if (request.to_height != std::numeric_limits<Height>::max())
			response.next_from_height = request.to_height - 1;
		else
			response.next_from_height = request.to_height;
	} else
		response.next_to_height = request.from_height - 1;
	return true;
}

bool WalletNode::on_create_transaction(http::Client *who, http::RequestBody &&raw_request,
    json_rpc::Request &&raw_js_request, api::walletd::CreateTransaction::Request &&request,
    api::walletd::CreateTransaction::Response &response) {
	m_log(logging::TRACE) << "create_transaction request tip_height=" << m_wallet_state.get_tip_height()
	                      << " body=" << raw_request.body;
	for (auto &&tid : request.prevent_conflict_with_transactions) {
		if (m_wallet_state.api_has_transaction(tid, true))
			continue;
		response.transactions_required.push_back(tid);
	}
	if (!response.transactions_required.empty())
		return true;
	if (request.transaction.anonymity > 100)  // Arbitrary value
		throw json_rpc::Error(api::walletd::CreateTransaction::TOO_MUCH_ANONYMITY,
		    "Wallet will not create transactions with anonymity > 100 because large anonymity values actually reduce anonymity due to tiny number of similar transactions");
	const auto min_anonymity  = m_wallet_state.get_currency().minimum_anonymity(m_wallet_state.get_tip().major_version);
	const auto good_anonymity = std::max(min_anonymity, request.transaction.anonymity);
	Height confirmed_height   = api::ErrorWrongHeight::fix_height_or_depth(
        request.confirmed_height_or_depth, m_wallet_state.get_tip_height(), true, false);
	bool is_amethyst = false;
	{
		api::BlockHeader confirmed_header;
		if (m_wallet_state.read_chain(confirmed_height, &confirmed_header) &&
		    confirmed_header.major_version >= m_wallet_state.get_currency().amethyst_block_version)
			is_amethyst = true;
	}
	if (!request.fee_per_byte) {
		if (m_last_node_status.recommended_fee_per_byte == 0)
			throw json_rpc::Error(json_rpc::INVALID_PARAMS,
			    "'fee_per_byte' set to 0, and it is impossible to set it to 'status.recommended_fee_per_byte', "
			    "because walletd never connected to " CRYPTONOTE_NAME "d after it was restarted");
		request.fee_per_byte = m_last_node_status.recommended_fee_per_byte;
	}
	if (m_wallet_state.get_wallet().is_view_only())
		throw json_rpc::Error(api::walletd::CreateTransaction::VIEW_ONLY_WALLET,
		    "Unable to create transaction - view-only wallet contains no spend keys");
	AccountAddress change_addr;
	if (request.any_spend_address && request.change_address.empty())
		change_addr = m_wallet_state.get_wallet().get_first_address();
	else {
		// We require change address, even if you are lucky and would get zero change
		if (!m_wallet_state.get_currency().parse_account_address_string(request.change_address, &change_addr))
			throw api::ErrorAddress(
			    api::ErrorAddress::ADDRESS_FAILED_TO_PARSE, "Failed to parse change address", request.change_address);
	}
	// We do not require that change_addr should be in our wallet
	if (request.spend_addresses.empty() && !request.any_spend_address)
		throw json_rpc::Error(json_rpc::INVALID_PARAMS,
		    "Empty spend addresses requires setting 'any_spend_address':true for additional protection");
	if (!request.spend_addresses.empty() && request.any_spend_address)
		throw json_rpc::Error(json_rpc::INVALID_PARAMS,
		    "Non-empty spend addresses requires setting 'any_spend_address':false for additional protection");
	std::set<AccountAddress> only_records;
	// We protect against our programming errors by filling only_records and then checking against them during signing
	for (const auto &ad : request.spend_addresses) {
		AccountAddress addr;
		if (!m_wallet_state.get_currency().parse_account_address_string(ad, &addr))
			throw api::ErrorAddress(api::ErrorAddress::ADDRESS_FAILED_TO_PARSE, "Failed to parse spend address", ad);
		if (!m_wallet_state.get_wallet().is_our_address(addr))
			throw api::ErrorAddress(api::ErrorAddress::ADDRESS_NOT_IN_WALLET, "Address not in wallet", ad);
		only_records.insert(addr);
	}
	Wallet::History history;
	TransactionBuilder builder;
	builder.m_transaction.version =
	    is_amethyst ? m_wallet_state.get_currency().amethyst_transaction_version : uint8_t(1);
	builder.m_transaction.unlock_block_or_timestamp = request.transaction.unlock_block_or_timestamp;
	if (request.transaction.payment_id != Hash{})
		extra::add_payment_id(builder.m_transaction.extra, request.transaction.payment_id);

	Amount sum_positive_transfers = 0;
	std::map<AccountAddress, Amount> combined_outputs;
	std::map<AccountAddress, std::string> combined_messages;
	auto max_transaction_size = m_wallet_state.get_currency().get_recommended_max_transaction_size();
	for (const auto &tr : request.transaction.transfers) {
		if (tr.amount < 0 || (tr.amount == 0 && tr.message.empty()))
			throw json_rpc::Error(json_rpc::INVALID_PARAMS,
			    "Negative or zero transfer amount " + m_wallet_state.get_currency().format_amount(tr.amount) +
			        " for address " + tr.address);
		AccountAddress addr;
		if (!m_wallet_state.get_currency().parse_account_address_string(tr.address, &addr))
			throw api::ErrorAddress(
			    api::ErrorAddress::ADDRESS_FAILED_TO_PARSE, "Failed to parse transfer address", tr.address);
		if (addr.type() == typeid(AccountAddressLegacy))
			history.insert(boost::get<AccountAddressLegacy>(addr));
		if (!is_amethyst && addr.type() == typeid(AccountAddressAmethyst))
			throw json_rpc::Error(
			    json_rpc::INVALID_PARAMS, "You cannot send to amethyst address before amethyst upgrade");
		if (tr.amount != 0)
			combined_outputs[addr] += tr.amount;
		if (!add_amount(sum_positive_transfers, tr.amount))
			throw json_rpc::Error(json_rpc::INVALID_PARAMS, "Sum of transfers overflow max amount ");
		if (!tr.message.empty()) {
			if (!is_amethyst)
				throw json_rpc::Error(
				    json_rpc::INVALID_PARAMS, "You cannot send secret messages before amethyst upgrade");
			if (!combined_messages[addr].empty())
				throw json_rpc::Error(json_rpc::INVALID_PARAMS,
				    "Transaction with several encrypted messages to the same address is not supported.");
			combined_messages[addr] = tr.message;
			auto ms                 = extra::get_encrypted_message_size(tr.message.size());
			if (ms > max_transaction_size)
				throw json_rpc::Error(
				    json_rpc::INVALID_PARAMS, "Encrypted messages size too big, will not fit into transaction.");
			max_transaction_size -= ms;
		}
	}
	size_t total_outputs = 0;
	for (const auto &aa : combined_outputs) {
		std::vector<uint64_t> decomposed_amounts;
		decompose_amount(aa.second, m_wallet_state.get_currency().min_dust_threshold, &decomposed_amounts);
		total_outputs += decomposed_amounts.size();
	}
	if (combined_outputs.empty() && combined_messages.empty())
		throw json_rpc::Error(json_rpc::INVALID_PARAMS, "Transaction without transfers not supported");
	const std::string optimization = request.transaction.unlock_block_or_timestamp == 0
	                                     ? request.optimization
	                                     : "minimal";  // Do not lock excess coins :)
	Amount change       = 0;
	Amount receiver_fee = 0;
	std::vector<api::Output> unspents;
	Amount total_unspents                  = 0;
	const Amount sum_positive_transfers_2x = sum_positive_transfers <= std::numeric_limits<Amount>::max() / 2
	                                             ? sum_positive_transfers * 2
	                                             : std::numeric_limits<Amount>::max();
	if (!request.spend_addresses.empty()) {
		for (auto &&ad : request.spend_addresses) {
			if (!m_wallet_state.api_add_unspent(
			        &unspents, &total_unspents, ad, confirmed_height, sum_positive_transfers_2x))
				break;  // found enough funds
		}
	} else {
		m_wallet_state.api_add_unspent(
		    &unspents, &total_unspents, std::string(), confirmed_height, sum_positive_transfers_2x);
	}
	UnspentSelector selector(m_log.get_logger(), m_wallet_state.get_currency(), std::move(unspents));
	// First we select just outputs with sum = 2x requires sum
	try {
		selector.select_optimal_outputs(max_transaction_size, good_anonymity, min_anonymity, sum_positive_transfers,
		    total_outputs, request.fee_per_byte.get(), optimization, &change,
		    request.subtract_fee_from_amount ? &receiver_fee : nullptr);
	} catch (const std::exception &) {
		// If selected outputs do not fit in recommended_max_transaction_size, we try all outputs
		unspents.clear();
		total_unspents = 0;
		if (!request.spend_addresses.empty())
			for (auto &&ad : request.spend_addresses) {
				m_wallet_state.api_add_unspent(&unspents, &total_unspents, ad, confirmed_height);
			}
		else
			m_wallet_state.api_add_unspent(&unspents, &total_unspents, std::string(), confirmed_height);
		selector.reset(std::move(unspents));
		selector.select_optimal_outputs(max_transaction_size, good_anonymity, min_anonymity, sum_positive_transfers,
		    total_outputs, request.fee_per_byte.get(), optimization, &change,
		    request.subtract_fee_from_amount ? &receiver_fee : nullptr);
	}
	if (receiver_fee != 0) {
		// We should subtract fee in order of transfers, hence some code repetition from above
		combined_outputs.clear();
		history.clear();
		for (const auto &tr : request.transaction.transfers) {
			Amount am = static_cast<Amount>(tr.amount);
			if (am <= receiver_fee) {
				receiver_fee -= am;
				continue;
			}
			am -= receiver_fee;
			receiver_fee = 0;
			AccountAddress addr;
			if (!m_wallet_state.get_currency().parse_account_address_string(tr.address, &addr))
				throw api::ErrorAddress(
				    api::ErrorAddress::ADDRESS_FAILED_TO_PARSE, "Failed to parse transfer address", tr.address);
			combined_outputs[addr] += am;
			if (addr.type() == typeid(AccountAddressLegacy))
				history.insert(boost::get<AccountAddressLegacy>(addr));
		}
		if (combined_outputs.empty() && combined_messages.empty())
			throw json_rpc::Error(json_rpc::INVALID_PARAMS, "Fee to subtract cannot be more than sum of all transfers");
	}
	// Selector ensures the change should be as "round" as possible
	if (change > 0)
		combined_outputs[change_addr] += change;
	for (const auto &aa : combined_messages)
		builder.add_message(aa.first, aa.second);
	for (const auto &aa : combined_outputs) {
		std::vector<uint64_t> decomposed_amounts;
		decompose_amount(aa.second, m_wallet_state.get_currency().min_dust_threshold, &decomposed_amounts);
		for (auto &&da : decomposed_amounts)
			builder.add_output(aa.first, da);
	}
	api::cnd::GetRandomOutputs::Request ra_request;
	ra_request.confirmed_height_or_depth = confirmed_height;
	ra_request.output_count              = good_anonymity + 1;
	// We ask excess output for the case of collision with our output
	// We ask minimum anonymity, though less than requested might be returned
	ra_request.amounts = selector.get_ra_amounts();
#ifndef __EMSCRIPTEN__
	if (m_inproc_node) {
		api::cnd::GetRandomOutputs::Response ra_response;
		m_inproc_node->on_get_random_outputs(
		    nullptr, http::RequestBody(raw_request), json_rpc::Request(), std::move(ra_request), ra_response);
		const auto actual_anonymity = selector.add_mixed_inputs(&builder, good_anonymity, std::move(ra_response));
		if (actual_anonymity < request.transaction.anonymity) {
			m_log(logging::TRACE) << "Transaction anonymity is " << actual_anonymity << "/"
			                      << request.transaction.anonymity;
			//			throw json_rpc::Error(api::walletd::CreateTransaction::NOT_ENOUGH_ANONYMITY,
			//			    "Requested anonymity too high, please reduce anonymity for this transaction.");
		}
		Transaction tx = builder.sign(
		    m_wallet_state, &m_wallet_state.get_wallet(), request.any_spend_address ? nullptr : &only_records);
		response.binary_transaction = seria::to_binary(tx);
		const Hash tx_hash          = get_transaction_hash(tx);
		if (!is_amethyst && request.save_history && !m_wallet_state.get_wallet().save_history(tx_hash, history)) {
			m_log(logging::ERROR)
			    << "Saving transaction history failed, you will need to pass list of destination addresses to generate sending proof for tx="
			    << tx_hash;
			response.save_history_error = true;
		}
		api::Transaction ptx{};
		if (!m_wallet_state.parse_raw_transaction(
		        false, ptx, std::move(tx), tx_hash, response.binary_transaction.size()))
			throw json_rpc::Error(json_rpc::INTERNAL_ERROR, "Created transaction cannot be parsed");
		ptx.size             = response.binary_transaction.size();
		response.transaction = ptx;
		return true;
	}
#endif
	http::RequestBody new_request =
	    json_rpc::create_request(api::cnd::url(), api::cnd::GetRandomOutputs::method(), ra_request);
	new_request.r.basic_authorization = m_config.bytecoind_authorization;
	m_log(logging::TRACE) << "sending get_random_outputs, body=" << new_request.body;
	add_waiting_command(who, std::move(raw_request), raw_js_request.get_id().get(), std::move(new_request),
	    [=](const WaitingClient &wc, http::ResponseBody &&random_response) mutable {
		    m_log(logging::TRACE) << "got response to get_random_outputs, status=" << random_response.r.status
		                          << " body " << random_response.body;
		    if (random_response.r.status != 200) {
			    throw json_rpc::Error(api::walletd::CreateTransaction::BYTECOIND_REQUEST_ERROR,
			        "got error as response on get_random_outputs");
		    }
		    Transaction tx{};
		    api::walletd::CreateTransaction::Response last_response;
		    json_rpc::Response json_resp(random_response.body);
		    api::cnd::GetRandomOutputs::Response ra_response;
		    json_resp.get_result(ra_response);
		    const auto actual_anonymity = selector.add_mixed_inputs(&builder, good_anonymity, std::move(ra_response));
		    if (actual_anonymity < request.transaction.anonymity) {
			    m_log(logging::TRACE) << "Transaction anonymity is " << actual_anonymity << "/"
			                          << request.transaction.anonymity;
			    //				throw json_rpc::Error(api::walletd::CreateTransaction::NOT_ENOUGH_ANONYMITY,
			    //									  "Requested anonymity too high, please reduce anonymity for this
			    // transaction.");
		    }
		    tx = builder.sign(
		        m_wallet_state, &m_wallet_state.get_wallet(), request.any_spend_address ? nullptr : &only_records);
		    last_response.binary_transaction = seria::to_binary(tx);
		    const Hash tx_hash               = get_transaction_hash(tx);
		    if (!is_amethyst && request.save_history && !m_wallet_state.get_wallet().save_history(tx_hash, history)) {
			    m_log(logging::ERROR)
			        << "Saving transaction history failed, you will need to pass list of destination addresses to generate sending proof for tx="
			        << tx_hash;
			    last_response.save_history_error = true;
		    }
		    http::ResponseBody last_http_response(wc.original_request.r);
		    last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
		    last_http_response.r.status = 200;
		    if (!m_wallet_state.parse_raw_transaction(false, last_response.transaction, std::move(tx), tx_hash,
		            last_response.binary_transaction.size())) {
			    last_http_response.set_body(json_rpc::create_error_response_body(
			        json_rpc::Error(json_rpc::INTERNAL_ERROR, "Created transaction cannot be parsed"),
			        wc.original_jsonrpc_id));
		    } else {
			    last_response.transaction.size = last_response.binary_transaction.size();
			    last_http_response.set_body(json_rpc::create_response_body(last_response, wc.original_jsonrpc_id));
		    }
		    http::Server::write(wc.original_who, std::move(last_http_response));
	    },
	    [=](const WaitingClient &wc, std::string err) mutable {
		    m_log(logging::INFO) << "got error to get_random_outputs from " CRYPTONOTE_NAME "d, " << err;
		    http::ResponseBody last_http_response(wc.original_request.r);
		    last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
		    last_http_response.r.status = 200;
		    last_http_response.set_body(json_rpc::create_error_response_body(
		        json_rpc::Error(api::walletd::CreateTransaction::BYTECOIND_REQUEST_ERROR, err),
		        wc.original_jsonrpc_id));
		    http::Server::write(wc.original_who, std::move(last_http_response));
	    });
	return false;
}

bool WalletNode::on_create_sendproof(http::Client *who, http::RequestBody &&raw_request,
    json_rpc::Request &&raw_js_request, api::walletd::CreateSendproof::Request &&request,
    api::walletd::CreateSendproof::Response &response) {
	api::Transaction ptx;
	if (!m_wallet_state.api_get_transaction(request.transaction_hash, true, nullptr, &ptx))
		throw json_rpc::Error(json_rpc::INTERNAL_ERROR, "Created trsnsaction cannot be parsed");
	if (!request.address.empty() && !request.addresses.empty())
		throw json_rpc::Error(json_rpc::INVALID_PARAMS,
		    "You cannot specify both 'address' and 'addresses'. Also, 'addresses' field is deprecated");
	if (request.address.empty() && request.addresses.empty()) {
		for (const auto &tr : ptx.transfers)
			if (tr.amount > 0 && !tr.address.empty()) {
				AccountAddress address;
				invariant(m_wallet_state.get_currency().parse_account_address_string(tr.address, &address), "");
				if (!m_wallet_state.get_wallet().is_our_address(address))
					request.addresses.push_back(tr.address);
			}
	}
	api::cnd::GetRawTransaction::Request ra_request;
	ra_request.hash = request.transaction_hash;
	http::RequestBody new_request =
	    json_rpc::create_request(api::cnd::url(), api::cnd::GetRawTransaction::method(), ra_request);
	new_request.r.basic_authorization = m_config.bytecoind_authorization;
	m_log(logging::TRACE) << "sending get_raw_transaction, body=" << new_request.body;
	add_waiting_command(who, std::move(raw_request), raw_js_request.get_id().get(), std::move(new_request),
	    [=](const WaitingClient &wc, http::ResponseBody &&raw_transaction_response) mutable {
		    m_log(logging::TRACE) << "got response to get_raw_transaction, status=" << raw_transaction_response.r.status
		                          << " body " << raw_transaction_response.body;
		    if (raw_transaction_response.r.status != 200) {
			    throw json_rpc::Error(api::walletd::CreateSendproof::BYTECOIND_REQUEST_ERROR,
			        "Transaction not in blockchain or " CRYPTONOTE_NAME "d out of sync");
		    }
		    api::walletd::CreateSendproof::Response last_response;
		    json_rpc::Response json_resp(raw_transaction_response.body);
		    api::cnd::GetRawTransaction::Response ra_response;
		    json_resp.get_result(ra_response);

		    if (ptx.prefix_hash != get_transaction_prefix_hash(ra_response.raw_transaction))
			    throw json_rpc::Error(
			        json_rpc::INTERNAL_ERROR, "Wrong transaction body returned from  " CRYPTONOTE_NAME "d");
		    if (!request.address.empty()) {
			    last_response.sendproof =
			        m_wallet_state.api_create_proof(ra_response.raw_transaction, ra_response.mixed_public_keys,
			            request.address, request.transaction_hash, request.message, request.reveal_secret_message);
			    if (last_response.sendproof.empty())
				    throw api::ErrorAddress{api::ErrorAddress::ADDRESS_NOT_IN_TRANSACTION,
				        "No transfers to address in this transaction", request.address};
		    } else {
			    for (const auto &addr_str : request.addresses) {
				    std::string sp =
				        m_wallet_state.api_create_proof(ra_response.raw_transaction, ra_response.mixed_public_keys,
				            addr_str, request.transaction_hash, request.message, request.reveal_secret_message);
				    last_response.sendproofs.push_back(sp);
			    }
		    }
		    http::ResponseBody last_http_response(wc.original_request.r);
		    last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
		    last_http_response.r.status = 200;
		    last_http_response.set_body(json_rpc::create_response_body(last_response, wc.original_jsonrpc_id));
		    http::Server::write(wc.original_who, std::move(last_http_response));
	    },
	    [=](const WaitingClient &wc, std::string err) mutable {
		    m_log(logging::INFO) << "got error to get_raw_transaction from " CRYPTONOTE_NAME "d, " << err;
		    http::ResponseBody last_http_response(wc.original_request.r);
		    last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
		    last_http_response.r.status = 200;
		    last_http_response.set_body(json_rpc::create_error_response_body(
		        json_rpc::Error(api::walletd::CreateSendproof::BYTECOIND_REQUEST_ERROR, err), wc.original_jsonrpc_id));
		    http::Server::write(wc.original_who, std::move(last_http_response));
	    });
	return false;
}

bool WalletNode::on_send_transaction(http::Client *who, http::RequestBody &&raw_request,
    json_rpc::Request &&raw_js_request, api::cnd::SendTransaction::Request &&request,
    api::cnd::SendTransaction::Response &response) {
	m_wallet_state.add_to_payment_queue(request.binary_transaction, true);
	advance_long_poll();
#ifndef __EMSCRIPTEN__
	if (m_inproc_node) {
		m_inproc_node->on_send_transaction(
		    nullptr, std::move(raw_request), std::move(raw_js_request), std::move(request), response);
		return true;
	}
#endif
	http::RequestBody new_request;
	new_request.set_body(std::move(raw_request.body));  // We save on copying body here
	new_request.r.set_firstline("POST", api::cnd::url(), 1, 1);
	new_request.r.basic_authorization = m_config.bytecoind_authorization;
	add_waiting_command(who, std::move(raw_request), raw_js_request.get_id().get(), std::move(new_request),
	    [](const WaitingClient &wc2, http::ResponseBody &&send_response) mutable {
		    http::ResponseBody resp(std::move(send_response));
		    resp.r.http_version_major = wc2.original_request.r.http_version_major;
		    resp.r.http_version_minor = wc2.original_request.r.http_version_minor;
		    resp.r.keep_alive         = wc2.original_request.r.keep_alive;
		    http::Server::write(wc2.original_who, std::move(resp));
	    },
	    [](const WaitingClient &wc2, std::string err) {
		    http::ResponseBody resp(wc2.original_request.r);
		    resp.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
		    resp.r.status = 200;
		    resp.set_body(json_rpc::create_error_response_body(
		        json_rpc::Error(api::walletd::SendTransaction::BYTECOIND_REQUEST_ERROR, err), wc2.original_jsonrpc_id));
		    http::Server::write(wc2.original_who, std::move(resp));
	    });
	return false;
}

bool WalletNode::on_get_transaction(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::walletd::GetTransaction::Request &&req, api::walletd::GetTransaction::Response &res) {
	TransactionPrefix tx;
	if (!m_wallet_state.api_get_transaction(req.hash, true, &tx, &res.transaction))
		throw api::ErrorHash(
		    "Transaction does not exist (in main chain or memory pool) or does not belong to this wallet.", req.hash);
	return true;
}

void WalletNode::process_waiting_command_response(http::ResponseBody &&resp) {
	WaitingClient cli = std::move(m_waiting_command_requests.front());
	m_waiting_command_requests.pop_front();
	m_command_request.reset();

	if (cli.original_who) {
		auto err_fun = std::move(cli.err_fun);
		auto fun     = std::move(cli.fun);
		try {
			try {
				fun(cli, std::move(resp));
			} catch (const std::exception &ex) {
				m_log(logging::WARNING) << "    Parsing received waiting command leads to throw/catch what="
				                        << common::what(ex);
				err_fun(cli, common::what(ex));
			} catch (...) {
				m_log(logging::WARNING) << "    Parsing received waiting command leads to throw/catch";
				err_fun(cli, "catch ...");
			}
		} catch (const std::exception &ex) {
			m_log(logging::WARNING) << "    Error function leads to throw/catch what=" << common::what(ex);
		} catch (...) {
			m_log(logging::WARNING) << "    Error function leads to throw/catch";
		}
	}
	send_next_waiting_command();
}

void WalletNode::process_waiting_command_error(std::string err) {
	WaitingClient cli = std::move(m_waiting_command_requests.front());
	m_waiting_command_requests.pop_front();
	m_command_request.reset();

	if (cli.original_who) {
		auto err_fun = std::move(cli.err_fun);
		err_fun(cli, err);
	}
	send_next_waiting_command();
}

void WalletNode::send_next_waiting_command() {
	if (m_waiting_command_requests.empty() || m_command_request)
		return;
	auto fun          = std::bind(&WalletNode::process_waiting_command_response, this, _1);
	auto e_fun        = std::bind(&WalletNode::process_waiting_command_error, this, _1);
	m_command_request = std::make_unique<http::Request>(
	    m_commands_agent, std::move(m_waiting_command_requests.front().request), fun, e_fun);
}

void WalletNode::add_waiting_command(http::Client *who, http::RequestBody &&original_request,
    const common::JsonValue &original_rpc_id, http::RequestBody &&request,
    std::function<void(const WalletNode::WaitingClient &wc, http::ResponseBody &&resp)> &&fun,
    std::function<void(const WalletNode::WaitingClient &wc, std::string)> &&err_fun) {
	WaitingClient wc2;
	wc2.original_who        = who;
	wc2.original_request    = std::move(original_request);
	wc2.original_jsonrpc_id = original_rpc_id;
	wc2.fun                 = std::move(fun);
	wc2.err_fun             = std::move(err_fun);
	wc2.request             = std::move(request);
	m_waiting_command_requests.push_back(wc2);
	send_next_waiting_command();
}

void WalletNode::advance_long_poll() {
	if (m_long_poll_http_clients.empty())
		return;
	const api::walletd::GetStatus::Response resp = create_status_response();

	for (auto lit = m_long_poll_http_clients.begin(); lit != m_long_poll_http_clients.end();)
		if (resp.ready_for_longpoll(lit->original_get_status)) {
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
			last_http_response.set_body(json_rpc::create_response_body(resp, cli.original_jsonrpc_id));
			http::Server::write(cli.original_who, std::move(last_http_response));
		} else
			++lit;
}
