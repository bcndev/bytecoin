// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletNode.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

using namespace bytecoin;

const WalletNode::HandlersMap WalletNode::m_jsonrpc3_handlers = {
    {api::walletd::GetStatus::method(), json_rpc::make_member_method(&WalletNode::handle_get_status3)},
    {api::walletd::GetAddresses::method(), json_rpc::make_member_method(&WalletNode::handle_get_addresses3)},
    {api::walletd::CreateAddresses::method(), json_rpc::make_member_method(&WalletNode::handle_create_address_list3)},
    {api::walletd::GetViewKeyPair::method(), json_rpc::make_member_method(&WalletNode::handle_get_view_key3)},
    {api::walletd::GetBalance::method(), json_rpc::make_member_method(&WalletNode::handle_get_balance3)},
    {api::walletd::GetUnspents::method(), json_rpc::make_member_method(&WalletNode::handle_get_unspent3)},
    {api::walletd::GetTransfers::method(), json_rpc::make_member_method(&WalletNode::handle_get_transfers3)},
    {api::walletd::CreateTransaction::method(), json_rpc::make_member_method(&WalletNode::handle_create_transaction3)},
    {api::walletd::SendTransaction::method(), json_rpc::make_member_method(&WalletNode::handle_send_transaction3)},
    {api::walletd::CreateSendProof::method(), json_rpc::make_member_method(&WalletNode::handle_create_send_proof3)},
    {api::walletd::GetTransaction::method(), json_rpc::make_member_method(&WalletNode::handle_get_transaction3)}};

WalletNode::WalletNode(Node *inproc_node, logging::ILogger &log, const Config &config, WalletState &wallet_state)
    : WalletSync(log, config, wallet_state, std::bind(&WalletNode::advance_long_poll, this))
    , m_inproc_node(inproc_node) {
	if (!config.walletd_bind_ip.empty() && config.walletd_bind_port != 0)
		m_api.reset(new http::Server(config.walletd_bind_ip, config.walletd_bind_port,
		    std::bind(&WalletNode::on_api_http_request, this, _1, _2, _3),
		    std::bind(&WalletNode::on_api_http_disconnect, this, _1)));
}

bool WalletNode::on_api_http_request(http::Client *who, http::RequestData &&request, http::ResponseData &response) {
	response.r.add_headers_nocache();
	bool method_found = false;
	if (request.r.uri == api::walletd::url()) {
		bool result = process_json_rpc_request(m_jsonrpc3_handlers, who, std::move(request), response, method_found);
		if (method_found)
			return result;
	}
	if (m_inproc_node)
		return m_inproc_node->process_json_rpc_request(who, std::move(request), response);
	m_log(logging::INFO) << "http_request node tunneling url=" << request.r.uri << std::endl;
	http::RequestData original_request;
	original_request.r            = request.r;
	request.r.http_version_major  = 1;
	request.r.http_version_minor  = 1;
	request.r.keep_alive          = true;
	request.r.basic_authorization = m_config.bytecoind_authorization;
	add_waiting_command(who, std::move(original_request), json_rpc::OptionalJsonValue{}, std::move(request),
	    [=](const WaitingClient &wc, http::ResponseData &&send_response) mutable {
		    send_response.r.http_version_major = wc.original_request.r.http_version_major;
		    send_response.r.http_version_minor = wc.original_request.r.http_version_minor;
		    send_response.r.keep_alive         = wc.original_request.r.keep_alive;
		    // bytecoind never sends connection-close, so we are safe to retain all
		    // headers
		    wc.original_who->write(std::move(send_response));
		},
	    [=](const WaitingClient &wc, std::string err) {
		    http::ResponseData send_response;
		    send_response.r.http_version_major = wc.original_request.r.http_version_major;
		    send_response.r.http_version_minor = wc.original_request.r.http_version_minor;
		    send_response.r.keep_alive         = wc.original_request.r.keep_alive;
		    send_response.r.status             = 504;  // TODO -test this code path
		    wc.original_who->write(std::move(send_response));
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

bool WalletNode::process_json_rpc_request(const HandlersMap &handlers,
    http::Client *who,
    http::RequestData &&request,
    http::ResponseData &response,
    bool &method_found) {
	method_found = false;
	response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});

	json_rpc::Response json_resp;

	try {
		json_rpc::Request json_req(request.body);
		json_resp.set_id(json_req.get_id());  // copy id

		auto it = handlers.find(json_req.get_method());
		if (it == handlers.end()) {
			return false;
			//			m_log(logging::INFO) << "json request method not
			// found - " << json_req.get_method() << std::endl;
			//			throw
			// json_rpc::Error(json_rpc::METHOD_NOT_FOUND);
		}
		method_found = true;
		if (!m_config.walletd_authorization.empty() &&
		    request.r.basic_authorization != m_config.walletd_authorization) {
			response.r.headers.push_back({"WWW-Authenticate", "Basic realm=\"Wallet\", charset=\"UTF-8\""});
			response.r.status = 401;
			return true;
		}
		//		m_log(logging::INFO) << "json request method=" <<
		// json_req.get_method()
		//<< std::endl;
		bool result = it->second(this, who, std::move(request), std::move(json_req), json_resp);
		if (!result)
			return false;

	} catch (const json_rpc::Error &err) {
		json_resp.set_error(err);
	} catch (const std::exception &e) {
		json_resp.set_error(json_rpc::Error(json_rpc::INTERNAL_ERROR, e.what()));
	}

	response.set_body(json_resp.get_body());
	response.r.status = 200;
	return true;
}

// New protocol

api::walletd::GetStatus::Response WalletNode::create_status_response3() const {
	api::walletd::GetStatus::Response response = m_last_node_status;
	response.top_block_height                  = m_wallet_state.get_tip_height();
	response.top_block_hash                    = m_wallet_state.get_tip().hash;
	response.top_block_timestamp               = m_wallet_state.get_tip().timestamp;
	if (m_wallet_state.get_tip_height() == Height(-1)) {  // WalletState empty state
		response.top_block_height    = 0;
		response.top_block_hash      = m_wallet_state.get_currency().genesis_block_hash;
		response.top_block_timestamp = m_wallet_state.get_currency().genesis_block_template.timestamp;
	}
	response.transaction_pool_version = m_wallet_state.get_tx_pool_version();
	response.lower_level_error        = m_sync_error;
	return response;
}

bool WalletNode::handle_get_status3(http::Client *who, http::RequestData &&raw_request,
    json_rpc::Request &&raw_js_request, api::walletd::GetStatus::Request &&request,
    api::walletd::GetStatus::Response &response) {
	response = create_status_response3();
	if (request == response) {
		//		m_log(logging::INFO) << "handle_get_status3 will long poll, json="
		//<<
		// raw_request.body << std::endl;
		LongPollClient lpc;
		lpc.original_who        = who;
		lpc.original_request    = raw_request;
		lpc.original_jsonrpc_id = raw_js_request.get_id();
		lpc.original_get_status = request;
		m_long_poll_http_clients.push_back(lpc);
		return false;
	}
	return true;
}

bool WalletNode::handle_get_addresses3(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::walletd::GetAddresses::Request &&, api::walletd::GetAddresses::Response &response) {
	response.view_only = m_wallet_state.get_wallet().is_view_only();
	response.addresses.reserve(m_wallet_state.get_wallet().get_records().size());
	// We want "first address" to actually be first in list
	AccountPublicAddress fa = m_wallet_state.get_wallet().get_first_address();
	response.addresses.push_back(m_wallet_state.get_currency().account_address_as_string(fa));
	for (auto &&wc : m_wallet_state.get_wallet().get_records()) {
		AccountPublicAddress addr{wc.second.spend_public_key, m_wallet_state.get_wallet().get_view_public_key()};
		if (addr != fa)
			response.addresses.push_back(m_wallet_state.get_currency().account_address_as_string(addr));
	}
	return true;
}

bool WalletNode::handle_get_view_key3(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::walletd::GetViewKeyPair::Request &&, api::walletd::GetViewKeyPair::Response &response) {
	response.public_view_key = m_wallet_state.get_wallet().get_view_public_key();
	response.secret_view_key = m_wallet_state.get_wallet().get_view_secret_key();
	return true;
}

bool WalletNode::handle_create_address_list3(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::walletd::CreateAddresses::Request &&request, api::walletd::CreateAddresses::Response &response) {
	if (request.secret_spend_keys.empty())
		return true;
	Timestamp ct =
	    request.creation_timestamp != 0 ? request.creation_timestamp : static_cast<Timestamp>(std::time(nullptr));
	auto records = m_wallet_state.generate_new_addresses(request.secret_spend_keys, ct);
	if (records.empty())
		throw json_rpc::Error(json_rpc::INVALID_PARAMS, "wallet is view-only, impossible to create addresses");
	response.addresses.reserve(records.size());
	response.secret_spend_keys.reserve(records.size());
	for (auto &&rec : records) {
		AccountPublicAddress addr{rec.spend_public_key, m_wallet_state.get_wallet().get_view_public_key()};
		response.addresses.push_back(m_wallet_state.get_currency().account_address_as_string(addr));
		response.secret_spend_keys.push_back(rec.spend_secret_key);
	}
	return true;
}

bool WalletNode::handle_get_balance3(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::walletd::GetBalance::Request &&request, api::walletd::GetBalance::Response &response) {
	if (request.height_or_depth < 0)
		request.height_or_depth =
		    std::max(0, static_cast<api::HeightOrDepth>(m_wallet_state.get_tip_height()) + 1 + request.height_or_depth);
	// TODO - error if address does not exist
	response = m_wallet_state.get_balance(request.address, request.height_or_depth);
	return true;
}

bool WalletNode::handle_get_unspent3(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::walletd::GetUnspents::Request &&request, api::walletd::GetUnspents::Response &response) {
	if (request.height_or_depth < 0)
		request.height_or_depth =
		    std::max(0, static_cast<api::HeightOrDepth>(m_wallet_state.get_tip_height()) + 1 + request.height_or_depth);
	// TODO - error if address does not exist
	Amount total_amount = 0;
	m_wallet_state.api_add_unspent(response.spendable, total_amount, request.address, request.height_or_depth);
	response.locked_or_unconfirmed =
	    m_wallet_state.api_get_locked_or_unconfirmed_unspent(request.address, request.height_or_depth);
	return true;
}

bool WalletNode::handle_get_transfers3(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::walletd::GetTransfers::Request &&request, api::walletd::GetTransfers::Response &response) {
	response.next_to_height   = request.to_height;
	response.next_from_height = request.from_height;
	response.blocks           = m_wallet_state.api_get_transfers(
	    request.address, request.from_height, request.to_height, request.forward, request.desired_transactions_count);
	if (request.from_height < m_wallet_state.get_tip_height() && request.to_height >= m_wallet_state.get_tip_height()) {
		api::Block pool_block = m_wallet_state.api_get_pool_as_history(request.address);
		if (!pool_block.transactions.empty()) {
			if (request.forward)
				response.blocks.push_back(pool_block);
			else
				response.blocks.insert(response.blocks.begin(), pool_block);
		}
	}
	// TODO - error if address does not exist

	auto unlocked_outputs =
	    m_wallet_state.api_get_unlocked_outputs(request.address, request.from_height, request.to_height);
	response.unlocked_transfers.reserve(unlocked_outputs.size());
	for (auto &&lou : unlocked_outputs) {
		api::Transfer tr;
		tr.ours    = true;
		tr.amount  = lou.second.amount;
		tr.address = lou.second.address;
		tr.outputs.push_back(lou.second);
		response.unlocked_transfers.push_back(std::move(tr));
	}
	if (request.forward)
		response.next_from_height = request.to_height;
	else
		response.next_to_height = request.from_height;
	return true;
}

bool WalletNode::handle_create_transaction3(http::Client *who, http::RequestData &&raw_request,
    json_rpc::Request &&raw_js_request, api::walletd::CreateTransaction::Request &&request,
    api::walletd::CreateTransaction::Response &response) {
	if (request.confirmed_height_or_depth < 0)
		request.confirmed_height_or_depth = std::max(0,
		    static_cast<api::HeightOrDepth>(m_wallet_state.get_tip_height()) + 1 - request.confirmed_height_or_depth);
	if (request.fee_per_byte == 0)
		request.fee_per_byte = m_last_node_status.recommended_fee_per_byte;
	if (request.fee_per_byte == 0)
		throw json_rpc::Error(json_rpc::INVALID_PARAMS,
		    "'fee_per_byte' set to 0, and it is impossible to "
		    "set it to 'status.recommended_fee_per_byte', "
		    "because walletd never connected to bytecoind after "
		    "it was restarted");
	AccountPublicAddress change_addr;  // We require change address, even if you are lucky and would get zero change
	if (m_wallet_state.get_wallet().is_view_only())
		throw json_rpc::Error(json_rpc::INVALID_PARAMS,
		    "Unable to create transaction - view-only wallet "
		    "contains no spend keys");
	if (!m_wallet_state.get_currency().parse_account_address_string(request.change_address, change_addr))
		throw json_rpc::Error(json_rpc::INVALID_PARAMS, "Failed to parse change address " + request.change_address);
	if (request.spend_addresses.empty() && !request.any_spend_address)
		throw json_rpc::Error(json_rpc::INVALID_PARAMS,
		    "Empty spend addresses requires setting "
		    "'any_spend_address':true for additional protection");
	if (!request.spend_addresses.empty() && request.any_spend_address)
		throw json_rpc::Error(json_rpc::INVALID_PARAMS,
		    "Non-empty spend addresses requires setting "
		    "'any_spend_address':false for additional "
		    "protection");
	std::unordered_map<PublicKey, WalletRecord> only_records;
	for (auto &&ad : request.spend_addresses) {
		AccountPublicAddress addr;
		if (!m_wallet_state.get_currency().parse_account_address_string(ad, addr))
			throw json_rpc::Error(json_rpc::INVALID_PARAMS, "Failed to parse change address " + ad);
		if (!m_wallet_state.get_wallet().get_only_record(only_records, addr))
			throw json_rpc::Error(json_rpc::INVALID_PARAMS, "Spend address does not belong to wallet " + ad);
	}
	TransactionBuilder builder(m_wallet_state.get_currency(), request.transaction.unlock_time);
	Wallet::History history;
	if (request.transaction.payment_id != Hash{})
		builder.set_payment_id(request.transaction.payment_id);

	Amount sum_positive_transfers = 0;
	std::map<AccountPublicAddress, Amount> combined_outputs;

	for (auto &&tr : request.transaction.transfers) {
		if (tr.amount <= 0)  // Not an output
			throw json_rpc::Error(json_rpc::INVALID_PARAMS,
			    "Negative transfer amount " + std::to_string(tr.amount) + " for address " + tr.address);
		AccountPublicAddress addr;
		if (!m_wallet_state.get_currency().parse_account_address_string(tr.address, addr))
			throw json_rpc::Error(json_rpc::INVALID_PARAMS, "Failed to parse address " + tr.address);
		combined_outputs[addr] += tr.amount;
		history.insert(addr);
		sum_positive_transfers += tr.amount;
	}
	size_t total_outputs = 0;
	for (auto aa : combined_outputs) {
		std::vector<uint64_t> decomposed_amounts;
		decompose_amount(aa.second, m_wallet_state.get_currency().default_dust_threshold, decomposed_amounts);
		total_outputs += decomposed_amounts.size();
	}
	if (sum_positive_transfers == 0)
		throw json_rpc::Error(json_rpc::INVALID_PARAMS, "Sum of amounts of all outgoing transfers cannot be 0");
	const std::string optimization =
	    request.transaction.unlock_time == 0 ? request.optimization : "minimal";  // Do not lock excess coins :)
	Amount change = 0;
	std::vector<api::Output> unspents;
	Amount total_unspents = 0;
	if (!request.spend_addresses.empty())
		for (auto &&ad : request.spend_addresses) {
			if (!m_wallet_state.api_add_unspent(
					unspents, total_unspents, ad, request.confirmed_height_or_depth, sum_positive_transfers * 2))
				break;  // found enough funds
		}
	else
		m_wallet_state.api_add_unspent( unspents, total_unspents, std::string(), request.confirmed_height_or_depth, sum_positive_transfers * 2);
	UnspentSelector selector(m_wallet_state.get_currency(), std::move(unspents));
	// First we select just outputs with sum = 2x requires sum
	if (!selector.select_optimal_outputs(m_wallet_state.get_tip_height(), m_wallet_state.get_tip().timestamp,
	        request.confirmed_height_or_depth, m_last_node_status.next_block_effective_median_size,
	        request.transaction.anonymity, sum_positive_transfers, total_outputs, request.fee_per_byte, optimization,
	        change)) {
		// If selected outputs do not fit in next_block_effective_median_size, we try all outputs
		unspents.clear();
		total_unspents = 0;
		if (!request.spend_addresses.empty())
			for (auto &&ad : request.spend_addresses) {
				m_wallet_state.api_add_unspent(unspents, total_unspents, ad, request.confirmed_height_or_depth);
			}
		else
			m_wallet_state.api_add_unspent( unspents, total_unspents, std::string(), request.confirmed_height_or_depth);
		selector.reset(std::move(unspents));
		if (!selector.select_optimal_outputs(m_wallet_state.get_tip_height(), m_wallet_state.get_tip().timestamp,
		        request.confirmed_height_or_depth, m_last_node_status.next_block_effective_median_size,
		        request.transaction.anonymity, sum_positive_transfers, total_outputs, request.fee_per_byte,
		        optimization, change))
			throw json_rpc::Error(
			    json_rpc::INVALID_PARAMS, "Not enough funds on selected addresses with desired confirmations");
	}
	// Selector ensures the change should be as "round" as possible
	if (change > 0) {
		combined_outputs[change_addr] += change;
		history.insert(change_addr);
	}
	for (auto aa : combined_outputs) {
		std::vector<uint64_t> decomposed_amounts;
		decompose_amount(aa.second, m_wallet_state.get_currency().default_dust_threshold, decomposed_amounts);
		for (auto &&da : decomposed_amounts)
			builder.add_output(da, aa.first);
	}
	api::bytecoind::GetRandomOutputs::Request ra_request;
	ra_request.confirmed_height_or_depth = request.confirmed_height_or_depth;
	ra_request.outs_count =
	    request.transaction.anonymity + 1;  // Ask excess output for the case of collision with our output
	ra_request.amounts = selector.get_ra_amounts();
	api::bytecoind::GetRandomOutputs::Response ra_response;
	if (m_inproc_node) {
		m_inproc_node->on_get_random_outputs3(
		    nullptr, http::RequestData(raw_request), json_rpc::Request(), std::move(ra_request), ra_response);
		selector.add_mixed_inputs(m_wallet_state.get_wallet().get_view_secret_key(),
		    request.any_spend_address ? m_wallet_state.get_wallet().get_records() : only_records, builder,
		    request.transaction.anonymity, std::move(ra_response));
		Transaction tx              = builder.sign(m_wallet_state.get_wallet().get_tx_derivation_seed());
		response.binary_transaction = seria::to_binary(tx);
		Hash transaction_hash       = get_transaction_hash(tx);
		if (request.save_history && !m_wallet_state.get_wallet().save_history(transaction_hash, history)) {
			m_log(logging::ERROR) << "Saving transaction history failed, proof of "
			                         "sending will be unavailable for tx="
			                      << common::pod_to_hex(transaction_hash) << std::endl;
			response.save_history_error = true;
		}

		api::Transaction ptx{};
		if (!m_wallet_state.parse_raw_transaction(ptx, tx, transaction_hash)) {
			// TODO - process error
		}
		response.transaction = ptx;
		return true;
	}

	api::walletd::CreateTransaction::Request request_copy = request;  // TODO ???
	http::RequestData new_request =
	    json_rpc::create_request(api::bytecoind::url(), api::bytecoind::GetRandomOutputs::method(), ra_request);
	add_waiting_command(who, std::move(raw_request), raw_js_request.get_id(), std::move(new_request),
	    [=](const WaitingClient &wc, const http::ResponseData &random_response) mutable {
		    m_log(logging::INFO) << "got random response" << std::endl;
		    Transaction tx{};
		    api::walletd::CreateTransaction::Response last_response;
		    Hash tx_hash{};
		    json_rpc::Response json_resp(random_response.body);
		    api::bytecoind::GetRandomOutputs::Response ra_response;
		    json_resp.get_result(ra_response);
		    selector.add_mixed_inputs(m_wallet_state.get_wallet().get_view_secret_key(),
		        request.any_spend_address ? m_wallet_state.get_wallet().get_records() : only_records, builder,
		        request.transaction.anonymity, std::move(ra_response));
		    tx                               = builder.sign(m_wallet_state.get_wallet().get_tx_derivation_seed());
		    last_response.binary_transaction = seria::to_binary(tx);
		    tx_hash                          = get_transaction_hash(tx);
		    if (request.save_history && !m_wallet_state.get_wallet().save_history(tx_hash, history)) {
			    m_log(logging::ERROR) << "Saving transaction history failed, proof "
			                             "of sending will not be available for tx="
			                          << common::pod_to_hex(tx_hash) << std::endl;
			    last_response.save_history_error = true;
		    }
		    if (!m_wallet_state.parse_raw_transaction(last_response.transaction, tx, tx_hash)) {
			    // TODO - process error
		    }
		    http::ResponseData last_http_response =
		        json_rpc::create_response(wc.original_request, last_response, wc.original_jsonrpc_id);
		    wc.original_who->write(std::move(last_http_response));
		},
	    [=](const WaitingClient &wc, std::string err) mutable {
		    http::ResponseData last_http_response = json_rpc::create_error_response(
		        wc.original_request, json_rpc::Error(json_rpc::INTERNAL_ERROR, err), wc.original_jsonrpc_id);
		    wc.original_who->write(std::move(last_http_response));
		});
	return false;
}

bool WalletNode::handle_create_send_proof3(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::walletd::CreateSendProof::Request &&request, api::walletd::CreateSendProof::Response &response) {
	std::set<AccountPublicAddress> addresses;
	if (request.addresses.empty()) {
		Wallet::History history = m_wallet_state.get_wallet().load_history(request.transaction_hash);
		for (auto &&address : history) {
			if (m_wallet_state.get_wallet().get_view_public_key() == address.view_public_key)
				continue;  // our address
			addresses.insert(address);
		}
	}
	for (auto &&addr : request.addresses) {
		AccountPublicAddress address;
		if (!m_wallet_state.get_currency().parse_account_address_string(addr, address))
			throw json_rpc::Error(json_rpc::INVALID_PARAMS, "Address failed to parse " + addr);
		addresses.insert(address);
	}
	for (auto &&address : addresses) {
		SendProof sp;
		sp.transaction_hash = request.transaction_hash;
		sp.message          = request.message;
		sp.address          = address;
		if (m_wallet_state.api_create_proof(sp))
			response.send_proofs.push_back(seria::to_json_value(sp).to_string());
	}
	return true;
}

bool WalletNode::handle_send_transaction3(http::Client *who, http::RequestData &&raw_request,
    json_rpc::Request &&raw_js_request, api::bytecoind::SendTransaction::Request &&request,
    api::bytecoind::SendTransaction::Response &response) {
	Transaction tx;
	seria::from_binary(tx, request.binary_transaction);
	Hash tid = get_transaction_hash(tx);
	m_wallet_state.add_transient_transaction(tid, tx);
	if (m_inproc_node) {
		m_inproc_node->handle_send_transaction3(
		    nullptr, std::move(raw_request), std::move(raw_js_request), std::move(request), response);
		return true;
	}
	http::RequestData new_request;
	new_request.set_body(std::move(raw_request.body));  // We save on copying body here
	new_request.r.set_firstline("POST", api::bytecoind::url(), 1, 1);
	transient_transactions_counter += 1;
	add_waiting_command(who, std::move(raw_request), raw_js_request.get_id(), std::move(new_request),
	    [=](const WaitingClient &wc2, const http::ResponseData &send_response) mutable {
		    transient_transactions_counter -= 1;
		    try {  // Manual try to prevent double decrement of transient_transactions_counter
			    advance_sync();
			    http::ResponseData resp(send_response);
			    resp.r.http_version_major = wc2.original_request.r.http_version_major;
			    resp.r.http_version_minor = wc2.original_request.r.http_version_minor;
			    resp.r.keep_alive         = wc2.original_request.r.keep_alive;
			    wc2.original_who->write(std::move(resp));
		    } catch (const std::exception &ex) {
			    http::ResponseData resp = json_rpc::create_error_response(wc2.original_request,
			        json_rpc::Error(json_rpc::INTERNAL_ERROR, ex.what()), wc2.original_jsonrpc_id);
			    wc2.original_who->write(std::move(resp));
		    } catch (...) {
			    http::ResponseData resp = json_rpc::create_error_response(wc2.original_request,
			        json_rpc::Error(json_rpc::INTERNAL_ERROR, "catch..."), wc2.original_jsonrpc_id);
			    wc2.original_who->write(std::move(resp));
		    }
		},
	    [=](const WaitingClient &wc2, std::string err) {
		    transient_transactions_counter -= 1;
		    http::ResponseData resp = json_rpc::create_error_response(
		        wc2.original_request, json_rpc::Error(json_rpc::INTERNAL_ERROR, err), wc2.original_jsonrpc_id);
		    wc2.original_who->write(std::move(resp));
		});
	return false;
}

bool WalletNode::handle_get_transaction3(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::walletd::GetTransaction::Request &&req, api::walletd::GetTransaction::Response &res) {
	TransactionPrefix tx;
	m_wallet_state.api_get_transaction(req.hash, tx, res.transaction);
	return true;
}

void WalletNode::process_waiting_command_response(http::ResponseData &&resp) {
	WaitingClient cli = std::move(m_waiting_command_requests.front());
	m_waiting_command_requests.pop_front();
	m_command_request.reset();

	if (cli.original_who) {
		auto err_fun = std::move(cli.err_fun);
		auto fun     = std::move(cli.fun);
		try {
			fun(cli, std::move(resp));
		} catch (std::exception &ex) {
			std::cout << "    Parsing received waiting command leads to throw/catch what=" << ex.what() << std::endl;
			err_fun(cli, ex.what());
		} catch (...) {
			std::cout << "    Parsing received waiting command leads to throw/catch" << std::endl;
			err_fun(cli, "catch ...");
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

void WalletNode::add_waiting_command(http::Client *who, http::RequestData &&original_request,
    const json_rpc::OptionalJsonValue &original_rpc_id, http::RequestData &&request,
    std::function<void(const WalletNode::WaitingClient &wc, http::ResponseData &&resp)> fun,
    std::function<void(const WalletNode::WaitingClient &wc, std::string)> err_fun) {
	WaitingClient wc2;
	wc2.original_who        = who;
	wc2.original_request    = std::move(original_request);
	wc2.original_jsonrpc_id = original_rpc_id;
	wc2.fun                 = fun;
	wc2.err_fun             = err_fun;
	wc2.request             = std::move(request);
	m_waiting_command_requests.push_back(wc2);
	send_next_waiting_command();
}

void WalletNode::advance_long_poll() {
	if (m_long_poll_http_clients.empty())
		return;
	api::walletd::GetStatus::Response resp = create_status_response3();
	json_rpc::Response last_json_resp;
	last_json_resp.set_result(resp);

	for (auto lit = m_long_poll_http_clients.begin(); lit != m_long_poll_http_clients.end();)
		if (lit->original_get_status != resp) {
			last_json_resp.set_id(lit->original_jsonrpc_id);
			http::ResponseData last_http_response;
			last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
			last_http_response.r.status             = 200;
			last_http_response.r.http_version_major = lit->original_request.r.http_version_major;
			last_http_response.r.http_version_minor = lit->original_request.r.http_version_minor;
			last_http_response.r.keep_alive         = lit->original_request.r.keep_alive;
			last_http_response.set_body(last_json_resp.get_body());
			//			m_log(logging::INFO) << "advance_long_poll will
			// reply to long poll json=" << last_http_response.body << std::endl;
			lit->original_who->write(std::move(last_http_response));
			lit = m_long_poll_http_clients.erase(lit);
		} else
			++lit;
}
