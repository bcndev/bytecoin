// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <iostream>
#include "Core/Config.hpp"
#include "CryptoNoteTools.hpp"
#include "Node.hpp"
#include "TransactionExtra.hpp"
#include "WalletNode.hpp"
#include "common/JsonValue.hpp"
#include "common/exception.hpp"
#include "http/Server.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

using namespace cn;

bool Node::on_json_rpc(http::Client *who, http::RequestBody &&request, http::ResponseBody &response) {
	response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});

	common::JsonValue jid(nullptr);

	try {
		json_rpc::Request json_req(request.body);
		jid = json_req.get_id().get();

		auto it = m_jsonrpc_handlers.find(json_req.get_method());
		if (it == m_jsonrpc_handlers.end()) {
			m_log(logging::INFO) << "jsonrpc request method not found - " << json_req.get_method();
			if (WalletNode::m_jsonrpc_handlers.count(json_req.get_method()) != 0)
				throw json_rpc::Error(json_rpc::METHOD_NOT_FOUND,
				    "Method not found " + json_req.get_method() +
				        " (attempt to call walletd method on " CRYPTONOTE_NAME "d)");
			throw json_rpc::Error(json_rpc::METHOD_NOT_FOUND, "Method not found " + json_req.get_method());
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

bool Node::on_binary_rpc(http::Client *who, http::RequestBody &&request, http::ResponseBody &response) {
	response.r.headers.push_back({"Content-Type", "application/octet-stream"});

	common::JsonValue jid(nullptr);
	try {
		size_t sep = request.body.find(char(0));
		if (sep == std::string::npos)
			throw std::runtime_error("binary request contains no 0-character separator");
		json_rpc::Request binary_req(request.body.substr(0, sep));
		jid = binary_req.get_id().get();

		common::MemoryInputStream body_stream(request.body.data() + sep + 1, request.body.size() - sep - 1);

		auto it = m_binaryrpc_handlers.find(binary_req.get_method());
		if (it == m_binaryrpc_handlers.end()) {
			m_log(logging::INFO) << "binaryrpc request method not found - " << binary_req.get_method();
			throw json_rpc::Error(json_rpc::METHOD_NOT_FOUND, "Method not found " + binary_req.get_method());
		}
		std::string response_body;
		if (!it->second(this, who, body_stream, std::move(binary_req), response_body))
			return false;
		response.set_body(std::move(response_body));
	} catch (const json_rpc::Error &err) {
		response.set_body(json_rpc::create_binary_response_error_body(err, jid));
	} catch (const std::exception &e) {
		json_rpc::Error json_err(json_rpc::INTERNAL_ERROR, common::what(e));
		response.set_body(json_rpc::create_binary_response_error_body(json_err, jid));
	}
	response.r.status = 200;
	return true;
}

bool Node::on_getblocktemplate(http::Client *who, http::RequestBody &&raw_request, json_rpc::Request &&raw_js_request,
    api::cnd::GetBlockTemplate::Request &&req, api::cnd::GetBlockTemplate::Response &res) {
	if (!m_config.good_bytecoind_auth_private(raw_request.r.basic_authorization))
		throw http::ErrorAuthorization("authorization-private");
	api::cnd::GetStatus::Request sta;
	sta.top_block_hash                       = req.top_block_hash;
	sta.transaction_pool_version             = req.transaction_pool_version;
	api::cnd::GetStatus::Response status_res = create_status_response();
	m_log(logging::INFO) << "Node received getblocktemplate REQ transaction_pool_version="
	                     << (req.transaction_pool_version ? common::to_string(req.transaction_pool_version.get())
	                                                      : "empty")
	                     << " top_block_hash="
	                     << (req.top_block_hash ? common::pod_to_hex(req.top_block_hash.get()) : "empty");
	m_log(logging::INFO) << "Node received getblocktemplate CUR transaction_pool_version="
	                     << m_block_chain.get_tx_pool_version() << " top_block_hash=" << m_block_chain.get_tip_bid();
	if (!status_res.ready_for_longpoll(sta)) {
		LongPollClient lpc;
		lpc.original_who          = who;
		lpc.original_request      = raw_request;
		lpc.original_json_request = std::move(raw_js_request);
		lpc.original_get_status   = sta;
		m_long_poll_http_clients.push_back(lpc);
		return false;
	}
	getblocktemplate(req, res);
	return true;
}

void Node::getblocktemplate(const api::cnd::GetBlockTemplate::Request &req, api::cnd::GetBlockTemplate::Response &res) {
	if (req.reserve_size > extra::Nonce::MAX_COUNT)
		throw json_rpc::Error{api::cnd::GetBlockTemplate::TOO_BIG_RESERVE_SIZE,
		    "To big reserved size, maximum " + common::to_string(extra::Nonce::MAX_COUNT)};
	AccountAddress acc{};
	if (!m_block_chain.get_currency().parse_account_address_string(req.wallet_address, &acc))
		throw api::ErrorAddress(
		    api::ErrorAddress::ADDRESS_FAILED_TO_PARSE, "Failed to parse wallet address", req.wallet_address);

	BlockTemplate block_template{};
	BinaryArray blob_reserve;
	uint8_t reserve_magic = 0xbb;
	blob_reserve.resize(req.reserve_size, reserve_magic);
	size_t reserve_back_offset = 0;

	try {
		m_block_chain.create_mining_block_template(m_block_chain.get_tip_bid(), acc, blob_reserve, req.miner_secret,
		    &block_template, &res.difficulty, &res.height, &reserve_back_offset);
	} catch (const std::exception &ex) {
		m_log(logging::ERROR) << logging::BrightRed << "getblocktemplate exception " << ex.what();
		throw;
	}
	BinaryArray block_blob = seria::to_binary(block_template);
	if (req.reserve_size > 0) {
		if (reserve_back_offset + blob_reserve.size() > block_blob.size()) {
			m_log(logging::ERROR) << "Failed to calculate offset for reserved bytes";
			throw json_rpc::Error{json_rpc::INTERNAL_ERROR, "Internal error: failed to create block template"};
		}
		res.reserved_offset = block_blob.size() - reserve_back_offset - blob_reserve.size();
		for (size_t i = 0; i != req.reserve_size; ++i) {
			invariant(block_blob.at(res.reserved_offset + i) == reserve_magic, "");
			block_blob.at(res.reserved_offset + i) = 0;
		}
	}
	res.blocktemplate_blob       = block_blob;
	res.top_block_hash           = m_block_chain.get_tip_bid();
	res.transaction_pool_version = m_block_chain.get_tx_pool_version();
	res.previous_block_hash      = m_block_chain.get_tip().previous_block_hash;
#if bytecoin_ALLOW_CM
	// Experimental, a bit hacky
	if (block_template.major_version >= m_block_chain.get_currency().amethyst_block_version) {
		try {
			block_template.major_version += 1;
			auto body_proxy = get_body_proxy_from_template(block_template);
			res.cm_prehash  = get_block_header_prehash(block_template, body_proxy);
			res.cm_path     = m_block_chain.get_genesis_bid();
		} catch (const std::exception &) {
		}
	}
#endif
}

bool Node::on_get_currency_id(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::GetCurrencyId::Request &&, api::cnd::GetCurrencyId::Response &res) {
	res.currency_id_blob = m_block_chain.get_genesis_bid();
	return true;
}

bool Node::on_submitblock_legacy(http::Client *who, http::RequestBody &&rd, json_rpc::Request &&jr,
    api::cnd::SubmitBlockLegacy::Request &&req, api::cnd::SubmitBlockLegacy::Response &res) {
	if (!m_config.good_bytecoind_auth_private(rd.r.basic_authorization))
		throw http::ErrorAuthorization("authorization-private");
	if (req.size() != 1)
		throw json_rpc::Error{json_rpc::INVALID_PARAMS, "Request params should be an array with exactly 1 element"};

	BinaryArray blocktemplate_blob;
	if (!common::from_hex(req[0], &blocktemplate_blob)) {
		throw json_rpc::Error{api::cnd::SubmitBlock::WRONG_BLOCKBLOB, "blocktemplate_blob should be in hex"};
	}
	api::BlockHeader info;
	submit_block(blocktemplate_blob, &info);
	return true;
}

bool Node::on_get_last_block_header(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::GetLastBlockHeaderLegacy::Request &&, api::cnd::GetLastBlockHeaderLegacy::Response &response) {
	static_cast<api::BlockHeader &>(response.block_header) = m_block_chain.get_tip();
	response.block_header.orphan_status                    = false;
	response.block_header.depth = api::HeightOrDepth(m_block_chain.get_tip_height() - response.block_header.height);
	return true;
}

bool Node::on_get_block_header_by_hash(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::GetBlockHeaderByHashLegacy::Request &&request, api::cnd::GetBlockHeaderByHashLegacy::Response &response) {
	if (!m_block_chain.get_header(request.hash, &response.block_header))
		throw api::ErrorHashNotFound("Block is neither in main nor in any side chain", request.hash);
	response.block_header.orphan_status =
	    !m_block_chain.in_chain(response.block_header.height, response.block_header.hash);
	response.block_header.depth = api::HeightOrDepth(m_block_chain.get_tip_height() - response.block_header.height);
	return true;
}

bool Node::on_get_block_header_by_height(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::GetBlockHeaderByHeightLegacy::Request &&request,
    api::cnd::GetBlockHeaderByHeightLegacy::Response &response) {
	Hash block_hash;
	// Freaking legacy, this call request counts blocks from 1, response counts from 0
	if (request.height == 0 || !m_block_chain.get_chain(request.height - 1, &block_hash)) {
		throw api::ErrorWrongHeight(
		    "Too big height. Note, this method request counts blocks from 1, not 0 as all other methods, height=",
		    request.height - 1, m_block_chain.get_tip_height());
	}
	invariant(m_block_chain.get_header(block_hash, &response.block_header), "");
	response.block_header.orphan_status = false;
	response.block_header.depth = api::HeightOrDepth(m_block_chain.get_tip_height() - response.block_header.height);
	return true;
}
