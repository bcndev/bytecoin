// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <iostream>
#include "Core/Config.hpp"
#include "CryptoNoteTools.hpp"
#include "Node.hpp"
#include "TransactionExtra.hpp"
#include "common/JsonValue.hpp"
#include "common/exception.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

// TODO - move to appropriate place

#define CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT -2

using namespace bytecoin;

bool Node::on_json_rpc(http::Client *who, http::RequestData &&request, http::ResponseData &response) {
	response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});

	common::JsonValue jid(nullptr);

	try {
		json_rpc::Request json_req(request.body);
		jid = json_req.get_id().get();

		auto it = m_jsonrpc_handlers.find(json_req.get_method());
		if (it == m_jsonrpc_handlers.end()) {
			m_log(logging::INFO) << "jsonrpc request method not found - " << json_req.get_method() << std::endl;
			throw json_rpc::Error(json_rpc::METHOD_NOT_FOUND, "Method not found " + json_req.get_method());
		}
		//		m_log(logging::INFO) << "jsonrpc request method=" <<
		// json_req.get_method() << std::endl;
		std::string response_body;
		if (!it->second(this, who, std::move(request), std::move(json_req), response_body))
			return false;
		response.set_body(std::move(response_body));
		//	} catch (const api::bytecoind::SendTransaction::Error &err) {
		//		response.set_body(json_rpc::create_error_response_body(err, jid));
		//	} catch (const api::bytecoind::GetArchive::Error &err) {
		//		response.set_body(json_rpc::create_error_response_body(err, jid));
	} catch (const json_rpc::Error &err) {
		response.set_body(json_rpc::create_error_response_body(err, jid));
	} catch (const std::exception &e) {
		json_rpc::Error json_err(json_rpc::INTERNAL_ERROR, common::what(e));
		response.set_body(json_rpc::create_error_response_body(json_err, jid));
	}
	response.r.status = 200;
	return true;
}

bool Node::on_binary_rpc(http::Client *who, http::RequestData &&request, http::ResponseData &response) {
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
			m_log(logging::INFO) << "binaryrpc request method not found - " << binary_req.get_method() << std::endl;
			throw json_rpc::Error(json_rpc::METHOD_NOT_FOUND, "Method not found " + binary_req.get_method());
		}
		//		m_log(logging::INFO) << "jsonrpc request method=" <<
		// json_req.get_method() << std::endl;
		std::string response_body;
		if (!it->second(this, who, body_stream, std::move(binary_req), response_body))
			return false;
		response.set_body(std::move(response_body));
		//	} catch (const api::bytecoind::SendTransaction::Error &err) {
		//		response.set_body(json_rpc::create_binary_response_error_body(err, jid));
		//	} catch (const api::bytecoind::GetArchive::Error &err) {
		//		response.set_body(json_rpc::create_binary_response_error_body(err, jid));
	} catch (const json_rpc::Error &err) {
		response.set_body(json_rpc::create_binary_response_error_body(err, jid));
	} catch (const std::exception &e) {
		json_rpc::Error json_err(json_rpc::INTERNAL_ERROR, common::what(e));
		response.set_body(json_rpc::create_binary_response_error_body(json_err, jid));
	}
	response.r.status = 200;
	return true;
}
namespace {
// Seeking blob in blob. TODO - check that it works the same as common::slow_memmem
size_t slow_memmem(void *start_buff, size_t buflen, void *pat, size_t patlen) {
	void *buf = start_buff;
	void *end = (char *)buf + buflen - patlen;
	while ((buf = memchr(buf, ((char *)pat)[0], buflen))) {
		if (buf > end)
			return 0;
		if (memcmp(buf, pat, patlen) == 0)
			return (char *)buf - (char *)start_buff;
		buf = (char *)buf + 1;
	}
	return 0;
}
}  // anonymous namespace

bool Node::on_getblocktemplate(http::Client *who, http::RequestData &&raw_request, json_rpc::Request &&raw_js_request,
    api::bytecoind::GetBlockTemplate::Request &&req, api::bytecoind::GetBlockTemplate::Response &res) {
	api::bytecoind::GetStatus::Request sta;
	sta.top_block_hash           = req.top_block_hash;
	sta.transaction_pool_version = req.transaction_pool_version;
	m_log(logging::INFO) << "Node received getblocktemplate REQ transaction_pool_version="
	                     << (req.transaction_pool_version ? common::to_string(req.transaction_pool_version.get())
	                                                      : "empty")
	                     << " top_block_hash="
	                     << (req.top_block_hash ? common::pod_to_hex(req.top_block_hash.get()) : "empty") << std::endl;
	m_log(logging::INFO) << "Node received getblocktemplate CUR transaction_pool_version="
	                     << m_block_chain.get_tx_pool_version() << " top_block_hash=" << m_block_chain.get_tip_bid()
	                     << std::endl;
	if ((!sta.top_block_hash || sta.top_block_hash.get() == m_block_chain.get_tip_bid()) &&
	    (!sta.transaction_pool_version || sta.transaction_pool_version.get() == m_block_chain.get_tx_pool_version()) &&
	    (sta.top_block_hash || sta.transaction_pool_version)) {
		//		m_log(logging::INFO) << "on_getblocktemplate will long poll,
		// json="
		//<<
		// raw_request.body << std::endl;
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

void Node::getblocktemplate(const api::bytecoind::GetBlockTemplate::Request &req,
    api::bytecoind::GetBlockTemplate::Response &res) {
	if (req.reserve_size > TransactionExtraNonce::MAX_COUNT)
		throw json_rpc::Error{api::bytecoind::GetBlockTemplate::TOO_BIG_RESERVE_SIZE,
		    "To big reserved size, maximum " + common::to_string(TransactionExtraNonce::MAX_COUNT)};
	AccountPublicAddress acc{};
	if (!m_block_chain.get_currency().parse_account_address_string(req.wallet_address, &acc))
		throw api::ErrorAddress(
		    api::ErrorAddress::ADDRESS_FAILED_TO_PARSE, "Failed to parse wallet address", req.wallet_address);

	BlockTemplate block_template{};
	BinaryArray blob_reserve;
	blob_reserve.resize(req.reserve_size, 0);

	if (!m_block_chain.create_mining_block_template(acc, blob_reserve, &block_template, &res.difficulty, &res.height)) {
		m_log(logging::ERROR) << "Failed to create block template";
		throw json_rpc::Error{json_rpc::INTERNAL_ERROR, "Internal error: failed to create block template"};
	}

	BinaryArray block_blob = seria::to_binary(block_template);
	PublicKey tx_pub_key   = extra_get_transaction_public_key(block_template.base_transaction.extra);
	if (tx_pub_key == PublicKey{}) {
		m_log(logging::ERROR) << "Failed to find tx pub key in coinbase extra";
		throw json_rpc::Error{json_rpc::INTERNAL_ERROR, "Internal error: failed to find tx pub key in coinbase extra"};
	}

	if (0 < req.reserve_size) {
		res.reserved_offset =
		    static_cast<uint32_t>(slow_memmem(block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key)));
		if (!res.reserved_offset) {
			m_log(logging::ERROR) << "Failed to find tx pub key in blockblob";
			throw json_rpc::Error{json_rpc::INTERNAL_ERROR, "Internal error: failed to create block template"};
		}
		res.reserved_offset += sizeof(tx_pub_key) + 3;  // 3 bytes: tag for TX_EXTRA_TAG_PUBKEY(1 byte), tag for
		// TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
		if (res.reserved_offset + req.reserve_size > block_blob.size()) {
			m_log(logging::ERROR) << "Failed to calculate offset for reserved bytes";
			throw json_rpc::Error{json_rpc::INTERNAL_ERROR, "Internal error: failed to create block template"};
		}
	} else {
		res.reserved_offset = 0;
	}

	res.blocktemplate_blob       = block_blob;
	res.top_block_hash           = m_block_chain.get_tip_bid();
	res.transaction_pool_version = m_block_chain.get_tx_pool_version();
	res.previous_block_hash      = m_block_chain.get_tip().previous_block_hash;
}

bool Node::on_get_currency_id(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::GetCurrencyId::Request && /*req*/, api::bytecoind::GetCurrencyId::Response &res) {
	res.currency_id_blob = m_block_chain.get_genesis_bid();
	return true;
}

bool Node::on_submitblock_legacy(http::Client *who, http::RequestData &&rd, json_rpc::Request &&jr,
    api::bytecoind::SubmitBlockLegacy::Request &&req, api::bytecoind::SubmitBlockLegacy::Response &res) {
	if (req.size() != 1)
		throw json_rpc::Error{json_rpc::INVALID_PARAMS, "Request params should be an array with exactly 1 element"};

	BinaryArray blocktemplate_blob;
	if (!common::from_hex(req[0], blocktemplate_blob)) {
		throw json_rpc::Error{api::bytecoind::SubmitBlock::WRONG_BLOCKBLOB, "blocktemplate_blob should be in hex"};
	}
	api::BlockHeader info;
	submit_block(blocktemplate_blob, &info);
	return true;
}

bool Node::on_get_last_block_header(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::GetLastBlockHeaderLegacy::Request &&,
    api::bytecoind::GetLastBlockHeaderLegacy::Response &response) {
	static_cast<api::BlockHeader &>(response.block_header) = m_block_chain.get_tip();
	m_block_chain.fix_block_sizes(&response.block_header);
	response.block_header.orphan_status = false;
	response.block_header.depth = api::HeightOrDepth(m_block_chain.get_tip_height() - response.block_header.height);
	return true;
}

bool Node::on_get_block_header_by_hash(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::GetBlockHeaderByHashLegacy::Request &&request,
    api::bytecoind::GetBlockHeaderByHashLegacy::Response &response) {
	if (!m_block_chain.read_header(request.hash, &response.block_header))
		throw api::ErrorHashNotFound("Block is neither in main nor in any side chain", request.hash);
	m_block_chain.fix_block_sizes(&response.block_header);
	response.block_header.orphan_status =
	    !m_block_chain.in_chain(response.block_header.height, response.block_header.hash);
	response.block_header.depth = api::HeightOrDepth(m_block_chain.get_tip_height() - response.block_header.height);
	return true;
}

bool Node::on_get_block_header_by_height(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::GetBlockHeaderByHeightLegacy::Request &&request,
    api::bytecoind::GetBlockHeaderByHeightLegacy::Response &response) {
	Hash block_hash;
	// Freaking legacy, this call request counts blocks from 1, response counts from 0
	if (request.height == 0 || !m_block_chain.read_chain(request.height - 1, &block_hash)) {
		throw api::ErrorWrongHeight(
		    "Too big height. Note, this method request counts blocks from 1, not 0 as all other methods",
		    request.height - 1, m_block_chain.get_tip_height());
	}
	invariant(m_block_chain.read_header(block_hash, &response.block_header), "");
	m_block_chain.fix_block_sizes(&response.block_header);
	response.block_header.orphan_status = false;
	response.block_header.depth = api::HeightOrDepth(m_block_chain.get_tip_height() - response.block_header.height);
	return true;
}
