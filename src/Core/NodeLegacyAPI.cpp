// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include <iostream>
#include "Core/Config.hpp"
#include "CryptoNoteTools.hpp"
#include "Node.hpp"
#include "TransactionExtra.hpp"
#include "common/JsonValue.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

// TODO - move to appropriate place
#define CORE_RPC_STATUS_OK "OK"

#define CORE_RPC_ERROR_CODE_WRONG_PARAM -1
#define CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT -2
#define CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE -3
#define CORE_RPC_ERROR_CODE_WRONG_WALLET_ADDRESS -4
#define CORE_RPC_ERROR_CODE_INTERNAL_ERROR -5
#define CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB -6
#define CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED -7

using namespace bytecoin;

bool Node::process_json_rpc_request(http::Client *who, http::RequestData &&request, http::ResponseData &response) {
	response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});

	json_rpc::Response json_resp;

	try {
		json_rpc::Request json_req(request.body);
		json_resp.set_id(json_req.get_id());  // copy id

		auto it = m_jsonrpc_handlers.find(json_req.get_method());
		if (it == m_jsonrpc_handlers.end()) {
			m_log(logging::INFO) << "jsonrpc request method not found - " << json_req.get_method() << std::endl;
			throw json_rpc::Error(json_rpc::errMethodNotFound);
		}
		//		m_log(logging::INFO) << "jsonrpc request method=" <<
		// json_req.get_method() << std::endl;

		if (!it->second(this, who, std::move(request), std::move(json_req), json_resp))
			return false;

	} catch (const json_rpc::Error &err) {
		json_resp.set_error(err);
	} catch (const std::exception &e) {
		json_resp.set_error(json_rpc::Error(json_rpc::errInternalError, e.what()));
	}

	response.set_body(json_resp.get_body());
	response.r.status = 200;
	return true;
}

namespace {
// Seeking blob in blob
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
	                     << req.transaction_pool_version << " top_block_hash=" << common::pod_to_hex(req.top_block_hash)
	                     << std::endl;
	m_log(logging::INFO) << "Node received getblocktemplate CUR transaction_pool_version="
	                     << m_block_chain.get_tx_pool_version()
	                     << " top_block_hash=" << common::pod_to_hex(m_block_chain.get_tip_bid()) << std::endl;
	if (sta.top_block_hash == m_block_chain.get_tip_bid() &&
	    sta.transaction_pool_version == m_block_chain.get_tx_pool_version()) {
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
	if (req.reserve_size > TX_EXTRA_NONCE_MAX_COUNT) {
		throw json_rpc::Error{CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE, "To big reserved size, maximum 255"};
	}

	AccountPublicAddress acc{};

	if (req.wallet_address.empty() ||
	    !m_block_chain.get_currency().parse_account_address_string(req.wallet_address, acc)) {
		throw json_rpc::Error{CORE_RPC_ERROR_CODE_WRONG_WALLET_ADDRESS, "Failed to parse wallet address"};
	}

	BlockTemplate block_template{};
	BinaryArray blob_reserve;
	blob_reserve.resize(req.reserve_size, 0);

	if (!m_block_chain.create_mining_block_template(block_template, acc, blob_reserve, res.difficulty, res.height)) {
		m_log(logging::ERROR) << "Failed to create block template";
		throw json_rpc::Error{CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template"};
	}

	BinaryArray block_blob = seria::to_binary(block_template);
	//	BinaryArray block_blob = toBinaryArray(block_template);
	PublicKey tx_pub_key = get_transaction_public_key_from_extra(block_template.base_transaction.extra);
	if (tx_pub_key == PublicKey{}) {
		m_log(logging::ERROR) << "Failed to find tx pub key in coinbase extra";
		throw json_rpc::Error{
		    CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to find tx pub key in coinbase extra"};
	}

	if (0 < req.reserve_size) {
		res.reserved_offset =
		    static_cast<uint32_t>(slow_memmem(block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key)));
		if (!res.reserved_offset) {
			m_log(logging::ERROR) << "Failed to find tx pub key in blockblob";
			throw json_rpc::Error{
			    CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template"};
		}
		res.reserved_offset += sizeof(tx_pub_key) + 3;  // 3 bytes: tag for TX_EXTRA_TAG_PUBKEY(1 byte), tag for
		// TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
		if (res.reserved_offset + req.reserve_size > block_blob.size()) {
			m_log(logging::ERROR) << "Failed to calculate offset for reserved bytes";
			throw json_rpc::Error{
			    CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template"};
		}
	} else {
		res.reserved_offset = 0;
	}

	res.blocktemplate_blob       = block_blob;
	res.top_block_hash           = m_block_chain.get_tip_bid();
	res.transaction_pool_version = m_block_chain.get_tx_pool_version();
	res.status                   = CORE_RPC_STATUS_OK;
}

bool Node::on_get_currency_id(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::GetCurrencyId::Request && /*req*/, api::bytecoind::GetCurrencyId::Response &res) {
	res.currency_id_blob = m_block_chain.get_genesis_bid();
	return true;
}

bool Node::on_submitblock(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::SubmitBlock::Request &&req, api::bytecoind::SubmitBlock::Response &res) {
	BinaryArray blockblob = req.blocktemplate_blob;

	BlockTemplate block_template;
	//	bool result = fromBinaryArray(block_template, blockblob);
	//	if (!result) {
	// logger(Logging::WARNING) << "Couldn't deserialize block template";
	//		throw json_rpc::Error{CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB,
	//"Wrong
	// block blob 2"};
	//	}
	seria::from_binary(block_template, blockblob);
	RawBlock raw_block;
	api::BlockHeader info;
	auto broad = m_block_chain.add_mined_block(blockblob, raw_block, info);
	if (broad == BroadcastAction::BAN)
		throw json_rpc::Error{CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED, "Block not accepted"};
	NOTIFY_NEW_BLOCK::request msg;
	msg.b                         = RawBlockLegacy{raw_block.block, raw_block.transactions};
	msg.hop                       = 1;
	msg.current_blockchain_height = m_block_chain.get_tip_height() + 1;  // TODO check
	BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_NEW_BLOCK::ID, LevinProtocol::encode(msg), false);
	m_p2p.broadcast(nullptr, raw_msg);
	advance_long_poll();
	res.status = CORE_RPC_STATUS_OK;
	return true;
}

bool Node::on_submitblock_legacy(http::Client *who, http::RequestData &&rd, json_rpc::Request &&jr,
    api::bytecoind::SubmitBlockLegacy::Request &&req, api::bytecoind::SubmitBlockLegacy::Response &res) {
	if (req.size() != 1) {
		throw json_rpc::Error{CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong param"};
	}

	api::bytecoind::SubmitBlock::Request other_req;
	if (!common::from_hex(req[0], other_req.blocktemplate_blob)) {
		throw json_rpc::Error{CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB, "Wrong block blob 1"};
	}
	return on_submitblock(who, std::move(rd), std::move(jr), std::move(other_req), res);
}
