// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Node.hpp"
#include <boost/algorithm/string.hpp>
#include <iostream>
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionExtra.hpp"
#include "common/JsonValue.hpp"
#include "platform/PathTools.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"
#include "version.hpp"

using namespace bytecoin;

Node::Node(logging::ILogger &log, const Config &config, BlockChainState &block_chain)
    : m_block_chain(block_chain)
    , m_config(config)
    , m_block_chain_was_far_behind(true)
    , m_log(log, "Node")
    , m_peer_db(config)
    , m_p2p(log, config, m_peer_db, std::bind(&Node::client_factory, this, _1, _2))
    , m_commit_timer(std::bind(&Node::db_commit, this))
    , m_downloader(this, block_chain) {
	const std::string old_path = platform::get_default_data_directory(config.crypto_note_name);
	const std::string new_path = config.get_data_folder();

	if (!config.is_testnet) {
		m_block_chain_reader1 =
		    std::make_unique<LegacyBlockChainReader>(new_path + "/blockindexes.bin", new_path + "/blocks.bin");
		if (m_block_chain_reader1->get_block_count() <= block_chain.get_tip_height())
			m_block_chain_reader1.reset();
		if (new_path != old_path) {  // Current situation on Linux
			m_block_chain_reader2 =
			    std::make_unique<LegacyBlockChainReader>(old_path + "/blockindexes.bin", old_path + "/blocks.bin");
			if (m_block_chain_reader2->get_block_count() <= block_chain.get_tip_height())
				m_block_chain_reader2.reset();
		}
	}
	if (!config.bytecoind_bind_ip.empty() && config.bytecoind_bind_port != 0)
		m_api.reset(new http::Server(config.bytecoind_bind_ip, config.bytecoind_bind_port,
		    std::bind(&Node::on_api_http_request, this, _1, _2, _3), std::bind(&Node::on_api_http_disconnect, this, _1),
		    config.ssl_certificate_pem_file,
		    config.ssl_certificate_password ? config.ssl_certificate_password.get() : std::string()));

	m_commit_timer.once(DB_COMMIT_PERIOD_BYTECOIND);
	advance_long_poll();
}

bool Node::on_idle() {
	if (!m_block_chain_reader1 && !m_block_chain_reader2 &&
	    m_block_chain.get_tip_height() >= m_block_chain.internal_import_known_height())
		return m_downloader.on_idle();
	if (m_block_chain.get_tip_height() < m_block_chain.internal_import_known_height())
		m_block_chain.internal_import();
	else {
		if (m_block_chain_reader1 && !m_block_chain_reader1->import_blocks(m_block_chain)) {
			m_block_chain_reader1.reset();
		}
		if (m_block_chain_reader2 && !m_block_chain_reader2->import_blocks(m_block_chain)) {
			m_block_chain_reader2.reset();
		}
	}
	advance_long_poll();
	m_downloader.advance_download(Hash{});
	return true;
}

void Node::sync_transactions(P2PClientBytecoin *who) {
	NOTIFY_REQUEST_TX_POOL::request msg;
	auto mytxs = m_block_chain.get_memory_state_transactions();
	msg.txs.reserve(mytxs.size());
	for (auto &&tx : mytxs) {
		msg.txs.push_back(tx.first);
	}
	BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_REQUEST_TX_POOL::ID, LevinProtocol::encode(msg), false);
	who->send(std::move(raw_msg));
}

void Node::P2PClientBytecoin::on_msg_bytes(size_t, size_t) {  // downloaded. uploaded
	//    node->peers.on_peer_bytes(get_address(), downloaded, uploaded,
	//    node->p2p.get_local_time());
}

CORE_SYNC_DATA
Node::P2PClientBytecoin::get_sync_data() const {
	CORE_SYNC_DATA sync_data;
	sync_data.current_height = m_node->m_block_chain.get_tip_height();
	sync_data.top_id         = m_node->m_block_chain.get_tip_bid();
	return sync_data;
}

std::vector<PeerlistEntry> Node::P2PClientBytecoin::get_peers_to_share() const {
	auto result =
	    m_node->m_peer_db.get_peerlist_to_p2p(m_node->m_p2p.get_local_time(), config.p2p_default_peers_in_handshake);
	return result;
}

void Node::P2PClientBytecoin::on_first_message_after_handshake() {
	// if we set just seen on handshake, we will keep connecting to seed nodes
	// forever
	m_node->m_peer_db.set_peer_just_seen(
	    get_last_received_unique_number(), get_address(), m_node->m_p2p.get_local_time());
}

void Node::P2PClientBytecoin::on_msg_handshake(COMMAND_HANDSHAKE::request &&req) {
	NetworkAddress addr;
	addr.ip   = get_address().ip;
	addr.port = req.node_data.my_port;
	m_node->m_peer_db.add_incoming_peer(addr, req.node_data.peer_id, m_node->m_p2p.get_local_time());
	m_node->m_p2p.peers_updated();
	m_node->m_downloader.on_connect(this);
	m_node->advance_long_poll();
}

void Node::P2PClientBytecoin::on_msg_handshake(COMMAND_HANDSHAKE::response &&req) {
	m_node->m_peer_db.merge_peerlist_from_p2p(req.local_peerlist, m_node->m_p2p.get_local_time());
	m_node->m_p2p.peers_updated();
	m_node->m_downloader.on_connect(this);
	m_node->advance_long_poll();
}

void Node::P2PClientBytecoin::on_msg_notify_request_chain(NOTIFY_REQUEST_CHAIN::request &&req) {
	NOTIFY_RESPONSE_CHAIN_ENTRY::request msg;
	msg.m_block_ids = m_node->m_block_chain.get_sync_headers_chain(
	    req.block_ids, msg.start_height, config.p2p_block_ids_sync_default_count);
	msg.total_height = m_node->m_block_chain.get_tip_height() + 1;

	BinaryArray raw_msg =
	    LevinProtocol::send_message(NOTIFY_RESPONSE_CHAIN_ENTRY::ID, LevinProtocol::encode(msg), false);
	send(std::move(raw_msg));
}

void Node::P2PClientBytecoin::on_msg_notify_request_chain(NOTIFY_RESPONSE_CHAIN_ENTRY::request &&req) {
	m_node->m_downloader.on_msg_notify_request_chain(this, req);
}

void Node::P2PClientBytecoin::on_msg_notify_request_objects(NOTIFY_REQUEST_GET_OBJECTS::request &&req) {
	NOTIFY_RESPONSE_GET_OBJECTS::request msg;
	msg.current_blockchain_height = m_node->m_block_chain.get_tip_height() + 1;
	for (auto &&bh : req.blocks) {
		RawBlock raw_block;
		if (m_node->m_block_chain.read_block(bh, raw_block)) {
			msg.blocks.push_back(RawBlockLegacy{raw_block.block, raw_block.transactions});
		} else
			msg.missed_ids.push_back(bh);
	}
	if (!req.txs.empty()) {
		// TODO - remove after we are sure transactions are never asked
		throw std::runtime_error(
		    "Transactions asked in NOTIFY_REQUEST_GET_OBJECTS by " + common::ip_address_to_string(get_address().ip));
	}
	BinaryArray raw_msg =
	    LevinProtocol::send_message(NOTIFY_RESPONSE_GET_OBJECTS::ID, LevinProtocol::encode(msg), false);
	send(std::move(raw_msg));
}

void Node::P2PClientBytecoin::on_msg_notify_request_objects(NOTIFY_RESPONSE_GET_OBJECTS::request &&req) {
	m_node->m_downloader.on_msg_notify_request_objects(this, req);
}

void Node::P2PClientBytecoin::on_disconnect(const std::string &ban_reason) {
	m_node->m_downloader.on_disconnect(this);

	P2PClientBasic::on_disconnect(ban_reason);
	m_node->advance_long_poll();
}

void Node::P2PClientBytecoin::on_msg_notify_request_tx_pool(NOTIFY_REQUEST_TX_POOL::request &&req) {
	NOTIFY_NEW_TRANSACTIONS::request msg;
	auto mytxs = m_node->m_block_chain.get_memory_state_transactions();
	msg.txs.reserve(mytxs.size());
	std::sort(req.txs.begin(), req.txs.end());  // Should have been sorted on wire,
	                                            // checked here, but alas, legacy
	for (auto &&tx : mytxs) {
		auto it = std::lower_bound(req.txs.begin(), req.txs.end(), tx.first);
		if (it != req.txs.end() && *it == tx.first)
			continue;
		BinaryArray raw_tx = seria::to_binary(tx.second);
		msg.txs.push_back(std::move(raw_tx));
	}
	if (msg.txs.empty())
		return;
	BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_NEW_TRANSACTIONS::ID, LevinProtocol::encode(msg), false);
	send(std::move(raw_msg));
}

void Node::P2PClientBytecoin::on_msg_timed_sync(COMMAND_TIMED_SYNC::request &&req) {
	m_node->m_downloader.on_msg_timed_sync(req.payload_data);
}
void Node::P2PClientBytecoin::on_msg_timed_sync(COMMAND_TIMED_SYNC::response &&req) {
	m_node->m_downloader.on_msg_timed_sync(req.payload_data);
}

void Node::P2PClientBytecoin::on_msg_notify_new_block(NOTIFY_NEW_BLOCK::request &&req) {
	RawBlock raw_block{req.b.block, req.b.transactions};
	PreparedBlock pb(std::move(raw_block), nullptr);
	api::BlockHeader info;
	auto action = m_node->m_block_chain.add_block(pb, info);
	switch (action) {
	case BroadcastAction::BAN:
		disconnect("NOTIFY_NEW_BLOCK add_block BAN");
		return;
	case BroadcastAction::BROADCAST_ALL: {
		req.hop += 1;
		BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_NEW_BLOCK::ID, LevinProtocol::encode(req), false);
		m_node->m_p2p.broadcast(this, raw_msg);
		m_node->advance_long_poll();
		return;
	}
	case BroadcastAction::NOTHING:
		break;
	}
}

void Node::P2PClientBytecoin::on_msg_notify_new_transactions(NOTIFY_NEW_TRANSACTIONS::request &&req) {
	if (m_node->m_block_chain_reader1 || m_node->m_block_chain_reader2 ||
	    m_node->m_block_chain.get_tip_height() < m_node->m_block_chain.internal_import_known_height())
		return;  // We cannot check tx while downloading anyway
	NOTIFY_NEW_TRANSACTIONS::request msg;
	for (auto &&raw_tx : req.txs) {
		Transaction tx;
		try {
			seria::from_binary(tx, raw_tx);
		} catch (const std::exception &ex) {
			disconnect("NOTIFY_NEW_TRANSACTIONS add_transaction BAN from_binary failed " + std::string(ex.what()));
			return;
		}
		auto action = m_node->m_block_chain.add_transaction(tx, m_node->m_p2p.get_local_time());
		switch (action) {
		case BroadcastAction::BAN:
			disconnect("NOTIFY_NEW_TRANSACTIONS add_transaction BAN");
			return;
		case BroadcastAction::BROADCAST_ALL:
			msg.txs.push_back(raw_tx);
			break;
		case BroadcastAction::NOTHING:
			break;
		}
	}
	if (msg.txs.empty())
		return;
	BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_NEW_TRANSACTIONS::ID, LevinProtocol::encode(msg), false);
	m_node->m_p2p.broadcast(this, raw_msg);
	m_node->advance_long_poll();
}

#if bytecoin_ALLOW_DEBUG_COMMANDS
void Node::P2PClientBytecoin::on_msg_network_state(COMMAND_REQUEST_NETWORK_STATE::request &&req) {
	if (!m_node->check_trust(req.tr)) {
		disconnect(std::string());
		return;
	}
	COMMAND_REQUEST_NETWORK_STATE::response msg;
	msg.local_time = m_node->m_p2p.get_local_time();
	msg.my_id      = get_unique_number();
	for (auto &&cc : m_node->m_downloader.get_good_clients()) {
		connection_entry item;
		item.is_income = cc.first->is_incoming();
		item.id        = cc.first->get_unique_number();
		item.adr       = cc.first->get_address();
		msg.connections_list.push_back(item);
	}
	BinaryArray raw_msg = LevinProtocol::send_reply(COMMAND_REQUEST_NETWORK_STATE::ID, LevinProtocol::encode(msg), 0);
	send(std::move(raw_msg));
}

void Node::P2PClientBytecoin::on_msg_stat_info(COMMAND_REQUEST_STAT_INFO::request &&req) {
	if (!m_node->check_trust(req.tr)) {
		disconnect(std::string());
		return;
	}
	COMMAND_REQUEST_STAT_INFO::response msg;
	msg.incoming_connections_count = m_node->m_p2p.good_clients(true).size();
	msg.connections_count          = msg.incoming_connections_count + m_node->m_p2p.good_clients(false).size();
	msg.version                    = app_version();
	msg.os_version                 = platform::get_os_version_string();
	msg.payload_info               = CoreStatistics{};
	BinaryArray raw_msg = LevinProtocol::send_reply(COMMAND_REQUEST_STAT_INFO::ID, LevinProtocol::encode(msg), 0);
	send(std::move(raw_msg));
}

#endif

bool Node::check_trust(const proof_of_trust &tr) {
	uint64_t local_time  = time(nullptr);
	uint64_t time_delata = local_time > tr.time ? local_time - tr.time : tr.time - local_time;

	if (time_delata > 24 * 60 * 60)
		return false;
	if (m_last_stat_request_time >= tr.time)
		return false;
	if (m_p2p.get_unique_number() != tr.peer_id)
		return false;

	crypto::Hash h = tr.get_hash();
	if (!crypto::check_signature(h, m_config.trusted_public_key, tr.sign))
		return false;
	m_last_stat_request_time = tr.time;
	return true;
}

void Node::advance_long_poll() {
	const auto now = m_p2p.get_local_time();
	if (!prevent_sleep && m_block_chain.get_tip().timestamp < now - 86400)
		prevent_sleep = std::make_unique<platform::PreventSleep>("Downloading blockchain");
	if (prevent_sleep &&
	    m_block_chain.get_tip().timestamp > now - m_block_chain.get_currency().block_future_time_limit * 2)
		prevent_sleep = nullptr;
	if (m_long_poll_http_clients.empty())
		return;
	api::bytecoind::GetStatus::Response resp = create_status_response3();
	json_rpc::Response last_json_resp;
	last_json_resp.set_result(resp);

	for (auto lit = m_long_poll_http_clients.begin(); lit != m_long_poll_http_clients.end();) {
		const bool method_status = lit->original_json_request.get_method() == api::bytecoind::GetStatus::method() ||
		                           lit->original_json_request.get_method() == api::bytecoind::GetStatus::method2();
		if (method_status && lit->original_get_status == resp) {
			++lit;
			continue;
		}
		if (!method_status && lit->original_get_status.top_block_hash == resp.top_block_hash &&
		    lit->original_get_status.transaction_pool_version == resp.transaction_pool_version) {
			++lit;
			continue;
		}
		http::ResponseData last_http_response;
		last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
		last_http_response.r.status             = 200;
		last_http_response.r.http_version_major = lit->original_request.r.http_version_major;
		last_http_response.r.http_version_minor = lit->original_request.r.http_version_minor;
		last_http_response.r.keep_alive         = lit->original_request.r.keep_alive;
		if (method_status) {
			last_json_resp.set_id(lit->original_json_request.get_id());
			last_http_response.set_body(last_json_resp.get_body());
		} else {
			json_rpc::Response gbt_json_resp;
			try {
				api::bytecoind::GetBlockTemplate::Request gbt_req;
				lit->original_json_request.load_params(gbt_req);
				api::bytecoind::GetBlockTemplate::Response gbt_res;
				getblocktemplate(std::move(gbt_req), gbt_res);
				gbt_json_resp.set_result(gbt_res);
				gbt_json_resp.set_id(lit->original_json_request.get_id());
			} catch (const json_rpc::Error &err) {
				gbt_json_resp.set_error(err);
			} catch (const std::exception &e) {
				gbt_json_resp.set_error(json_rpc::Error(json_rpc::INTERNAL_ERROR, e.what()));
			}
			last_http_response.set_body(gbt_json_resp.get_body());
		}
		lit->original_who->write(std::move(last_http_response));
		lit = m_long_poll_http_clients.erase(lit);
	}
}

static const std::string beautiful_index_start =
    R"(<html><body><table valign="middle"><tr><td width="30px">
<svg xmlns="http://www.w3.org/2000/svg" width="30px" viewBox="0 0 215.99 215.99">
<circle fill="#f04086" cx="107.99" cy="107.99" r="107.99"></circle>
<path fill="#fff" d="M158.2 113.09q-6.37-7.05-18.36-8.75v-.17c7-1.13 12.5-4 16.24-8.59a25.09 25.09 0 0 0 5.82-16.23c0-9.86-3.18-16.56-9.75-21.83s-16.44-7-29.81-7h-50.5v47h-29v18H122c6.23 0 10.91.44 14 2.93s4.67 5.71 4.67 10.47-1.56 8.82-4.67 11.37-7.79 4.23-14 4.23H94.84v-14h-23v32H124c13.26 0 23.4-3.46 30.43-8.84s10.33-13.33 10.33-23.08a25.72 25.72 0 0 0-6.56-17.51zm-39.1-15.62H94.84v-29h24.26c12.47 0 18.7 4.87 18.7 14.5s-6.23 14.5-18.7 14.5z"></path>
</svg></td><td>bytecoind &bull; version
)";
static const std::string beautiful_index_finish = " </td></tr></table></body></html>";
static const std::string robots_txt             = "User-agent: *\r\nDisallow: /";

bool Node::on_api_http_request(http::Client *who, http::RequestData &&request, http::ResponseData &response) {
	response.r.add_headers_nocache();
	if (request.r.uri == "/" || request.r.uri == "/index.html") {
		response.r.headers.push_back({"Content-Type", "text/html; charset=UTF-8"});
		response.r.status = 200;
		auto stat         = create_status_response3();
		response.set_body(beautiful_index_start + app_version() + " &bull; sync status " +
		                  std::to_string(stat.top_block_height) + "/" + std::to_string(stat.top_known_block_height) +
		                  beautiful_index_finish);
		return true;
	}
	if (request.r.uri == "/robots.txt") {
		response.r.headers.push_back({"Content-Type", "text/plain; charset=UTF-8"});
		response.r.status = 200;
		response.set_body(std::string(robots_txt));
		return true;
	}
	auto it = m_http_handlers.find(request.r.uri);
	if (it == m_http_handlers.end()) {
		response.r.status = 404;
		return true;
	}
	if (!m_config.bytecoind_authorization.empty() &&
	    request.r.basic_authorization != m_config.bytecoind_authorization) {
		response.r.headers.push_back({"WWW-Authenticate", "Basic realm=\"Blockchain\", charset=\"UTF-8\""});
		response.r.status = 401;
		return true;
	}
	if (!it->second(this, who, std::move(request), response))
		return false;
	response.r.status = 200;
	return true;
}

void Node::on_api_http_disconnect(http::Client *who) {
	for (auto lit = m_long_poll_http_clients.begin(); lit != m_long_poll_http_clients.end();)
		if (lit->original_who == who)
			lit = m_long_poll_http_clients.erase(lit);
		else
			++lit;
}

namespace {

template<typename CommandRequest, typename CommandResponse>
Node::HTTPHandlerFunction bin_method(bool (Node::*handler)(http::Client *who, http::RequestData &&raw_request,
    json_rpc::Request &&raw_js_request, CommandRequest &&, CommandResponse &)) {
	return [handler](Node *obj, http::Client *who, http::RequestData &&request, http::ResponseData &response) {

		CommandRequest req{};
		CommandResponse res{};

		seria::from_binary(req, request.body);

		bool result = (obj->*handler)(who, std::move(request), json_rpc::Request(), std::move(req), res);
		if (result) {
			response.set_body(seria::to_binary_str(res));
			response.r.status = 200;
		}
		return result;
	};
}
}  // anonymous namespace

const std::unordered_map<std::string, Node::HTTPHandlerFunction> Node::m_http_handlers = {

    {api::bytecoind::SyncBlocks::bin_method(), bin_method(&Node::on_wallet_sync3)},
    {api::bytecoind::SyncMemPool::bin_method(), bin_method(&Node::on_sync_mempool3)},
    {"/json_rpc", std::bind(&Node::process_json_rpc_request, std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3, std::placeholders::_4)}};

const std::unordered_map<std::string, Node::JSONRPCHandlerFunction> Node::m_jsonrpc_handlers = {
    {api::bytecoind::GetLastBlockHeaderLegacy::method(), json_rpc::make_member_method(&Node::on_get_last_block_header)},
    {api::bytecoind::GetBlockHeaderByHashLegacy::method(),
        json_rpc::make_member_method(&Node::on_get_block_header_by_hash)},
    {api::bytecoind::GetBlockHeaderByHeightLegacy::method(),
        json_rpc::make_member_method(&Node::on_get_block_header_by_height)},
    {api::bytecoind::GetBlockTemplate::method(), json_rpc::make_member_method(&Node::on_getblocktemplate)},
    {api::bytecoind::GetBlockTemplate::method_legacy(), json_rpc::make_member_method(&Node::on_getblocktemplate)},
    {api::bytecoind::GetCurrencyId::method(), json_rpc::make_member_method(&Node::on_get_currency_id)},
    {api::bytecoind::GetCurrencyId::method_legacy(), json_rpc::make_member_method(&Node::on_get_currency_id)},
    {api::bytecoind::SubmitBlock::method(), json_rpc::make_member_method(&Node::on_submitblock)},
    {api::bytecoind::SubmitBlockLegacy::method(), json_rpc::make_member_method(&Node::on_submitblock_legacy)},
    {api::bytecoind::GetRandomOutputs::method(), json_rpc::make_member_method(&Node::on_get_random_outputs3)},
    {api::bytecoind::GetStatus::method(), json_rpc::make_member_method(&Node::on_get_status3)},
    {api::bytecoind::GetStatus::method2(), json_rpc::make_member_method(&Node::on_get_status3)},
    {api::bytecoind::SendTransaction::method(), json_rpc::make_member_method(&Node::handle_send_transaction3)},
    {api::bytecoind::CheckSendProof::method(), json_rpc::make_member_method(&Node::handle_check_send_proof3)},
    {api::bytecoind::SyncBlocks::method(), json_rpc::make_member_method(&Node::on_wallet_sync3)},
    {api::bytecoind::SyncMemPool::method(), json_rpc::make_member_method(&Node::on_sync_mempool3)}};

bool Node::on_get_random_outputs3(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::GetRandomOutputs::Request &&request, api::bytecoind::GetRandomOutputs::Response &response) {
	if (request.confirmed_height_or_depth < 0)
		request.confirmed_height_or_depth = std::max(
		    0, static_cast<api::HeightOrDepth>(m_block_chain.get_tip_height()) + 1 + request.confirmed_height_or_depth);
	api::BlockHeader tip_header = m_block_chain.get_tip();
	for (uint64_t amount : request.amounts) {
		auto random_outputs = m_block_chain.get_outputs_by_amount(
		    amount, request.outs_count, request.confirmed_height_or_depth, tip_header.timestamp);
		auto &outs = response.outputs[amount];
		outs.insert(outs.end(), random_outputs.begin(), random_outputs.end());
	}
	return true;
}

api::bytecoind::GetStatus::Response Node::create_status_response3() const {
	api::bytecoind::GetStatus::Response res;
	res.top_block_height = m_block_chain.get_tip_height();
	if (m_block_chain_reader1)
		res.top_block_height = std::max<Height>(res.top_block_height, m_block_chain_reader1->get_block_count());
	if (m_block_chain_reader2)
		res.top_block_height     = std::max<Height>(res.top_block_height, m_block_chain_reader2->get_block_count());
	res.top_block_height         = std::max<Height>(res.top_block_height, m_block_chain.internal_import_known_height());
	res.top_known_block_height   = m_downloader.get_known_block_count(res.top_block_height);
	res.incoming_peer_count      = static_cast<uint32_t>(m_p2p.good_clients(true).size());
	res.outgoing_peer_count      = static_cast<uint32_t>(m_p2p.good_clients(false).size());
	api::BlockHeader tip         = m_block_chain.get_tip();
	res.top_block_hash           = m_block_chain.get_tip_bid();
	res.top_block_timestamp      = tip.timestamp;
	res.top_block_difficulty     = tip.difficulty;
	res.recommended_fee_per_byte = m_block_chain.get_currency().coin() / 1000000;  // TODO - calculate
	res.next_block_effective_median_size = m_block_chain.get_next_effective_median_size();
	res.transaction_pool_version         = m_block_chain.get_tx_pool_version();
	return res;
}

bool Node::on_get_status3(http::Client *who, http::RequestData &&raw_request, json_rpc::Request &&raw_js_request,
    api::bytecoind::GetStatus::Request &&req, api::bytecoind::GetStatus::Response &res) {
	res = create_status_response3();
	if (req == res) {
		//		m_log(logging::INFO) << "on_get_status3 will long poll, json="
		//<<
		// raw_request.body << std::endl;
		LongPollClient lpc;
		lpc.original_who          = who;
		lpc.original_request      = raw_request;
		lpc.original_json_request = std::move(raw_js_request);
		lpc.original_get_status   = req;
		m_long_poll_http_clients.push_back(lpc);
		return false;
	}
	return true;
}

bool Node::on_wallet_sync3(http::Client *, http::RequestData &&, json_rpc::Request &&json_req,
    api::bytecoind::SyncBlocks::Request &&req, api::bytecoind::SyncBlocks::Response &res) {
	if (req.sparse_chain.empty()) {
		//        res.status = "Empty sparse chain";
		return true;
	}

	if (req.sparse_chain.back() != m_block_chain.get_genesis_bid()) {
		//        res.status = "Different currency";
		return true;
	}
	if (req.max_count > api::bytecoind::SyncBlocks::Request::MAX_COUNT) {
		//        res.status = "max_count too big";
		return true;
	}
	auto first_block_timestamp = req.first_block_timestamp < m_block_chain.get_currency().block_future_time_limit
	                                 ? 0
	                                 : req.first_block_timestamp - m_block_chain.get_currency().block_future_time_limit;
	Height full_offset = m_block_chain.get_timestamp_lower_bound_block_index(first_block_timestamp);
	Height start_block_index;
	std::vector<crypto::Hash> supplement =
	    m_block_chain.get_sync_headers_chain(req.sparse_chain, start_block_index, req.max_count);
	if (full_offset >= start_block_index + supplement.size()) {
		start_block_index = full_offset;
		supplement.clear();
		while (supplement.size() < req.max_count) {
			Hash ha;
			if (!m_block_chain.read_chain(start_block_index + static_cast<Height>(supplement.size()), ha))
				break;
			supplement.push_back(ha);
		}
	} else if (full_offset > start_block_index) {
		supplement.erase(supplement.begin(), supplement.begin() + (full_offset - start_block_index));
		start_block_index = full_offset;
	}

	res.start_height = start_block_index;
	res.blocks.resize(supplement.size());
	for (size_t i = 0; i != supplement.size(); ++i) {
		auto bhash = supplement[i];
		if (!m_block_chain.read_header(bhash, res.blocks[i].header))
			throw std::logic_error("Block header must be there, but it is not there");
		BlockChainState::BlockGlobalIndices global_indices;
		// if (res.blocks[i].header.timestamp >= req.first_block_timestamp) //
		// commented out becuase empty Block cannot be serialized
		{
			RawBlock rb;
			if (!m_block_chain.read_block(bhash, rb))
				throw std::logic_error("Block must be there, but it is not there");
			Block block;
			if (!block.from_raw_block(rb))
				throw std::logic_error("RawBlock failed to convert into block");
			res.blocks[i].base_transaction_hash = get_transaction_hash(block.header.base_transaction);
			res.blocks[i].bc_header             = std::move(block.header);
			res.blocks[i].bc_transactions.reserve(block.transactions.size());
			for (auto &&tx : block.transactions)
				res.blocks[i].bc_transactions.push_back(std::move(tx));
			if (!m_block_chain.read_block_output_global_indices(bhash, res.blocks[i].global_indices))
				throw std::logic_error(
				    "Invariant dead - bid is in chain but "
				    "blockchain has no block indices");
		}
	}
	res.status = create_status_response3();
	return true;
}

bool Node::on_sync_mempool3(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::SyncMemPool::Request &&req, api::bytecoind::SyncMemPool::Response &res) {
	const auto &pool = m_block_chain.get_memory_state_transactions();
	for (auto &&ex : req.known_hashes)
		if (pool.count(ex) == 0)
			res.removed_hashes.push_back(ex);
	for (auto &&tx : pool)
		if (!std::binary_search(req.known_hashes.begin(), req.known_hashes.end(), tx.first)) {
			res.added_binary_transactions.push_back(seria::to_binary(tx.second));
			res.added_transactions.push_back(api::Transaction{});
			res.added_transactions.back().hash      = tx.first;
			res.added_transactions.back().timestamp = m_block_chain.read_first_seen_timestamp(tx.first);
		}
	res.status = create_status_response3();
	return true;
}

bool Node::handle_send_transaction3(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::SendTransaction::Request &&request, api::bytecoind::SendTransaction::Response &response) {
	NOTIFY_NEW_TRANSACTIONS::request msg;
	Transaction tx;
	seria::from_binary(tx, request.binary_transaction);
	if (m_block_chain.add_transaction(tx, m_p2p.get_local_time()) != BroadcastAction::BROADCAST_ALL) {
		response.send_result = "Failed to be broadcasted";  // TODO - process error
		return true;
	}
	msg.txs.push_back(request.binary_transaction);
	BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_NEW_TRANSACTIONS::ID, LevinProtocol::encode(msg), false);
	m_p2p.broadcast(nullptr, raw_msg);
	response.send_result = "broadcast";  // Success
	advance_long_poll();
	return true;
}

bool Node::handle_check_send_proof3(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::CheckSendProof::Request &&request, api::bytecoind::CheckSendProof::Response &response) {
	Transaction tx;
	SendProof sp;
	try {
		seria::from_json_value(sp, common::JsonValue::from_string(request.send_proof));
	} catch (const std::exception &ex) {
		response.validation_error = "Failed to parse proof object ex.what=" + std::string(ex.what());
		return true;
	}
	Height height         = 0;
	size_t index_in_block = 0;
	if (!m_block_chain.read_transaction(sp.transaction_hash, tx, height, index_in_block)) {
		response.validation_error = "transaction is not in main chain";
		return true;
	}
	PublicKey tx_public_key = get_transaction_public_key_from_extra(tx.extra);
	Hash message_hash       = crypto::cn_fast_hash(sp.message.data(), sp.message.size());
	if (!crypto::check_send_proof(
	        tx_public_key, sp.address.view_public_key, sp.derivation, message_hash, sp.signature)) {
		response.validation_error = "proof object does not match transaction, address or message";
		return true;
	}
	Amount total_amount = 0;
	size_t key_index    = 0;
	uint32_t out_index  = 0;
	for (const auto &output : tx.outputs) {
		if (output.target.type() == typeid(KeyOutput)) {
			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			PublicKey spend_key;
			if (underive_public_key(sp.derivation, key_index, key_output.key, spend_key) &&
			    spend_key == sp.address.spend_public_key) {
				total_amount += output.amount;
			}
			++key_index;
		}
		++out_index;
	}
	if (total_amount == 0)
		response.validation_error = "no outputs found in transaction for the address being proofed";
	else if (total_amount != sp.amount)
		response.validation_error = "wrong amount in outputs, actual amount is " + std::to_string(total_amount);
	// here proof is checked, validation_error is empty
	return true;
}

/*static void parse_raw_transaction(api::Transaction & ptx, const Currency &
currency, const Transaction & tx, const std::vector<uint32_t> &global_indices,
Hash tid, Height block_height, Timestamp block_unlock_timestamp){
        PublicKey tx_public_key = get_transaction_public_key_from_extra(tx.extra);
        KeyPair tx_keys;
        ptx.hash         = tid;
        ptx.block_height = block_height;
        ptx.anonymity    = std::numeric_limits<uint32_t>::max();
        ptx.unlock_time  = tx.unlock_time;
        const bool tx_unlocked =
currency.is_transaction_spend_time_unlocked(ptx.unlock_time, block_height,
block_unlock_timestamp);
        ptx.public_key   = tx_public_key;
        ptx.extra        = tx.extra;
        get_payment_id_from_tx_extra(tx.extra, ptx.payment_id);
        size_t key_index     = 0;
        uint32_t out_index   = 0;
        Amount output_amount = 0;
        // We combine outputs into transfers by address
        for (const auto &output : tx.outputs) {
                const auto global_index = global_indices.at(out_index);
                output_amount += output.amount;
                ptx.fee -= output.amount;
                if (output.target.type() == typeid(KeyOutput)) {
                        const KeyOutput &key_output =
boost::get<KeyOutput>(output.target);
                        api::Output out;
                        out.amount      = output.amount;
                        out.dust      = Currency::is_dust(output.amount);
                        out.global_index = global_index;
                        out.height      = block_height;
                        out.index_in_tx   = out_index;
                        out.public_key         = key_output.key;
                        out.transaction_public_key       = tx_public_key;
                        out.unlock_time = tx.unlock_time;
                        api::Transfer transfer;
                        transfer.amount  = output.amount;
                        transfer.locked = !tx_unlocked;
                        transfer.outputs.push_back(out);
                        ptx.transfers.push_back(std::move(transfer));
                        ++key_index;
                }
                ++out_index;
        }
        Amount input_amount  = 0;
        for (const auto &input : tx.inputs) {
                if (input.type() == typeid(CoinbaseInput)) {
                        api::Transfer transfer;
                        transfer.amount =
-static_cast<SignedAmount>(output_amount);
                        ptx.transfers.push_back(std::move(transfer));
                } else if (input.type() == typeid(KeyInput)) {
                        const KeyInput &in = boost::get<KeyInput>(input);
                        input_amount += in.amount;
                        ptx.fee += in.amount;
                        ptx.anonymity = std::min(ptx.anonymity,
static_cast<uint32_t>(in.output_indexes.size()));
                        api::Output out;
                        out.key_image = in.key_image;
                        api::Transfer transfer;
                        transfer.amount -= in.amount;
                        transfer.outputs.push_back(out);
                        ptx.transfers.push_back(std::move(transfer));
                }
        }
        ptx.amount = std::max(input_amount, output_amount);
        if (ptx.anonymity == std::numeric_limits<uint32_t>::max())
                ptx.anonymity = 0;  // No key inputs
}
*/
