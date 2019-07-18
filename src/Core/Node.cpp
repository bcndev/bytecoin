// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Node.hpp"
#include <boost/algorithm/string/replace.hpp>
#include <iostream>
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "TransactionExtra.hpp"
#include "common/Base58.hpp"
#include "common/JsonValue.hpp"
#include "common/StringTools.hpp"
#include "http/Server.hpp"
#include "p2p/PeerDB.hpp"
#include "platform/PathTools.hpp"
#include "platform/PreventSleep.hpp"
#include "platform/Time.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"
#include "version.hpp"

using namespace cn;

Node::Node(logging::ILogger &log, const Config &config, BlockChainState &block_chain)
    : m_block_chain(block_chain)
    , m_config(config)
    , m_log(log, "Node")
    , m_peer_db(std::make_unique<PeerDB>(log, config, "peer_db"))
    , m_p2p(log, config, *m_peer_db, std::bind(&Node::client_factory, this, _1))
    , multicast(config.multicast_address, config.multicast_port, std::bind(&Node::on_multicast, this, _1, _2, _3))
    , m_multicast_timer(std::bind(&Node::send_multicast, this))
    , m_start_time(m_p2p.get_local_time())
    , m_commit_timer(std::bind(&Node::db_commit, this))
    , log_request_timestamp(std::chrono::steady_clock::now())
    , log_response_timestamp(std::chrono::steady_clock::now())
    , m_pow_checker(block_chain.get_currency(), platform::EventLoop::current()) {
	if (config.bytecoind_bind_port != 0) {
		m_api = std::make_unique<http::Server>(config.bytecoind_bind_ip, config.bytecoind_bind_port,
		    std::bind(&Node::on_api_http_request, this, _1, _2, _3),
		    std::bind(&Node::on_api_http_disconnect, this, _1));
		common::console::set_text_color(common::console::BrightGreen);
		m_log(logging::INFO) << "Node RPC listening on " << config.bytecoind_bind_ip << ":"
		                     << config.bytecoind_bind_port;
		common::console::set_text_color(common::console::Default);
	}
	m_commit_timer.once(float(m_config.db_commit_period_blockchain));
	advance_long_poll();
	send_multicast();
}

Node::~Node() {}  // we have unique_ptr to incomplete type

void Node::send_multicast() {
	if (!m_config.use_multicast())
		return;
	//	std::cout << "sending multicast about node listening on port=" << m_config.p2p_external_port << std::endl;
	BinaryArray ha = P2PProtocolBasic::create_multicast_announce(
	    m_config.network_id, m_block_chain.get_currency().genesis_block_hash, m_config.p2p_external_port);
	platform::UDPMulticast::send(m_config.multicast_address, m_config.multicast_port, ha.data(), ha.size());
	m_multicast_timer.once(m_config.multicast_period);
}

void Node::on_multicast(const std::string &addr, const unsigned char *data, size_t size) {
	if (!m_config.use_multicast())
		return;
	NetworkAddress na;
	na.port = P2PProtocolBasic::parse_multicast_announce(
	    data, size, m_config.network_id, m_block_chain.get_currency().genesis_block_hash);
	if (!na.port)
		return;
	if (common::parse_ip_address(addr, &na.ip)) {
		if (m_peer_db->add_incoming_peer(na, m_p2p.get_local_time()))
			m_log(logging::INFO) << "Adding peer from multicast announce addr=" << na;
	}
	// We do not receive multicast from loopback, so we just guess peer could be from localhost
	if (common::parse_ip_address("127.0.0.1", &na.ip)) {
		if (m_peer_db->add_incoming_peer(na, m_p2p.get_local_time()))
			m_log(logging::INFO) << "Adding local peer from multicast announce addr=" << na;
	}
	m_p2p.peers_updated();
}

void Node::db_commit() {
	m_block_chain.db_commit();
	m_commit_timer.once(float(m_config.db_commit_period_blockchain));
}

void Node::remove_chain_block(std::map<Hash, DownloadInfo>::iterator it) {
	invariant(it->second.chain_counter > 0, "");
	it->second.chain_counter -= 1;
	if (it->second.chain_counter == 0 && !it->second.preparing)
		chain_blocks.erase(it);
}

void Node::advance_all_downloads() {
	for (auto &&who : m_broadcast_protocols)
		who->advance_blocks();
}

bool Node::on_idle() {
	auto idle_start     = std::chrono::steady_clock::now();
	Hash was_top_bid    = m_block_chain.get_tip_bid();
	bool on_idle_result = false;
	if (m_block_chain.get_tip_height() >= m_block_chain.internal_import_known_height()) {
		for (size_t s = 0; s != 10; ++s) {
			bool on_idle_result_s = false;
			std::vector<P2PProtocolBytecoin *> bp_copy{m_broadcast_protocols.begin(), m_broadcast_protocols.end()};
			// We need bp_copy because on_idle can disconnect, modifying m_broadcast_protocols
			for (auto &&who : bp_copy)
				on_idle_result_s = who->on_idle(idle_start) | on_idle_result_s;
			if (!on_idle_result_s)
				break;
			on_idle_result = true;
		}
	}
	if (m_block_chain.get_tip_height() < m_block_chain.internal_import_known_height())
		m_block_chain.internal_import();
	if (m_block_chain.get_tip_bid() != was_top_bid) {
		advance_long_poll();
	}
	advance_all_downloads();
	return on_idle_result;
}

bool Node::check_trust(const p2p::ProofOfTrust &tr) {
	Timestamp local_time = platform::now_unix_timestamp();
	Timestamp time_delta = local_time > tr.time ? local_time - tr.time : tr.time - local_time;

	if (time_delta > 24 * 60 * 60)
		return false;
	if (m_last_stat_request_time >= tr.time)
		return false;
	if (m_p2p.get_unique_number() != tr.peer_id)
		return false;

	Hash h = tr.get_hash();
	if (!crypto::check_signature(h, m_config.trusted_public_key, tr.sign))
		return false;
	m_last_stat_request_time = tr.time;
	return true;
}

void Node::advance_long_poll() {
	const auto now = m_p2p.get_local_time();
	if (!m_prevent_sleep && m_block_chain.get_tip().timestamp < now - 86400)
		m_prevent_sleep = std::make_unique<platform::PreventSleep>("Downloading blockchain");
	if (m_prevent_sleep &&
	    m_block_chain.get_tip().timestamp > now - m_block_chain.get_currency().block_future_time_limit * 2)
		m_prevent_sleep = nullptr;
	if (m_long_poll_http_clients.empty())
		return;
	const api::cnd::GetStatus::Response resp = create_status_response();

	for (auto lit = m_long_poll_http_clients.begin(); lit != m_long_poll_http_clients.end();) {
		const bool method_status = lit->original_json_request.get_method() == api::cnd::GetStatus::method() ||
		                           lit->original_json_request.get_method() == api::cnd::GetStatus::method2();
		if (!resp.ready_for_longpoll(lit->original_get_status)) {
			++lit;
			continue;
		}
		LongPollClient cli = std::move(*lit);
		lit                = m_long_poll_http_clients.erase(lit);

		http::ResponseBody last_http_response;
		last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
		last_http_response.r.status             = 200;
		last_http_response.r.http_version_major = cli.original_request.r.http_version_major;
		last_http_response.r.http_version_minor = cli.original_request.r.http_version_minor;
		last_http_response.r.keep_alive         = cli.original_request.r.keep_alive;
		fill_cors(cli.original_request, last_http_response);
		if (method_status) {
			last_http_response.set_body(json_rpc::create_response_body(resp, cli.original_json_request));
		} else {
			try {
				api::cnd::GetBlockTemplate::Request gbt_req;
				cli.original_json_request.load_params(gbt_req);
				api::cnd::GetBlockTemplate::Response gbt_res;
				getblocktemplate(gbt_req, gbt_res);
				last_http_response.set_body(json_rpc::create_response_body(gbt_res, cli.original_json_request));
			} catch (const json_rpc::Error &err) {
				last_http_response.set_body(json_rpc::create_error_response_body(err, cli.original_json_request));
			} catch (const std::exception &e) {
				json_rpc::Error json_err(json_rpc::INTERNAL_ERROR, common::what(e));
				last_http_response.set_body(json_rpc::create_error_response_body(json_err, cli.original_json_request));
			}
		}
		http::Server::write(cli.original_who, std::move(last_http_response));
	}
}

static const std::string beautiful_index_start =
    R"(<html><head><meta http-equiv='refresh' content='30'/></head><body><table valign="middle"><tr><td width="30px">
<svg xmlns="http://www.w3.org/2000/svg" width="30px" viewBox="0 0 215.99 215.99">
<circle fill="#f04086" cx="107.99" cy="107.99" r="107.99"></circle>
<path fill="#fff" d="M158.2 113.09q-6.37-7.05-18.36-8.75v-.17c7-1.13 12.5-4 16.24-8.59a25.09 25.09 0 0 0 5.82-16.23c0-9.86-3.18-16.56-9.75-21.83s-16.44-7-29.81-7h-50.5v47h-29v18H122c6.23 0 10.91.44 14 2.93s4.67 5.71 4.67 10.47-1.56 8.82-4.67 11.37-7.79 4.23-14 4.23H94.84v-14h-23v32H124c13.26 0 23.4-3.46 30.43-8.84s10.33-13.33 10.33-23.08a25.72 25.72 0 0 0-6.56-17.51zm-39.1-15.62H94.84v-29h24.26c12.47 0 18.7 4.87 18.7 14.5s-6.23 14.5-18.7 14.5z"></path>
</svg></td><td>)" CRYPTONOTE_NAME R"(d &bull; version
)";
static const std::string beautiful_index_finish = " </td></tr></table></body></html>";
static const std::string robots_txt             = "User-agent: *\r\nDisallow: /";

void Node::fill_cors(const http::RequestBody &req, http::ResponseBody &res) {
	if (req.r.origin.empty() || !m_config.bytecoind_cors_asterisk)
		return;
	res.r.headers.push_back({"Access-Control-Allow-Origin", "*"});
	res.r.headers.push_back({"Access-Control-Allow-Methods", "GET, POST, OPTIONS"});
	res.r.headers.push_back({"Access-Control-Allow-Headers",
	    "DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range"});
	if (req.r.method == "OPTIONS")
		return;
	res.r.headers.push_back({"Access-Control-Expose-Headers", "Content-Length,Content-Range"});
}

bool Node::on_api_http_request(http::Client *who, http::RequestBody &&request, http::ResponseBody &response) {
	fill_cors(request, response);
	if (request.r.method == "OPTIONS") {
		response.r.headers.push_back({"Content-Type", "text/plain"});
		response.r.headers.push_back({"Access-Control-Max-Age", "172800"});  // 2 days
		response.r.status = 200;
		return true;
	}
	if (request.r.uri == "/robots.txt") {
		response.r.add_headers_nocache();
		response.r.headers.push_back({"Content-Type", "text/plain; charset=UTF-8"});
		response.r.status = 200;
		response.set_body(std::string(robots_txt));
		return true;
	}
	if (!m_config.good_bytecoind_auth(request.r.basic_authorization))
		throw http::ErrorAuthorization("authorization");
	// Private methods will check for private authorization again
	if (request.r.uri == "/" || request.r.uri == "/index.html") {
		response.r.add_headers_nocache();
		response.r.headers.push_back({"Content-Type", "text/html; charset=UTF-8"});
		response.r.status = 200;
		auto stat         = create_status_response();
		auto body = beautiful_index_start + app_version() + " &bull; " + m_config.net + "net &bull; sync status " +
		            common::to_string(stat.top_block_height) + "/" + common::to_string(stat.top_known_block_height) +
		            beautiful_index_finish;
		if (m_config.net != "main")
			boost::replace_all(body, "#f04086", "#00afa5");
		response.set_body(std::move(body));
		return true;
	}
	if (request.r.uri == api::cnd::url()) {
		response.r.add_headers_nocache();
		if (!on_json_rpc(who, std::move(request), response))
			return false;
		response.r.status = 200;
		return true;
	}
	if (request.r.uri == api::cnd::binary_url()) {
		response.r.add_headers_nocache();
		if (!on_binary_rpc(who, std::move(request), response))
			return false;
		response.r.status = 200;
		return true;
	}
	// We emulate nginx here, will remove later
	if (m_config.bytecoind_cors_asterisk && common::starts_with(request.r.uri, api::cnd::SyncBlocks::url_prefix())) {
		Height height = 0;
		if (api::cnd::SyncBlocks::parse_filename(
		        request.r.uri.substr(api::cnd::SyncBlocks::url_prefix().size()), &height)) {
			if (height > m_block_chain.get_currency().last_hard_checkpoint().height) {
				response.r.headers.push_back({"Content-Type", "text/html; charset=UTF-8"});
				response.r.status = 404;
				response.set_body(
				    "<html><body>404 Not Found - static blocks can be queried only up to last hard checkpoint</body></html>");
				return true;
			}
			response.r.headers.push_back({"Content-Type", "application/octet-stream"});
			response.r.headers.push_back({"Cache-Control", "max-age=2628000, public"});  // month
			response.r.status = 200;
			if (height % 10 != 0) {
				// Emulate static link
				response.set_body(common::to_string(height - height % 10));
				return true;
			}
			api::cnd::SyncBlocks::ResponseCompact res;
			size_t total_size = 0;
			Hash hash;
			while (m_block_chain.get_chain(height + static_cast<Height>(res.blocks.size()), &hash)) {
				res.blocks.push_back(m_block_chain.fill_sync_block_compact(hash));
				total_size += res.blocks.back().header.block_size;
				// We emulate redirect from % 10, so should return at least 10, otherwise cliens will loop
				if ((total_size >= 1024 * 1024 && res.blocks.size() >= 10) ||
				    height + static_cast<Height>(res.blocks.size()) >
				        m_block_chain.get_currency().last_hard_checkpoint().height)
					break;
			}
			response.set_body(json_rpc::create_binary_response_body(res, common::JsonValue(nullptr)));
			return true;
		}
	}
	response.r.status = 404;
	response.r.headers.push_back({"Content-Type", "text/html; charset=UTF-8"});
	response.set_body("<html><body>404 Not Found</body></html>");
	return true;
}

void Node::on_api_http_disconnect(http::Client *who) {
	for (auto lit = m_long_poll_http_clients.begin(); lit != m_long_poll_http_clients.end();)
		if (lit->original_who == who)
			lit = m_long_poll_http_clients.erase(lit);
		else
			++lit;
}

const std::unordered_map<std::string, Node::BINARYRPCHandlerFunction> Node::m_binaryrpc_handlers = {
    {api::cnd::SyncBlocks::bin_method(), json_rpc::make_binary_member_method(&Node::on_sync_blocks_bin)},
    {api::cnd::SyncMemPool::bin_method(), json_rpc::make_binary_member_method(&Node::on_sync_mempool)}};

std::unordered_map<std::string, Node::JSONRPCHandlerFunction> Node::m_jsonrpc_handlers = {
    {api::cnd::GetLastBlockHeaderLegacy::method(), json_rpc::make_member_method(&Node::on_get_last_block_header)},
    {api::cnd::GetBlockHeaderByHashLegacy::method(), json_rpc::make_member_method(&Node::on_get_block_header_by_hash)},
    {api::cnd::GetBlockHeaderByHeightLegacy::method(),
        json_rpc::make_member_method(&Node::on_get_block_header_by_height)},
    {api::cnd::GetBlockTemplate::method(), json_rpc::make_member_method(&Node::on_getblocktemplate)},
    {api::cnd::GetBlockTemplate::method_legacy(), json_rpc::make_member_method(&Node::on_getblocktemplate)},
    {api::cnd::GetCurrencyId::method(), json_rpc::make_member_method(&Node::on_get_currency_id)},
    {api::cnd::GetCurrencyId::method_legacy(), json_rpc::make_member_method(&Node::on_get_currency_id)},
    {api::cnd::SubmitBlock::method(), json_rpc::make_member_method(&Node::on_submitblock)},
    {api::cnd::SubmitBlockLegacy::method(), json_rpc::make_member_method(&Node::on_submitblock_legacy)},
    {api::cnd::GetRandomOutputs::method(), json_rpc::make_member_method(&Node::on_get_random_outputs)},
    {api::cnd::GetStatus::method(), json_rpc::make_member_method(&Node::on_get_status)},
    {api::cnd::GetStatus::method2(), json_rpc::make_member_method(&Node::on_get_status)},
    {api::cnd::GetStatistics::method(), json_rpc::make_member_method(&Node::on_get_statistics)},
    {api::cnd::GetArchive::method(), json_rpc::make_member_method(&Node::on_get_archive)},
    {api::cnd::SendTransaction::method(), json_rpc::make_member_method(&Node::on_send_transaction)},
    {api::cnd::CheckSendproof::method(), json_rpc::make_member_method(&Node::on_check_sendproof)},
    {api::cnd::SyncBlocks::method(), json_rpc::make_member_method(&Node::on_sync_blocks)},
    {api::cnd::GetRawBlock::method(), json_rpc::make_member_method(&Node::on_get_raw_block)},
    {api::cnd::GetBlockHeader::method(), json_rpc::make_member_method(&Node::on_get_block_header)},
    {api::cnd::GetRawTransaction::method(), json_rpc::make_member_method(&Node::on_get_raw_transaction)},
    {api::cnd::SyncMemPool::method(), json_rpc::make_member_method(&Node::on_sync_mempool)}};

bool Node::on_get_random_outputs(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::GetRandomOutputs::Request &&request, api::cnd::GetRandomOutputs::Response &response) {
	Height confirmed_height_or_depth = api::ErrorWrongHeight::fix_height_or_depth(
	    request.confirmed_height_or_depth, m_block_chain.get_tip_height(), true, false);
	api::BlockHeader confirmed_header = m_block_chain.get_tip();
	Hash confirmed_hash;
	invariant(m_block_chain.get_chain(confirmed_height_or_depth, &confirmed_hash), "");
	invariant(m_block_chain.get_header(confirmed_hash, &confirmed_header), "");
	for (auto amount : request.amounts) {
		auto random_outputs =
		    m_block_chain.get_random_outputs(confirmed_header.major_version, amount, request.output_count,
		        confirmed_height_or_depth, confirmed_header.timestamp, confirmed_header.timestamp_median);
		auto &outs = response.outputs[amount];
		outs.insert(outs.end(), random_outputs.begin(), random_outputs.end());
	}
	return true;
}

api::cnd::GetStatus::Response Node::create_status_response() const {
	api::cnd::GetStatus::Response res;
	res.top_block_height       = m_block_chain.get_tip_height();
	res.top_known_block_height = res.top_block_height;
	for (auto &&gc : m_broadcast_protocols)
		res.top_known_block_height = std::max(res.top_known_block_height, gc->get_peer_sync_data().current_height);
	res.top_known_block_height =
	    std::max<Height>(res.top_known_block_height, m_block_chain.internal_import_known_height());
	for (auto &&pb : m_broadcast_protocols)
		if (pb->is_incoming())
			res.incoming_peer_count += 1;
		else
			res.outgoing_peer_count += 1;
	api::BlockHeader tip                 = m_block_chain.get_tip();
	res.top_block_hash                   = m_block_chain.get_tip_bid();
	res.top_block_timestamp              = tip.timestamp;
	res.top_block_timestamp_median       = tip.timestamp_median;
	res.top_block_difficulty             = tip.difficulty;
	res.top_block_cumulative_difficulty  = tip.cumulative_difficulty;
	res.recommended_fee_per_byte         = m_block_chain.get_currency().coin() / 1000000;  // TODO - calculate
	res.recommended_max_transaction_size = m_block_chain.get_currency().get_recommended_max_transaction_size();
	res.transaction_pool_version         = m_block_chain.get_tx_pool_version();
	return res;
}

void Node::broadcast(P2PProtocolBytecoin *exclude, const BinaryArray &data) {
	for (auto &&p : m_broadcast_protocols)
		if (p != exclude)
			p->P2PProtocol::send(BinaryArray(data));  // Move is impossible here
}

bool Node::on_get_status(http::Client *who, http::RequestBody &&raw_request, json_rpc::Request &&raw_js_request,
    api::cnd::GetStatus::Request &&req, api::cnd::GetStatus::Response &res) {
	res = create_status_response();
	if (!res.ready_for_longpoll(req)) {
		//	m_log(logging::INFO) << "on_get_status will long poll, json=" << raw_request.body;
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

api::cnd::GetStatistics::Response Node::create_statistics_response(const api::cnd::GetStatistics::Request &req) const {
	api::cnd::GetStatistics::Response res;
	res.peer_id = m_p2p.get_unique_number();
	if (req.need_connected_peers) {
		for (auto &&p : m_broadcast_protocols) {
			ConnectionDesc desc;
			desc.address               = p->get_address();
			desc.is_incoming           = p->is_incoming();
			desc.p2p_version           = p->get_peer_version();
			desc.peer_id               = p->get_peer_unique_number();
			desc.top_block_desc.hash   = p->get_peer_sync_data().top_id;
			desc.top_block_desc.height = p->get_peer_sync_data().current_height;
			res.connected_peers.push_back(desc);
		}
	}
	if (req.need_peer_lists) {
		res.peer_list_gray = m_peer_db->get_peer_list_gray();
		res.peer_list_gray = m_peer_db->get_peer_list_white();
	}
	res.platform           = platform::get_platform_name();
	res.version            = cn::app_version();
	res.net                = m_config.net;
	res.genesis_block_hash = m_block_chain.get_currency().genesis_block_hash;
	res.start_time         = m_start_time;
	m_block_chain.fill_statistics(res);
	return res;
}

bool Node::on_get_statistics(http::Client *, http::RequestBody &&http_request, json_rpc::Request &&,
    api::cnd::GetStatistics::Request &&req, api::cnd::GetStatistics::Response &res) {
	if (!m_config.good_bytecoind_auth_private(http_request.r.basic_authorization))
		throw http::ErrorAuthorization("authorization-private");
	res = create_statistics_response(req);
	return true;
}

bool Node::on_get_archive(http::Client *, http::RequestBody &&http_request, json_rpc::Request &&,
    api::cnd::GetArchive::Request &&req, api::cnd::GetArchive::Response &resp) {
	if (!m_config.good_bytecoind_auth_private(http_request.r.basic_authorization))
		throw http::ErrorAuthorization("authorization-private");
	m_block_chain.read_archive(std::move(req), resp);
	return true;
}

// mixed_outputs can be null if keys not needed
void Node::fill_transaction_info(
    const TransactionPrefix &tx, api::Transaction *api_tx, std::vector<std::vector<api::Output>> *mixed_outputs) const {
	api_tx->unlock_block_or_timestamp = tx.unlock_block_or_timestamp;
	api_tx->extra                     = tx.extra;
	api_tx->anonymity                 = std::numeric_limits<size_t>::max();
	extra::get_transaction_public_key(tx.extra, &api_tx->public_key);
	api_tx->prefix_hash = get_transaction_prefix_hash(tx);
	api_tx->inputs_hash = get_transaction_inputs_hash(tx);
	extra::get_payment_id(tx.extra, &api_tx->payment_id);
	Amount input_amount = 0;
	if (mixed_outputs)
		mixed_outputs->reserve(tx.inputs.size());
	for (size_t input_index = 0; input_index != tx.inputs.size(); ++input_index) {
		const auto &input = tx.inputs.at(input_index);
		if (input.type() == typeid(InputKey)) {
			const InputKey &in = boost::get<InputKey>(input);
			api_tx->anonymity  = std::min(api_tx->anonymity, in.output_indexes.size() - 1);
			input_amount += in.amount;
			if (mixed_outputs)
				mixed_outputs->push_back(m_block_chain.get_mixed_outputs(tx.version, input_index, in));
		}
	}
	Amount output_amount = get_tx_sum_outputs(tx);
	api_tx->amount       = output_amount;
	if (input_amount >= output_amount)
		api_tx->fee = input_amount - output_amount;
	if (api_tx->anonymity == std::numeric_limits<size_t>::max())
		api_tx->anonymity = 0;  // No key inputs
}

std::vector<Hash> Node::fill_sync_blocks_subchain(api::cnd::SyncBlocks::Request &req, Height *start_height) const {
	if (req.sparse_chain.empty())
		throw std::runtime_error("Empty sparse chain - must include at least 1 block (usually genesis)");
	if (req.sparse_chain.back() == Hash{})  // We allow to ask for "whatever genesis bid. Useful for explorer, etc."
		req.sparse_chain.back() = m_block_chain.get_genesis_bid();
	if (req.max_count > m_config.rpc_sync_blocks_max_count)
		req.max_count = m_config.rpc_sync_blocks_max_count;
	if (req.max_size > m_config.rpc_sync_blocks_max_size)
		req.max_size = m_config.rpc_sync_blocks_max_size;
	auto first_block_timestamp = req.first_block_timestamp < m_block_chain.get_currency().block_future_time_limit
	                                 ? 0
	                                 : req.first_block_timestamp - m_block_chain.get_currency().block_future_time_limit;
	Height full_offset = m_block_chain.get_timestamp_lower_bound_height(first_block_timestamp);
	// We need range of blocks to cover req.timestamp, otherwise wallet cannot be sure it got the whole chain
	if (full_offset != 0)
		full_offset -= 1;
	std::vector<Hash> subchain =
	    m_block_chain.get_sync_headers_chain(req.sparse_chain, start_height, req.max_count + 1);
	// Will throw if no common subchain
	if (!subchain.empty() && *start_height != 0) {
		subchain.erase(subchain.begin());  // Caller never needs common block she already has
		*start_height += 1;                // Except if genesis (caller knows hash, but has no block)
	} else if (subchain.size() > req.max_count) {
		subchain.pop_back();
	}
	if (full_offset >= *start_height + subchain.size()) {
		*start_height = full_offset;
		subchain.clear();
		while (subchain.size() < req.max_count) {
			Hash ha;
			if (!m_block_chain.get_chain(*start_height + static_cast<Height>(subchain.size()), &ha))
				break;
			subchain.push_back(ha);
		}
	} else if (full_offset > *start_height) {
		subchain.erase(subchain.begin(), subchain.begin() + (full_offset - *start_height));
		*start_height = full_offset;
	}
	return subchain;
}

bool Node::on_sync_blocks(http::Client *, http::RequestBody &&http_request, json_rpc::Request &&json_req,
    api::cnd::SyncBlocks::Request &&req, api::cnd::SyncBlocks::Response &res) {
	const bool is_binary = http_request.r.http_version_major == 0;
	if ((!is_binary || req.need_redundant_data) &&
	    !m_config.good_bytecoind_auth_private(http_request.r.basic_authorization))
		throw http::ErrorAuthorization("authorization-private");  // slow variants are private
	std::vector<Hash> subchain = fill_sync_blocks_subchain(req, &res.start_height);
	res.blocks.resize(subchain.size());
	size_t total_size = 0;
	for (size_t i = 0; i != subchain.size(); ++i) {
		const auto &bhash = subchain[i];
		auto &res_block   = res.blocks[i];
		invariant(
		    m_block_chain.get_header(bhash, &res_block.header), "Block header must be there, but it is not there");

		RawBlock rb;
		invariant(m_block_chain.get_block(bhash, &rb), "Block must be there, but it is not there");
		Block block(rb);
		res_block.transactions.resize(block.transactions.size() + 1);
		res_block.transactions.at(0).hash = get_transaction_hash(block.header.base_transaction);
		res_block.transactions.at(0).size = seria::binary_size(block.header.base_transaction);
		if (req.need_redundant_data) {
			fill_transaction_info(block.header.base_transaction, &res_block.transactions.at(0), nullptr);
			res_block.transactions.at(0).block_height = res_block.header.height;
			res_block.transactions.at(0).block_hash   = bhash;
			res_block.transactions.at(0).coinbase     = true;
			res_block.transactions.at(0).timestamp    = res_block.header.timestamp;
		}
		res_block.raw_header = std::move(block.header);
		res_block.raw_transactions.reserve(block.transactions.size());
		for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
			res_block.transactions.at(tx_index + 1).hash = res_block.raw_header.transaction_hashes.at(tx_index);
			res_block.transactions.at(tx_index + 1).size = rb.transactions.at(tx_index).size();
			if (req.need_redundant_data) {
				fill_transaction_info(
				    block.transactions.at(tx_index), &res_block.transactions.at(tx_index + 1), nullptr);
				res_block.transactions.at(tx_index + 1).block_height = res_block.header.height;
				res_block.transactions.at(tx_index + 1).block_hash   = bhash;
				res_block.transactions.at(tx_index + 1).timestamp    = res_block.raw_header.timestamp;
			}
			res_block.raw_transactions.push_back(std::move(block.transactions.at(tx_index)));
		}
		invariant(m_block_chain.read_block_output_stack_indexes(bhash, &res_block.output_stack_indexes),
		    "Invariant dead - bid is in chain but blockchain has no block indexes");
		total_size += res_block.header.transactions_size;
		if (total_size >= req.max_size) {
			res.blocks.resize(i + 1);
			break;
		}
	}
	res.status = create_status_response();
	return true;
}

bool Node::on_sync_blocks_bin(http::Client *, http::RequestBody &&http_request, json_rpc::Request &&json_req,
    api::cnd::SyncBlocks::Request &&req, api::cnd::SyncBlocks::ResponseCompact &res) {
	Height start_height        = 0;
	std::vector<Hash> subchain = fill_sync_blocks_subchain(req, &start_height);

	res.blocks.reserve(subchain.size());
	size_t total_size = 0;
	for (const auto &bid : subchain) {
		res.blocks.push_back(m_block_chain.fill_sync_block_compact(bid));
		total_size += res.blocks.back().header.transactions_size;  // Approximate, ok for our purpose
		if (total_size >= req.max_size)
			break;
	}
	res.status = create_status_response();
	return true;
}

bool Node::on_sync_mempool(http::Client *, http::RequestBody &&http_request, json_rpc::Request &&,
    api::cnd::SyncMemPool::Request &&req, api::cnd::SyncMemPool::Response &res) {
	const bool is_binary = http_request.r.http_version_major == 0;
	if ((!is_binary || req.need_redundant_data) &&
	    !m_config.good_bytecoind_auth_private(http_request.r.basic_authorization))
		throw http::ErrorAuthorization("authorization-private");  // slow variants are private
	const auto &pool = m_block_chain.get_memory_state_transactions();
	for (auto &&ex : req.known_hashes)
		if (pool.count(ex) == 0)
			res.removed_hashes.push_back(ex);
	for (auto &&tx : pool)
		if (!std::binary_search(req.known_hashes.begin(), req.known_hashes.end(), tx.first)) {
			res.added_raw_transactions.push_back(tx.second.tx);
			res.added_transactions.push_back(api::Transaction{});
			if (req.need_redundant_data)
				fill_transaction_info(tx.second.tx, &res.added_transactions.back(), nullptr);
			res.added_transactions.back().hash      = tx.first;
			res.added_transactions.back().timestamp = tx.second.timestamp;
			res.added_transactions.back().amount    = tx.second.amount;
			res.added_transactions.back().fee       = tx.second.fee;
			res.added_transactions.back().size      = tx.second.binary_tx.size();
		}
	res.status = create_status_response();
	return true;
}

bool Node::on_get_block_header(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::GetBlockHeader::Request &&request, api::cnd::GetBlockHeader::Response &response) {
	if (!request.hash && !request.height_or_depth)
		throw json_rpc::Error(json_rpc::INVALID_REQUEST, "You must set either 'hash' or 'height_or_depth'");
	if (request.hash && request.height_or_depth)
		throw json_rpc::Error(json_rpc::INVALID_REQUEST, "You cannot set both 'hash' and 'height_or_depth'");
	if (request.hash) {
		if (!m_block_chain.get_header(request.hash.get(), &response.block_header))
			throw api::ErrorHash("Block not found in either main or side chains", request.hash.get());
	} else {
		Height height_or_depth = api::ErrorWrongHeight::fix_height_or_depth(
		    request.height_or_depth.get(), m_block_chain.get_tip_height(), true, true);
		Hash hash;
		invariant(m_block_chain.get_chain(height_or_depth, &hash), "");  // after fix_height it must always succeed
		invariant(m_block_chain.get_header(hash, &response.block_header), "");
	}
	response.orphan_status = !m_block_chain.in_chain(response.block_header.height, response.block_header.hash);
	response.depth =
	    api::HeightOrDepth(response.block_header.height) - api::HeightOrDepth(m_block_chain.get_tip_height()) - 1;
	return true;
}
bool Node::on_get_raw_block(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::GetRawBlock::Request &&request, api::cnd::GetRawBlock::Response &response) {
	if (!request.hash && !request.height_or_depth)
		throw json_rpc::Error(json_rpc::INVALID_REQUEST, "You must set either 'hash' or 'height_or_depth'");
	if (request.hash && request.height_or_depth)
		throw json_rpc::Error(json_rpc::INVALID_REQUEST, "You cannot set both 'hash' and 'height_or_depth'");
	if (request.hash) {
		if (!m_block_chain.get_header(request.hash.get(), &response.block.header))
			throw api::ErrorHash("Block not found in either main or side chains", request.hash.get());
	} else {
		Height height_or_depth = api::ErrorWrongHeight::fix_height_or_depth(
		    request.height_or_depth.get(), m_block_chain.get_tip_height(), true, true);
		Hash hash;
		invariant(m_block_chain.get_chain(height_or_depth, &hash), "");  // after fix_height it must always succeed
		invariant(m_block_chain.get_header(hash, &response.block.header), "");
	}
	RawBlock rb;
	invariant(m_block_chain.get_block(response.block.header.hash, &rb), "Block must be there, but it is not there");
	Block block(rb);

	api::RawBlock &b = response.block;
	b.transactions.resize(block.transactions.size() + 1);
	b.transactions.at(0).hash = get_transaction_hash(block.header.base_transaction);
	b.transactions.at(0).size = seria::binary_size(block.header.base_transaction);
	fill_transaction_info(block.header.base_transaction, &b.transactions.at(0), nullptr);
	b.transactions.at(0).block_height = b.header.height;
	b.transactions.at(0).block_hash   = b.header.hash;
	b.transactions.at(0).coinbase     = true;
	b.transactions.at(0).timestamp    = block.header.timestamp;
	b.raw_header                      = std::move(block.header);
	b.raw_transactions.reserve(block.transactions.size());
	for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
		b.transactions.at(tx_index + 1).hash = b.raw_header.transaction_hashes.at(tx_index);
		b.transactions.at(tx_index + 1).size = rb.transactions.at(tx_index).size();
		fill_transaction_info(block.transactions.at(tx_index), &b.transactions.at(tx_index + 1), nullptr);
		b.transactions.at(tx_index + 1).block_height = b.header.height;
		b.transactions.at(tx_index + 1).block_hash   = b.header.hash;
		b.transactions.at(tx_index + 1).timestamp    = b.raw_header.timestamp;
		b.raw_transactions.push_back(std::move(block.transactions.at(tx_index)));
	}
	m_block_chain.read_block_output_stack_indexes(response.block.header.hash, &b.output_stack_indexes);
	// If block not in main chain - stack indexes will be empty
	response.orphan_status = !m_block_chain.in_chain(b.header.height, b.header.hash);
	response.depth = api::HeightOrDepth(b.header.height) - api::HeightOrDepth(m_block_chain.get_tip_height()) - 1;
	return true;
}

bool Node::on_get_raw_transaction(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::GetRawTransaction::Request &&req, api::cnd::GetRawTransaction::Response &res) {
	const auto &pool = m_block_chain.get_memory_state_transactions();
	auto tit         = pool.find(req.hash);
	if (tit != pool.end()) {
		res.raw_transaction = static_cast<const TransactionPrefix &>(tit->second.tx);
		fill_transaction_info(tit->second.tx, &res.transaction, &res.mixed_outputs);
		for (const auto &outputs : res.mixed_outputs) {
			res.mixed_public_keys.push_back(std::vector<PublicKey>{});
			for (const auto &output : outputs)
				res.mixed_public_keys.back().push_back(output.public_key);
		}
		res.transaction.fee          = tit->second.fee;
		res.transaction.hash         = req.hash;
		res.transaction.block_height = m_block_chain.get_tip_height() + 1;
		res.transaction.timestamp    = tit->second.timestamp;
		res.transaction.size         = tit->second.binary_tx.size();
		res.signatures               = tit->second.tx.signatures;
		return true;
	}
	BinaryArray binary_tx;
	Transaction tx;
	size_t index_in_block = 0;
	if (m_block_chain.get_transaction(
	        req.hash, &binary_tx, &res.transaction.block_height, &res.transaction.block_hash, &index_in_block)) {
		api::BlockHeader bh;
		invariant(m_block_chain.get_header(res.transaction.block_hash, &bh, res.transaction.block_height), "");
		res.transaction.timestamp = bh.timestamp;
		res.transaction.size      = binary_tx.size();
		seria::from_binary(tx, binary_tx);
		res.raw_transaction = static_cast<const TransactionPrefix &>(tx);
		fill_transaction_info(tx, &res.transaction, &res.mixed_outputs);
		for (const auto &outputs : res.mixed_outputs) {
			res.mixed_public_keys.push_back(std::vector<PublicKey>{});
			for (const auto &output : outputs)
				res.mixed_public_keys.back().push_back(output.public_key);
		}
		res.transaction.coinbase = (index_in_block == 0);
		res.transaction.hash     = req.hash;
		res.transaction.fee      = get_tx_fee(res.raw_transaction);
		res.signatures           = tx.signatures;
		return true;
	}
	throw api::ErrorHash(
	    "Transaction not found in main chain or memory pool. You cannot get transactions from side chains with this method.",
	    req.hash);
}

bool Node::on_send_transaction(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::SendTransaction::Request &&request, api::cnd::SendTransaction::Response &response) {
	response.send_result = "broadcast";

	p2p::RelayTransactions::Notify msg_v4;
	Transaction tx;
	try {
		seria::from_binary(tx, request.binary_transaction);
		const Hash tid = get_transaction_hash(tx);
		if (m_block_chain.add_transaction(tid, tx, request.binary_transaction, true, "json_rpc")) {
			TransactionDesc desc;
			desc.hash                       = tid;
			desc.size                       = request.binary_transaction.size();
			desc.fee                        = get_tx_fee(tx);
			Height newest_referenced_height = 0;
			invariant(m_block_chain.get_largest_referenced_height(tx, &newest_referenced_height), "");
			invariant(m_block_chain.get_chain(newest_referenced_height, &desc.newest_referenced_block), "");
			msg_v4.transaction_descs.push_back(desc);

			BinaryArray raw_msg_v4 = LevinProtocol::send(msg_v4);
			broadcast(nullptr, raw_msg_v4);
			advance_long_poll();
		}
	} catch (const ConsensusErrorOutputDoesNotExist &ex) {
		throw api::cnd::SendTransaction::Error(api::cnd::SendTransaction::WRONG_OUTPUT_REFERENCE, common::what(ex),
		    m_block_chain.get_currency().max_block_height);
	} catch (const ConsensusErrorBadOutputOrSignature &ex) {
		throw api::cnd::SendTransaction::Error(
		    api::cnd::SendTransaction::WRONG_OUTPUT_REFERENCE, common::what(ex), ex.conflict_height);
	} catch (const ConsensusErrorOutputSpent &ex) {
		throw api::cnd::SendTransaction::Error(
		    api::cnd::SendTransaction::OUTPUT_ALREADY_SPENT, common::what(ex), ex.conflict_height);
	} catch (const std::exception &ex) {
		std::throw_with_nested(api::cnd::SendTransaction::Error(
		    api::cnd::SendTransaction::INVALID_TRANSACTION_BINARY_FORMAT, common::what(ex), 0));
	}
	return true;
}

void Node::check_sendproof(const SendproofLegacy &sp, api::cnd::CheckSendproof::Response &response) const {
	BinaryArray binary_tx;
	Height height = 0;
	Hash block_hash;
	size_t index_in_block = 0;
	if (!m_block_chain.get_transaction(sp.transaction_hash, &binary_tx, &height, &block_hash, &index_in_block)) {
		throw api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::PROOF_NOT_IN_MAIN_CHAIN, "Transaction is not in main chain", sp.transaction_hash);
	}
	response.transaction_hash = sp.transaction_hash;
	response.depth            = api::HeightOrDepth(height) - api::HeightOrDepth(m_block_chain.get_tip_height()) - 1;
	response.message          = sp.message;
	Transaction tx;
	seria::from_binary(tx, binary_tx);
	const Hash message_hash = crypto::cn_fast_hash(sp.message.data(), sp.message.size());
	if (tx.version >= m_block_chain.get_currency().amethyst_transaction_version)
		throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
		    "Legacy proof cannot be used for amethyst transactions", sp.transaction_hash);
	AccountAddress address;
	if (!m_block_chain.get_currency().parse_account_address_string(sp.address, &address))
		throw api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE, "Failed to parse sendproof address", sp.transaction_hash);
	if (address.type() != typeid(AccountAddressLegacy))
		throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
		    "Legacy proof for sending to address type other than legacy is invalid", sp.transaction_hash);
	auto &addr = boost::get<AccountAddressLegacy>(address);
	PublicKey tx_public_key;
	extra::get_transaction_public_key(tx.extra, &tx_public_key);
	if (!crypto::check_sendproof(tx_public_key, addr.V, sp.derivation, message_hash, sp.signature)) {
		throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
		    "Proof object does not match transaction or was tampered with", sp.transaction_hash);
	}
	Amount total_amount = 0;
	size_t out_index    = 0;
	for (const auto &output : tx.outputs) {
		if (const auto *out = boost::get<OutputKey>(&output)) {
			const PublicKey spend_key = underive_address_S(sp.derivation, out_index, out->public_key);
			if (spend_key == addr.S) {
				total_amount += out->amount;
				response.output_indexes.push_back(out_index);
			}
		}
		++out_index;
	}
	if (total_amount == 0)
		throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
		    "No transfers found to proof address", sp.transaction_hash);
	response.address = sp.address;
	response.amount  = total_amount;
}

void Node::check_sendproof(const BinaryArray &data_inside_base58, api::cnd::CheckSendproof::Response &response) const {
	common::MemoryInputStream stream(data_inside_base58.data(), data_inside_base58.size());
	seria::BinaryInputStream ba(stream);
	ba.begin_object();
	SendproofAmethyst sp;
	try {
		seria::ser_members(sp, ba);
	} catch (const std::exception &) {
		std::throw_with_nested(
		    json_rpc::Error(api::cnd::CheckSendproof::PROOF_FAILED_TO_PARSE, "Failed to parse proof object"));
	}
	if (sp.version < m_block_chain.get_currency().amethyst_transaction_version) {
		ba.end_object();
		if (!stream.empty())
			throw json_rpc::Error(
			    api::cnd::CheckSendproof::PROOF_FAILED_TO_PARSE, "Failed to parse proof object - too many bytes");
		SendproofLegacy spk;
		spk.transaction_hash = sp.transaction_hash;
		spk.message          = sp.message;
		spk.address          = m_block_chain.get_currency().account_address_as_string(sp.address_simple);
		spk.derivation       = sp.derivation;
		spk.signature        = sp.signature;
		check_sendproof(spk, response);
		return;
	}
	BinaryArray binary_tx;
	Height height = 0;
	Hash block_hash;
	size_t index_in_block = 0;
	if (!m_block_chain.get_transaction(sp.transaction_hash, &binary_tx, &height, &block_hash, &index_in_block)) {
		throw api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::PROOF_NOT_IN_MAIN_CHAIN, "Transaction is not in main chain", sp.transaction_hash);
	}
	response.transaction_hash = sp.transaction_hash;
	response.depth            = api::HeightOrDepth(height) - api::HeightOrDepth(m_block_chain.get_tip_height()) - 1;
	response.message          = sp.message;
	Transaction tx;
	seria::from_binary(tx, binary_tx);
	if (tx.inputs.empty() || tx.inputs.at(0).type() != typeid(InputKey))
		throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_FAILED_TO_PARSE,
		    "Proof object invalid, because references coinbase transactions", sp.transaction_hash);
	if (tx.version != sp.version)
		throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
		    "Proof version wrong for transaction version", sp.transaction_hash);
	const Hash tx_inputs_hash = get_transaction_inputs_hash(tx);

	const InputKey &in = boost::get<InputKey>(tx.inputs.at(0));
	TransactionPrefix fake_prefix;
	fake_prefix.version = tx.version;
	fake_prefix.inputs.push_back(in);
	RingSignatureAmethyst rsa;
	try {
		seria::ser_members(rsa, ba, fake_prefix);
	} catch (const std::exception &) {
		std::throw_with_nested(
		    json_rpc::Error(api::cnd::CheckSendproof::PROOF_FAILED_TO_PARSE, "Failed to parse proof object"));
	}
	ba.end_object();
	if (!stream.empty())
		throw json_rpc::Error(
		    api::cnd::CheckSendproof::PROOF_FAILED_TO_PARSE, "Failed to parse proof object - too many bytes");

	const auto proof_body = seria::to_binary(sp);
	//	std::cout << "Proof body: " << common::to_hex(proof_body) << std::endl;
	const auto proof_prefix_hash = crypto::cn_fast_hash(proof_body);
	//	std::cout << "Proof hash: " << proof_prefix_hash << std::endl;

	std::vector<KeyImage> all_keyimages{in.key_image};
	std::vector<std::vector<PublicKey>> all_output_keys(1);
	const auto mixed_outputs = m_block_chain.get_mixed_outputs(tx.version, 0, in);
	for (size_t i = 0; i != mixed_outputs.size(); ++i)
		all_output_keys.at(0).push_back(mixed_outputs.at(i).public_key);

	if (!crypto::check_ring_signature_amethyst(proof_prefix_hash, all_keyimages, all_output_keys, rsa)) {
		throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
		    "Proof object does not match transaction or was tampered with", sp.transaction_hash);
	}
	for (size_t oi = 1; oi < sp.elements.size(); ++oi) {
		if (sp.elements.at(oi).out_index <= sp.elements.at(oi - 1).out_index)
			throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
			    "Proof object elements are not in strict ascending order", sp.transaction_hash);
	}
	std::reverse(sp.elements.begin(), sp.elements.end());  // pop_back instead of erase(begin)
	Amount total_amount = 0;
	std::string message;
	boost::optional<AccountAddress> all_addresses;
	for (size_t out_index = 0; out_index != tx.outputs.size() && !sp.elements.empty(); ++out_index) {
		const auto &output = tx.outputs.at(out_index);
		if (output.type() != typeid(OutputKey))
			continue;
		const auto &out = boost::get<OutputKey>(output);
		if (sp.elements.empty() || sp.elements.back().out_index != out_index)
			continue;
		const auto &el = sp.elements.back();
		AccountAddress output_address;
		PublicKey output_shared_secret;
		if (!TransactionBuilder::detect_not_our_output_amethyst(
		        tx_inputs_hash, el.output_seed, out_index, out, &output_address, &output_shared_secret)) {
			throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
			    "Cannot underive address for proof output", sp.transaction_hash);
		}
		if (all_addresses && all_addresses.get() != output_address) {
			throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
			    "Send proof address inconsistent", sp.transaction_hash);
		}
		all_addresses = output_address;
		total_amount += out.amount;
		response.output_indexes.push_back(out_index);
		sp.elements.pop_back();
	}
	auto encrypted_messages = extra::get_encrypted_messages(tx.extra);
	for (size_t m_index = 0; m_index != encrypted_messages.size(); ++m_index) {
		const auto &em                 = encrypted_messages.at(m_index);
		const size_t fake_output_index = tx.outputs.size() + m_index;
		if (sp.elements.empty() || sp.elements.back().out_index != fake_output_index)
			continue;
		const auto &el = sp.elements.back();
		AccountAddress output_address;
		PublicKey output_shared_secret;
		if (!TransactionBuilder::detect_not_our_output_amethyst(
		        tx_inputs_hash, el.output_seed, fake_output_index, em.output, &output_address, &output_shared_secret)) {
			throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
			    "Cannot underive address for proof output", sp.transaction_hash);
		}
		if (all_addresses && all_addresses.get() != output_address) {
			throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
			    "Send proof address inconsistent", sp.transaction_hash);
		}
		all_addresses = output_address;
		message += TransactionBuilder::decrypt_message_chunk(em.message, output_shared_secret);
		sp.elements.pop_back();
	}
	if (!sp.elements.empty())
		throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
		    "Proof object contains excess elements", sp.transaction_hash);
	if (!all_addresses)
		throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::PROOF_WRONG_SIGNATURE,
		    "No transfers found to proof address", sp.transaction_hash);
	response.address        = m_block_chain.get_currency().account_address_as_string(all_addresses.get());
	response.secret_message = message;
	response.amount         = total_amount;
}

bool Node::on_check_sendproof(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::CheckSendproof::Request &&request, api::cnd::CheckSendproof::Response &response) {
	uint64_t utag = 0;
	BinaryArray data_inside_base58;
	if (common::base58::decode_addr(request.sendproof, &utag, &data_inside_base58)) {
		if (utag != m_block_chain.get_currency().sendproof_base58_prefix)
			throw json_rpc::Error(
			    api::cnd::CheckSendproof::PROOF_FAILED_TO_PARSE, "Failed to parse proof object, wrong prefix");
		check_sendproof(data_inside_base58, response);
		return true;
	}
	SendproofLegacy sp;
	try {
		common::JsonValue jv = common::JsonValue::from_string(request.sendproof);
		seria::from_json_value(sp, jv);
	} catch (const std::exception &ex) {
		std::throw_with_nested(json_rpc::Error(api::cnd::CheckSendproof::PROOF_FAILED_TO_PARSE,
		    "Failed to parse proof object ex.what=" + common::what(ex)));
	}
	check_sendproof(sp, response);
	return true;
}

void Node::submit_block(const BinaryArray &blockblob, api::BlockHeader *info) {
	BlockTemplate block_template;
	seria::from_binary(block_template, blockblob);
	RawBlock raw_block;
	try {
		if (!m_block_chain.add_mined_block(blockblob, &raw_block, info))
			return;
	} catch (const std::exception &ex) {
		throw json_rpc::Error{
		    api::cnd::SubmitBlock::BLOCK_NOT_ACCEPTED, "Block not accepted, reason=" + common::what(ex)};
	}
	for (auto who : m_broadcast_protocols)
		who->advance_transactions();
	p2p::RelayBlock::Notify msg_v4;
	msg_v4.b.block                   = raw_block.block;
	msg_v4.current_blockchain_height = m_block_chain.get_tip_height();
	msg_v4.top_id                    = m_block_chain.get_tip_bid();

	BinaryArray raw_msg_v4 = LevinProtocol::send(msg_v4);
	broadcast(nullptr, raw_msg_v4);
	advance_long_poll();
}

bool Node::on_submitblock(http::Client *, http::RequestBody &&http_request, json_rpc::Request &&,
    api::cnd::SubmitBlock::Request &&req, api::cnd::SubmitBlock::Response &res) {
	if (!m_config.good_bytecoind_auth_private(http_request.r.basic_authorization))
		throw http::ErrorAuthorization("authorization-private");
	if (!req.cm_nonce.empty()) {
#if bytecoin_ALLOW_CM
		// Experimental, a bit hacky
		BlockTemplate bt;
		seria::from_binary(bt, req.blocktemplate_blob);
		bt.major_version += 1;
		bt.nonce               = req.cm_nonce;
		bt.cm_merkle_branch    = req.cm_merkle_branch;
		req.blocktemplate_blob = seria::to_binary(bt);
		//		auto body_proxy = get_body_proxy_from_template(bt);
		//		auto cm_prehash  = get_block_header_prehash(bt, body_proxy);
		//		std::cout << "submit CM data " << body_proxy.transactions_merkle_root << " " << cm_prehash << std::endl;
#else
		throw json_rpc::Error{
		    api::cnd::SubmitBlock::BLOCK_NOT_ACCEPTED, "Block not accepted, CM mining is not supported"};
#endif
	}
	submit_block(req.blocktemplate_blob, &res.block_header);
	res.orphan_status = !m_block_chain.in_chain(res.block_header.height, res.block_header.hash);
	res.depth = api::HeightOrDepth(res.block_header.height) - api::HeightOrDepth(m_block_chain.get_tip_height()) - 1;
	return true;
}

void Node::export_static_sync_blocks(const BlockChainState &block_chain, const std::string &folder) {
	if (block_chain.get_tip_height() < block_chain.get_currency().last_hard_checkpoint().height)
		throw std::runtime_error("Daemon must be synced at least to last hard checkpoint");
	if (!platform::folder_exists(folder))
		throw std::runtime_error("Folder for static sync_blocks must exist " + folder);
	api::cnd::SyncBlocks::Request req;
	req.max_size            = 1024 * 1024;
	req.max_count           = 1000;
	req.need_redundant_data = false;
	std::vector<Hash> all_chain(block_chain.get_currency().last_hard_checkpoint().height + 1);
	std::cout << "Reading chain, can take a minute or two..." << std::endl;
	for (Height i = 0; i != block_chain.get_currency().last_hard_checkpoint().height + 1; ++i)
		invariant(block_chain.get_chain(i, &all_chain.at(i)), "");
	Height ha = 0;
	api::cnd::SyncBlocks::ResponseCompact res;
	size_t max_total_count     = 0;
	size_t min_total_count     = std::numeric_limits<size_t>::max();
	size_t sum_total_size_real = 0;
	size_t sum_total_size_link = 0;
	while (ha <= block_chain.get_currency().last_hard_checkpoint().height) {
		res.blocks.clear();
		size_t total_size = 0;
		while (ha + res.blocks.size() <= block_chain.get_currency().last_hard_checkpoint().height) {
			res.blocks.push_back(block_chain.fill_sync_block_compact(all_chain.at(ha + res.blocks.size())));
			total_size += seria::binary_size(res.blocks.back());
			if (total_size >= req.max_size)
				break;
		}
		invariant(!res.blocks.empty(), "");
		auto ba = json_rpc::create_binary_response_body(res, common::JsonValue(nullptr));
		std::cout << "Saving chunk start=" << ha << ", count=" << res.blocks.size() << ", size=" << ba.size()
		          << std::endl;
		sum_total_size_real += ba.size();
		for (size_t d = 0; d != res.blocks.size(); ++d) {
			if (d == 1) {
				ba = common::to_string(ha);
				sum_total_size_link += ba.size() * (res.blocks.size() - 1);
			}
			std::string subfolder;
			auto file_name = api::cnd::SyncBlocks::get_filename(Height(ha + d), &subfolder);
			invariant(
			    platform::create_folders_if_necessary(folder + api::cnd::SyncBlocks::url_prefix() + "/" + subfolder),
			    "");
			invariant(platform::save_file(
			              folder + api::cnd::SyncBlocks::url_prefix() + "/" + file_name, ba.data(), ba.size()),
			    "");
		}
		ha += res.blocks.size();
		max_total_count = std::max(max_total_count, res.blocks.size());
		min_total_count = std::min(min_total_count, res.blocks.size());
	}
	std::cout << "min_total_count=" << min_total_count << " max_total_count=" << max_total_count << std::endl;
	std::cout << "sum_total_size_real=" << sum_total_size_real << " sum_total_size_link=" << sum_total_size_link
	          << std::endl;
}
