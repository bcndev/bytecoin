// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Node.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <iostream>
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionExtra.hpp"
#include "common/JsonValue.hpp"
#include "platform/PathTools.hpp"
#include "platform/Time.hpp"
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
    , m_peer_db(log, config, "peer_db")
    , m_p2p(log, config, m_peer_db, std::bind(&Node::client_factory, this, _1))
    , multicast(config.multicast_address, config.multicast_port, std::bind(&Node::on_multicast, this, _1, _2, _3))
    , m_multicast_timer(std::bind(&Node::send_multicast, this))
    , m_start_time(m_p2p.get_local_time())
    , m_commit_timer(std::bind(&Node::db_commit, this))
    , m_downloader(this, block_chain)
    , m_downloader_v3(this, block_chain) {
	const std::string old_path = platform::get_default_data_directory(config.crypto_note_name);
	const std::string new_path = config.get_data_folder();

	m_block_chain_reader1 = std::make_unique<LegacyBlockChainReader>(
	    block_chain.get_currency(), new_path + "/blockindexes.bin", new_path + "/blocks.bin");
	if (m_block_chain_reader1->get_block_count() <= block_chain.get_tip_height())
		m_block_chain_reader1.reset();
	if (!config.bytecoind_bind_ip.empty() && config.bytecoind_bind_port != 0)
		m_api.reset(new http::Server(config.bytecoind_bind_ip, config.bytecoind_bind_port,
		    std::bind(&Node::on_api_http_request, this, _1, _2, _3), std::bind(&Node::on_api_http_disconnect, this, _1),
		    config.ssl_certificate_pem_file,
		    config.ssl_certificate_password ? config.ssl_certificate_password.get() : std::string()));

	m_commit_timer.once(m_config.db_commit_period_blockchain);
	advance_long_poll();
	send_multicast();
}

void Node::send_multicast() {
	if (m_config.multicast_period == 0)
		return;
	std::cout << "sending multicast about node listening on port=" << m_config.p2p_external_port << std::endl;
	BinaryArray ha = P2PProtocolNew::create_multicast_announce(
	    m_block_chain.get_currency().genesis_block_hash, m_config.p2p_external_port);
	platform::UDPMulticast::send(m_config.multicast_address, m_config.multicast_port, ha.data(), ha.size());
	m_multicast_timer.once(m_config.multicast_period);
}

void Node::on_multicast(const std::string &addr, const unsigned char *data, size_t size) {
	//	std::cout << " on_multicast from=" << addr << " size=" << size << std::endl;
	NetworkAddress na;
	na.port = P2PProtocolNew::parse_multicast_announce(data, size, m_block_chain.get_currency().genesis_block_hash);
	if (!na.port)
		return;
	if (common::parse_ip_address(addr, &na.ip)) {
		std::cout << "* good on_multicast from=" << na << " size=" << size << std::endl;  // TODO - remove
		if (m_peer_db.add_incoming_peer(na, m_p2p.get_local_time()))
			m_log(logging::INFO) << "Adding peer from multicast announce addr=" << na << std::endl;
	}
	// We do not receive multicast from loopback, so we just guess peer could be from localhost
	if (common::parse_ip_address("127.0.0.1", &na.ip)) {
		if (m_peer_db.add_incoming_peer(na, m_p2p.get_local_time()))
			m_log(logging::INFO) << "Adding local peer from multicast announce addr=" << na << std::endl;
	}
	m_p2p.peers_updated();
}

void Node::db_commit() {
	m_block_chain.db_commit();
	m_commit_timer.once(m_config.db_commit_period_blockchain);
}

bool Node::on_idle() {
	if (!m_block_chain_reader1 && !m_block_chain_reader2 &&
	    m_block_chain.get_tip_height() >= m_block_chain.internal_import_known_height())
		return m_downloader.on_idle();
	if (m_block_chain.get_tip_height() < m_block_chain.internal_import_known_height())
		m_block_chain.internal_import();
	else {
		if (m_block_chain_reader1 && !m_block_chain_reader1->import_blocks(&m_block_chain)) {
			m_block_chain_reader1.reset();
		}
		if (m_block_chain_reader2 && !m_block_chain_reader2->import_blocks(&m_block_chain)) {
			m_block_chain_reader2.reset();
		}
	}
	advance_long_poll();
	m_downloader.advance_download();
	return true;
}

void Node::sync_transactions(P2PProtocolBytecoin *who) {
	NOTIFY_REQUEST_TX_POOL::request msg;
	auto mytxs = m_block_chain.get_memory_state_transactions();
	msg.txs.reserve(mytxs.size());
	for (auto &&tx : mytxs) {
		msg.txs.push_back(tx.first);
	}
	BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_REQUEST_TX_POOL::ID, LevinProtocol::encode(msg), false);
	who->send(std::move(raw_msg));
}

bool Node::check_trust(const np::ProofOfTrust &tr) {
	uint64_t local_time = platform::now_unix_timestamp();
	uint64_t time_delta = local_time > tr.time ? local_time - tr.time : tr.time - local_time;

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

bool Node::check_trust(const ProofOfTrustLegacy &tr) {
	uint64_t local_time = platform::now_unix_timestamp();
	uint64_t time_delta = local_time > tr.time ? local_time - tr.time : tr.time - local_time;

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
	if (!prevent_sleep && m_block_chain.get_tip().timestamp < now - 86400)
		prevent_sleep = std::make_unique<platform::PreventSleep>("Downloading blockchain");
	if (prevent_sleep &&
	    m_block_chain.get_tip().timestamp > now - m_block_chain.get_currency().block_future_time_limit * 2)
		prevent_sleep = nullptr;
	if (m_long_poll_http_clients.empty())
		return;
	const api::bytecoind::GetStatus::Response resp = create_status_response();

	for (auto lit = m_long_poll_http_clients.begin(); lit != m_long_poll_http_clients.end();) {
		const bool method_status = lit->original_json_request.get_method() == api::bytecoind::GetStatus::method() ||
		                           lit->original_json_request.get_method() == api::bytecoind::GetStatus::method2();
		if (method_status && !resp.ready_for_longpoll(lit->original_get_status)) {
			++lit;
			continue;
		}
		if (!method_status && lit->original_get_status.top_block_hash == resp.top_block_hash &&
		    lit->original_get_status.transaction_pool_version == resp.transaction_pool_version) {
			++lit;
			continue;
		}
		const common::JsonValue &jid = lit->original_json_request.get_id().get();
		http::ResponseData last_http_response;
		last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
		last_http_response.r.status             = 200;
		last_http_response.r.http_version_major = lit->original_request.r.http_version_major;
		last_http_response.r.http_version_minor = lit->original_request.r.http_version_minor;
		last_http_response.r.keep_alive         = lit->original_request.r.keep_alive;
		if (method_status) {
			last_http_response.set_body(json_rpc::create_response_body(resp, jid));
		} else {
			try {
				api::bytecoind::GetBlockTemplate::Request gbt_req;
				lit->original_json_request.load_params(gbt_req);
				api::bytecoind::GetBlockTemplate::Response gbt_res;
				getblocktemplate(std::move(gbt_req), gbt_res);
				last_http_response.set_body(json_rpc::create_response_body(gbt_res, jid));
			} catch (const json_rpc::Error &err) {
				last_http_response.set_body(json_rpc::create_error_response_body(err, jid));
			} catch (const std::exception &e) {
				json_rpc::Error json_err(json_rpc::INTERNAL_ERROR, common::what(e));
				last_http_response.set_body(json_rpc::create_error_response_body(json_err, jid));
			}
		}
		lit->original_who->write(std::move(last_http_response));
		lit = m_long_poll_http_clients.erase(lit);
	}
}

static const std::string beautiful_index_start =
    R"(<html><head><meta http-equiv='refresh' content='30'/></head><body><table valign="middle"><tr><td width="30px">
<svg xmlns="http://www.w3.org/2000/svg" width="30px" viewBox="0 0 215.99 215.99">
<circle fill="#f04086" cx="107.99" cy="107.99" r="107.99"></circle>
<path fill="#fff" d="M158.2 113.09q-6.37-7.05-18.36-8.75v-.17c7-1.13 12.5-4 16.24-8.59a25.09 25.09 0 0 0 5.82-16.23c0-9.86-3.18-16.56-9.75-21.83s-16.44-7-29.81-7h-50.5v47h-29v18H122c6.23 0 10.91.44 14 2.93s4.67 5.71 4.67 10.47-1.56 8.82-4.67 11.37-7.79 4.23-14 4.23H94.84v-14h-23v32H124c13.26 0 23.4-3.46 30.43-8.84s10.33-13.33 10.33-23.08a25.72 25.72 0 0 0-6.56-17.51zm-39.1-15.62H94.84v-29h24.26c12.47 0 18.7 4.87 18.7 14.5s-6.23 14.5-18.7 14.5z"></path>
</svg></td><td>bytecoind &bull; version
)";
static const std::string beautiful_index_finish = " </td></tr></table></body></html>";
static const std::string robots_txt             = "User-agent: *\r\nDisallow: /";

bool Node::on_api_http_request(http::Client *who, http::RequestData &&request, http::ResponseData &response) {
	response.r.add_headers_nocache();
	if (request.r.uri == "/robots.txt") {
		response.r.headers.push_back({"Content-Type", "text/plain; charset=UTF-8"});
		response.r.status = 200;
		response.set_body(std::string(robots_txt));
		return true;
	}
	bool good_auth =
	    m_config.bytecoind_authorization.empty() || request.r.basic_authorization == m_config.bytecoind_authorization;
	bool good_auth_private = m_config.bytecoind_authorization_private.empty() ||
	                         request.r.basic_authorization == m_config.bytecoind_authorization_private;
	if (!good_auth && !good_auth_private)  // Private methods will check for private authorization again
		throw http::ErrorAuthorization("Blockchain");
	if (request.r.uri == "/" || request.r.uri == "/index.html") {
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
	if (request.r.uri == api::bytecoind::url()) {
		if (!on_json_rpc(who, std::move(request), response))
			return false;
		response.r.status = 200;
		return true;
	}
	if (request.r.uri == api::bytecoind::binary_url()) {
		if (!on_binary_rpc(who, std::move(request), response))
			return false;
		response.r.status = 200;
		return true;
	}
	response.r.status = 404;
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
    {api::bytecoind::SyncBlocks::method(), json_rpc::make_binary_member_method(&Node::on_sync_blocks)},
    {api::bytecoind::SyncMemPool::method(), json_rpc::make_binary_member_method(&Node::on_sync_mempool)}};

std::unordered_map<std::string, Node::JSONRPCHandlerFunction> Node::m_jsonrpc_handlers = {
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
    {api::bytecoind::GetRandomOutputs::method(), json_rpc::make_member_method(&Node::on_get_random_outputs)},
    {api::bytecoind::GetStatus::method(), json_rpc::make_member_method(&Node::on_get_status)},
    {api::bytecoind::GetStatus::method2(), json_rpc::make_member_method(&Node::on_get_status)},
    {api::bytecoind::GetStatistics::method(), json_rpc::make_member_method(&Node::on_get_statistics)},
    {api::bytecoind::GetArchive::method(), json_rpc::make_member_method(&Node::on_get_archive)},
    {api::bytecoind::SendTransaction::method(), json_rpc::make_member_method(&Node::handle_send_transaction)},
    {api::bytecoind::CheckSendproof::method(), json_rpc::make_member_method(&Node::handle_check_sendproof)},
    {api::bytecoind::SyncBlocks::method(), json_rpc::make_member_method(&Node::on_sync_blocks)},
    {api::bytecoind::GetRawBlock::method(), json_rpc::make_member_method(&Node::on_get_raw_block)},
    {api::bytecoind::GetBlockHeader::method(), json_rpc::make_member_method(&Node::on_get_block_header)},
    {api::bytecoind::GetRawTransaction::method(), json_rpc::make_member_method(&Node::on_get_raw_transaction)},
    {api::bytecoind::SyncMemPool::method(), json_rpc::make_member_method(&Node::on_sync_mempool)}};

bool Node::on_get_random_outputs(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::GetRandomOutputs::Request &&request, api::bytecoind::GetRandomOutputs::Response &response) {
	Height confirmed_height_or_depth = api::ErrorWrongHeight::fix_height_or_depth(
	    request.confirmed_height_or_depth, m_block_chain.get_tip_height(), true, false);
	api::BlockHeader tip_header = m_block_chain.get_tip();
	for (uint64_t amount : request.amounts) {
		auto random_outputs = m_block_chain.get_random_outputs(
		    amount, request.output_count, confirmed_height_or_depth, tip_header.timestamp);
		auto &outs = response.outputs[amount];
		outs.insert(outs.end(), random_outputs.begin(), random_outputs.end());
	}
	return true;
}

api::bytecoind::GetStatus::Response Node::create_status_response() const {
	api::bytecoind::GetStatus::Response res;
	res.top_block_height       = m_block_chain.get_tip_height();
	res.top_known_block_height = m_downloader.get_known_block_count(res.top_block_height);
	res.top_known_block_height =
	    std::max<Height>(res.top_known_block_height, m_block_chain.internal_import_known_height());
	if (m_block_chain_reader1)
		res.top_known_block_height =
		    std::max<Height>(res.top_known_block_height, m_block_chain_reader1->get_block_count());
	if (m_block_chain_reader2)
		res.top_known_block_height =
		    std::max<Height>(res.top_known_block_height, m_block_chain_reader2->get_block_count());
	for (auto &&pb : broadcast_protocols)
		if (pb->is_incoming())
			res.incoming_peer_count += 1;
		else
			res.outgoing_peer_count += 1;
	for (auto &&pb : broadcast_protocols_new)
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
	res.next_block_effective_median_size = m_block_chain.get_next_effective_median_size();
	res.transaction_pool_version         = m_block_chain.get_tx_pool_version();
	return res;
}

void Node::broadcast(P2PProtocolBytecoin *exclude, const BinaryArray &data) {
	for (auto &&p : broadcast_protocols)
		if (p != exclude)
			p->P2PProtocol::send(BinaryArray(data));  // Move is impossible here
}
void Node::broadcast_new(P2PProtocolBytecoinNew *exclude, const BinaryArray &binary_header) {
	np::RelayBlockHeader msg;
	msg.binary_header = binary_header;
	// TODO - do not forget to check
	msg.top_block_desc.cd     = m_block_chain.get_tip_cumulative_difficulty();
	msg.top_block_desc.height = m_block_chain.get_tip_height();
	msg.top_block_desc.hash   = m_block_chain.get_tip_bid();
	BinaryArray body          = seria::to_binary_kv(msg);
	BinaryArray header        = P2PProtocolBytecoinNew::create_header(np::RelayBlockHeader::ID, body.size());
	for (auto &&p : broadcast_protocols_new)
		if (p != exclude) {
			p->P2PProtocol::send(BinaryArray(header));
			p->P2PProtocol::send(BinaryArray(body));
		}
}
void Node::broadcast_new(P2PProtocolBytecoinNew *exclude, const std::vector<np::TransactionDesc> &transaction_descs) {
	np::RelayTransactionDescs msg;
	msg.transaction_descs = transaction_descs;
	// TODO - split into chunks
	msg.top_block_desc.cd     = m_block_chain.get_tip_cumulative_difficulty();
	msg.top_block_desc.height = m_block_chain.get_tip_height();
	msg.top_block_desc.hash   = m_block_chain.get_tip_bid();
	BinaryArray body          = seria::to_binary_kv(msg);
	BinaryArray header        = P2PProtocolBytecoinNew::create_header(np::RelayBlockHeader::ID, body.size());
	for (auto &&p : broadcast_protocols_new)
		if (p != exclude) {
			p->P2PProtocol::send(BinaryArray(header));
			p->P2PProtocol::send(BinaryArray(body));
		}
}

// void Node::broadcast_new(P2PProtocolBytecoinNew * exclude, const BinaryArray &data){
//	for(auto && p : broadcast_protocols_new)
//		if( p != exclude )
//			p->P2PProtocol::send(BinaryArray(data)); // Move is impossible here
//}

bool Node::on_get_status(http::Client *who, http::RequestData &&raw_request, json_rpc::Request &&raw_js_request,
    api::bytecoind::GetStatus::Request &&req, api::bytecoind::GetStatus::Response &res) {
	res = create_status_response();
	if (!res.ready_for_longpoll(req)) {
		//		m_log(logging::INFO) << "on_get_status will long poll, json="
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

api::bytecoind::GetStatistics::Response Node::create_statistics_response() const {
	api::bytecoind::GetStatistics::Response res;
	res.peer_id = m_p2p.get_unique_number();
	for (auto &&p : broadcast_protocols_new) {
		np::ConnectionDesc desc;
		desc.address        = p->get_address();
		desc.is_incoming    = p->is_incoming();
		desc.p2p_version    = p->get_other_peer_desc().p2p_version;
		desc.peer_id        = p->get_other_peer_desc().peer_id;
		desc.top_block_desc = p->get_other_top_block_desc();
		res.connections.push_back(desc);
	}
	for (auto &&p : broadcast_protocols) {
		np::ConnectionDesc desc;
		desc.address               = p->get_address();
		desc.is_incoming           = p->is_incoming();
		desc.p2p_version           = p->get_version();
		desc.peer_id               = p->get_last_received_unique_number();
		desc.top_block_desc.hash   = p->get_last_received_sync_data().top_id;
		desc.top_block_desc.height = p->get_last_received_sync_data().current_height;
		res.connections.push_back(desc);
	}
	res.platform           = platform::get_platform_name();
	res.version            = bytecoin::app_version();
	res.net                = m_config.net;
	res.genesis_block_hash = m_block_chain.get_currency().genesis_block_hash;
	res.start_time         = m_start_time;
	m_block_chain.fill_statistics(res);
	return res;
}

bool Node::on_get_statistics(http::Client *, http::RequestData &&http_request, json_rpc::Request &&,
    api::bytecoind::GetStatistics::Request &&, api::bytecoind::GetStatistics::Response &res) {
	bool good_auth_private = m_config.bytecoind_authorization_private.empty() ||
	                         http_request.r.basic_authorization == m_config.bytecoind_authorization_private;
	if (!good_auth_private)
		throw http::ErrorAuthorization("Statistics");
	res = create_statistics_response();
	return true;
}

bool Node::on_get_archive(http::Client *, http::RequestData &&http_request, json_rpc::Request &&,
    api::bytecoind::GetArchive::Request &&req, api::bytecoind::GetArchive::Response &resp) {
	bool good_auth_private = m_config.bytecoind_authorization_private.empty() ||
	                         http_request.r.basic_authorization == m_config.bytecoind_authorization_private;
	if (!good_auth_private)
		throw http::ErrorAuthorization("Archive");
	m_block_chain.read_archive(std::move(req), resp);
	return true;
}

static void fill_transaction_info(const TransactionPrefix &tx, api::Transaction *api_tx) {
	api_tx->unlock_block_or_timestamp = tx.unlock_block_or_timestamp;
	api_tx->extra                     = tx.extra;
	api_tx->anonymity                 = std::numeric_limits<uint32_t>::max();
	api_tx->public_key                = extra_get_transaction_public_key(tx.extra);
	extra_get_payment_id(tx.extra, api_tx->payment_id);
	Amount input_amount = 0;
	for (const auto &input : tx.inputs) {
		if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			api_tx->anonymity  = std::min(api_tx->anonymity, static_cast<uint32_t>(in.output_indexes.size() - 1));
			input_amount += in.amount;
		}
	}
	Amount output_amount = 0;
	for (const auto &output : tx.outputs) {
		if (output.target.type() == typeid(KeyOutput)) {
			//			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			output_amount += output.amount;
		}
	}
	api_tx->amount = output_amount;
	if (input_amount >= output_amount)
		api_tx->fee = input_amount - output_amount;
	if (api_tx->anonymity == std::numeric_limits<uint32_t>::max())
		api_tx->anonymity = 0;  // No key inputs
}

bool Node::on_sync_blocks(http::Client *, http::RequestData &&, json_rpc::Request &&json_req,
    api::bytecoind::SyncBlocks::Request &&req, api::bytecoind::SyncBlocks::Response &res) {
	if (req.sparse_chain.empty())
		throw std::runtime_error("Empty sparse chain - must include at least genesis block");
	if (req.sparse_chain.back() != m_block_chain.get_genesis_bid())
		throw std::runtime_error(
		    "Wrong currency - different genesis block. Must be " + common::pod_to_hex(m_block_chain.get_genesis_bid()));
	if (req.max_count > api::bytecoind::SyncBlocks::Request::MAX_COUNT)
		throw std::runtime_error(
		    "Too big max_count - must be <= " + common::to_string(api::bytecoind::SyncBlocks::Request::MAX_COUNT));
	auto first_block_timestamp = req.first_block_timestamp < m_block_chain.get_currency().block_future_time_limit
	                                 ? 0
	                                 : req.first_block_timestamp - m_block_chain.get_currency().block_future_time_limit;
	Height full_offset = m_block_chain.get_timestamp_lower_bound_height(first_block_timestamp);
	Height start_height;
	std::vector<Hash> supplement = m_block_chain.get_sync_headers_chain(req.sparse_chain, &start_height, req.max_count);
	if (full_offset >= start_height + supplement.size()) {
		start_height = full_offset;
		supplement.clear();
		while (supplement.size() < req.max_count) {
			Hash ha;
			if (!m_block_chain.read_chain(start_height + static_cast<Height>(supplement.size()), &ha))
				break;
			supplement.push_back(ha);
		}
	} else if (full_offset > start_height) {
		supplement.erase(supplement.begin(), supplement.begin() + (full_offset - start_height));
		start_height = full_offset;
	}

	res.start_height = start_height;
	res.blocks.resize(supplement.size());
	for (size_t i = 0; i != supplement.size(); ++i) {
		const auto bhash = supplement[i];
		auto &res_block  = res.blocks[i];
		invariant(
		    m_block_chain.read_header(bhash, &res_block.header), "Block header must be there, but it is not there");
		m_block_chain.fix_block_sizes(&res_block.header);
		//		BlockChainState::BlockGlobalIndices output_indexes;
		// if (res.blocks[i].header.timestamp >= req.first_block_timestamp) //
		// commented out becuase empty Block cannot be serialized
		{
			RawBlock rb;
			invariant(m_block_chain.read_block(bhash, &rb), "Block must be there, but it is not there");
			Block block;
			invariant(block.from_raw_block(rb), "RawBlock failed to convert into block");
			res_block.transactions.resize(block.transactions.size() + 1);
			res_block.transactions.at(0).hash = get_transaction_hash(block.header.base_transaction);
			res_block.transactions.at(0).size =
			    static_cast<uint32_t>(seria::binary_size(block.header.base_transaction));
			if (req.need_redundant_data) {
				fill_transaction_info(block.header.base_transaction, &res_block.transactions.at(0));
				res_block.transactions.at(0).block_height = start_height + static_cast<uint32_t>(i);
				res_block.transactions.at(0).block_hash   = bhash;
				res_block.transactions.at(0).coinbase     = true;
				res_block.transactions.at(0).timestamp    = block.header.timestamp;
			}
			res_block.raw_header = std::move(block.header);
			res_block.raw_transactions.reserve(block.transactions.size());
			for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
				res_block.transactions.at(tx_index + 1).hash = res_block.raw_header.transaction_hashes.at(tx_index);
				res_block.transactions.at(tx_index + 1).size =
				    static_cast<uint32_t>(rb.transactions.at(tx_index).size());
				if (req.need_redundant_data) {
					fill_transaction_info(block.transactions.at(tx_index), &res_block.transactions.at(tx_index + 1));
					res_block.transactions.at(tx_index + 1).block_height = start_height + static_cast<uint32_t>(i);
					res_block.transactions.at(tx_index + 1).block_hash   = bhash;
					res_block.transactions.at(tx_index + 1).timestamp    = res_block.raw_header.timestamp;
				}
				if (req.need_signatures)
					res_block.signatures.push_back(std::move(block.transactions.at(tx_index).signatures));
				res_block.raw_transactions.push_back(std::move(block.transactions.at(tx_index)));
			}
			invariant(m_block_chain.read_block_output_global_indices(bhash, &res_block.output_indexes),
			    "Invariant dead - bid is in chain but blockchain has no block indices");
		}
	}
	res.status = create_status_response();
	return true;
}

bool Node::on_sync_mempool(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::SyncMemPool::Request &&req, api::bytecoind::SyncMemPool::Response &res) {
	const auto &pool = m_block_chain.get_memory_state_transactions();
	for (auto &&ex : req.known_hashes)
		if (pool.count(ex) == 0)
			res.removed_hashes.push_back(ex);
	for (auto &&tx : pool)
		if (!std::binary_search(req.known_hashes.begin(), req.known_hashes.end(), tx.first)) {
			res.added_raw_transactions.push_back(tx.second.tx);
			if (req.need_signatures)
				res.added_signatures.push_back(tx.second.tx.signatures);
			res.added_transactions.push_back(api::Transaction{});
			if (req.need_redundant_data)
				fill_transaction_info(tx.second.tx, &res.added_transactions.back());
			res.added_transactions.back().hash      = tx.first;
			res.added_transactions.back().timestamp = tx.second.timestamp;
			res.added_transactions.back().fee       = tx.second.fee;
			res.added_transactions.back().size      = static_cast<uint32_t>(tx.second.binary_tx.size());
		}
	res.status = create_status_response();
	return true;
}

bool Node::on_get_block_header(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::GetBlockHeader::Request &&request, api::bytecoind::GetBlockHeader::Response &response) {
	if (request.hash != Hash{} && request.height_or_depth != std::numeric_limits<api::HeightOrDepth>::max())
		throw json_rpc::Error(
		    json_rpc::INVALID_REQUEST, "You cannot specify both hash and height_or_depth to this method");
	if (request.hash != Hash{}) {
		if (!m_block_chain.read_header(request.hash, &response.block_header))
			throw api::ErrorHashNotFound("Block not found in either main or side chains", request.hash);
	} else {
		Height height_or_depth =
		    api::ErrorWrongHeight::fix_height_or_depth(request.height_or_depth, m_block_chain.get_tip_height(), true, true);
		invariant(
		    m_block_chain.read_chain(height_or_depth, &request.hash), "");  // after fix_height it must always succeed
		invariant(m_block_chain.read_header(request.hash, &response.block_header), "");
	}
	m_block_chain.fix_block_sizes(&response.block_header);
	response.orphan_status = !m_block_chain.in_chain(response.block_header.height, response.block_header.hash);
	response.depth =
	    api::HeightOrDepth(response.block_header.height) - api::HeightOrDepth(m_block_chain.get_tip_height()) - 1;
	return true;
}
bool Node::on_get_raw_block(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::GetRawBlock::Request &&request, api::bytecoind::GetRawBlock::Response &response) {
	if (request.hash != Hash{} && request.height_or_depth != std::numeric_limits<api::HeightOrDepth>::max())
		throw json_rpc::Error(
		    json_rpc::INVALID_REQUEST, "You cannot specify both hash and height_or_depth to this method");
	if (request.hash != Hash{}) {
		if (!m_block_chain.read_header(request.hash, &response.block.header))
			throw api::ErrorHashNotFound("Block not found in either main or side chains", request.hash);
	} else {
		Height height_or_depth =
		    api::ErrorWrongHeight::fix_height_or_depth(request.height_or_depth, m_block_chain.get_tip_height(), true, true);
		invariant(
		    m_block_chain.read_chain(height_or_depth, &request.hash), "");  // after fix_height it must always succeed
		invariant(m_block_chain.read_header(request.hash, &response.block.header), "");
	}
	m_block_chain.fix_block_sizes(&response.block.header);

	//	BlockChainState::BlockGlobalIndices output_indexes;
	RawBlock rb;
	invariant(m_block_chain.read_block(request.hash, &rb), "Block must be there, but it is not there");
	Block block;
	invariant(block.from_raw_block(rb), "RawBlock failed to convert into block");

	api::RawBlock &b = response.block;
	b.transactions.resize(block.transactions.size() + 1);
	b.transactions.at(0).hash = get_transaction_hash(block.header.base_transaction);
	b.transactions.at(0).size = static_cast<uint32_t>(seria::binary_size(block.header.base_transaction));
	fill_transaction_info(block.header.base_transaction, &b.transactions.at(0));
	b.transactions.at(0).block_height = b.header.height;
	b.transactions.at(0).block_hash   = b.header.hash;
	b.transactions.at(0).coinbase     = true;
	b.transactions.at(0).timestamp    = block.header.timestamp;
	b.raw_header                      = std::move(block.header);
	b.raw_transactions.reserve(block.transactions.size());
	for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
		b.transactions.at(tx_index + 1).hash = b.raw_header.transaction_hashes.at(tx_index);
		b.transactions.at(tx_index + 1).size = static_cast<uint32_t>(rb.transactions.at(tx_index).size());
		fill_transaction_info(block.transactions.at(tx_index), &b.transactions.at(tx_index + 1));
		b.transactions.at(tx_index + 1).block_height = b.header.height;
		b.transactions.at(tx_index + 1).block_hash   = b.header.hash;
		b.transactions.at(tx_index + 1).timestamp    = b.raw_header.timestamp;
		if (request.need_signatures)
			b.signatures.push_back(std::move(block.transactions.at(tx_index).signatures));
		b.raw_transactions.push_back(std::move(block.transactions.at(tx_index)));
	}
	m_block_chain.read_block_output_global_indices(request.hash, &b.output_indexes);
	// If block not in main chain - global indices will be empty
	response.orphan_status = !m_block_chain.in_chain(b.header.height, b.header.hash);
	response.depth = api::HeightOrDepth(b.header.height) - api::HeightOrDepth(m_block_chain.get_tip_height()) - 1;
	return true;
}

bool Node::on_get_raw_transaction(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::GetRawTransaction::Request &&req, api::bytecoind::GetRawTransaction::Response &res) {
	const auto &pool = m_block_chain.get_memory_state_transactions();
	auto tit         = pool.find(req.hash);
	if (tit != pool.end()) {
		res.raw_transaction = static_cast<TransactionPrefix>(tit->second.tx);
		if (req.need_signatures)
			res.signatures = tit->second.tx.signatures;
		fill_transaction_info(tit->second.tx, &res.transaction);
		res.transaction.fee          = tit->second.fee;
		res.transaction.hash         = req.hash;
		res.transaction.block_height = m_block_chain.get_tip_height() + 1;
		res.transaction.timestamp    = tit->second.timestamp;
		res.transaction.size         = static_cast<uint32_t>(tit->second.binary_tx.size());
		return true;
	}
	BinaryArray binary_tx;
	Transaction tx;
	size_t index_in_block = 0;
	if (m_block_chain.read_transaction(
	        req.hash, &binary_tx, &res.transaction.block_height, &res.transaction.block_hash, &index_in_block)) {
		res.transaction.size = static_cast<uint32_t>(binary_tx.size());
		seria::from_binary(tx, binary_tx);
		res.raw_transaction = static_cast<TransactionPrefix>(tx);  // TODO - std::move?
		if (req.need_signatures)
			res.signatures = tx.signatures;
		fill_transaction_info(tx, &res.transaction);
		res.transaction.hash = req.hash;
		res.transaction.fee  = get_tx_fee(res.raw_transaction);  // 0 for coinbase
		return true;
	}
	throw api::ErrorHashNotFound(
	    "Transaction not found in main chain. You cannot get transactions from side chains with this method.",
	    req.hash);
}

bool Node::handle_send_transaction(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::SendTransaction::Request &&request, api::bytecoind::SendTransaction::Response &response) {
	response.send_result = "broadcast";

	NOTIFY_NEW_TRANSACTIONS::request msg;
	Height conflict_height =
	    m_block_chain.get_currency().max_block_height;  // So will not be accidentally viewed as confirmed
	Transaction tx;
	try {
		seria::from_binary(tx, request.binary_transaction);
	} catch (const std::exception &ex) {
		std::throw_with_nested(api::bytecoind::SendTransaction::Error(
		    api::bytecoind::SendTransaction::INVALID_TRANSACTION_BINARY_FORMAT, common::what(ex), conflict_height));
	}
	const Hash tid = get_transaction_hash(tx);
	auto action    = m_block_chain.add_transaction(
	    tid, tx, request.binary_transaction, m_p2p.get_local_time(), &conflict_height, "json_rpc");
	switch (action) {
	case AddTransactionResult::BAN:
		throw json_rpc::Error(
		    api::bytecoind::SendTransaction::INVALID_TRANSACTION_BINARY_FORMAT, "Binary transaction format is wrong");
	case AddTransactionResult::BROADCAST_ALL: {
		msg.txs.push_back(request.binary_transaction);
		BinaryArray raw_msg =
		    LevinProtocol::send_message(NOTIFY_NEW_TRANSACTIONS::ID, LevinProtocol::encode(msg), false);
		broadcast(nullptr, raw_msg);
		//		broadcast_new(nullptr, ); // TODO - broadcast transaction
		advance_long_poll();
		break;
	}
	case AddTransactionResult::ALREADY_IN_POOL:
		break;
	case AddTransactionResult::INCREASE_FEE:
		break;
	case AddTransactionResult::FAILED_TO_REDO:
		throw api::bytecoind::SendTransaction::Error(api::bytecoind::SendTransaction::WRONG_OUTPUT_REFERENCE,
		    "Transaction references outputs changed during reorganization or signature wrong", conflict_height);
	case AddTransactionResult::OUTPUT_ALREADY_SPENT:
		throw api::bytecoind::SendTransaction::Error(api::bytecoind::SendTransaction::OUTPUT_ALREADY_SPENT,
		    "One of referenced outputs is already spent", conflict_height);
	}
	return true;
}

bool Node::handle_check_sendproof(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::CheckSendproof::Request &&request, api::bytecoind::CheckSendproof::Response &response) {
	SendProof sp;
	try {
		seria::from_json_value(sp, common::JsonValue::from_string(request.sendproof), m_block_chain.get_currency());
//		seria::JsonInputStreamValue s();
//		s.begin_object();
//		ser_members(sp, s, );
//		s.end_object();
	} catch (const std::exception &ex) {
		std::throw_with_nested(api::bytecoind::CheckSendproof::Error(api::bytecoind::CheckSendproof::FAILED_TO_PARSE,
		    "Failed to parse proof object ex.what=" + common::what(ex)));
	}
	BinaryArray binary_tx;
	Height height = 0;
	Hash block_hash;
	size_t index_in_block = 0;
	if (!m_block_chain.read_transaction(sp.transaction_hash, &binary_tx, &height, &block_hash, &index_in_block)) {
		throw api::bytecoind::CheckSendproof::Error(
		    api::bytecoind::CheckSendproof::NOT_IN_MAIN_CHAIN, "Transaction is not in main chain");
	}
	Transaction tx;
	seria::from_binary(tx, binary_tx);
	PublicKey tx_public_key = extra_get_transaction_public_key(tx.extra);
	Hash message_hash       = crypto::cn_fast_hash(sp.message.data(), sp.message.size());
	if (!crypto::check_sendproof(
	        tx_public_key, sp.address.view_public_key, sp.derivation, message_hash, sp.signature)) {
		throw api::bytecoind::CheckSendproof::Error(api::bytecoind::CheckSendproof::WRONG_SIGNATURE,
		    "Proof object does not match transaction or was tampered with");
	}
	Amount total_amount = 0;
	size_t key_index    = 0;
	uint32_t out_index  = 0;
	for (const auto &output : tx.outputs) {
		if (output.target.type() == typeid(KeyOutput)) {
			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			PublicKey spend_key;
			if (underive_public_key(sp.derivation, key_index, key_output.public_key, spend_key) &&
			    spend_key == sp.address.spend_public_key) {
				total_amount += output.amount;
			}
			++key_index;
		}
		++out_index;
	}
	if (total_amount == 0)
		throw api::bytecoind::CheckSendproof::Error(api::bytecoind::CheckSendproof::ADDRESS_NOT_IN_TRANSACTION,
		    "No outputs found in transaction for the address being proofed");
	if (total_amount != sp.amount)
		throw api::bytecoind::CheckSendproof::Error(api::bytecoind::CheckSendproof::WRONG_AMOUNT,
		    "Wrong amount in outputs, actual amount is " + common::to_string(total_amount));
	response.transaction_hash = sp.transaction_hash;
	response.address          = m_block_chain.get_currency().account_address_as_string(sp.address);
	response.message          = sp.message;
	response.amount           = sp.amount;
	return true;
}

void Node::submit_block(const BinaryArray &blockblob, api::BlockHeader *info) {
	BlockTemplate block_template;
	seria::from_binary(block_template, blockblob);
	RawBlock raw_block;
	//	api::BlockHeader info;
	auto broad = m_block_chain.add_mined_block(blockblob, &raw_block, info);
	if (broad == BroadcastAction::BAN)
		throw json_rpc::Error{api::bytecoind::SubmitBlock::BLOCK_NOT_ACCEPTED, "Block not accepted"};
	NOTIFY_NEW_BLOCK::request msg;
	msg.b                         = RawBlockLegacy{raw_block.block, raw_block.transactions};
	msg.hop                       = 1;
	msg.current_blockchain_height = m_block_chain.get_tip_height() + 1;  // TODO check
	BinaryArray raw_msg = LevinProtocol::send_message(NOTIFY_NEW_BLOCK::ID, LevinProtocol::encode(msg), false);
	broadcast(nullptr, raw_msg);
	broadcast_new(nullptr, blockblob);
	advance_long_poll();
}

bool Node::on_submitblock(http::Client *, http::RequestData &&, json_rpc::Request &&,
    api::bytecoind::SubmitBlock::Request &&req, api::bytecoind::SubmitBlock::Response &res) {
	submit_block(req.blocktemplate_blob, &res.block_header);
	res.orphan_status = !m_block_chain.in_chain(res.block_header.height, res.block_header.hash);
	res.depth = api::HeightOrDepth(res.block_header.height) - api::HeightOrDepth(m_block_chain.get_tip_height()) - 1;
	return true;
}
