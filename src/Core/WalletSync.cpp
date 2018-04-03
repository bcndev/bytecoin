// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletSync.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

constexpr float STATUS_POLL_PERIOD  = 0.1f;
constexpr float STATUS_ERROR_PERIOD = 5;

using namespace bytecoin;

WalletSync::WalletSync(
    logging::ILogger &log, const Config &config, WalletState &wallet_state, std::function<void()> state_changed_handler)
    : m_state_changed_handler(state_changed_handler)
    , m_log(log, "WalletSync")
    , m_config(config)
    , m_sync_error("CONNECTING")
    , m_status_timer(std::bind(&WalletSync::send_get_status, this))
    , m_sync_agent(config.bytecoind_remote_ip,
          config.bytecoind_remote_port ? config.bytecoind_remote_port : config.bytecoind_bind_port)
    , m_commands_agent(config.bytecoind_remote_ip,
          config.bytecoind_remote_port ? config.bytecoind_remote_port : config.bytecoind_bind_port)
    , m_wallet_state(wallet_state)
    , m_commit_timer(std::bind(&WalletSync::db_commit, this)) {
	advance_sync();
	m_commit_timer.once(DB_COMMIT_PERIOD_WALLET_CACHE);
}

void WalletSync::db_commit() {
	m_wallet_state.db_commit();
	m_commit_timer.once(DB_COMMIT_PERIOD_WALLET_CACHE);
}

void WalletSync::send_get_status() {
	api::bytecoind::GetStatus::Request req;
	req.top_block_hash           = m_wallet_state.get_tip_bid();
	req.transaction_pool_version = m_wallet_state.get_tx_pool_version();
	req.outgoing_peer_count      = m_last_node_status.outgoing_peer_count;
	req.incoming_peer_count      = m_last_node_status.incoming_peer_count;
	req.lower_level_error        = m_last_node_status.lower_level_error;
	json_rpc::Request json_send_raw_req;
	json_send_raw_req.set_method(api::bytecoind::GetStatus::method());
	json_send_raw_req.set_params(req);
	http::RequestData req_header;
	req_header.r.set_firstline("POST", api::bytecoind::url(), 1, 1);
	req_header.r.basic_authorization = m_config.bytecoind_authorization;
	req_header.set_body(json_send_raw_req.get_body());

	m_sync_request.reset(new http::Request(m_sync_agent, std::move(req_header),
	    [&](http::ResponseData &&response) {
		    m_sync_request.reset();
		    if (response.r.status == 504) {  // Common for longpoll
			    advance_sync();
			    return;
		    }
		    api::bytecoind::GetStatus::Response resp;
		    json_rpc::parse_response(response.body, resp);
		    m_last_node_status = resp;
		    m_sync_error       = std::string();
		    m_state_changed_handler();
		    advance_sync();
		},
	    [&](std::string err) {
		    m_sync_error = "CONNECTION_FAILED";
		    m_status_timer.once(STATUS_ERROR_PERIOD);
		    m_state_changed_handler();
		}));
}

void WalletSync::advance_sync() {
	const Timestamp now = static_cast<Timestamp>(time(nullptr));
	if (!prevent_sleep && m_wallet_state.get_tip().timestamp < now - 86400)
		prevent_sleep = std::make_unique<platform::PreventSleep>("Synchronizing wallet");
	if (prevent_sleep &&
	    m_wallet_state.get_tip().timestamp > now - m_wallet_state.get_currency().block_future_time_limit * 2)
		prevent_sleep = nullptr;
	if (m_sync_request)
		return;
	if (m_last_node_status.top_block_hash == m_wallet_state.get_tip_bid() &&
	    m_last_node_status.transaction_pool_version == m_wallet_state.get_tx_pool_version()) {
		m_status_timer.once(STATUS_POLL_PERIOD);
		return;
	}
	if (m_last_node_status.top_block_hash != m_wallet_state.get_tip_bid()) {
		send_get_blocks();
		return;
	}
	if (transient_transactions_counter == 0)
		send_sync_pool();
}

void WalletSync::send_sync_pool() {
	api::bytecoind::SyncMemPool::Request msg;
	msg.known_hashes = m_wallet_state.get_tx_pool_hashes();
	http::RequestData req_header;
	req_header.r.set_firstline("POST", api::bytecoind::SyncMemPool::bin_method(), 1, 1);
	req_header.r.basic_authorization = m_config.bytecoind_authorization;
	req_header.set_body(seria::to_binary_str(msg));
	m_sync_request = std::make_unique<http::Request>(m_sync_agent, std::move(req_header),
	    [&](http::ResponseData &&response) {
		    m_sync_request.reset();
		    api::bytecoind::SyncMemPool::Response resp;
		    seria::from_binary(resp, response.body);
		    m_last_node_status = resp.status;
		    m_sync_error       = "WRONG_BLOCKCHAIN";
		    if (m_wallet_state.sync_with_blockchain(resp)) {
			    m_sync_error = std::string();
			    advance_sync();
		    } else
			    m_status_timer.once(STATUS_ERROR_PERIOD);
		    m_state_changed_handler();
		},
	    [&](std::string err) {
		    m_sync_error = "CONNECTION_FAILED";
		    m_status_timer.once(STATUS_ERROR_PERIOD);
		    m_state_changed_handler();
		});
	//	m_log(logging::INFO) << "WalletNode::send_sync_pool" << std::endl;
}

void WalletSync::send_get_blocks() {
	api::bytecoind::SyncBlocks::Request msg;
	msg.sparse_chain          = m_wallet_state.get_sparse_chain();
	msg.first_block_timestamp = m_wallet_state.get_wallet().get_oldest_timestamp();
	http::RequestData req_header;
	req_header.r.set_firstline("POST", api::bytecoind::SyncBlocks::bin_method(), 1, 1);
	req_header.r.basic_authorization = m_config.bytecoind_authorization;
	req_header.set_body(seria::to_binary_str(msg));
	m_sync_request = std::make_unique<http::Request>(m_sync_agent, std::move(req_header),
	    [&](http::ResponseData &&response) {
		    m_sync_request.reset();
		    api::bytecoind::SyncBlocks::Response resp;
		    seria::from_binary(resp, response.body);
		    m_last_node_status = resp.status;
		    m_sync_error       = "WRONG_BLOCKCHAIN";
		    if (m_wallet_state.sync_with_blockchain(resp)) {
			    m_sync_error = std::string();
			    advance_sync();
		    } else
			    m_status_timer.once(STATUS_ERROR_PERIOD);
		    m_state_changed_handler();
		},
	    [&](std::string err) {
		    m_sync_error = "CONNECTION_FAILED";
		    m_status_timer.once(STATUS_ERROR_PERIOD);
		    m_state_changed_handler();
		});
	//	m_log(logging::INFO) << "WalletNode::send_get_blocks" << std::endl;
}
