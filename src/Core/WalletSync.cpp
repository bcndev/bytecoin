// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletSync.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "platform/Time.hpp"
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
	m_commit_timer.once(m_config.db_commit_period_wallet_cache);
}

void WalletSync::db_commit() {
	m_wallet_state.db_commit();
	m_commit_timer.once(m_config.db_commit_period_wallet_cache);
}

void WalletSync::send_get_status() {
	api::bytecoind::GetStatus::Request req;
	req.top_block_hash           = m_wallet_state.get_tip_bid();
	req.transaction_pool_version = m_wallet_state.get_tx_pool_version();
	req.outgoing_peer_count      = m_last_node_status.outgoing_peer_count;
	req.incoming_peer_count      = m_last_node_status.incoming_peer_count;
	req.lower_level_error        = m_last_node_status.lower_level_error;

	http::RequestData req_header =
	    json_rpc::create_request(api::bytecoind::url(), api::bytecoind::GetStatus::method(), req);
	req_header.r.basic_authorization = m_config.bytecoind_authorization;

	m_sync_request = std::make_unique<http::Request>(m_sync_agent, std::move(req_header),
	    [&](http::ResponseData &&response) {
		    m_sync_request.reset();
		    if (response.r.status == 504) {  // Common for longpoll
			    advance_sync();
		    } else if (response.r.status == 401) {
			    m_sync_error = "AUTHORIZATION_FAILED";
			    m_log(logging::INFO) << "Wrong daemon password - please check --bytecoind-authorization" << std::endl;
			    m_status_timer.once(STATUS_ERROR_PERIOD);
		    } else {
			    api::bytecoind::GetStatus::Response resp;
			    json_rpc::Error error;
			    if (json_rpc::parse_response(response.body, resp, error)) {
				    m_last_node_status = resp;
				    m_sync_error       = std::string();
				    m_state_changed_handler();
				    advance_sync();
			    } else {
				    m_log(logging::INFO) << "GetStatus request RPC error code=" << error.code
				                         << " message=" << error.message << std::endl;
				    m_status_timer.once(STATUS_ERROR_PERIOD);
			    }
		    }
		},
	    [&](std::string err) {
		    m_sync_error = "CONNECTION_FAILED";
		    m_status_timer.once(STATUS_ERROR_PERIOD);
		    m_state_changed_handler();
		});
}

void WalletSync::advance_sync() {
	const Timestamp now = platform::now_unix_timestamp();
	if (!prevent_sleep && m_wallet_state.get_tip().timestamp < now - 86400) {
		m_log(logging::INFO) << "Preventing computer sleep to sync wallet" << std::endl;
		prevent_sleep = std::make_unique<platform::PreventSleep>("Synchronizing wallet");
	}
	if (prevent_sleep &&
	    m_wallet_state.get_tip().timestamp > now - m_wallet_state.get_currency().block_future_time_limit * 2) {
		m_log(logging::INFO) << "Allowing computer sleep after sync wallet" << std::endl;
		prevent_sleep = nullptr;
	}
	if (m_sync_request)
		return;
	if (m_last_node_status.top_block_hash != m_wallet_state.get_tip_bid()) {
		next_send_hash = Hash{};  // We start sending again after new block
		send_get_blocks();
		return;
	}
	if (send_send_transaction())
		return;
	if (m_last_node_status.transaction_pool_version == m_wallet_state.get_tx_pool_version()) {
		m_status_timer.once(STATUS_POLL_PERIOD);
		return;
	}
	send_sync_pool();
}

void WalletSync::send_sync_pool() {
	m_log(logging::TRACE) << "Sending SyncMemPool request" << std::endl;
	api::bytecoind::SyncMemPool::Request msg;
	msg.known_hashes = m_wallet_state.get_tx_pool_hashes();
	http::RequestData req_header;
	req_header.r.set_firstline("POST", api::bytecoind::binary_url(), 1, 1);
	req_header.r.basic_authorization = m_config.bytecoind_authorization;
	req_header.set_body(json_rpc::create_binary_request_body(api::bytecoind::SyncMemPool::method(), msg));
	m_sync_request = std::make_unique<http::Request>(m_sync_agent, std::move(req_header),
	    [&](http::ResponseData &&response) {
		    m_sync_request.reset();
		    m_log(logging::TRACE) << "Received SyncMemPool response status=" << response.r.status << std::endl;
		    if (response.r.status == 401) {
			    m_sync_error = "AUTHORIZATION_FAILED";
			    m_log(logging::INFO) << "Wrong daemon password - please check --bytecoind-authorization" << std::endl;
			    m_status_timer.once(STATUS_ERROR_PERIOD);
		    } else if (response.r.status == 200) {
			    m_sync_error = "WRONG_BLOCKCHAIN";
			    api::bytecoind::SyncMemPool::Response resp;
			    json_rpc::Error error;
			    if (json_rpc::parse_binary_response(response.body, resp, error)) {
				    m_last_node_status = resp.status;
				    if (m_wallet_state.sync_with_blockchain(resp)) {
					    m_sync_error = std::string();
					    advance_sync();
				    } else
					    m_status_timer.once(STATUS_ERROR_PERIOD);
			    } else {
				    m_log(logging::INFO) << "SyncMemPool request RPC error code=" << error.code
				                         << " message=" << error.message << std::endl;
				    m_status_timer.once(STATUS_ERROR_PERIOD);
			    }
		    } else {
			    m_sync_error = response.body;
			    m_status_timer.once(STATUS_ERROR_PERIOD);
		    }
		    m_state_changed_handler();
		},
	    [&](std::string err) {
		    m_log(logging::TRACE) << "SyncMemPool request error " << err << std::endl;
		    m_sync_error = "CONNECTION_FAILED";
		    m_status_timer.once(STATUS_ERROR_PERIOD);
		    m_state_changed_handler();
		});
	//	m_log(logging::INFO) << "WalletNode::send_sync_pool" << std::endl;
}

void WalletSync::send_get_blocks() {
	m_log(logging::TRACE) << "Sending SyncBlocks request" << std::endl;
	api::bytecoind::SyncBlocks::Request msg;
	msg.sparse_chain          = m_wallet_state.get_sparse_chain();
	msg.first_block_timestamp = m_wallet_state.get_wallet().get_oldest_timestamp();
	msg.need_redundant_data   = false;
	http::RequestData req_header;
	req_header.r.set_firstline("POST", api::bytecoind::binary_url(), 1, 1);
	req_header.r.basic_authorization = m_config.bytecoind_authorization;
	req_header.set_body(json_rpc::create_binary_request_body(api::bytecoind::SyncBlocks::method(), msg));
	m_sync_request = std::make_unique<http::Request>(m_sync_agent, std::move(req_header),
	    [&](http::ResponseData &&response) {
		    m_sync_request.reset();
		    m_log(logging::TRACE) << "Received SyncBlocks response status=" << response.r.status << std::endl;
		    if (response.r.status == 401) {
			    m_sync_error = "AUTHORIZATION_FAILED";
			    m_log(logging::INFO) << "Wrong daemon password - please check --bytecoind-authorization" << std::endl;
			    m_status_timer.once(STATUS_ERROR_PERIOD);
		    } else if (response.r.status == 200) {
			    m_sync_error = "WRONG_BLOCKCHAIN";
			    api::bytecoind::SyncBlocks::Response resp;
			    json_rpc::Error error;
			    if (json_rpc::parse_binary_response(response.body, resp, error)) {
				    m_last_node_status = resp.status;
				    if (m_wallet_state.sync_with_blockchain(resp)) {
					    m_sync_error = std::string();
					    advance_sync();
				    } else
					    m_status_timer.once(STATUS_ERROR_PERIOD);
			    } else {
				    m_log(logging::INFO) << "SyncBlocks request RPC error code=" << error.code
				                         << " message=" << error.message << std::endl;
				    m_status_timer.once(STATUS_ERROR_PERIOD);
			    }
		    } else {
			    m_sync_error = response.body;
			    m_status_timer.once(STATUS_ERROR_PERIOD);
		    }
		    m_state_changed_handler();
		},
	    [&](std::string err) {
		    m_log(logging::TRACE) << "SyncBlocks request error " << err << std::endl;
		    m_sync_error = "CONNECTION_FAILED";
		    m_status_timer.once(STATUS_ERROR_PERIOD);
		    m_state_changed_handler();
		});
	//	m_log(logging::INFO) << "WalletNode::send_get_blocks" << std::endl;
}

bool WalletSync::send_send_transaction() {
	api::bytecoind::SendTransaction::Request msg;
	msg.binary_transaction = m_wallet_state.get_next_from_sending_queue(&next_send_hash);
	if (msg.binary_transaction.empty())
		return false;
	sending_transaction_hash = next_send_hash;
	m_log(logging::INFO) << "Sending transaction from payment queue " << sending_transaction_hash << std::endl;
	http::RequestData new_request =
	    json_rpc::create_request(api::bytecoind::url(), api::bytecoind::SendTransaction::method(), msg);
	new_request.r.basic_authorization = m_config.bytecoind_authorization;
	m_sync_request                    = std::make_unique<http::Request>(m_sync_agent, std::move(new_request),
	    [&](http::ResponseData &&response) {
		    m_sync_request.reset();
		    m_log(logging::TRACE) << "Received send_transaction response status=" << response.r.status << std::endl;
		    if (response.r.status == 401) {
			    m_sync_error = "AUTHORIZATION_FAILED";
			    m_log(logging::INFO) << "Wrong daemon password - please check --bytecoind-authorization" << std::endl;
			    m_status_timer.once(STATUS_ERROR_PERIOD);
		    } else if (response.r.status == 200) {
			    m_sync_error = "SEND_ERROR";
			    api::bytecoind::SendTransaction::Response resp;
			    api::bytecoind::SendTransaction::Error error;
			    if (json_rpc::parse_response(response.body, resp, error)) {
				    m_log(logging::INFO) << "Success sending transaction from payment queue with result "
				                         << resp.send_result << std::endl;
				    m_sync_error = std::string();
			    } else {
				    m_log(logging::INFO) << "Json Error sending transaction from payment queue conflict height="
				                         << error.conflict_height << " code=" << error.code << " msg=" << error.message
				                         << std::endl;
				    m_wallet_state.process_payment_queue_send_error(sending_transaction_hash, error);
			    }
			    advance_sync();
		    } else {
			    m_log(logging::INFO) << "Error sending transaction from payment queue " << response.body << std::endl;
			    m_sync_error = response.body;
			    m_status_timer.once(STATUS_ERROR_PERIOD);
		    }
		    m_state_changed_handler();
		},
	    [&](std::string err) {
		    m_log(logging::INFO) << "Error sending transaction from payment queue " << err << std::endl;
		    m_status_timer.once(STATUS_ERROR_PERIOD);
		    m_state_changed_handler();
		});
	//	m_log(logging::INFO) << "WalletNode::send_get_blocks" << std::endl;
	return true;
}
