// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletSync.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "platform/PreventSleep.hpp"
#include "platform/Time.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

constexpr float STATUS_POLL_PERIOD  = 0.1f;  // Do not send get_status more often, saves CPU resources
constexpr float STATUS_ERROR_PERIOD = 5;

using namespace cn;

WalletSync::WalletSync(logging::ILogger &log, const Config &config, WalletState &wallet_state,
    std::function<void()> &&state_changed_handler)
    : m_state_changed_handler(std::move(state_changed_handler))
    , m_log(log, "WalletSync")
    , m_config(config)
    , m_sync_error("CONNECTING")
    , m_status_timer(std::bind(&WalletSync::send_get_status, this))
    , m_sync_agent(config.bytecoind_remote_ip,
          config.bytecoind_remote_port ? config.bytecoind_remote_port : config.bytecoind_bind_port)
    , m_commands_agent(config.bytecoind_remote_ip,
          config.bytecoind_remote_port ? config.bytecoind_remote_port : config.bytecoind_bind_port)
    , m_wallet_state(wallet_state)
    , m_commit_timer(std::bind(&WalletSync::db_commit, this))
    , m_hw_reconnect_timer(std::bind(&WalletSync::on_hw_reconnect, this)) {
	advance_sync();
	m_commit_timer.once(float(m_config.db_commit_period_wallet_cache));
	if (m_wallet_state.get_wallet().get_hw())
		m_hw_reconnect_timer.once(10.0f);  // TODO - improve after prototyping
}

WalletSync::~WalletSync() {}  // we have unique_ptr to incomplete type

void WalletSync::on_hw_reconnect() {
	m_hw_reconnect_timer.once(10.0f);
	if (m_wallet_state.get_wallet().get_hw()->reconnect())
		m_wallet_state.get_preparator().wallet_reconnected();
}

bool WalletSync::on_idle() {
	if (!m_wallet_state.on_idle(m_last_node_status.top_known_block_height))
		return false;
	advance_sync();
	m_state_changed_handler();
	return true;
}

void WalletSync::db_commit() {
	m_wallet_state.db_commit();
	m_commit_timer.once(float(m_config.db_commit_period_wallet_cache));
}

void WalletSync::send_get_status() {
	api::cnd::GetStatus::Request req;
	req.top_block_hash           = m_wallet_state.get_tip_bid();
	req.transaction_pool_version = m_wallet_state.get_tx_pool_version();
	req.outgoing_peer_count      = m_last_node_status.outgoing_peer_count;
	req.incoming_peer_count      = m_last_node_status.incoming_peer_count;
	req.lower_level_error        = m_last_node_status.lower_level_error;

	http::RequestBody req_header     = json_rpc::create_request(api::cnd::url(), api::cnd::GetStatus::method(), req);
	req_header.r.basic_authorization = m_config.bytecoind_authorization;

	m_sync_request = std::make_unique<http::Request>(m_sync_agent, std::move(req_header),
	    [&](http::ResponseBody &&response) {
		    m_sync_request.reset();
		    if (response.r.status == 504) {  // Common for longpoll
			    advance_sync();
		    } else if (response.r.status == 401) {
			    m_sync_error = "AUTHORIZATION_FAILED";
			    m_state_changed_handler();
			    m_log(logging::INFO) << "Wrong daemon password - please check --" CRYPTONOTE_NAME "-authorization"
			                         << std::endl;
			    m_status_timer.once(STATUS_ERROR_PERIOD);
		    } else {
			    api::cnd::GetStatus::Response resp;
			    json_rpc::Error error;
			    if (json_rpc::parse_response(response.body, resp, error)) {
				    m_last_node_status = resp;
				    //				    m_sync_error       = std::string();
				    //				    m_state_changed_handler();
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
		    m_state_changed_handler();
		    m_status_timer.once(STATUS_ERROR_PERIOD);
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
	if (!next_sparse_chain.empty() &&
	    m_wallet_state.get_preparator().get_total_block_size() < m_config.wallet_sync_preparator_queue_size) {
		// Fill preparator queue
		send_get_blocks();
		return;
	}
	if (m_wallet_state.get_preparator().get_total_block_size() != 0) {
		return;  // Wait for preparator queue to drain
	}
	if (m_last_node_status.top_block_hash != m_wallet_state.get_tip_bid()) {
		m_next_send_hash = Hash{};  // We start sending again after new block
		send_get_blocks();
		return;
	}
	if (send_send_transaction())
		return;
	if (m_wallet_state.get_preparator().get_total_mempool_count() != 0) {
		return;  // Wait for preparator queue to drain
	}
	if (m_last_node_status.top_block_hash != m_last_syncpool_status.top_block_hash ||
	    m_last_node_status.transaction_pool_version != m_last_syncpool_status.transaction_pool_version) {
		send_sync_pool();
		return;
	}
	m_sync_error = std::string();
	m_state_changed_handler();
	m_status_timer.once(STATUS_POLL_PERIOD);
}

void WalletSync::send_sync_pool() {
	m_log(logging::TRACE) << "Sending SyncMemPool request" << std::endl;
	api::cnd::SyncMemPool::Request msg;
	msg.known_hashes = m_wallet_state.get_tx_pool_hashes();
	http::RequestBody req_header;
	req_header.r.set_firstline("POST", api::cnd::binary_url(), 1, 1);
	req_header.r.basic_authorization = m_config.bytecoind_authorization;
	req_header.set_body(json_rpc::create_binary_request_body(api::cnd::SyncMemPool::bin_method(), msg));
	m_sync_request = std::make_unique<http::Request>(m_sync_agent, std::move(req_header),
	    [&](http::ResponseBody &&response) {
		    m_sync_request.reset();
		    m_log(logging::TRACE) << "Received SyncMemPool response status=" << response.r.status << std::endl;
		    if (response.r.status == 401) {
			    m_sync_error = "AUTHORIZATION_FAILED";
			    m_log(logging::INFO) << "Wrong daemon password - please check --" CRYPTONOTE_NAME "d-authorization"
			                         << std::endl;
			    m_status_timer.once(STATUS_ERROR_PERIOD);
		    } else if (response.r.status == 200) {
			    //			    m_sync_error = "WRONG_BLOCKCHAIN";
			    api::cnd::SyncMemPool::Response resp;
			    json_rpc::Error error;
			    if (json_rpc::parse_binary_response(response.body, resp, error)) {
				    m_last_node_status = m_last_syncpool_status = resp.status;
				    if (m_wallet_state.sync_with_blockchain(resp)) {
					    m_sync_error = std::string();
					    advance_sync();
				    } else {
					    m_sync_error = "INCOMPATIBLE_DAEMON_VERSION";
					    m_status_timer.once(STATUS_ERROR_PERIOD);
				    }
			    } else {
				    m_log(logging::INFO) << "SyncMemPool request RPC error code=" << error.code
				                         << " message=" << error.message << std::endl;
				    if (error.code == json_rpc::METHOD_NOT_FOUND)
					    m_sync_error = "INCOMPATIBLE_DAEMON_VERSION";
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
	api::cnd::SyncBlocks::Request msg;
	msg.first_block_timestamp =
	    (m_wallet_state.get_wallet().get_oldest_timestamp() / m_config.wallet_sync_timestamp_granularity) *
	    m_config.wallet_sync_timestamp_granularity;
	if (!next_sparse_chain.empty()) {
		msg.sparse_chain = next_sparse_chain;
	} else
		msg.sparse_chain = m_wallet_state.get_sparse_chain();
	msg.need_redundant_data = false;
	msg.max_size            = m_config.wallet_sync_request_max_size;
	http::RequestBody req_header;
	req_header.r.set_firstline("POST", api::cnd::binary_url(), 1, 1);
	req_header.r.basic_authorization = m_config.bytecoind_authorization;
	req_header.set_body(json_rpc::create_binary_request_body(api::cnd::SyncBlocks::bin_method(), msg));
	m_sync_request = std::make_unique<http::Request>(m_sync_agent, std::move(req_header),
	    [&](http::ResponseBody &&response) {
		    m_sync_request.reset();
		    m_log(logging::TRACE) << "Received SyncBlocks response status=" << response.r.status << std::endl;
		    if (response.r.status == 401) {
			    m_sync_error = "AUTHORIZATION_FAILED";
			    m_log(logging::INFO) << "Wrong daemon password - please check --" CRYPTONOTE_NAME "d-authorization"
			                         << std::endl;
			    m_status_timer.once(STATUS_ERROR_PERIOD);
		    } else if (response.r.status == 200) {
			    api::cnd::SyncBlocks::Response resp;
			    json_rpc::Error error;
			    if (json_rpc::parse_binary_response(response.body, resp, error)) {
				    m_last_node_status = resp.status;
				    next_sparse_chain.clear();
				    if (!resp.blocks.empty() && m_last_node_status.top_block_hash != resp.blocks.back().header.hash) {
					    // Construct crude sparse chain for subsequent preparator queue fill
					    for (size_t i = 0; i != std::min<size_t>(10, resp.blocks.size()); ++i)
						    next_sparse_chain.push_back(resp.blocks.at(resp.blocks.size() - 1 - i).header.hash);
				    }
				    m_wallet_state.sync_with_blockchain(std::move(resp.blocks));
				    m_sync_error = std::string();
				    advance_sync();
			    } else {
				    if (!next_sparse_chain.empty()) {
					    next_sparse_chain.clear();
					    advance_sync();
				    } else {
					    m_log(logging::INFO) << "SyncBlocks request RPC error code=" << error.code
					                         << " message=" << error.message << std::endl;
					    if (error.code == json_rpc::METHOD_NOT_FOUND)
						    m_sync_error = "INCOMPATIBLE_DAEMON_VERSION";
					    m_status_timer.once(STATUS_ERROR_PERIOD);
				    }
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
	api::cnd::SendTransaction::Request msg;
	msg.binary_transaction = m_wallet_state.get_next_from_sending_queue(&m_next_send_hash);
	if (msg.binary_transaction.empty())
		return false;
	m_sending_transaction_hash = m_next_send_hash;
	m_log(logging::INFO) << "Sending transaction from payment queue " << m_sending_transaction_hash << std::endl;
	http::RequestBody new_request = json_rpc::create_request(api::cnd::url(), api::cnd::SendTransaction::method(), msg);
	new_request.r.basic_authorization = m_config.bytecoind_authorization;
	m_sync_request                    = std::make_unique<http::Request>(m_sync_agent, std::move(new_request),
        [&](http::ResponseBody &&response) {
            m_sync_request.reset();
            m_log(logging::TRACE) << "Received send_transaction response status=" << response.r.status << std::endl;
            if (response.r.status == 401) {
                m_sync_error = "AUTHORIZATION_FAILED";
                m_log(logging::INFO) << "Wrong daemon password - please check --" CRYPTONOTE_NAME "d-authorization"
                                     << std::endl;
                m_status_timer.once(STATUS_ERROR_PERIOD);
            } else if (response.r.status == 200) {
                api::cnd::SendTransaction::Response resp;
                api::cnd::SendTransaction::Error error;
                if (json_rpc::parse_response(response.body, resp, error)) {
                    m_log(logging::INFO) << "Success sending transaction from payment queue with result "
                                         << resp.send_result << std::endl;
                    m_sync_error = std::string();
                } else {
                    m_log(logging::INFO) << "Json Error sending transaction from payment queue conflict height="
                                         << error.conflict_height << " code=" << error.code << " msg=" << error.message
                                         << std::endl;
                    m_sync_error = "SEND_ERROR";
                    m_wallet_state.process_payment_queue_send_error(m_sending_transaction_hash, error);
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
