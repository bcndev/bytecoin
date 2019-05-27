// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletSync.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "hardware/Proxy.hpp"
#include "http/BinaryRpc.hpp"
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
    , m_status_timer(std::bind(&WalletSync::advance_sync, this))
    , m_sync_agent(config.bytecoind_remote_ip,
          config.bytecoind_remote_port ? config.bytecoind_remote_port : config.bytecoind_bind_port)
    , m_commands_agent(config.bytecoind_remote_ip,
          config.bytecoind_remote_port ? config.bytecoind_remote_port : config.bytecoind_bind_port)
    , m_wallet_state(wallet_state)
    , preparator(m_wallet_state.get_wallet().get_hw(), m_wallet_state.get_wallet().get_output_handler(),
          m_wallet_state.get_wallet().get_view_secret_key(), std::bind(&WalletSync::on_prepared_block, this, _1),
          std::bind(&WalletSync::on_prepared_tx, this, _1), std::bind(&WalletSync::on_prepared_chunk_finished, this))
    , m_commit_timer(std::bind(&WalletSync::db_commit, this))
    , m_hw_reconnect_timer(std::bind(&WalletSync::on_hw_reconnect, this)) {
	send_get_status();
	m_commit_timer.once(float(m_config.db_commit_period_wallet_cache));
	if (m_wallet_state.get_wallet().get_hw())
		m_hw_reconnect_timer.once(10.0f);  // TODO - improve after prototyping
}

WalletSync::~WalletSync() = default;  // we have unique_ptr to incomplete type

void WalletSync::set_sync_error(const std::string &str, bool immediate_sync) {
	if (!immediate_sync) {
		if (str.empty())
			m_status_timer.once(STATUS_POLL_PERIOD);
		else
			m_status_timer.once(STATUS_ERROR_PERIOD);
	}
	if (!m_sync_error.empty() && str.empty())
		m_log(logging::INFO) << "Sync successfully continues from state " << m_sync_error;
	if (m_sync_error.empty() && !str.empty())
		m_log(logging::INFO) << "Sync stopped with error " << str;
	if (m_sync_error != str) {
		m_sync_error = str;
		m_state_changed_handler();
	}
	if (immediate_sync)
		advance_sync();
}

void WalletSync::on_hw_reconnect() {
	m_hw_reconnect_timer.once(10.0f);
	if (m_wallet_state.get_wallet().get_hw()->reconnect())
		preparator.wallet_reconnected();
}

bool WalletSync::on_prepared_block(const PreparedWalletBlock &block) {
	return m_wallet_state.sync_with_blockchain(block, m_last_node_status.top_known_block_height);
}

bool WalletSync::on_prepared_tx(const PreparedWalletTransaction &pwtx) {
	return m_wallet_state.sync_with_blockchain(pwtx);
}

void WalletSync::on_prepared_chunk_finished() {
	if (preparator.is_wallet_connected() && preparator.get_total_block_size() == 0) {
		// Only after blockchain is synced. Otherwise we will waste CPU to reapply
		// transaction every time used output is discovered or O(#inputs)
		m_wallet_state.sync_with_blockchain_finished();
	}
	m_wallet_state.fix_payment_queue_after_undo_redo();
	advance_sync();
	m_state_changed_handler();
}

/*void WalletSync::something_prepared() {
    std::deque<PreparedWalletBlock> blocks;
    std::deque<PreparedWalletTransaction> transactions;
    preparator.get_ready_work(&blocks, &transactions);
    if (blocks.empty() && transactions.empty())
        return;
    //	m_log(logging::INFO) << "WalletSync::on_idle queue size=" << preparator.get_total_block_size() << " count=" <<
    // ppb.size();
    while (!blocks.empty()) {
        if (m_wallet_state.sync_with_blockchain(blocks.front(), m_last_node_status.top_known_block_height)) {
            blocks.pop_front();
        } else {
            preparator.return_ready_work(std::move(blocks));
            break;
        }
    }
    while (!transactions.empty()) {
        if (m_wallet_state.sync_with_blockchain(transactions.front())) {
            transactions.pop_front();
        } else {
            preparator.return_ready_work(std::move(transactions));
            break;
        }
    }
    if (preparator.is_wallet_connected() && preparator.get_total_block_size() == 0) {
        // Only after blockchain is synced. Otherwise we will waste CPU to reapply
        // transaction every time used output is discovered or O(#inputs)
        m_wallet_state.sync_with_blockchain_finished();
    }
    m_wallet_state.fix_payment_queue_after_undo_redo();
    advance_sync();
    m_state_changed_handler();
}*/

void WalletSync::db_commit() {
	m_wallet_state.db_commit();
	m_commit_timer.once(float(m_config.db_commit_period_wallet_cache));
}

void WalletSync::send_get_status() {
	api::cnd::GetStatus::Request req;
	req.top_block_hash           = m_last_node_status.top_block_hash;
	req.transaction_pool_version = m_last_node_status.transaction_pool_version;
	req.outgoing_peer_count      = m_last_node_status.outgoing_peer_count;
	req.incoming_peer_count      = m_last_node_status.incoming_peer_count;
	req.lower_level_error        = m_last_node_status.lower_level_error;

	http::RequestBody req_header     = json_rpc::create_request(api::cnd::url(), api::cnd::GetStatus::method(), req);
	req_header.r.basic_authorization = m_config.bytecoind_authorization;

	m_sync_request = std::make_unique<http::Request>(m_sync_agent, std::move(req_header),
	    [&](http::ResponseBody &&response) {
		    m_sync_request.reset();
		    m_log(logging::TRACE) << "Received GetStatus response status=" << response.r.status;
		    if (response.r.status == 504) {  // Common for longpoll
			    m_status_timer.once(STATUS_POLL_PERIOD);
			    return;
		    }
		    if (response.r.status == 401) {
			    m_log(logging::INFO) << "Wrong daemon password - please check --" CRYPTONOTE_NAME "-authorization";
			    set_sync_error("AUTHORIZATION_FAILED");
			    return;
		    }
		    if (response.r.status != 200) {
			    set_sync_error("CONNECTION_HTTP_FAILED");
			    return;
		    }
		    api::cnd::GetStatus::Response resp;
		    json_rpc::Error error;
		    if (!json_rpc::parse_response(response.body, resp, error)) {
			    m_log(logging::INFO) << "GetStatus request RPC error code=" << error.code
			                         << " message=" << error.message;
			    set_sync_error("CONNECTION_HTTP_FAILED");
			    return;
		    }
		    m_last_node_status = resp;
		    advance_sync();
	    },
	    [&](std::string err) {
		    m_sync_request.reset();
		    set_sync_error("CONNECTION_FAILED");
	    });
}

void WalletSync::advance_sync() {
	const Timestamp now = platform::now_unix_timestamp();
	if (!prevent_sleep && m_wallet_state.get_tip().timestamp < now - 86400) {
		m_log(logging::INFO) << "Preventing computer sleep to sync wallet";
		prevent_sleep = std::make_unique<platform::PreventSleep>("Synchronizing wallet");
	}
	if (prevent_sleep &&
	    m_wallet_state.get_tip().timestamp > now - m_wallet_state.get_currency().block_future_time_limit * 2) {
		m_log(logging::INFO) << "Allowing computer sleep after sync wallet";
		prevent_sleep = nullptr;
	}
	if (m_sync_request)
		return;
	if (!m_wallet_state.db_empty() && !next_sparse_chain.empty() &&
	    preparator.get_total_block_size() < m_config.wallet_sync_preparator_queue_size) {
		// Fill preparator queue
		send_get_blocks();
		return;
	}
	if (preparator.get_total_block_size() != 0) {
		return;  // Wait for preparator queue to drain
	}
	const bool node_behind_us_and_before_last_checkpoint =
	    m_last_node_status.top_block_height < m_wallet_state.get_tip_height() &&
	    m_last_node_status.top_block_height < m_wallet_state.get_currency().last_hard_checkpoint().height;
	// We do not retreat until node passes checkpoint
	if (m_last_node_status.top_block_hash != m_wallet_state.get_tip_bid()) {
		if (node_behind_us_and_before_last_checkpoint) {
			if (m_last_node_status.top_block_hash != Hash{})
				m_sync_error = "Node is far behind, waiting";
			m_state_changed_handler();
			send_get_status();
		} else {
			m_next_send_hash = Hash{};  // We start sending again after new block
			send_get_blocks();
		}
		return;
	}
	if (send_send_transaction())
		return;
	if (preparator.get_total_mempool_count() != 0) {
		return;  // Wait for preparator queue to drain
	}
	if (m_last_node_status.top_block_hash != m_last_syncpool_status.top_block_hash ||
	    m_last_node_status.transaction_pool_version != m_last_syncpool_status.transaction_pool_version) {
		send_sync_pool();
		return;
	}
	if (m_sync_error != std::string()) {
		m_sync_error = std::string();
		m_state_changed_handler();
	}
	send_get_status();
}

void WalletSync::send_sync_pool() {
	m_log(logging::TRACE) << "Sending SyncMemPool request";
	api::cnd::SyncMemPool::Request msg;
	msg.known_hashes = m_wallet_state.get_tx_pool_hashes();
	http::RequestBody req_header;
	req_header.r.set_firstline("POST", api::cnd::binary_url(), 1, 1);
	req_header.r.basic_authorization = m_config.bytecoind_authorization;
	req_header.set_body(json_rpc::create_binary_request_body(api::cnd::SyncMemPool::bin_method(), msg));
	m_sync_request = std::make_unique<http::Request>(m_sync_agent, std::move(req_header),
	    [&](http::ResponseBody &&response) {
		    m_sync_request.reset();
		    m_log(logging::TRACE) << "Received SyncMemPool response status=" << response.r.status;
		    if (response.r.status == 401) {
			    m_log(logging::INFO) << "Wrong daemon password - please check --" CRYPTONOTE_NAME "d-authorization";
			    set_sync_error("AUTHORIZATION_FAILED");
			    return;
		    }
		    if (response.r.status != 200) {
			    m_log(logging::INFO) << "SyncMemPool request http status=" << response.r.status;
			    set_sync_error("CONNECTION_HTTP_FAILED");
			    return;
		    }
		    api::cnd::SyncMemPool::Response resp;
		    json_rpc::Error error;
		    if (!json_rpc::parse_binary_response(response.body, resp, error)) {
			    m_log(logging::INFO) << "SyncMemPool request RPC error code=" << error.code
			                         << " message=" << error.message;
			    set_sync_error(error.code == json_rpc::METHOD_NOT_FOUND ? "INCOMPATIBLE_DAEMON_VERSION"
			                                                            : "CONNECTION_HTTP_FAILED");
			    return;
		    }
		    m_last_node_status = m_last_syncpool_status = resp.status;
		    m_wallet_state.sync_with_blockchain(resp.removed_hashes);
		    size_t c = std::min(resp.added_raw_transactions.size(), resp.added_transactions.size());
		    for (size_t i = 0; i != c; ++i) {
			    const Hash tid    = resp.added_transactions.at(i).hash;
			    const size_t size = resp.added_transactions.at(i).size;
			    preparator.add_work(tid, size, std::move(resp.added_raw_transactions.at(i)));
		    }
		    set_sync_error(std::string{}, true);
	    },
	    [&](std::string err) {
		    m_sync_request.reset();
		    m_log(logging::DEBUGGING) << "SyncMemPool request error " << err;
		    set_sync_error("CONNECTION_FAILED");
	    });
}

void WalletSync::send_get_blocks() {
	m_log(logging::TRACE) << "Sending SyncBlocks request";
	http::RequestBody req_header;
	req_header.r.basic_authorization = m_config.bytecoind_authorization;
	// Reset to static, but use rpc call first time on empty wallet state
	// (We do not know block number for creation timestamp of wallet, so have to ask node)
	// We ignore next_sparse_chain because after reset beyond history we must start from rpc again
	if (m_wallet_state.db_empty())
		last_static_sync_blocks_failed = false;
	bool is_static = !last_static_sync_blocks_failed && !m_wallet_state.db_empty();
	if (is_static) {
		auto url = api::cnd::SyncBlocks::url_prefix() +
		           api::cnd::SyncBlocks::get_filename(
		               next_static_block ? next_static_block.get() : (m_wallet_state.get_tip_height() + 1));
		req_header.r.set_firstline("GET", url, 1, 1);
	} else {
		api::cnd::SyncBlocks::Request msg;
		msg.first_block_timestamp =
		    (m_wallet_state.get_wallet().get_oldest_timestamp() / m_config.wallet_sync_timestamp_granularity) *
		    m_config.wallet_sync_timestamp_granularity;
		if (!next_sparse_chain.empty() && !m_wallet_state.db_empty()) {
			msg.sparse_chain = next_sparse_chain;
		} else
			msg.sparse_chain = m_wallet_state.get_sparse_chain();
		msg.need_redundant_data = false;
		req_header.r.set_firstline("POST", api::cnd::binary_url(), 1, 1);
		req_header.set_body(json_rpc::create_binary_request_body(api::cnd::SyncBlocks::bin_method(), msg));
	}
	m_sync_request = std::make_unique<http::Request>(m_sync_agent, std::move(req_header),
	    [&, is_static](http::ResponseBody &&response) {
		    m_sync_request.reset();
		    m_log(logging::DEBUGGING) << "Received SyncBlocks response status=" << response.r.status;
		    if (response.r.status == 401) {
			    m_log(logging::INFO) << "Wrong daemon password - please check --" CRYPTONOTE_NAME "d-authorization";
			    set_sync_error("AUTHORIZATION_FAILED");
			    return;
		    }
		    if (response.r.status == 404 && is_static) {
			    m_log(logging::DEBUGGING) << "Static sync_block request returned 404, switching to rpc request";
			    last_static_sync_blocks_failed = true;
			    advance_sync();
			    // node checkpoint is behind walletd. will not use static until next launch
			    return;
		    }
		    if (response.r.status != 200) {
			    m_log(logging::INFO) << "SyncBlocks request http status=" << response.r.status;
			    set_sync_error("CONNECTION_HTTP_FAILED");
			    return;
		    }
		    api::cnd::SyncBlocks::ResponseCompact resp;
		    json_rpc::Error error;
		    Height redirect_height = 0;
		    if (is_static && api::cnd::SyncBlocks::is_static_redirect(response.body, &redirect_height)) {
			    if (next_static_block && redirect_height >= next_static_block.get()) {
				    m_log(logging::INFO) << "Static sync_blocks forward redirect forbidden " << redirect_height;
				    last_static_sync_blocks_failed = true;
			    } else {
				    m_log(logging::INFO) << "Static sync_blocks redirect to " << redirect_height;
				    next_static_block = redirect_height;
			    }
			    advance_sync();
			    return;
		    }
		    if (!json_rpc::parse_binary_response(response.body, resp, error)) {
			    if (!next_sparse_chain.empty()) {
				    m_log(logging::INFO) << "SyncBlocks speculative SyncBlocks guess wrong, recovering";
				    next_sparse_chain.clear();
				    next_static_block = boost::optional<Height>();
				    advance_sync();
				    return;
			    }
			    m_log(logging::INFO) << "SyncBlocks request RPC error code=" << error.code
			                         << " message=" << error.message;
			    set_sync_error(error.code == json_rpc::METHOD_NOT_FOUND ? "INCOMPATIBLE_DAEMON_VERSION"
			                                                            : "CONNECTION_HTTP_FAILED");
			    return;
		    }
		    if (resp.status.top_block_hash != Hash{})  // rpc, not static
			    m_last_node_status = resp.status;
		    next_sparse_chain.clear();
		    next_static_block = boost::optional<Height>{};
		    cut_common_start(resp);
		    if (!resp.blocks.empty() && m_last_node_status.top_block_hash != resp.blocks.back().header.hash) {
			    // Construct crude sparse chain for subsequent preparator queue fill
			    for (size_t i = 0; i != std::min<size_t>(10, resp.blocks.size()); ++i)
				    next_sparse_chain.push_back(resp.blocks.at(resp.blocks.size() - 1 - i).header.hash);
			    next_static_block = resp.blocks.back().header.height + 1;
		    }
			m_log(logging::DEBUGGING) << "SyncBlocks received " << resp.blocks.size() << " blocks, starting from "
			                         << (resp.blocks.empty() ? 0 : resp.blocks.at(0).header.height);
		    preparator.add_work(std::move(resp.blocks));
		    set_sync_error(std::string{}, true);
	    },
	    [&](std::string err) {
		    m_sync_request.reset();
		    m_log(logging::DEBUGGING) << "SyncBlocks request error " << err;
		    set_sync_error("CONNECTION_FAILED");
	    });
}

bool WalletSync::send_send_transaction() {
	api::cnd::SendTransaction::Request msg;
	msg.binary_transaction = m_wallet_state.get_next_from_sending_queue(&m_next_send_hash);
	if (msg.binary_transaction.empty())
		return false;
	m_sending_transaction_hash = m_next_send_hash;
	m_log(logging::INFO) << "Sending transaction from payment queue " << m_sending_transaction_hash;
	http::RequestBody new_request = json_rpc::create_request(api::cnd::url(), api::cnd::SendTransaction::method(), msg);
	new_request.r.basic_authorization = m_config.bytecoind_authorization;
	m_sync_request                    = std::make_unique<http::Request>(m_sync_agent, std::move(new_request),
        [&](http::ResponseBody &&response) {
            m_sync_request.reset();
            m_log(logging::DEBUGGING) << "Received send_transaction response status=" << response.r.status;
            if (response.r.status == 401) {
                m_log(logging::INFO) << "Wrong daemon password - please check --" CRYPTONOTE_NAME "d-authorization";
                set_sync_error("AUTHORIZATION_FAILED");
                return;
            }
            if (response.r.status != 200) {
                m_log(logging::INFO) << "Error sending transaction from payment queue http status="
                                     << response.r.status;
                set_sync_error("CONNECTION_HTTP_FAILED");
                return;
            }
            api::cnd::SendTransaction::Response resp;
            api::cnd::SendTransaction::Error error;
            if (!json_rpc::parse_response(response.body, resp, error)) {
                m_log(logging::INFO) << "Json Error sending transaction from payment queue conflict height="
                                     << error.conflict_height << " code=" << error.code << " msg=" << error.message;
                m_wallet_state.process_payment_queue_send_error(m_sending_transaction_hash, error);
                set_sync_error("SEND_ERROR");
                return;
            }
            m_log(logging::INFO) << "Success sending transaction from payment queue with result " << resp.send_result;
            set_sync_error(std::string{}, true);
        },
        [&](std::string err) {
            m_sync_request.reset();
            m_log(logging::INFO) << "Error sending transaction from payment queue " << err;
            set_sync_error("CONNECTION_FAILED");
        });
	return true;
}

bool WalletSync::cut_common_start(api::cnd::SyncBlocks::ResponseCompact &res) {
	if (res.blocks.empty())
		return true;
	// When getting static chain, we can get long common part
	// We do not want to undo/redo it, because our undo history can be shorter
	// so we will have to zero DB. Instead we cut common part
	for (size_t i = res.blocks.size(); i-- > 0;) {
		if (res.blocks.at(i).header.height > m_wallet_state.get_tip_height())
			continue;
		api::BlockHeader bh;
		if (!m_wallet_state.read_chain(res.blocks.at(i).header.height, &bh))
			continue;
		if (bh.hash == res.blocks.at(i).header.hash) {
			res.blocks.erase(res.blocks.begin(), res.blocks.begin() + i + 1);
			break;
		}
	}
	return true;
}
