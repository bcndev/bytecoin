// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "CryptoNote.hpp"
#include "MulticoreWallet.hpp"
#include "WalletState.hpp"
#include "http/Agent.hpp"
#include "http/JsonRpc.hpp"
#include "platform/Network.hpp"
#include "platform/PreventSleep.hpp"

namespace cn {

class WalletState;

class WalletSync {
public:
	explicit WalletSync(
	    logging::ILogger &, const Config &, WalletState &, std::function<void()> &&state_changed_handler);
	~WalletSync();
	const api::cnd::GetStatus::Response &get_last_node_status() const { return m_last_node_status; }
	std::string get_sync_error() const { return m_sync_error; }

protected:
	bool on_prepared_block(const PreparedWalletBlock &block);
	bool on_prepared_tx(const PreparedWalletTransaction &pwtx);
	void on_prepared_chunk_finished();

	const std::function<void()> m_state_changed_handler;
	logging::LoggerRef m_log;
	const Config &m_config;

	api::cnd::GetStatus::Response m_last_node_status;
	api::cnd::GetStatus::Response m_last_syncpool_status;
	bool last_static_sync_blocks_failed = false;
	std::string m_sync_error;
	void set_sync_error(const std::string &str, bool immediate_sync = false);

	platform::Timer m_status_timer;
	http::Agent m_sync_agent;
	std::unique_ptr<http::Request> m_sync_request;
	void advance_sync();

	http::Agent m_commands_agent;
	std::unique_ptr<http::Request> m_command_request;

	WalletState &m_wallet_state;
	WalletPreparatorMulticore preparator;

	std::unique_ptr<platform::PreventSleep> prevent_sleep;
	platform::Timer m_commit_timer;

	Hash m_next_send_hash;
	Hash m_sending_transaction_hash;

	// those 2 vars are always set together, we check second one.
	boost::optional<Height> next_static_block;
	std::vector<Hash> next_sparse_chain;

	platform::Timer m_hw_reconnect_timer;

	void on_hw_reconnect();
	void db_commit();
	void send_get_status();
	bool send_send_transaction();  // nothing to send
	void send_sync_pool();
	void send_get_blocks();

	bool cut_common_start(api::cnd::SyncBlocks::ResponseCompact &res);
};

}  // namespace cn
