// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "CryptoNote.hpp"
#include "Node.hpp"
#include "WalletState.hpp"
#include "http/Agent.hpp"
#include "http/JsonRpc.h"

namespace bytecoin {

class WalletSync {
public:
	explicit WalletSync(logging::ILogger &, const Config &, WalletState &, std::function<void()> state_changed_handler);

	const api::bytecoind::GetStatus::Response &get_last_node_status() const { return m_last_node_status; }
	std::string get_sync_error() const { return m_sync_error; }

protected:
	const std::function<void()> m_state_changed_handler;
	logging::LoggerRef m_log;
	const Config &m_config;

	api::bytecoind::GetStatus::Response m_last_node_status;
	std::string m_sync_error;
	platform::Timer m_status_timer;
	http::Agent m_sync_agent;
	std::unique_ptr<http::Request> m_sync_request;
	void advance_sync();
	int transient_transactions_counter = 0;  // This works as mutex for create_raw_transaction and sync_pool

	http::Agent m_commands_agent;
	std::unique_ptr<http::Request> m_command_request;

	WalletState &m_wallet_state;

	std::unique_ptr<platform::PreventSleep> prevent_sleep;
	platform::Timer m_commit_timer;
	void db_commit();
	void send_get_status();
	void send_sync_pool();
	void send_get_blocks();
};

}  // namespace bytecoin
