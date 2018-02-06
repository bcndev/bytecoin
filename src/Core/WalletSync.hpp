#pragma once

#include "CryptoNote.hpp"
#include "http/Agent.hpp"
#include "http/JsonRpc.h"
#include "Node.hpp"
#include "WalletState.hpp"

namespace bytecoin {

class WalletSync {
public:
	explicit WalletSync(logging::ILogger &, const Config &, WalletState &, std::function<void()> state_changed_handler);

	const api::bytecoind::GetStatus::Response & get_last_node_status()const { return m_last_node_status; }
protected:
	const std::function<void()> m_state_changed_handler;

	logging::LoggerRef m_log;

	api::bytecoind::GetStatus::Response m_last_node_status;
	platform::Timer m_status_timer;
	http::Agent m_sync_agent;
	std::unique_ptr<http::Request> m_sync_request;
	void advance_sync();
	int transient_transactions_counter = 0; // This works as mutex for create_raw_transaction and sync_pool

	http::Agent m_commands_agent;
	std::unique_ptr<http::Request> m_command_request;

	WalletState &m_wallet_state;
	
	std::unique_ptr<platform::PreventSleep> prevent_sleep;
	platform::Timer m_commit_timer;
	void db_commit() {
		m_wallet_state.db_commit();
		m_commit_timer.once(DB_COMMIT_PERIOD_WALLET_CACHE);
	}

	void send_get_status();
	void send_sync_pool();
	void send_get_blocks();
};

}  // namespace bytecoin
