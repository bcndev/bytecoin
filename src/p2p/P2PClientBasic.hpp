// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "CryptoNoteProtocolDefinitions.hpp"
#include "LevinProtocol.hpp"
#include "P2P.hpp"
#include "P2pProtocolDefinitions.hpp"

namespace bytecoin {

class Config;

class P2PClientBasic : public P2PClient {
public:
	typedef std::function<void(P2PClientBasic *who, BinaryArray &&body)> LevinHandlerFunction;

private:
	platform::Timer no_activity_timer;
	platform::Timer timed_sync_timer;
	int version                                  = 0;  // 0 means no handshake yet
	bool first_message_after_handshake_processed = false;
	// we add node to peerdb after first non-handshake message received to avoid adding seed nodes
	const uint64_t unique_number;
	CORE_SYNC_DATA last_received_sync_data;
	uint64_t last_received_unique_number = 0;
	Timestamp get_local_time() const;
	static std::map<std::pair<uint32_t, bool>, LevinHandlerFunction> before_handshake_handlers;
	static std::map<std::pair<uint32_t, bool>, LevinHandlerFunction> after_handshake_handlers;

	void send_timed_sync();

	void msg_handshake(COMMAND_HANDSHAKE::request &&req);
	void msg_handshake(COMMAND_HANDSHAKE::response &&req);
	void msg_ping(COMMAND_PING::request &&req);
	void msg_ping(COMMAND_PING::response &&req);
	void msg_timed_sync(COMMAND_TIMED_SYNC::request &&req);
	void msg_timed_sync(COMMAND_TIMED_SYNC::response &&req);

protected:
	const Config &config;
	virtual void on_connect() override;
	virtual void on_disconnect(const std::string &ban_reason) override;
	virtual size_t on_request_header(const BinaryArray &header, std::string &ban_reason) const override;
	virtual void on_request_ready() override;
	virtual bool handshake_ok() const override { return version != 0; }

	virtual void on_msg_bytes(size_t, size_t) {}  // downloaded, uploaded
	virtual void on_first_message_after_handshake() {}
	virtual void on_msg_handshake(COMMAND_HANDSHAKE::request &&) {}     // called after some internal processing
	virtual void on_msg_handshake(COMMAND_HANDSHAKE::response &&) {}    // called after some internal processing
	virtual void on_msg_ping(COMMAND_PING::request &&) {}               // called after some internal processing
	virtual void on_msg_ping(COMMAND_PING::response &&) {}              // called after some internal processing
	virtual void on_msg_timed_sync(COMMAND_TIMED_SYNC::request &&) {}   // called after some internal processing
	virtual void on_msg_timed_sync(COMMAND_TIMED_SYNC::response &&) {}  // called after some internal processing
#if bytecoin_ALLOW_DEBUG_COMMANDS
	virtual void on_msg_network_state(COMMAND_REQUEST_NETWORK_STATE::request &&) {}
	virtual void on_msg_network_state(COMMAND_REQUEST_NETWORK_STATE::response &&) {}
	virtual void on_msg_stat_info(COMMAND_REQUEST_STAT_INFO::request &&) {}
	virtual void on_msg_stat_info(COMMAND_REQUEST_STAT_INFO::response &&) {}
#endif
	virtual void on_msg_notify_new_block(NOTIFY_NEW_BLOCK::request &&) {}
	virtual void on_msg_notify_new_transactions(NOTIFY_NEW_TRANSACTIONS::request &&) {}
	virtual void on_msg_notify_request_tx_pool(NOTIFY_REQUEST_TX_POOL::request &&) {}
	virtual void on_msg_notify_request_chain(NOTIFY_REQUEST_CHAIN::request &&) {}
	virtual void on_msg_notify_request_chain(NOTIFY_RESPONSE_CHAIN_ENTRY::request &&) {}
	virtual void on_msg_notify_request_objects(NOTIFY_REQUEST_GET_OBJECTS::request &&) {}
	virtual void on_msg_notify_request_objects(NOTIFY_RESPONSE_GET_OBJECTS::request &&) {}
	virtual void on_msg_notify_checkpoint(NOTIFY_CHECKPOINT::request &&) {}
	virtual CORE_SYNC_DATA get_sync_data() const = 0;
	virtual std::vector<PeerlistEntry> get_peers_to_share() const { return std::vector<PeerlistEntry>(); }

	void set_last_received_sync_data(CORE_SYNC_DATA cd) { last_received_sync_data = cd; }

public:
	explicit P2PClientBasic(const Config &config, uint64_t unique_number, bool incoming, D_handler d_handler);
	int get_version() const { return version; }
	uint64_t get_unique_number() const { return unique_number; }
	virtual void send(BinaryArray &&body) override;
	basic_node_data get_node_data() const;
	CORE_SYNC_DATA get_last_received_sync_data() const { return last_received_sync_data; }
	uint64_t get_last_received_unique_number() const { return last_received_unique_number; }
};
}
