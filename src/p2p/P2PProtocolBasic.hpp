// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "LevinProtocol.hpp"
#include "P2P.hpp"
#include "P2pProtocolDefinitions.hpp"

namespace cn {

class Config;

class P2PProtocolBasic : public P2PProtocol {
public:
	typedef std::function<void(P2PProtocolBasic *who, BinaryArray &&body)> LevinHandlerFunction;

private:
	platform::Timer no_incoming_timer;
	platform::Timer no_outgoing_timer;
	int peer_version                             = 0;  // 0 means no handshake yet
	bool first_message_after_handshake_processed = false;
	// we add node to peerdb after first non-handshake message received to avoid adding seed nodes
	const uint64_t my_unique_number;
	CoreSyncData peer_sync_data;
	uint64_t peer_unique_number = 0;
	Timestamp get_local_time() const;
	static const std::map<std::pair<uint32_t, LevinProtocol::CommandType>, std::pair<LevinHandlerFunction, size_t>>
	    before_handshake_handlers;
	static const std::map<std::pair<uint32_t, LevinProtocol::CommandType>, std::pair<LevinHandlerFunction, size_t>>
	    after_handshake_handlers;

	void send_timed_sync();

	void msg_handshake(p2p::Handshake::Request &&req);
	void msg_handshake(p2p::Handshake::Response &&req);
	void msg_ping(p2p::PingLegacy::Request &&req);
	void msg_ping(p2p::PingLegacy::Response &&req);
	void msg_timed_sync(p2p::TimedSync::Request &&req);
	void msg_timed_sync(p2p::TimedSync::Response &&req);

protected:
	const Config &config;
	void on_connect() override;
	void on_disconnect(const std::string &ban_reason) override;
	size_t on_parse_header(common::CircularBuffer &buffer, BinaryArray &request) override;
	void on_request_ready(BinaryArray &&header, BinaryArray &&body) override;
	bool handshake_ok() const override { return peer_version != 0; }

	virtual void on_msg_bytes(size_t, size_t) {}                    // downloaded, uploaded
	virtual void on_first_message_after_handshake() {}              // calling disconnect from here will crash
	virtual void on_msg_handshake(p2p::Handshake::Request &&) {}    // called after some internal processing
	virtual void on_msg_handshake(p2p::Handshake::Response &&) {}   // called after some internal processing
	virtual void on_msg_ping(p2p::PingLegacy::Request &&) {}        // called after some internal processing
	virtual void on_msg_ping(p2p::PingLegacy::Response &&) {}       // called after some internal processing
	virtual void on_msg_timed_sync(p2p::TimedSync::Request &&) {}   // called after some internal processing
	virtual void on_msg_timed_sync(p2p::TimedSync::Response &&) {}  // called after some internal processing
#if bytecoin_ALLOW_DEBUG_COMMANDS
	virtual void on_msg_stat_info(p2p::GetStatInfo::Request &&) {}
	virtual void on_msg_stat_info(p2p::GetStatInfo::Response &&) {}
#endif
	virtual void on_msg_notify_new_block(p2p::RelayBlock::Notify &&) {}
	virtual void on_msg_notify_new_transactions(p2p::RelayTransactions::Notify &&) {}
	virtual void on_msg_notify_request_tx_pool(p2p::SyncPool::Notify &&) {}
	virtual void on_msg_notify_request_tx_pool(p2p::SyncPool::Request &&) {}
	virtual void on_msg_notify_request_tx_pool(p2p::SyncPool::Response &&) {}
	virtual void on_msg_notify_request_chain(p2p::GetChainRequest::Notify &&) {}
	virtual void on_msg_notify_request_chain(p2p::GetChainResponse::Notify &&) {}
	virtual void on_msg_notify_request_objects(p2p::GetObjectsRequest::Notify &&) {}
	virtual void on_msg_notify_request_objects(p2p::GetObjectsResponse::Notify &&) {}
	virtual void on_msg_notify_checkpoint(p2p::Checkpoint::Notify &&) {}
	virtual CoreSyncData get_my_sync_data() const = 0;
	virtual std::vector<PeerlistEntryLegacy> get_peers_to_share(bool lots) const {
		return std::vector<PeerlistEntryLegacy>();
	}

	void set_peer_sync_data(CoreSyncData cd) { peer_sync_data = cd; }

public:
	explicit P2PProtocolBasic(const Config &config, uint64_t my_unique_number, P2PClient *client);
	int get_peer_version() const { return peer_version; }
	uint64_t get_my_unique_number() const { return my_unique_number; }
	void send(BinaryArray &&body) override;
	virtual BasicNodeData get_my_node_data() const;
	CoreSyncData get_peer_sync_data() const { return peer_sync_data; }
	uint64_t get_peer_unique_number() const { return peer_unique_number; }

	static BinaryArray create_multicast_announce(const UUID &network_id, Hash genesis_bid, uint16_t p2p_external_port);
	static uint16_t parse_multicast_announce(const unsigned char *data, size_t size, const UUID &network_id,
	    Hash genesis_bid);  // returns port or 0 if failed to parse
};
}  // namespace cn
