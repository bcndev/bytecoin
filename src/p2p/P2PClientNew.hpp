// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "P2P.hpp"
#include "P2pProtocolNew.hpp"

namespace bytecoin {

class Config;
class Currency;

class P2PProtocolNew : public P2PProtocol {
public:
	typedef std::function<void(P2PProtocolNew *who, BinaryArray &&body)> HandlerFunction;

	static BinaryArray create_header(uint32_t cmd, size_t size);

private:
	platform::Timer no_incoming_timer;
	platform::Timer no_outgoing_timer;
	bool first_message_after_handshake_processed = false;
	// we add node to peerdb after first non-handshake message received to avoid adding seed nodes
	const uint64_t unique_number;
	np::PeerDesc other_peer_desc;  // version 0 if not received yet
	np::TopBlockDesc other_top_block_desc;

	Timestamp get_local_time() const;
	static std::map<uint32_t, HandlerFunction> handler_functions;

	void send_timed_sync();
	void msg_handshake(np::Handshake::Request &&req);
	void msg_handshake(np::Handshake::Response &&req);

protected:
	const Config &m_config;
	const Currency &m_currency;
	virtual void on_connect() override;
	virtual void on_disconnect(const std::string &ban_reason) override;
	virtual size_t on_parse_header(
	    common::CircularBuffer &buffer, BinaryArray &request, std::string &ban_reason) override;
	virtual void on_request_ready(BinaryArray &&header, BinaryArray &&body) override;
	virtual bool handshake_ok() const override { return other_peer_desc.p2p_version != 0; }

	virtual void on_msg_bytes(size_t, size_t) {}        // downloaded, uploaded
	virtual void on_first_message_after_handshake() {}  // calling disconnect from here will crash

	virtual void on_msg_handshake(np::Handshake::Request &&req) {}   // called after some internal processing
	virtual void on_msg_handshake(np::Handshake::Response &&req) {}  // called after some internal processing
	virtual void on_msg_find_diff(np::FindDiff::Request &&) {}
	virtual void on_msg_find_diff(np::FindDiff::Response &&) {}
	virtual void on_msg_sync_headers(np::SyncHeaders::Request &&) {}
	virtual void on_msg_sync_headers(np::SyncHeaders::Response &&) {}
	virtual void on_msg_get_transactions(np::GetTransactions::Request &&) {}
	virtual void on_msg_get_transactions(np::GetTransactions::Response &&) {}
	virtual void on_msg_get_pool_hashes(np::GetPoolHashes::Request &&) {}
	virtual void on_msg_get_pool_hashes(np::GetPoolHashes::Response &&) {}
	virtual void on_msg_relay_block_header(np::RelayBlockHeader &&) {}
	virtual void on_msg_relay_transaction_desc(np::RelayTransactionDescs &&) {}
#if bytecoin_ALLOW_DEBUG_COMMANDS
	virtual void on_msg_get_peer_statistics(np::GetPeerStatistics::Request &&) {}
	virtual void on_msg_get_peer_statistics(np::GetPeerStatistics::Response &&) {}
#endif
	virtual np::TopBlockDesc get_top_block_desc() const = 0;
	virtual std::vector<NetworkAddress> get_peers_to_share() const { return std::vector<NetworkAddress>(); }

public:
	explicit P2PProtocolNew(const Config &config, const Currency &currency, uint64_t unique_number, P2PClient *client);
	//	int get_version() const { return peer_desc.p2p_version; }
	uint64_t get_unique_number() const { return unique_number; }
	virtual void send(BinaryArray &&body) override;
	np::PeerDesc get_peer_desc() const;
	np::PeerDesc get_other_peer_desc() const { return other_peer_desc; }
	np::TopBlockDesc get_other_top_block_desc() const { return other_top_block_desc; }

	static bool parse_header(const BinaryArray &header_data, np::Header &header, std::string &ban_reason);
	static BinaryArray create_multicast_announce(Hash genesis_bid, uint16_t p2p_external_port);
	static uint16_t parse_multicast_announce(
	    const unsigned char *data, size_t size, Hash genesis_bid);  // returns port or 0 if failed to parse
};
}
