// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "P2P.hpp"
#include "P2pProtocolNew.hpp"

namespace bytecoin {

class Config;
class Currency;

class P2PClientNew : public P2PClient {
public:
	typedef std::function<void(P2PClientNew *who, BinaryArray &&body)> HandlerFunction;

private:
	platform::Timer no_incoming_timer;
	platform::Timer no_outgoing_timer;
	bool first_message_after_handshake_processed = false;
	// we add node to peerdb after first non-handshake message received to avoid adding seed nodes
	const uint64_t unique_number;
	np::PeerDesc peer_desc;  // version 0 if not received yet
	np::TopBlockDesc last_received_top_block_desc;

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
	virtual size_t on_request_header(const BinaryArray &header, std::string &ban_reason) const override;
	virtual void on_request_ready() override;
	virtual bool handshake_ok() const override { return peer_desc.p2p_version != 0; }

	virtual void on_msg_bytes(size_t, size_t) {}  // downloaded, uploaded
	virtual void on_first_message_after_handshake() {}

	virtual void on_msg_handshake(np::Handshake::Request &&req) {}
	virtual void on_msg_handshake(np::Handshake::Response &&req) {}
	virtual void on_msg_find_diff(np::FindDiff::Request &&) {}   // called after some internal processing
	virtual void on_msg_find_diff(np::FindDiff::Response &&) {}  // called after some internal processing
#if bytecoin_ALLOW_DEBUG_COMMANDS
#endif
	virtual np::TopBlockDesc get_top_block_desc() const = 0;
	virtual std::vector<np::NetworkAddress> get_peers_to_share() const { return std::vector<np::NetworkAddress>(); }

public:
	explicit P2PClientNew(
	    const Config &config, const Currency &currency, uint64_t unique_number, bool incoming, D_handler d_handler);
	int get_version() const { return peer_desc.p2p_version; }
	uint64_t get_unique_number() const { return unique_number; }
	virtual void send(BinaryArray &&body) override;
	np::PeerDesc get_peer_desc() const;
	np::TopBlockDesc get_last_received_top_block_desc() const { return last_received_top_block_desc; }
	uint64_t get_last_received_unique_number() const { return peer_desc.peer_id; }
};
}
