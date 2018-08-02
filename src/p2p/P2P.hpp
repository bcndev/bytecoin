// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <array>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include "PeerDB.hpp"
#include "common/MemoryStreams.hpp"
#include "logging/LoggerMessage.hpp"
#include "platform/Network.hpp"

namespace bytecoin {

class Config;
class P2P;

class P2PClient {
public:
	static const int RECOMMENDED_BUFFER_SIZE = 8192;

	typedef std::function<void(std::string ban_reason)> D_handler;

	explicit P2PClient(size_t header_size, bool incoming, D_handler d_handler);

	bool read_next_request(BinaryArray &header, BinaryArray &body);
	const NetworkAddress &get_address() const { return address; }
	bool is_incoming() const { return incoming; }
	virtual void send(BinaryArray &&body);  // We want to make sure to update stats when calling with a base class
	void send_shutdown();
	void disconnect(const std::string &ban_reason);  // empty for no ban
	bool test_connect(const NetworkAddress &addr);   // for single connects without p2p
	bool is_connected() const;
	virtual ~P2PClient() {}

protected:
	void update_my_port(uint16_t port) { address.port = port; }
	virtual void on_connect()                         = 0;
	virtual size_t on_request_header(const BinaryArray &header, std::string &ban_reason) const = 0;
	virtual void on_request_ready()                           = 0;
	virtual void on_disconnect(const std::string &ban_reason) = 0;
	virtual bool handshake_ok() const = 0;  // if true, will be used for broadcast and find_client
private:
	void advance_state(bool called_from_runloop);
	void on_socket_disconnect();
	void write();
	void read(bool called_from_runloop);

	friend class P2P;
	NetworkAddress address;
	platform::TCPSocket sock;

	const bool incoming;
	const size_t header_size;
	D_handler d_handler;

	BinaryArray request;
	size_t request_body_length = 0;
	bool receiving_body        = false;
	common::VectorStream receiving_body_stream;

	common::CircularBuffer buffer;

	std::deque<common::VectorStream> responses;
	bool waiting_shutdown = false;
};

class P2P {
public:
	typedef std::function<std::unique_ptr<P2PClient>(bool incoming, P2PClient::D_handler d_handler)> client_factory;

	explicit P2P(logging::ILogger &log, const Config &config, PeerDB &peers, client_factory c_factory);

	void broadcast(
	    P2PClient *exclude_who, const BinaryArray &data, bool incoming, bool outgoing);  // to all, except who
	void broadcast(P2PClient *exclude_who, const BinaryArray &data) { broadcast(exclude_who, data, true, true); }
	P2PClient *find_client(const NetworkAddress &address, bool incoming);
	P2PClient *find_connecting_client(const NetworkAddress &address);
	std::vector<NetworkAddress> good_clients(bool incoming) const;
	uint32_t get_p2p_time() const;
	uint32_t get_local_time() const;
	uint64_t get_unique_number() const { return unique_number; }

	void peers_updated();

private:
	const Config &config;
	logging::LoggerRef log;
	PeerDB &peers;

	std::unique_ptr<platform::TCPAcceptor> la_socket;

	// we index by bool incoming;
	std::map<P2PClient *, std::unique_ptr<P2PClient>>
	    clients[2];  // Alas, no way to look for an element in set<unique_ptr<_>>
	std::unique_ptr<P2PClient> next_client[2];
	std::vector<std::unique_ptr<P2PClient>> disconnected_clients;  // lacking autorelease

	platform::Timer reconnect_timer;
	unsigned failed_connection_attempts_counter = 0;
	platform::Timer free_diconnected_timer;  // lacking autorelease

	friend class P2PClient;
	void on_client_disconnected(P2PClient *who, std::string ban_reason);

	void accept_all();
	void connect_all();
	void connect_all_nodelay();
	bool connect_one(const NetworkAddress &address);

	client_factory c_factory;

	const uint64_t unique_number;  // random number to detect self-connects
};
}
