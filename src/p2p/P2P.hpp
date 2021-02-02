// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <array>
#include <chrono>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include "common/MemoryStreams.hpp"
#include "logging/LoggerMessage.hpp"
#include "p2p/P2pProtocolTypes.hpp"
#include "platform/Network.hpp"

namespace cn {

class Config;
class P2P;
class P2PClient;
class PeerDB;

class P2PProtocol {
public:
	explicit P2PProtocol(P2PClient *client) : m_client(client) {}
	virtual ~P2PProtocol()                                                               = default;
	virtual void on_connect()                                                            = 0;
	virtual size_t on_parse_header(common::CircularBuffer &buffer, BinaryArray &request) = 0;
	virtual void on_request_ready(BinaryArray &&header, BinaryArray &&body)              = 0;
	virtual void on_disconnect(const std::string &ban_reason);
	virtual bool handshake_ok() const = 0;  // if true, will be used for broadcast and find_client
	const NetworkAddress &get_address() const;
	bool is_incoming() const;
	virtual void send(BinaryArray &&body);
	void send_shutdown();
	void disconnect(const std::string &ban_reason);
	P2PClient *get_client() const { return m_client; }

protected:
	void update_my_port(uint16_t port);

private:
	P2PClient *m_client;
};

class P2PClient {
public:
	static const int RECOMMENDED_BUFFER_SIZE = 8192;

	typedef std::function<void(std::string ban_reason)> D_handler;

	explicit P2PClient(bool incoming, D_handler &&d_handler);
	void set_protocol(std::unique_ptr<P2PProtocol> &&protocol);

	const NetworkAddress &get_address() const { return address; }
	bool is_incoming() const { return incoming; }
	virtual void send(BinaryArray &&body);  // We want to make sure to update stats when calling with a base class
	void send_shutdown();
	void disconnect(const std::string &ban_reason);  // empty for no ban
	bool test_connect(const NetworkAddress &addr);   // for single connects without p2p
	bool is_connected() const;
	virtual ~P2PClient() = default;
	P2PProtocol *get_protocol() const { return m_protocol.get(); }
	void update_my_port(uint16_t port) { address.port = port; }

private:
	void advance_state(bool called_from_runloop);
	void on_socket_disconnect();
	void write();
	void read(bool called_from_runloop);

	bool read_next_request(BinaryArray &header, BinaryArray &body);
	void process_requests();

	friend class P2P;
	std::unique_ptr<P2PProtocol> m_protocol;
	NetworkAddress address;
	platform::TCPSocket sock;

	const bool incoming;
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
	typedef std::function<std::unique_ptr<P2PProtocol>(P2PClient *client)> client_factory;

	explicit P2P(logging::ILogger &log, const Config &config, PeerDB &peers, client_factory &&c_factory);

	Timestamp get_local_time() const;
	uint64_t get_unique_number() const { return unique_number; }

	void peers_updated();

private:
	const Config &m_config;
	logging::LoggerRef m_log;
	PeerDB &peers;
	std::chrono::steady_clock::time_point m_log_banned_timestamp;

	std::unique_ptr<platform::TCPAcceptor> la_socket;

	// we index by bool incoming;
	std::map<P2PClient *, std::unique_ptr<P2PClient>>
	    clients[2];  // Alas, no way to look for an element in set<unique_ptr<_>>
	std::unique_ptr<P2PClient> next_client[2];
	std::vector<std::unique_ptr<P2PClient>> disconnected_clients;  // lacking autorelease

	platform::Timer reconnect_timer;
	unsigned failed_connection_attempts_counter = 0;
	platform::Timer free_disconnected_timer;  // lacking autorelease

	friend class P2PClient;
	void on_client_disconnected(P2PClient *who, std::string ban_reason);

	void accept_all();
	void connect_all();
	void connect_all_nodelay();
	bool connect_one(const NetworkAddress &address);

	client_factory c_factory;

	const uint64_t unique_number;  // random number to detect self-connects
};
}  // namespace cn
