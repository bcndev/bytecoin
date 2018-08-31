// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "P2P.hpp"
#include <algorithm>
#include <ctime>
#include <iostream>
#include <map>
#include "Core/Config.hpp"
#include "common/Invariant.hpp"
#include "crypto/crypto.hpp"
#include "platform/Time.hpp"

const float RECONNECT_TIMEOUT           = 10;    // when we tried all addresses, make a small delay
const float NO_INTERNET_RECONNECT_DELAY = 0.5f;  // when network is unreachable, do not try too often

using namespace bytecoin;

void P2PProtocol::on_disconnect(const std::string &ban_reason) {
	//	std::cout << "P2PProtocol::on_disconnect this=" << std::hex << (size_t)this << " m_client=" << (size_t)m_client
	//<< std::dec << std::endl;
	m_client = nullptr;
}

const NetworkAddress &P2PProtocol::get_address() const { return m_client->get_address(); }
bool P2PProtocol::is_incoming() const { return m_client->is_incoming(); }
void P2PProtocol::send(BinaryArray &&body) { return m_client->send(std::move(body)); }
void P2PProtocol::send_shutdown() { return m_client->send_shutdown(); }
void P2PProtocol::disconnect(const std::string &ban_reason) { return m_client->disconnect(ban_reason); }
void P2PProtocol::update_my_port(uint16_t port) { return m_client->update_my_port(port); }

P2PClient::P2PClient(bool incoming, D_handler d_handler)
    : sock([this](bool canread, bool canwrite) { advance_state(true); },
          std::bind(&P2PClient::on_socket_disconnect, this))
    , incoming(incoming)
    , d_handler(d_handler)
    , buffer(RECOMMENDED_BUFFER_SIZE) {}

void P2PClient::set_protocol(std::unique_ptr<P2PProtocol> &&protocol) {
	bool protocol_switch = protocol && m_protocol;
	//	std::cout << "P2PClient::set_protocol this=" << std::hex << (size_t)this << std::dec << " m_protocol=" <<
	//(size_t)m_protocol.get() << " protocol=" << (size_t)protocol.get() << std::endl;
	if (m_protocol)
		m_protocol->on_disconnect(std::string());
	m_protocol.reset();
	if (protocol_switch)
		std::cout << "P2PClient::set_protocol protocol switch" << std::endl;
	m_protocol = std::move(protocol);
	if (m_protocol)
		m_protocol->on_connect();
}

void P2PClient::write() {
	while (!responses.empty()) {
		responses.front().copy_to(sock);
		if (responses.front().size() != 0)
			break;
		responses.pop_front();
	}
	if (responses.empty() && waiting_shutdown)
		sock.shutdown_both();
}

void P2PClient::read(bool called_from_runloop) {
	if (!receiving_body) {
		buffer.copy_from(sock);
		while (true) {  // Support for N immediate protocol switches
			std::string ban_reason;
			P2PProtocol *was_protocol = m_protocol.get();
			request_body_length       = m_protocol->on_parse_header(buffer, request, ban_reason);
			if (!ban_reason.empty())
				return disconnect(ban_reason);
			if (request_body_length != std::string::npos)
				break;
			if (was_protocol == m_protocol.get())
				return;
			// Immediate protocol switch, repeat parse header for new protocol
		}
		receiving_body        = true;
		receiving_body_stream = common::VectorStream();
	}
	while (true) {
		invariant(receiving_body_stream.size() <= request_body_length, "");
		size_t max_count = request_body_length - receiving_body_stream.size();
		buffer.copy_to(receiving_body_stream, max_count);
		if (receiving_body_stream.size() == request_body_length) {
			if (called_from_runloop)
				process_requests();
			return;
		}
		buffer.copy_from(sock);
		if (buffer.empty())
			break;
	}
}

void P2PClient::process_requests() {
	BinaryArray header, body;
	while (m_protocol && read_next_request(header, body))
		m_protocol->on_request_ready(std::move(header), std::move(body));
}

bool P2PClient::read_next_request(BinaryArray &header, BinaryArray &body) {
	advance_state(false);
	if (!receiving_body)
		return false;
	if (receiving_body_stream.size() != request_body_length)
		return false;
	header                = std::move(request);
	body                  = std::move(receiving_body_stream.buffer());
	request               = BinaryArray();
	receiving_body_stream = common::VectorStream();
	receiving_body        = false;
	request_body_length   = 0;
	return !waiting_shutdown;  // consume input when waiting_shutdown. TODO - implement socket.shutdown_read
}

void P2PClient::send(BinaryArray &&body) {
	responses.emplace_back(std::move(body));

	write();
}

void P2PClient::send_shutdown() {
	waiting_shutdown = true;
	write();
}

void P2PClient::disconnect(const std::string &ban_reason) {
	buffer.clear();
	receiving_body        = false;
	request               = BinaryArray();
	receiving_body_stream = common::VectorStream();
	responses.clear();

	sock.close();
	//	std::cout << "P2PClient::disconnect this=" << std::hex << (size_t)this << std::dec << std::endl;
	if (m_protocol)
		m_protocol->on_disconnect(ban_reason);
	m_protocol.reset();
	d_handler(ban_reason);
}

bool P2PClient::test_connect(const NetworkAddress &addr) {
	if (incoming)
		return false;
	if (!sock.connect(common::ip_address_to_string(addr.ip), addr.port))
		return false;
	address = addr;
	m_protocol->on_connect();
	return true;
}

bool P2PClient::is_connected() const { return sock.is_open(); }

void P2PClient::advance_state(bool called_from_runloop) {
	write();
	if (responses.size() > 1)
		return;  // keep outward queue busy with (one) response
	// TODO - keep track of total number of bytes to send, read new data when that number is low enough
	read(called_from_runloop);
}

void P2PClient::on_socket_disconnect() { disconnect(std::string()); }

void P2P::on_client_disconnected(P2PClient *who, std::string ban_reason) {
	const bool incoming = who->is_incoming();
	auto cit            = clients[incoming].find(who);
	if (cit == clients[incoming].end())
		return;
	disconnected_clients.push_back(std::move(cit->second));
	free_diconnected_timer.once(1);
	cit = clients[incoming].erase(cit);
	if (incoming)
		accept_all();
	else
		connect_all();
}

// void P2P::broadcast(P2PProtocol *exclude_who, const BinaryArray &data, bool incoming, bool outgoing) {
//	for (int inc = 0; inc != 2; ++inc) {
//		if (!incoming && inc == 0)
//			continue;
//		if (!outgoing && inc == 1)
//			continue;
//		for (auto &&cli : clients[inc]) {
//			if (cli.first->get_protocol()->handshake_ok() && cli.first->get_protocol() != exclude_who) {
//				cli.first->send(BinaryArray(data));
//			}
//		}
//	}
//}

// P2PClient *P2P::find_connecting_client(const NetworkAddress &address) {
//	const bool incoming = false;
//	for (auto &&cli : clients[incoming])
//		if (cli.first->get_address() == address)
//			return cli.first;
//	return nullptr;
//}

// P2PClient *P2P::find_client(const NetworkAddress &address, bool incoming) {
//	for (auto &&cli : clients[incoming])
//		if (cli.first->handshake_ok() && cli.first->get_address() == address)
//			return cli.first;
//	return nullptr;
//}

void P2P::accept_all() {
	if (!la_socket)
		return;
	//        std::cout << "Server::accept=" << std::endl;
	const bool incoming = true;
	while (clients[incoming].size() < config.p2p_max_incoming_connections) {
		if (!next_client[incoming]) {
			next_client[incoming] =
			    std::make_unique<P2PClient>(incoming, [](std::string ban_reason) {});  // We do not know Client * yet
			next_client[incoming]->d_handler =
			    std::bind(&P2P::on_client_disconnected, this, next_client[incoming].get(), _1);
		}
		std::string addr;
		if (!la_socket->accept(next_client[incoming]->sock, addr))
			return;
		NetworkAddress address;
		common::parse_ip_address(addr, &address.ip);
		address.port                   = 0;  // Will set to self-reported port on handshake, was config.p2p_bind_port;
		next_client[incoming]->address = address;
		if (peers.is_peer_banned(address, get_local_time())) {
			// TODO - do not write to log more often than 1/sec or this can be attack vector
			log(logging::INFO) << "Accepted from banned address " << addr << " disconnecting immediately" << std::endl;
			next_client[incoming]->sock.close();
			continue;
		}
		P2PClient *who                                 = next_client[incoming].get();
		clients[incoming][next_client[incoming].get()] = std::move(next_client[incoming]);
		log(logging::INFO) << "Accepted from addr=" << addr << std::endl;
		who->set_protocol(c_factory(who));
	}
}

bool P2P::connect_one(const NetworkAddress &address) {
	const bool incoming = false;
	if (!next_client[incoming]) {
		next_client[incoming] =
		    std::make_unique<P2PClient>(incoming, [](std::string ban_reason) {});  // We do not know Client * yet
		next_client[incoming]->d_handler =
		    std::bind(&P2P::on_client_disconnected, this, next_client[incoming].get(), _1);
	}
	if (!next_client[incoming]->sock.connect(common::ip_address_to_string(address.ip), address.port)) {
		return false;
	}
	next_client[incoming]->address = address;
	P2PClient *who                 = next_client[incoming].get();
	clients[incoming][who]         = std::move(next_client[incoming]);
	log(logging::INFO) << "Connecting to=" << common::ip_address_and_port_to_string(address.ip, address.port)
	                   << std::endl;
	who->set_protocol(c_factory(who));
	return true;
}

void P2P::connect_all() {
	if (failed_connection_attempts_counter > config.p2p_max_outgoing_connections * 5)  // CONSTANT in code
		reconnect_timer.once(NO_INTERNET_RECONNECT_DELAY);
	else
		connect_all_nodelay();
}

void P2P::connect_all_nodelay() {
	const bool incoming         = false;
	unsigned immediate_attempts = 0;
	while (clients[incoming].size() < config.p2p_max_outgoing_connections) {
		std::set<NetworkAddress> connected;
		for (auto &&cit : clients[incoming]) {
			connected.insert(cit.first->address);
		}
		//		NetworkAddress self_connected;
		//		common::parse_ip_address("127.0.0.1", &self_connected.ip);
		//		self_connected.port = config.p2p_bind_port;
		//		connected.insert(self_connected);

		NetworkAddress best_address;
		if (!peers.get_peer_to_connect(best_address, connected, get_local_time())) {
			log(logging::TRACE) << "No peers to connect to, will try again after " << RECONNECT_TIMEOUT << " seconds"
			                    << std::endl;
			reconnect_timer.once(RECONNECT_TIMEOUT);
			return;
		}
		failed_connection_attempts_counter += 1;
		if (!connect_one(best_address))
			immediate_attempts += 1;
		if (immediate_attempts >=
		    config.p2p_max_outgoing_connections) {  // When network is not reachable, we try just a handfull times
			log(logging::INFO) << "Connect repeatedly fails, will try again after " << RECONNECT_TIMEOUT << " seconds"
			                   << std::endl;
			reconnect_timer.once(RECONNECT_TIMEOUT);
			return;
		}
	}
}

void P2P::peers_updated() {
	failed_connection_attempts_counter = 0;  // Brittle! We use the fact that this is called from handshake
	connect_all();
}

P2P::P2P(logging::ILogger &log, const Config &config, PeerDB &peers, client_factory c_factory)
    : config(config)
    , log(log, "P2P")
    , peers(peers)
    , reconnect_timer(std::bind(&P2P::connect_all_nodelay, this))
    , free_diconnected_timer([&]() { disconnected_clients.clear(); })
    , c_factory(c_factory)
    , unique_number(crypto::rand<uint64_t>()) {
	try {
		la_socket.reset(
		    new platform::TCPAcceptor{config.p2p_bind_ip, config.p2p_bind_port, std::bind(&P2P::accept_all, this)});
	} catch (const std::runtime_error &ex) {
		this->log(logging::WARNING) << " failed to create listening socket, what=" << common::what(ex)
		                            << ", working with outbound connections only" << std::endl;
	}
	connect_all();
	accept_all();
}

// We do not have p2p time yet
uint32_t P2P::get_p2p_time() const { return get_local_time(); }

uint32_t P2P::get_local_time() const { return platform::now_unix_timestamp(); }

// std::vector<NetworkAddress> P2P::good_clients(bool incoming) const {
//	std::vector<NetworkAddress> result;
//	for (auto &&cit : clients[incoming]) {
//		if (cit.first->get_protocol()->handshake_ok()) {
//			result.push_back(cit.first->address);
//		}
//	}
//	return result;
//}
