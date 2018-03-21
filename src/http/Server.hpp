// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <deque>
#include <map>
#include <memory>
#include "RequestParser.hpp"
#include "common/MemoryStreams.hpp"
#include "platform/Network.hpp"
#include "types.hpp"

namespace http {

class Client {
public:
	typedef std::function<void()> handler;

	explicit Client(handler r_handler, handler d_handler)
	    : buffer(8192)
	    , receiving_body(false)
	    , waiting_write_response(false)
	    , r_handler(r_handler)
	    , d_handler(d_handler)
	    , sock([this](bool, bool) { advance_state(true); }, std::bind(&Client::on_disconnect, this))
	    , keep_alive(true) {}
	bool read_next(RequestData &request);
	void write(ResponseData &&response);

	void disconnect();

private:
	void clear();
	friend class Server;

	common::CircularBuffer buffer;
	std::deque<common::StringStream> responses;

	http::request request;
	http::RequestParser parser;
	bool receiving_body;
	common::StringStream receiving_body_stream;

	bool waiting_write_response;

	void advance_state(bool called_from_runloop);
	void write();
	void on_disconnect();

	handler r_handler;
	handler d_handler;

	platform::TCPSocket sock;
	bool keep_alive;
};

class Server {
public:
	typedef std::function<bool(Client *who, RequestData &&request, ResponseData &response)> request_handler;
	typedef std::function<void(Client *who)> disconnect_handler;

	explicit Server(const std::string &address, uint16_t port, request_handler r_handler, disconnect_handler d_handler,
	    const std::string &ssl_pem_file = std::string(), const std::string &ssl_certificate_password = std::string())
	    : la_socket{new platform::TCPAcceptor{
	          address, port, std::bind(&Server::accept_all, this), ssl_pem_file, ssl_certificate_password}}
	    , r_handler(r_handler)
	    , d_handler(d_handler) {
		accept_all();
	}

	static void test();

private:
	std::unique_ptr<platform::TCPAcceptor> la_socket;

	std::map<Client *, std::unique_ptr<Client>> clients;  // Alas, no way to look for an element in set<unique_ptr<_>>
	std::unique_ptr<Client> next_client;

	void on_client_disconnected(Client *who);
	void on_client_handler(Client *who);
	void accept_all();

	request_handler r_handler;
	disconnect_handler d_handler;
};
}
