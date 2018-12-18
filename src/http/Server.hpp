// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <deque>
#include <map>
#include <memory>
#include "platform/Network.hpp"
#include "types.hpp"

namespace http {

class ErrorAuthorization : public std::runtime_error {
public:
	explicit ErrorAuthorization(std::string realm)
	    : std::runtime_error("Error Authorization Required"), realm(std::move(realm)) {}
	std::string realm;
};

class Client;

class Server {
public:
	typedef std::function<bool(Client *who, RequestBody &&request, ResponseBody &response)> request_handler;
	typedef std::function<void(Client *who)> disconnect_handler;

	explicit Server(
	    const std::string &address, uint16_t port, request_handler &&r_handler, disconnect_handler &&d_handler);
	~Server();

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
}  // namespace http
