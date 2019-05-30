// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <deque>
#include <map>
#include <memory>
#include <stdexcept>
#include <functional>

namespace platform {
class TCPAcceptor;
}
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

	static void write(Client *who, ResponseBody &&response);

#ifdef __EMSCRIPTEN__
	void global_request(std::unique_ptr<Client> &&client, RequestBody &&request);
	void global_disconnect(Client *client);
#endif
private:
	friend class Client;
	std::map<Client *, std::unique_ptr<Client>> clients;  // Alas, no way to look for an element in set<unique_ptr<_>>
#ifdef __EMSCRIPTEN__
	void on_client_disconnected(Client *who);
#else
	std::unique_ptr<platform::TCPAcceptor> la_socket;

	std::unique_ptr<Client> next_client;

	void on_client_handler(Client *who);
	void on_client_disconnected(Client *who);
	void accept_all();
#endif

	void on_client_handle_request(Client *who, RequestBody &&request);

	request_handler r_handler;
	disconnect_handler d_handler;
};
}  // namespace http
