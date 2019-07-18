// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Server.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#include "RequestParser.hpp"
#include "common/Invariant.hpp"
#include "common/exception.hpp"
#include "platform/Network.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

#ifdef __EMSCRIPTEN__

#include <emscripten/bind.h>
#include <emscripten/emscripten.h>

static http::Server *global_server = nullptr;
// If we later need more than 1, we will make a map of port->servers

namespace http {

class Client {
public:
	explicit Client(emscripten::val &&cb, size_t handle) : cb(std::move(cb)), handle(handle) {}
	emscripten::val cb;
	size_t handle;

	void write(ResponseBody &&response) {
		//		std::cout << "Client write " << handle << std::endl;
		try {
			cb(handle, response.r.status, response.body);
		} catch (...) {
			// We catch JS errors as ... and ignore them
			std::cout << "Client::write cb leads to throw/catch" << std::endl;
		}
		global_server->on_client_disconnected(this);
	}
};

}  // namespace http

void worker_http_request(emscripten::val cb, size_t handle, std::string method, std::string uri, std::string body) {
	//	std::cout << "worker_http_request " << handle << std::endl;

	auto next_client = std::make_unique<http::Client>(std::move(cb), handle);
	http::RequestBody req;
	req.r.http_version_major = 1;
	req.r.http_version_minor = 1;
	req.r.method             = std::move(method);
	req.r.uri                = std::move(uri);
	req.body                 = std::move(body);
	global_server->global_request(std::move(next_client), std::move(req));
}

EMSCRIPTEN_BINDINGS(my_module2) { emscripten::function("worker_http_request", &worker_http_request); }

using namespace http;

Server::Server(const std::string &address, uint16_t port, request_handler &&r_handler, disconnect_handler &&d_handler)
    : r_handler(std::move(r_handler)), d_handler(std::move(d_handler)) {
	if (global_server)
		throw std::runtime_error("You can have only 1 server for now");
	global_server = this;
}

Server::~Server() {
	if (global_server == this)  // Must be always
		global_server = nullptr;
}

void Server::global_request(std::unique_ptr<Client> &&client, RequestBody &&request) {
	//	std::cout << "global_request 1" << std::endl;
	Client *who = client.get();
	//	std::cout << "global_request 2" << std::endl;
	clients[who] = std::move(client);
	//	auto who     = next_client.get();
	//	if (!clients.emplace(handle, std::move(next_client)).second)
	//		throw std::runtime_error("cn_http_server_call with repeated handle");
	//	std::cout << "global_request 3" << std::endl;
	on_client_handle_request(who, std::move(request));
}

void Server::global_disconnect(Client *client) { on_client_disconnected(client); }

/*
#elif platform_USE_QT

Client::Client(){

}

void Client::send(const QString & body) {
    if(is_sent)
        throw std::runtime_error("You can send each request only once");
    is_sent = true;
    global_server->on_client_handle_request(who, std::move(request));
}

Client::~Client() {
    global_server->on_client_disconnected(this);
}

void Client::write(ResponseBody &&response) {
    std::cout << "Client write 1" << std::endl;
    try {
        cb(response.r.status, response.body);
        std::cout << "Client write 2" << std::endl;
    } catch (...) {
        // We catch JS errors as ... and ignore them
        std::cout << "Client::write cb leads to throw/catch" << std::endl;
    }
}

using namespace http;

static http::Server *global_server = nullptr;
// If we later need more than 1, we will make a map of port->servers

Server::Server(const std::string &address, uint16_t port, request_handler &&r_handler, disconnect_handler &&d_handler)
    : r_handler(std::move(r_handler)), d_handler(std::move(d_handler)) {
    if (global_server)
        throw std::runtime_error("You can have only 1 server for now");
    global_server = this;
}

Server::~Server() {
    if (global_server == this)  // Must be always
        global_server = nullptr;
}

void Server::global_request(std::unique_ptr<Client> &&client, RequestBody &&request) {
    //	std::cout << "global_request 1" << std::endl;
    Client *who = client.get();
    //	std::cout << "global_request 2" << std::endl;
    clients[who] = std::move(client);
    //	auto who     = next_client.get();
    //	if (!clients.emplace(handle, std::move(next_client)).second)
    //		throw std::runtime_error("cn_http_server_call with repeated handle");
    //	std::cout << "global_request 3" << std::endl;
}
*/
#else

#include "Client.hpp"

// to test
// httperf --port 8090 --num-calls 100000 --uri /index.html
// curl -s "http://127.0.0.1:8888/?[1-10000]"
// USELESS siege -b -r 1000 -c 100 http://127.0.0.1:8888/index.html
// USELESS ab -n 100000 -c 50 -k localhost:8090/index.html
// wrk -t2 -c20 -d5s http://127.0.0.1:8888/index.html

using namespace http;

Server::Server(const std::string &address, uint16_t port, request_handler &&r_handler, disconnect_handler &&d_handler)
    : la_socket{std::make_unique<platform::TCPAcceptor>(address, port, std::bind(&Server::accept_all, this))}
    , r_handler(std::move(r_handler))
    , d_handler(std::move(d_handler)) {
	accept_all();
}
Server::~Server() = default;  // we use unique_ptrs to incomplete type

void Server::on_client_handler(Client *who) {
	RequestBody request;
	while (who->read_next(request)) {
		on_client_handle_request(who, std::move(request));
	}
}

void Server::accept_all() {
	if (!la_socket)
		return;
	while (true) {  // clients.size() < max_incoming_connections
		if (!next_client) {
			next_client = std::make_unique<Client>();
			// We do not know Client * in constructor, so set handlers afterwards
			next_client->r_handler = std::bind(&Server::on_client_handler, this, next_client.get());
			next_client->d_handler = std::bind(&Server::on_client_disconnected, this, next_client.get());
		}
		std::string addr;
		if (!la_socket->accept(next_client->sock, addr))
			return;
		auto who     = next_client.get();
		clients[who] = std::move(next_client);
		//        std::cout << "HTTP Client accepted=" << cid << " addr=" << addr << std::endl;
	}
}

#endif

void Server::write(Client *who, ResponseBody &&response) { who->write(std::move(response)); }

void Server::on_client_disconnected(Client *who) {
	auto cit = clients.find(who);
	if (cit == clients.end())
		return;
	auto cli = std::move(cit->second);
	cit      = clients.erase(cit);
	d_handler(who);
}

void Server::on_client_handle_request(Client *who, RequestBody &&request) {
	ResponseBody response(request.r);
	response.r.status = 422;
	response.set_body(std::string{});

	bool result = true;
	try {
		result = r_handler(who, std::move(request), response);
	} catch (const ErrorAuthorization &e) {
		std::cout << "HTTP unauthorized request" << std::endl;
		response.r.headers.push_back({"WWW-Authenticate", "Basic realm=\"" + e.realm + "\", charset=\"UTF-8\""});
		response.r.status = 401;
	} catch (const std::exception &e) {
		std::cout << "HTTP request leads to throw/catch, what=" << common::what(e) << std::endl;
		response.r.status = 422;
		response.set_body(common::what(e));
	} catch (...) {
		std::cout << "HTTP request leads to throw/catch" << std::endl;
		response.r.status = 422;
	}
	if (result)
		who->write(std::move(response));
}
