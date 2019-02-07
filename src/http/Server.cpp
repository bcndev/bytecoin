// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Server.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#include "Client.hpp"
#include "RequestParser.hpp"
#include "common/Invariant.hpp"
#include "common/exception.hpp"

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
Server::~Server() {}  // we use unique_ptrs to incomplete type

void Server::on_client_disconnected(Client *who) {
	auto cit = clients.find(who);
	if (cit == clients.end())
		return;
	auto cli = std::move(cit->second);
	cit      = clients.erase(cit);
	d_handler(who);
}

void Server::on_client_handler(Client *who) {
	RequestBody request;
	while (who->read_next(request)) {
		ResponseBody response(request.r);
		response.r.status = 422;
		response.set_body(std::string());

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
}

void Server::accept_all() {
	if (!la_socket)
		return;
	while (true) {
		if (!next_client) {
			next_client            = std::make_unique<Client>([]() {}, []() {});  // We do not know Client * yet
			next_client->r_handler = std::bind(&Server::on_client_handler, this, next_client.get());
			next_client->d_handler = std::bind(&Server::on_client_disconnected, this, next_client.get());
		}
		std::string addr;
		if (!la_socket->accept(next_client->sock, addr))
			return;
		clients[next_client.get()] = std::move(next_client);
		//        std::cout << "HTTP Client accepted=" << cid << " addr=" << addr << std::endl;
	}
}
