// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Server.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#include "common/Invariant.hpp"

// to test
// httperf --port 8090 --num-calls 100000 --uri /index.html
// curl -s "http://localhost:8888/?[1-10000]"
// USELESS siege -b -r 1000 -c 100 http://localhost:8888/index.html
// USELESS ab -n 100000 -c 50 -k localhost:8090/index.html
// wrk -t2 -c20 -d5s http://127.0.0.1:8888/index.html

using namespace http;

void Client::disconnect() {
	clear();
	d_handler();
}

void Client::clear() {
	waiting_write_response = false;
	keep_alive             = true;
	parser.reset();
	buffer.clear();
	responses.clear();
	receiving_body = false;
	receiving_body_stream.clear();
	request = http::request();

	sock.close();
}

bool Client::read_next(RequestData &req) {
	if (waiting_write_response)
		return false;
	if (!receiving_body)
		return false;
	size_t expect_count = request.has_content_length() ? request.content_length : 0;
	if (receiving_body_stream.size() != expect_count)
		return false;
	req.body = std::move(receiving_body_stream.buffer());
	receiving_body_stream.clear();
	req.r   = std::move(request);
	request = http::request();
	parser.reset();
	receiving_body         = false;
	waiting_write_response = true;
	return true;
}

void Client::write() {
	while (!responses.empty()) {
		responses.front().copy_to(sock);
		if (responses.front().size() != 0)
			break;
		responses.pop_front();
	}
	if (!waiting_write_response && responses.empty() && !keep_alive) {
		sock.shutdown_both();
		keep_alive = true;
	}
}

void Client::write(ResponseData &&response) {
	invariant(waiting_write_response, "Client unexpected write");
	waiting_write_response = false;
	invariant(response.r.http_version_major, "Someone forgot to set version, method, status or url");
	this->keep_alive = response.r.keep_alive;
	std::string str  = response.r.to_string();
	responses.emplace_back();
	responses.back().write(str.data(), str.size());
	responses.emplace_back(std::move(response.body));
	write();
}

void Client::advance_state(bool called_from_runloop) {
	write();
	if (!responses.empty() || waiting_write_response) {
		return;  // do not process new request until previous response completely sent. TODO - process.short responses
	}
	if (!receiving_body) {
		buffer.copy_from(sock);
		// Twice to have a chance to read both parts of buffer
		auto ptr = parser.parse(request, buffer.read_ptr(), buffer.read_ptr() + buffer.read_count());
		buffer.did_read(ptr - buffer.read_ptr());
		ptr = parser.parse(request, buffer.read_ptr(), buffer.read_ptr() + buffer.read_count());
		buffer.did_read(ptr - buffer.read_ptr());
		if (!parser.is_bad() && !parser.is_good())
			return;
		if (parser.is_bad()) {
			sock.shutdown_both();  // Will potentially be called many times
			return;
		}
		receiving_body = true;
		receiving_body_stream.clear();
	}
	while (true) {
		size_t expect_count = request.has_content_length() ? request.content_length : 0;
		size_t max_count    = expect_count - receiving_body_stream.size();
		buffer.copy_to(receiving_body_stream, max_count);
		if (expect_count == receiving_body_stream.size()) {
			if (called_from_runloop)
				r_handler();
			return;
		}
		buffer.copy_from(sock);
		if (buffer.empty())
			break;
	}
}

void Client::on_disconnect() { disconnect(); }

void Server::on_client_disconnected(Client *who) {
	auto cit = clients.find(who);
	if (cit == clients.end())
		return;
	auto cli = std::move(cit->second);
	cit      = clients.erase(cit);
	d_handler(who);
}

void Server::on_client_handler(Client *who) {
	RequestData request;
	while (who->read_next(request)) {
		ResponseData response(request.r);
		response.r.status = 422;
		response.set_body(std::string());

		bool result = true;
		try {
			result = r_handler(who, std::move(request), response);
		} catch (const std::exception &e) {
			std::cout << "HTTP request leads to throw/catch, what=" << e.what() << std::endl;
			response.r.status = 422;
			response.set_body(e.what());
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

void Server::test() {}
