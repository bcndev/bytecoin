// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <algorithm>
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <set>
#include "ResponseParser.hpp"
#include "common/MemoryStreams.hpp"

namespace http {

class Request;

class Agent {
	class Connection;
	friend class Request;

	Request *sent_request = nullptr;
	std::string address;
	uint16_t port;
	std::unique_ptr<Connection> client;

	void on_client_response();
	void on_client_disconnect();
	void handle_error(const char *reason);
	void handle_response(ResponseBody &&response);

	void set_request(Request *req);
	void cancel_request(Request *req);

public:
	Agent(const std::string &address, uint16_t port);
	~Agent();
};

class Request {
public:
	typedef std::function<void(ResponseBody &&resp)> R_handler;
	typedef std::function<void(std::string err)> E_handler;

	Request(Agent &agent, RequestBody &&req, R_handler &&r_handler, E_handler &&e_handler);
	~Request();

private:
	friend class Agent;
	Agent &agent;
	RequestBody req;
	R_handler r_handler;
	E_handler e_handler;
};
}  // namespace http
