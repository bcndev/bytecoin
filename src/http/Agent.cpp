// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Agent.hpp"
#include <assert.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include "common/Invariant.hpp"

using namespace http;

static const int REQUEST_TIMEOUT = 30;

Agent::Connection::Connection(handler r_handler, handler d_handler)
    : buffer(8192)
    , receiving_body(false)
    , waiting_write_response(false)
    , r_handler(r_handler)
    , d_handler(d_handler)
    , sock([this](bool, bool) { advance_state(true); }, std::bind(&Connection::on_disconnect, this))
    , keep_alive(true) {}

bool Agent::Connection::connect(const std::string &address, uint16_t port) {
	clear();
	waiting_write_response = true;
	return sock.connect(address, port);
}

void Agent::Connection::disconnect() {
	clear();
	d_handler();
}

void Agent::Connection::clear() {
	waiting_write_response = false;
	keep_alive             = true;
	parser.reset();
	buffer.clear();
	responses.clear();
	receiving_body = false;
	receiving_body_stream.clear();
	request = http::response{};

	sock.close();
}

bool Agent::Connection::read_next(ResponseData &req) {
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
	request = http::response{};
	parser.reset();
	receiving_body         = false;
	waiting_write_response = true;
	return true;
}

void Agent::Connection::write() {
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

void Agent::Connection::write(RequestData &&response) {
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

void Agent::Connection::advance_state(bool called_from_runloop) {
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

void Agent::Connection::on_disconnect() { disconnect(); }

Agent::Agent(const std::string &address, uint16_t port)
    : sent_request(nullptr)
    , address(address)
    , port(port)
    , client(std::bind(&Agent::on_client_response, this), std::bind(&Agent::on_client_disconnect, this))
    , reconnect_timer(std::bind(&Agent::on_reconnect_timer, this)) {}

Agent::~Agent() { assert(!sent_request); }

void Agent::set_request(Request *req) {
	invariant(!sent_request, "Agent is busy with previous request");
	sent_request  = req;
	request_start = std::chrono::steady_clock::now();
	if (!client.is_open() && !client.connect(address, port)) {
		reconnect_timer.once(10);
		return;
	}
	client.write(RequestData(sent_request->req));
}

void Agent::cancel_request(Request *req) {
	if (sent_request == req) {
		sent_request = nullptr;
		client.disconnect();
		reconnect_timer.cancel();
	}
}

void Agent::on_client_response() {
	ResponseData response;
	if (client.read_next(response)) {
		auto was_sent_request = sent_request;
		sent_request          = nullptr;
		if (was_sent_request) {
			Request::R_handler r_handler = std::move(was_sent_request->r_handler);
			Request::E_handler e_handler = std::move(was_sent_request->e_handler);
			try {
				r_handler(std::move(response));
			} catch (const std::exception &ex) {
				std::cout << "    Parsing received submit leads to throw/catch what=" << ex.what() << std::endl;
				e_handler(ex.what());
			} catch (...) {
				std::cout << "    Parsing received submit leads to throw/catch" << std::endl;
				e_handler("catch ...");
			}
		}
	}
}

void Agent::on_client_disconnect() {
	if (sent_request)
		reconnect_timer.once(10);
}

void Agent::on_reconnect_timer() {
	if (!sent_request)
		return;  // Should not happen
	auto idea_sec = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - request_start);
	if (idea_sec.count() > REQUEST_TIMEOUT) {
		auto was_sent_request        = sent_request;
		sent_request                 = nullptr;
		Request::E_handler e_handler = std::move(was_sent_request->e_handler);
		e_handler("Timeout");
		return;
	}
	if (!client.is_open() && !client.connect(address, port)) {
		reconnect_timer.once(10);
		return;
	}
	client.write(RequestData(sent_request->req));
}

Request::Request(Agent &agent, RequestData &&req, R_handler r_handler, E_handler e_handler)
    : agent(agent), req(std::move(req)), r_handler(r_handler), e_handler(e_handler) {
	std::string host = agent.address;
	const std::string prefix1("https://");
	const std::string prefix2("ssl://");
	if (host.find(prefix1) == 0)
		host = host.substr(prefix1.size());
	else if (host.find(prefix2) == 0)
		host         = host.substr(prefix2.size());
	this->req.r.host = host;
	agent.set_request(this);
}

Request::~Request() { agent.cancel_request(this); }
