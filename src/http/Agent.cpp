// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include "Agent.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>

using namespace http;

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
		responses.front().copyTo(sock);
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
	if (!waiting_write_response)
		throw std::logic_error("Client unexpected write");
	waiting_write_response = false;
	if (!response.r.http_version_major)
		throw std::logic_error("Someone forgot to set version, method, status or url");
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
		buffer.copyFrom(sock);
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
		buffer.copyTo(receiving_body_stream, max_count);
		if (expect_count == receiving_body_stream.size()) {
			if (called_from_runloop)
				r_handler();
			return;
		}
		buffer.copyFrom(sock);
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
    , reconnect_timer(std::bind(&Agent::on_reconnect_timer, this)) {
	on_reconnect_timer();
}

Agent::~Agent() { assert(!sent_request); }

bool Agent::disconnected_for_long_time() const {
	return false;  // TODO - implement. For now will wait forever for reconnection
}

void Agent::set_request(Request *req) {
	if (sent_request)
		throw std::logic_error("Agent is busy with previous request");
	sent_request = req;
	send_request();
}

void Agent::cancel_request(Request *req) {
	if (sent_request == req) {
		sent_request = nullptr;
		client.disconnect();
		reconnect_timer.once(10);
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
			} catch (std::exception &ex) {
				std::cout << "    Parsing received submit leads to throw/catch what=" << ex.what() << std::endl;
				e_handler(ex.what());
			} catch (...) {
				std::cout << "    Parsing received submit leads to throw/catch" << std::endl;
				e_handler("catch ...");
			}
		}
	}
}

void Agent::on_client_disconnect() { reconnect_timer.once(10); }

void Agent::send_request() {
	if (client.is_open())
		client.write(RequestData(sent_request->req));
}

void Agent::on_reconnect_timer() {
	if (disconnected_for_long_time() && sent_request) {
		auto was_sent_request = sent_request;
		sent_request          = nullptr;
		if (was_sent_request) {
			Request::E_handler e_handler = std::move(was_sent_request->e_handler);
			e_handler("Timeout");
		}
	}
	if (!client.connect(address, port)) {
		reconnect_timer.once(10);
		return;
	}
	if (sent_request)
		send_request();
}

Request::Request(Agent &agent, RequestData &&req, R_handler r_handler, E_handler e_handler)
    : agent(agent), req(std::move(req)), r_handler(r_handler), e_handler(e_handler) {
	agent.set_request(this);
}

Request::~Request() { agent.cancel_request(this); }
