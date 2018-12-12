// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Client.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#include "common/Invariant.hpp"
#include "common/exception.hpp"

using namespace http;

Client::Client(handler &&r_handler, handler &&d_handler)
    : buffer(8192)
    , receiving_body(false)
    , waiting_write_response(false)
    , r_handler(std::move(r_handler))
    , d_handler(std::move(d_handler))
    , sock([this](bool, bool) { advance_state(true); }, std::bind(&Client::on_disconnect, this))
    , keep_alive(true) {}

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
	request = http::RequestHeader{};

	sock.close();
}

bool Client::read_next(RequestBody &req) {
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
	request = http::RequestHeader{};
	parser.reset();
	receiving_body         = false;
	waiting_write_response = true;
	return true;
}

void Client::write() {
	while (!responses.empty()) {
		responses.front().copy_to(sock);
		if (!responses.front().empty())
			break;
		responses.pop_front();
	}
	if (!waiting_write_response && responses.empty() && !keep_alive) {
		sock.shutdown_both();
		keep_alive = true;
	}
}

void Client::write(ResponseBody &&response) {
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
