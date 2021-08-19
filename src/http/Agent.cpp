// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Agent.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#include "common/Invariant.hpp"
#include "common/StringTools.hpp"
#include "common/exception.hpp"
#include "platform/Network.hpp"

using namespace http;

#ifdef __EMSCRIPTEN__
#include <emscripten/fetch.h>

class Agent::Connection {
public:
	explicit Connection(Agent *owner) : owner(owner), pending_wait(false) {}
	Agent *owner;
	bool pending_wait;
	RequestBody req;  // body pointer must be valid during request

	void disconnect() {
		if (pending_wait) {
			owner->client.release();  // owned by JS now
			owner = nullptr;
		}
	}
	static void static_success(emscripten_fetch_t *fetch) {
		reinterpret_cast<Connection *>(fetch->userData)->handle_result(fetch, true);
	}
	static void static_failed(emscripten_fetch_t *fetch) {
		reinterpret_cast<Connection *>(fetch->userData)->handle_result(fetch, false);
	}
	void handle_result(emscripten_fetch_t *fetch, bool success) {
		pending_wait = false;
		if (owner) {
			//  We ignore success, because we look at http status
			ResponseBody response;
			response.r.status      = fetch->status;
			response.r.status_text = fetch->statusText;
			response.body.assign(fetch->data, fetch->numBytes);
			//  std::cout << "handle_result " << response.r.status << " " << response.r.status_text << std::endl;
			//  std::cout << response.body << std::endl;
			owner->handle_response(std::move(response));  // never throws
			emscripten_fetch_close(fetch);
			return;
		}
		emscripten_fetch_close(fetch);
		delete this;  // was owned by JS
	}
	void start_request(RequestBody &&req2) {
		req = std::move(req2);
		// assert(pending_wait == false);
		emscripten_fetch_attr_t attr;
		emscripten_fetch_attr_init(&attr);
		invariant(req.r.method.size() + 1 <= sizeof(attr.requestMethod), "");
		memmove(attr.requestMethod, req.r.method.c_str(), req.r.method.size() + 1);
		// TODO - authorization
		//		attr.userName = req.r.basic_authorization;
		//		attr.password = req.r.basic_authorization;
		attr.userData        = this;
		attr.attributes      = EMSCRIPTEN_FETCH_LOAD_TO_MEMORY;
		attr.onsuccess       = static_success;
		attr.onerror         = static_failed;
		attr.requestData     = req.body.data();
		attr.requestDataSize = req.body.size();
		attr.timeoutMSecs    = 600 * 1000;
		std::vector<std::string> headers(req.r.headers.size());
		std::vector<const char *> pheaders(req.r.headers.size() + 1);  // trailing nullptr
		for (size_t i = 0; i != headers.size(); ++i) {
			headers[i] = req.r.headers[i].name + ": " + req.r.headers[i].value;
			//			std::cout << "header " << headers[i] << std::endl;
			pheaders[i] = headers[i].c_str();
		}
		attr.requestHeaders = pheaders.data();
		const std::string prefix1("https://");
		const std::string prefix2("http://");
		std::string addr = owner->address;
		if (!common::starts_with(owner->address, prefix1) && !common::starts_with(owner->address, prefix2))
			addr = prefix2 + addr;
		addr += ":" + common::to_string(owner->port) + req.r.uri;
		//		std::cout << "fetch " << addr << " size=" << attr.requestDataSize << std::endl;
		pending_wait = true;
		emscripten_fetch(&attr, addr.c_str());
	}
};

void Agent::on_client_response() {}

void Agent::on_client_disconnect() {}

void Agent::set_request(Request *req) {
	invariant(!sent_request, "Agent is busy with previous request");
	sent_request = req;
	if (!client)
		client = std::make_unique<Connection>(this);
	client->start_request(RequestBody(sent_request->req));
}

#else
class Agent::Connection {
public:
	typedef std::function<void()> handler;

	explicit Connection(handler &&r_handler, handler &&d_handler);

	bool connect(const std::string &address, uint16_t port);
	bool is_open() const { return sock.is_open(); }
	bool read_next(ResponseBody &request);
	void write(RequestBody &&response);

	void disconnect();

private:
	common::CircularBuffer buffer;
	std::deque<common::StringStream> responses;

	ResponseHeader request;
	ResponseParser parser;
	bool receiving_body;
	common::StringStream receiving_body_stream;

	bool waiting_write_response;

	void advance_state(bool called_from_runloop);
	void write();
	void on_disconnect();
	void clear();

	handler r_handler;
	handler d_handler;

	platform::TCPSocket sock;
	bool keep_alive;
};

Agent::Connection::Connection(handler &&r_handler, handler &&d_handler)
    : buffer(8192)
    , receiving_body(false)
    , waiting_write_response(false)
    , r_handler(std::move(r_handler))
    , d_handler(std::move(d_handler))
    , sock([this](bool, bool) { advance_state(true); }, std::bind(&Connection::on_disconnect, this))
    , keep_alive(true) {}

bool Agent::Connection::connect(const std::string &a, uint16_t p) {
	clear();
	waiting_write_response = true;
	return sock.connect(a, p);
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
	request = http::ResponseHeader{};

	sock.close();
}

bool Agent::Connection::read_next(ResponseBody &req) {
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
	request = http::ResponseHeader{};
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

void Agent::Connection::write(RequestBody &&response) {
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

void Agent::on_client_response() {
	ResponseBody response;
	if (client->read_next(response)) {
		handle_response(std::move(response));
	}
}

void Agent::on_client_disconnect() {
	if (sent_request)
		handle_error("Disconnect");
}

void Agent::set_request(Request *req) {
	invariant(!sent_request, "Agent is busy with previous request");
	sent_request = req;
	if (!client)
		client = std::make_unique<Connection>(
		    std::bind(&Agent::on_client_response, this), std::bind(&Agent::on_client_disconnect, this));
	if (!client->is_open() && !client->connect(address, port))
		return handle_error("Connect failed");
	client->write(RequestBody(sent_request->req));
}

#endif

Agent::Agent(const std::string &address, uint16_t port) : address(address), port(port) {}

Agent::~Agent() {
	//	assert(!sent_request);
}

void Agent::handle_response(ResponseBody &&response) {
	auto was_sent_request = sent_request;
	sent_request          = nullptr;
	if (was_sent_request) {
		Request::R_handler r_handler = std::move(was_sent_request->r_handler);
		Request::E_handler e_handler = std::move(was_sent_request->e_handler);
		try {
			try {
				r_handler(std::move(response));
			} catch (const std::exception &ex) {
				std::cout << "    Parsing received submit leads to throw/catch what=" << common::what(ex) << std::endl;
				e_handler(common::what(ex));
			} catch (...) {
				std::cout << "    Parsing received submit leads to throw/catch" << std::endl;
				e_handler("catch ...");
			}
		} catch (const std::exception &ex) {
			std::cout << "    Error handler leads to throw/catch what=" << common::what(ex) << std::endl;
		} catch (...) {
			std::cout << "    Error handler leads to throw/catch" << std::endl;
		}
	}
}

void Agent::handle_error(const char *reason) {
	auto was_sent_request        = sent_request;
	sent_request                 = nullptr;
	Request::E_handler e_handler = std::move(was_sent_request->e_handler);
	try {
		e_handler(reason);
	} catch (const std::exception &ex) {
		std::cout << "    Error handler 2 leads to throw/catch what=" << common::what(ex) << std::endl;
	} catch (...) {
		std::cout << "    Error handler 2 leads to throw/catch" << std::endl;
	}
}

void Agent::cancel_request(Request *req) {
	if (sent_request == req) {
		sent_request = nullptr;
		if (client)
			client->disconnect();
	}
}

Request::Request(Agent &agent, RequestBody &&req, R_handler &&r_handler, E_handler &&e_handler)
    : agent(agent), req(std::move(req)), r_handler(std::move(r_handler)), e_handler(std::move(e_handler)) {
	std::string host = agent.address;
	const std::string prefix1("https://");
	const std::string prefix2("http://");
	const std::string prefix3("ssl://");
	if (common::starts_with(host, prefix1))
		host = host.substr(prefix1.size());
	else if (common::starts_with(host, prefix2))
		host = host.substr(prefix2.size());
	else if (common::starts_with(host, prefix3))
		host = host.substr(prefix3.size());
	this->req.r.host = host;
	agent.set_request(this);
}

Request::~Request() { agent.cancel_request(this); }
