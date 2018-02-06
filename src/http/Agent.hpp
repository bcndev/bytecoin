#pragma once

#include <memory>
#include <algorithm>
#include <deque>
#include <set>
#include "platform/Network.hpp"
#include "common/MemoryStreams.hpp"
#include "ResponseParser.hpp"

namespace http {

class Request;

class Agent {
	class Connection {
	public:
		typedef std::function<void()> handler;

		explicit Connection(handler r_handler, handler d_handler);

		bool connect(const std::string &address, uint16_t port);
		bool is_open() const { return sock.is_open(); }
		bool read_next(ResponseData &request);
		void write(RequestData &&response);

		void disconnect();
	private:
		common::CircularBuffer buffer;
		std::deque<common::StringStream> responses;

		response request;
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

	friend class Request;

	Request *sent_request;
	std::string address;
	uint16_t port;
	Connection client;
	platform::Timer reconnect_timer;

	void send_request();
	void on_client_response();
	void on_client_disconnect();
	void on_reconnect_timer();

	void set_request(Request *req);
	void cancel_request(Request *req);
public:
	Agent(const std::string &address, uint16_t port);
	~Agent();
	bool disconnected_for_long_time() const;
};

class Request {
public:
	typedef std::function<void(ResponseData &&resp)> R_handler;
	typedef std::function<void(std::string err)> E_handler;

	Request(Agent &agent, RequestData &&req, R_handler r_handler, E_handler e_handler);
	~Request();
private:
	friend class Agent;
	Agent &agent;
    RequestData req;
	R_handler r_handler;
	E_handler e_handler;
};

}

