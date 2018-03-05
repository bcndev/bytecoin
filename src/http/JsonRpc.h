// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include <boost/foreach.hpp>
#include <boost/optional.hpp>
#include <functional>
#include <unordered_map>

#include "common/JsonValue.hpp"
#include "seria/JsonInputValue.hpp"
#include "seria/JsonOutputStream.hpp"
#include "types.hpp"

namespace byterub {
namespace json_rpc {

const int errParseError     = -32700;
const int errInvalidRequest = -32600;
const int errMethodNotFound = -32601;
const int errInvalidParams  = -32602;
const int errInternalError  = -32603;

class Error : public std::exception {
public:
	Error();
	explicit Error(int c);
	Error(int c, const std::string &msg);

	virtual const char *what() const throw() override { return message.c_str(); }
	static std::string get_message(int code);

	int code;
	std::string message;
};
}
}

namespace seria {
inline void ser_members(byterub::json_rpc::Error &v, ISeria &s) {
	seria_kv("code", v.code, s);
	seria_kv("message", v.message, s);
}
}

namespace byterub {
namespace json_rpc {

typedef boost::optional<common::JsonValue> OptionalJsonValue;

class Request {
	bool parse_request(const std::string &request_body) {
		common::JsonValue ps_req;
		try {
			ps_req = common::JsonValue::from_string(request_body);
		} catch (std::exception &) {
			throw Error(errParseError);
		}
		if (!ps_req.is_object() || !ps_req.contains("method"))
			throw Error(errInvalidRequest);
		method = ps_req("method").get_string();
		if (ps_req.contains("id"))
			id = ps_req("id");
		if (ps_req.contains("params"))
			params = ps_req("params");
		return true;
	}

public:
	Request() : params(common::JsonValue::NIL) {}
	explicit Request(const std::string &request_body) : params(common::JsonValue::NIL) { parse_request(request_body); }
	template<typename T>
	void set_params(const T &v) {
		params = seria::to_json_value(v);
	}
	template<typename T>
	void load_params(T &v) const {
		seria::from_json_value(v, params);
	}

	void set_method(const std::string &m) { method = m; }
	const std::string &get_method() const { return method; }

	void set_id(const OptionalJsonValue &sid) { id = sid; }
	const OptionalJsonValue &get_id() const { return id; }

	std::string get_body() {
		common::JsonValue ps_req(common::JsonValue::OBJECT);
		ps_req.set("jsonrpc", std::string("2.0"));
		ps_req.set("method", method);
		ps_req.set("params", params);
		if (id)
			ps_req.set("id", id.get());
		return ps_req.to_string();
	}

private:
	common::JsonValue params;
	OptionalJsonValue id;
	std::string method;
};

class Response {
	void parse(const std::string &response_body) {
		common::JsonValue ps_req;
		try {
			ps_req = common::JsonValue::from_string(response_body);
		} catch (std::exception &) {
			throw Error(errParseError);
		}
		if (!ps_req.is_object())
			throw Error(errInvalidRequest);
		if (ps_req.contains("id"))
			id = ps_req("id");
		if (ps_req.contains("result"))
			result = ps_req("result");
		if (ps_req.contains("error"))
			error = ps_req("error");
	}

public:
	Response() : result(common::JsonValue::NIL) {}
	explicit Response(const std::string &response_body) : result(common::JsonValue::NIL) { parse(response_body); }
	void set_id(const OptionalJsonValue &sid) { id = sid; }
	const OptionalJsonValue &get_id() const { return id; }

	void set_error(const Error &err) { error = seria::to_json_value(err); }

	bool get_error(Error &err) const {
		if (!error)
			return false;
		seria::from_json_value(err, error.get());
		return true;
	}

	std::string get_body() {
		common::JsonValue ps_req(common::JsonValue::OBJECT);
		ps_req.set("jsonrpc", std::string("2.0"));
		if (error)
			ps_req.set("error", error.get());
		else
			ps_req.set("result", result);
		if (id)
			ps_req.set("id", id.get());
		return ps_req.to_string();
	}

	template<typename T>
	void set_result(const T &v) {
		result = seria::to_json_value(v);
	}

	template<typename T>
	void get_result(T &v) const {
		seria::from_json_value(v, result);
	}

private:
	common::JsonValue result;
	OptionalJsonValue id;
	OptionalJsonValue error;
};

template<typename Agent, typename RawRequest, typename RequestType, typename ResponseType, typename Handler>
bool invoke_method(Agent *agent, RawRequest &&raw_request, Request &&jsReq, Response &jsRes, Handler handler) {
	RequestType req{};
	ResponseType res{};
	jsReq.load_params(req);

	bool result = handler(agent, std::move(raw_request), std::move(jsReq), std::move(req), res);

	if (result)
		jsRes.set_result(res);
	return result;
}

template<typename Owner, typename Agent, typename RawRequest, typename Params, typename Result>
std::function<bool(Owner *, Agent *, RawRequest &&raw_request, Request &&, Response &)> makeMemberMethodSeria(
    bool (Owner::*handler)(Agent *, RawRequest &&, json_rpc::Request &&, Params &&, Result &)) {
	return [handler](Owner *obj, Agent *agent, RawRequest &&raw_request, Request &&req, Response &res) -> bool {
		return json_rpc::invoke_method<Agent, RawRequest, Params, Result>(agent, std::move(raw_request), std::move(req),
		    res, std::bind(handler, obj, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3,
		             std::placeholders::_4, std::placeholders::_5));
	};
}

// Always POST HTTP/1.1
template<typename ParamsType>
http::RequestData create_request(const std::string &uri, const std::string &method, const ParamsType &params,
    const OptionalJsonValue &id = OptionalJsonValue{}) {
	Request json_send_raw_req;
	json_send_raw_req.set_method(method);
	json_send_raw_req.set_params(params);
	json_send_raw_req.set_id(id);
	http::RequestData req_header;
	req_header.r.set_firstline("POST", uri, 1, 1);
	req_header.set_body(json_send_raw_req.get_body());
	return req_header;
}

template<typename ResponseType>
http::ResponseData create_response(
    const http::RequestData &request, const ResponseType &response, const OptionalJsonValue &id = OptionalJsonValue{}) {
	json_rpc::Response last_json_resp;
	last_json_resp.set_id(id);
	last_json_resp.set_result(response);
	http::ResponseData last_http_response(request.r);
	last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
	last_http_response.set_body(last_json_resp.get_body());
	last_http_response.r.status = 200;
	return last_http_response;
}

template<typename ResponseType>
void parse_response(const std::string &body, ResponseType &response, OptionalJsonValue *jid = nullptr) {
	json_rpc::Response json_resp(body);
	if (jid)
		*jid = json_resp.get_id();
	response = ResponseType();
	json_resp.get_result(response);
}
}
}
