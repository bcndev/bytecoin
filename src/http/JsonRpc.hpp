// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <boost/foreach.hpp>
#include <boost/optional.hpp>
#include <functional>
#include <unordered_map>

#include "common/Invariant.hpp"
#include "common/JsonValue.hpp"
#include "seria/JsonInputStream.hpp"
#include "seria/JsonOutputStream.hpp"
#include "types.hpp"

namespace bytecoin {
namespace json_rpc {

const int PARSE_ERROR      = -32700;
const int INVALID_REQUEST  = -32600;
const int METHOD_NOT_FOUND = -32601;
const int INVALID_PARAMS   = -32602;
const int INTERNAL_ERROR   = -32603;

class Error : public std::exception {
public:
	Error();
	explicit Error(int c);
	Error(int c, const std::string &msg);

	virtual const char *what() const throw() override { return message.c_str(); }
	static std::string get_message(int code);

	int code;
	std::string message;

	virtual void seria_data(seria::ISeria &s);
	virtual void seria_data_members(seria::ISeria &s);
};

typedef boost::optional<common::JsonValue> OptionalJsonValue;

class Request {
public:
	Request() {}
	explicit Request(const std::string &request_body, bool allow_empty_id = false) {
		parse(request_body, allow_empty_id);
	}
	template<typename T>
	void load_params(T &v) const {
		if (params)
			seria::from_json_value(v, params.get());
	}
	const std::string &get_method() const { return method; }
	const OptionalJsonValue &get_id() const { return jid; }

private:
	void parse(const std::string &request_body, bool allow_empty_id);

	OptionalJsonValue params;
	OptionalJsonValue jid;
	std::string method;
};

class Response {
public:
	explicit Response(const std::string &response_body) { parse(response_body); }
	const common::JsonValue &get_id() const { return jid; }

	template<typename T>
	bool get_error(T &err) const {
		static_assert(std::is_base_of<Error, T>::value, "T must be an json_rpc::Error descendant");
		if (!error)
			return false;
		seria::from_json_value(err, error.get());
		return true;
	}
	template<typename T>
	void get_result(T &v) const {
		invariant(result, "");
		seria::from_json_value(v, result.get());
	}

private:
	void parse(const std::string &response_body);

	OptionalJsonValue result;
	std::string result_body;
	common::JsonValue jid;
	OptionalJsonValue error;
};

std::string prepare_result_prefix(const common::JsonValue &jid);

// Always POST HTTP/1.1
template<typename ParamsType>
http::RequestData create_request(const std::string &uri, const std::string &method, const ParamsType &params,
    const OptionalJsonValue &jid = common::JsonValue(nullptr)) {
	common::JsonValue ps_req(common::JsonValue::OBJECT);
	ps_req.set("jsonrpc", std::string("2.0"));
	ps_req.set("method", method);
	ps_req.set("params", seria::to_json_value(params));
	if (jid)
		ps_req.set("id", std::move(jid.get()));
	http::RequestData http_request;
	http_request.r.set_firstline("POST", uri, 1, 1);
	http_request.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
	http_request.set_body(ps_req.to_string());
	return http_request;
}

template<typename ResultType>
std::string create_response_body(const ResultType &result, const common::JsonValue &jid) {
	std::string result_body = prepare_result_prefix(jid);
	seria::JsonOutputStreamText s(result_body);
	ser(const_cast<ResultType &>(result), s);
	result_body += "}";
	return result_body;
	//	common::JsonValue ps_req(common::JsonValue::OBJECT);
	//	ps_req.set("jsonrpc", std::string("2.0"));
	//	ps_req.set("id", jid);
	//	ps_req.set("result", seria::to_json_value(result));
	//	return ps_req.to_string();
}
std::string create_error_response_body(const Error &error, const common::JsonValue &jid);

template<typename ResultType>  //, typename ErrorType
bool parse_response(const std::string &body, ResultType &result, Error &error, OptionalJsonValue *jid = nullptr) {
	json_rpc::Response json_resp(body);
	if (jid)
		*jid = json_resp.get_id();
	if (json_resp.get_error(error))
		return false;
	result = ResultType{};
	json_resp.get_result(result);
	return true;
}

template<typename Agent, typename ParamsType, typename ResultType, typename Handler>
bool invoke_method(
    Agent *agent, http::RequestData &&http_request, Request &&json_req, std::string &raw_response, Handler handler) {
	ParamsType params{};
	ResultType result{};
	json_req.load_params(params);

	common::JsonValue jid = json_req.get_id().get();
	bool success          = handler(agent, std::move(http_request), std::move(json_req), std::move(params), result);

	if (success)
		raw_response = create_response_body(result, jid);
	return success;
}

template<typename Owner, typename Agent, typename ParamsType, typename ResultType>
std::function<bool(Owner *, Agent *, http::RequestData &&raw_request, Request &&, std::string &)> make_member_method(
    bool (Owner::*handler)(Agent *, http::RequestData &&, json_rpc::Request &&, ParamsType &&, ResultType &)) {
	return [handler](Owner *obj, Agent *agent, http::RequestData &&raw_request, Request &&req,
	           std::string &raw_response) -> bool {
		return json_rpc::invoke_method<Agent, ParamsType, ResultType>(agent, std::move(raw_request), std::move(req),
		    raw_response, std::bind(handler, obj, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3,
		                      std::placeholders::_4, std::placeholders::_5));
	};
}
}
}

namespace seria {
inline void ser_members(bytecoin::json_rpc::Error &v, ISeria &s) {
	seria_kv("code", v.code, s);
	seria_kv("message", v.message, s);
	s.object_key("data");
	v.seria_data(s);
}
}
