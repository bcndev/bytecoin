// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <boost/optional.hpp>
#include <functional>

#include "common/Invariant.hpp"
#include "common/JsonValue.hpp"
#include "seria/JsonInputStream.hpp"
#include "seria/JsonOutputStream.hpp"
#include "types.hpp"

namespace cn { namespace json_rpc {

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

	const char *what() const noexcept override { return message.c_str(); }
	static std::string get_message(int code);

	int code;
	std::string message;

	virtual void seria_data(seria::ISeria &s);
	virtual void seria_data_members(seria::ISeria &s);
};

typedef boost::optional<common::JsonValue> OptionalJsonValue;

class Request {
public:
	Request() = default;
	explicit Request(const std::string &request_body, bool allow_empty_id = false) {
		parse(request_body, allow_empty_id);
	}
	template<typename T>
	void load_params(T &v) const {
		static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
		seria::JsonInputStreamValue s(stripped_req, false);
		try {
			s.begin_object();
			seria_kv("params", v, s);
			s.end_object();
		} catch (const std::exception &) {
			std::throw_with_nested(std::runtime_error(
			    "Error while deserializing json rpc request of type '" + common::demangle(typeid(T).name()) + "'"));
		}
	}
	const std::string &get_method() const { return method; }
	const OptionalJsonValue &get_id() const { return jid; }
	bool get_numbers_as_strings() const { return numbers_as_strings; }

private:
	void parse(const std::string &request_body, bool allow_empty_id);

	common::JsonValue stripped_req;  // req with params and excess fields
	bool numbers_as_strings = false;
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
http::RequestBody create_request(const std::string &uri, const std::string &method, const ParamsType &params,
    const OptionalJsonValue &jid = common::JsonValue(common::JsonValue::NUMBER)) {
	common::JsonValue ps_req(common::JsonValue::OBJECT);
	ps_req.set("jsonrpc", std::string("2.0"));
	ps_req.set("method", method);
	ps_req.set("params", seria::to_json_value(params));
	if (jid)
		ps_req.set("id", jid.get());
	http::RequestBody http_request;
	http_request.r.set_firstline("POST", uri, 1, 1);
	http_request.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
	http_request.set_body(ps_req.to_string());
	return http_request;
}

template<typename ResultType>
std::string create_response_body(const ResultType &result, const common::JsonValue &jid, bool numbers_as_strings) {
	std::string result_body = prepare_result_prefix(jid);
	seria::JsonOutputStreamText s(result_body);
	s.set_numbers_as_strings(numbers_as_strings);
	ser(const_cast<ResultType &>(result), s);
	result_body += "}";
	return result_body;
	//	common::JsonValue ps_req(common::JsonValue::OBJECT);
	//	ps_req.set("jsonrpc", std::string("2.0"));
	//	ps_req.set("id", jid);
	//	ps_req.set("result", seria::to_json_value(result));
	//	return ps_req.to_string();
}
template<typename ResultType>
std::string create_response_body(const ResultType &result, const Request &req) {
	return create_response_body(result, req.get_id().get(), req.get_numbers_as_strings());
}

std::string create_error_response_body(const Error &error, const common::JsonValue &jid, bool numbers_as_strings);
std::string create_error_response_body(const Error &error, const Request &req);

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
    Agent *agent, http::RequestBody &&http_request, Request &&json_req, std::string &raw_response, Handler handler) {
	ParamsType params{};
	ResultType result{};
	json_req.load_params(params);

	common::JsonValue jid = json_req.get_id().get();
	bool nas              = json_req.get_numbers_as_strings();
	bool success          = handler(agent, std::move(http_request), std::move(json_req), std::move(params), result);

	if (success)
		raw_response = create_response_body(result, jid, nas);
	return success;
}

template<typename Owner, typename Agent, typename ParamsType, typename ResultType>
std::function<bool(Owner *, Agent *, http::RequestBody &&raw_request, Request &&, std::string &)> make_member_method(
    bool (Owner::*handler)(Agent *, http::RequestBody &&, json_rpc::Request &&, ParamsType &&, ResultType &)) {
	return [handler](Owner *obj, Agent *agent, http::RequestBody &&raw_request, Request &&req,
	           std::string &raw_response) -> bool {
		return json_rpc::invoke_method<Agent, ParamsType, ResultType>(agent, std::move(raw_request), std::move(req),
		    raw_response,
		    std::bind(handler, obj, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3,
		        std::placeholders::_4, std::placeholders::_5));
	};
}
}}  // namespace cn::json_rpc

namespace seria {
void ser_members(cn::json_rpc::Error &v, ISeria &s);
}  // namespace seria
