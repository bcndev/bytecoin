// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "JsonRpc.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

namespace bytecoin {
namespace json_rpc {

// Binary Json Rpc:
// Request: normal json request with params set to {}, followed by 0 char, followed by binary params
// No Error Response: normal json response with result set to {}, followed by 0 char, followed by binary result
// Error Response: normal error json response, followed by 0 char

template<typename ResultType>  // , typename ErrorType
bool parse_binary_response(
    const std::string &body, ResultType &result, Error &error, OptionalJsonValue *jid = nullptr) {
	size_t sep = body.find(char(0));
	if (sep == std::string::npos)
		throw std::runtime_error("binary response contains no 0-character separator");
	Response json_resp(body.substr(0, sep));
	if (jid)
		*jid = json_resp.get_id();
	if (json_resp.get_error(error))
		return false;
	common::MemoryInputStream body_stream(body.data() + sep + 1, body.size() - sep - 1);
	seria::BinaryInputStream ba(body_stream);
	ser(result, ba);
	return true;
}

template<typename ParamsType>
std::string create_binary_request_body(
    const std::string &method, const ParamsType &params, const OptionalJsonValue &jid = common::JsonValue(nullptr)) {
	common::JsonValue ps_req(common::JsonValue::OBJECT);
	ps_req.set("jsonrpc", std::string("2.0"));
	ps_req.set("method", method);
	ps_req.set("params", common::JsonValue(common::JsonValue::OBJECT));
	if (jid)
		ps_req.set("id", std::move(jid.get()));
	std::string json_body = ps_req.to_string();
	json_body += char(0);
	common::StringOutputStream str(json_body);  // continue writing
	seria::BinaryOutputStream ba(str);
	ser(const_cast<ParamsType &>(params), ba);
	return json_body;
}

template<typename ResultType>
std::string create_binary_response_body(const ResultType &result, const common::JsonValue &jid) {
	common::JsonValue ps_req(common::JsonValue::OBJECT);
	ps_req.set("jsonrpc", std::string("2.0"));
	ps_req.set("id", jid);
	ps_req.set("result", common::JsonValue(common::JsonValue::OBJECT));
	std::string json_body = ps_req.to_string();
	json_body += char(0);
	common::StringOutputStream str(json_body);  // continue writing
	seria::BinaryOutputStream ba(str);
	ser(const_cast<ResultType &>(result), ba);
	return json_body;
}

// template<typename ErrorType>
std::string create_binary_response_error_body(const Error &error, const common::JsonValue &jid);

template<typename Agent, typename ParamsType, typename ResultType, typename Handler>
bool invoke_binary_method(
    Agent *agent, common::IInputStream &body_stream, Request &&binary_req, std::string &raw_response, Handler handler) {
	ParamsType params{};
	ResultType result{};

	seria::BinaryInputStream ba(body_stream);
	ser(params, ba);

	common::JsonValue jid = binary_req.get_id().get();
	http::RequestData empty_http_req;  // Do not move into handler call, will not compile on MSVC 2017
	bool success = handler(agent, std::move(empty_http_req), std::move(binary_req), std::move(params), result);

	if (success)
		raw_response = create_binary_response_body(result, jid);
	return success;
}

template<typename Owner, typename Agent, typename ParamsType, typename ResultType>
std::function<bool(Owner *, Agent *, common::IInputStream &, Request &&, std::string &)> make_binary_member_method(
    bool (Owner::*handler)(Agent *, http::RequestData &&, Request &&, ParamsType &&, ResultType &)) {
	return [handler](
	           Owner *obj, Agent *agent, common::IInputStream &body_stream, Request &&req, std::string &res) -> bool {
		return invoke_binary_method<Agent, ParamsType, ResultType>(agent, body_stream, std::move(req), res,
		    std::bind(handler, obj, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3,
		        std::placeholders::_4, std::placeholders::_5));
	};
}
}
}
