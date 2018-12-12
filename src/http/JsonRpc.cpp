// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "http/JsonRpc.hpp"

namespace cn { namespace json_rpc {

// throw it directly, without error_code or other complications
Error::Error() : code(0) {}

Error::Error(int c) : code(c), message(get_message(c)) {}
std::string Error::get_message(int code) {
	switch (code) {
	case PARSE_ERROR:
		return "Parse error";
	case INVALID_REQUEST:
		return "Invalid request";
	case METHOD_NOT_FOUND:
		return "Method not found";
	case INVALID_PARAMS:
		return "Invalid params";
	case INTERNAL_ERROR:
		return "Internal error";
	}
	return "Unknown error";
}

Error::Error(int c, const std::string &msg) : code(c), message(msg) {}

void Error::seria_data(seria::ISeria &s) {
	s.begin_object();
	seria_data_members(s);
	s.end_object();
}
void Error::seria_data_members(seria::ISeria &s) {}

void make_generic_error_reponse(common::JsonValue &resp, const std::string &what, int error_code) {
	common::JsonValue error(common::JsonValue::OBJECT);

	std::string msg = !what.empty() ? what : Error::get_message(error_code);

	error.insert("code", common::JsonValue::Integer(error_code));
	error.insert("message", msg);

	resp.insert("error", error);
}

void Request::parse(const std::string &request_body, bool allow_empty_id) {
	common::JsonValue ps_req;
	try {
		ps_req = common::JsonValue::from_string(request_body);
	} catch (const std::exception &ex) {
		throw Error(PARSE_ERROR, common::what(ex));
	}
	if (!ps_req.is_object())
		throw Error(INVALID_REQUEST, "Request is not a json object");
	if (!ps_req.contains("jsonrpc"))
		throw Error(INVALID_REQUEST, "Request must include jsonrpc key");
	auto &j = ps_req("jsonrpc");
	if (!j.is_string() || j.get_string() != "2.0")
		throw Error(INVALID_REQUEST, "jsonrpc value must be exactly \"2.0\"");
	if (!ps_req.contains("method"))
		throw Error(INVALID_REQUEST, "Request must include method key");
	auto &m = ps_req("method");
	if (!m.is_string())
		throw Error(INVALID_REQUEST, "method value must be string");
	method = m.get_string();
	if (ps_req.contains("id")) {
		auto &p = ps_req("id");
		if (!p.is_string() && !p.is_integer() && !p.is_nil())  // Json RPC spec 4.2
			throw Error(INVALID_REQUEST, "id value must be an integer number, string or null");
		jid = std::move(p);
	} else {
		if (!allow_empty_id)
			throw Error(INVALID_REQUEST, "id value is REQUIRED");
	}
	if (ps_req.contains("params")) {
		auto &p = ps_req("params");
		if (!p.is_object() && !p.is_array())  // Json RPC spec 4.2
			throw Error(INVALID_REQUEST, "params value must be an object or array");
		params = std::move(p);
	}
}

void Response::parse(const std::string &response_body) {
	common::JsonValue ps_req;
	try {
		ps_req = common::JsonValue::from_string(response_body);
	} catch (const std::exception &ex) {
		throw Error(PARSE_ERROR, common::what(ex));
	}
	if (!ps_req.is_object())
		throw Error(INVALID_REQUEST, "Response is not a json object");
	if (!ps_req.contains("jsonrpc"))
		throw Error(INVALID_REQUEST, "Response must include jsonrpc key");
	auto &j = ps_req("jsonrpc");
	if (!j.is_string() || j.get_string() != "2.0")
		throw Error(INVALID_REQUEST, "jsonrpc value must be exactly \"2.0\"");
	if (!ps_req.contains("id"))
		throw Error(INVALID_REQUEST, "id value is REQUIRED");
	auto &p = ps_req("id");
	if (!p.is_string() && !p.is_integer() && !p.is_nil())  // Json RPC spec 4.2
		throw Error(INVALID_REQUEST, "id value must be an integer number, string or null");
	jid = std::move(p);
	if (ps_req.contains("result"))
		result = std::move(ps_req("result"));
	if (ps_req.contains("error")) {
		auto &e = ps_req("error");
		if (!e.is_object())
			throw Error(INVALID_REQUEST, "error value must be an object");
		error = std::move(e);
	}
	if (result && error)
		throw Error(INVALID_REQUEST, "Response cannot contain both error and result");
	if (!result && !error)
		throw Error(INVALID_REQUEST, "Response must contain either error or result");
}

std::string create_error_response_body(const Error &error, const common::JsonValue &jid) {
	common::JsonValue ps_req(common::JsonValue::OBJECT);
	ps_req.set("jsonrpc", std::string("2.0"));
	ps_req.set("id", jid);
	ps_req.set("error", seria::to_json_value(error));
	return ps_req.to_string();
}
std::string create_binary_response_error_body(const Error &error, const common::JsonValue &jid) {
	//	static_assert(std::is_base_of<json_rpc::Error, ErrorType>::value, "ErrorType must be an json_rpc::Error
	// descendant");
	common::JsonValue ps_req(common::JsonValue::OBJECT);
	ps_req.set("jsonrpc", std::string("2.0"));
	ps_req.set("id", jid);
	ps_req.set("error", seria::to_json_value(error));
	std::string json_body = ps_req.to_string();
	json_body += char(0);
	return json_body;
}

std::string prepare_result_prefix(const common::JsonValue &jid) {
	std::string result = "{";
	result += "\"id\":" + jid.to_string() + ",";
	result += "\"jsonrpc\":\"2.0\",\"result\":";
	return result;
}

}}  // namespace cn::json_rpc

namespace seria {
void ser_members(cn::json_rpc::Error &v, ISeria &s) {
	seria_kv("code", v.code, s);
	seria_kv("message", v.message, s);
	s.object_key("data");
	v.seria_data(s);
}
}  // namespace seria
