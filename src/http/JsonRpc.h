// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <boost/optional.hpp>
#include <boost/foreach.hpp>
#include <functional>
#include <unordered_map>

#include "common/JsonValue.hpp"
#include "seria/JsonOutputStream.hpp"
#include "seria/JsonInputStream.hpp"
#include "types.hpp"

namespace bytecoin { namespace json_rpc {

const int errParseError = -32700;
const int errInvalidRequest = -32600;
const int errMethodNotFound = -32601;
const int errInvalidParams = -32602;
const int errInternalError = -32603;

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
}}
	
namespace seria {
	inline void serMembers(bytecoin::json_rpc::Error &v, ISeria &s) {
		seria_kv("code", v.code, s);
		seria_kv("message", v.message, s);
	}
}

namespace bytecoin { namespace json_rpc {

typedef boost::optional<common::JsonValue> OptionalJsonValue;

class Request {
	bool parseRequest(const std::string &requestBody) {
		common::JsonValue psReq;
		try {
			psReq = common::JsonValue::from_string(requestBody);
		} catch (std::exception &) {
			throw Error(errParseError);
		}
		if (!psReq.is_object() || !psReq.contains("method"))
			throw Error(errInvalidRequest);
		method = psReq("method").get_string();
		if (psReq.contains("id"))
			id = psReq("id");
		if (psReq.contains("params"))
			params = psReq("params");
		return true;
	}
public:
	Request() : params(common::JsonValue::NIL) {
	}
	explicit Request(const std::string &requestBody) : params(common::JsonValue::NIL){
		parseRequest(requestBody);
	}
	template<typename T>
	void setParams(const T &v) {
		params = seria::toJsonValue(v);
	}
	template<typename T>
	void loadParams(T &v) const {
		seria::fromJsonValue(v, params);
	}

	void setMethod(const std::string &m) { method = m; }
	const std::string &getMethod() const { return method; }

	void setId(const OptionalJsonValue & sid){ id = sid; }
	const OptionalJsonValue &getId()const{ return id; }

	std::string getBody() {
		common::JsonValue psReq(common::JsonValue::OBJECT);
		psReq.set("jsonrpc", std::string("2.0"));
		psReq.set("method", method);
		psReq.set("params", params);
		if( id )
			psReq.set("id", id.get());
		return psReq.to_string();
	}
private:
	common::JsonValue params;
	OptionalJsonValue id;
	std::string method;
};

class Response {
	void parse(const std::string &responseBody) {
		common::JsonValue psReq;
		try {
			psReq = common::JsonValue::from_string(responseBody);
		} catch (std::exception &) {
			throw Error(errParseError);
		}
		if(!psReq.is_object() )
			throw Error(errInvalidRequest);
		if (psReq.contains("id"))
			id = psReq("id");
		if (psReq.contains("result"))
			result = psReq("result");
		if (psReq.contains("error"))
			error = psReq("error");
	}
public:
	Response() : result(common::JsonValue::NIL) {}
	explicit Response(const std::string &responseBody) : result(common::JsonValue::NIL) {
		parse(responseBody);
	}
	void setId(const OptionalJsonValue & sid) { id = sid; }
	const OptionalJsonValue & getId() const { return id; }

	void setError(const Error &err) {
		error = seria::toJsonValue(err);
	}

	bool getError(Error &err) const {
		if (!error)
			return false;
		seria::fromJsonValue(err, error.get());
		return true;
	}

	std::string getBody() {
		common::JsonValue psResp(common::JsonValue::OBJECT);
		psResp.set("jsonrpc", std::string("2.0"));
		if( error )
			psResp.set("error", error.get());
		else
			psResp.set("result", result);
		if( id )
			psResp.set("id", id.get());
		return psResp.to_string();
	}

	template<typename T>
	void setResult(const T &v) {
		result = seria::toJsonValue(v);
	}

	template<typename T>
	void getResult(T &v) const {
		seria::fromJsonValue(v, result);
	}
private:
	common::JsonValue result;
	OptionalJsonValue id;
	OptionalJsonValue error;
};

template<typename Agent, typename RawRequest, typename RequestType, typename ResponseType, typename Handler>
bool invokeMethod(Agent *agent, RawRequest &&raw_request, Request &&jsReq, Response &jsRes, Handler handler) {
	RequestType req{};
	ResponseType res{};
	jsReq.loadParams(req);

	bool result = handler(agent, std::move(raw_request), std::move(jsReq), std::move(req), res);

	if (result)
		jsRes.setResult(res);
	return result;
}

template<typename Owner, typename Agent, typename RawRequest, typename Params, typename Result>
std::function<bool(Owner *, Agent *, RawRequest &&raw_request, Request &&, Response &)> makeMemberMethodSeria(bool (Owner::*handler)(Agent *, RawRequest &&, json_rpc::Request &&, Params &&, Result &)) {
	return [handler](Owner *obj, Agent *agent, RawRequest &&raw_request, Request &&req, Response &res) -> bool {
		return json_rpc::invokeMethod<Agent, RawRequest, Params, Result>(
				agent, std::move(raw_request), std::move(req), res, std::bind(handler, obj, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
	};
}

// Always POST HTTP/1.1
template<typename ParamsType>
http::RequestData createRequest(const std::string &uri, const std::string &method, const ParamsType &params, const OptionalJsonValue & id = OptionalJsonValue{}){
	Request json_send_raw_req;
	json_send_raw_req.setMethod(method);
	json_send_raw_req.setParams(params);
	json_send_raw_req.setId(id);
	http::RequestData req_header;
	req_header.r.set_firstline("POST", uri, 1, 1);
	req_header.setBody(json_send_raw_req.getBody());
	return req_header;
}

template<typename ResponseType>
http::ResponseData createResponse(const http::RequestData & request, const ResponseType &response, const OptionalJsonValue & id = OptionalJsonValue{}){
	json_rpc::Response last_json_resp;
	last_json_resp.setId(id);
	last_json_resp.setResult(response);
	http::ResponseData last_http_response(request.r);
	last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
	last_http_response.setBody(last_json_resp.getBody());
	last_http_response.r.status = 200;
	return last_http_response;
}

template<typename ResponseType>
void parseResponse(const std::string &body, ResponseType &response, OptionalJsonValue * jid = nullptr) {
	json_rpc::Response json_resp(body);
	if(jid)
		*jid = json_resp.getId();
	response = ResponseType();
	json_resp.getResult(response);
}

}


}
