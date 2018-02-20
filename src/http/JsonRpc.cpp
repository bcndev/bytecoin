// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include "http/JsonRpc.h"

namespace bytecoin {

namespace json_rpc {

// throw it directly, without error_code or other complications
Error::Error() : code(0) {}

Error::Error(int c) : code(c), message(get_message(c)) {}
std::string Error::get_message(int code) {
	switch (code) {
	case errParseError:
		return "Parse error";
	case errInvalidRequest:
		return "Invalid request";
	case errMethodNotFound:
		return "Method not found";
	case errInvalidParams:
		return "Invalid params";
	case errInternalError:
		return "Internal error";
	}
	return "Unknown error";
}

Error::Error(int c, const std::string &msg) : code(c), message(msg) {}
void makeErrorResponse(const std::error_code &ec, common::JsonValue &resp) {
	common::JsonValue error(common::JsonValue::OBJECT);

	// JsonValue code;
	// code = static_cast<int64_t>(-32000); //Application specific error code

	//        JsonValue message;
	//        message = ;

	common::JsonValue data(common::JsonValue::OBJECT);
	//        JsonValue appCode;
	//        appCode = static_cast<int64_t>();
	data.insert("application_code", common::JsonValue::Integer(ec.value()));

	error.insert("code", common::JsonValue::Integer(-32000));
	error.insert("message", ec.message());
	error.insert("data", data);

	resp.insert("error", error);
}

void makeGenericErrorReponse(common::JsonValue &resp, const std::string &what, int errorCode) {
	common::JsonValue error(common::JsonValue::OBJECT);

	//        JsonValue code;
	//        code = static_cast<int64_t>(errorCode);

	std::string msg = !what.empty() ? what : Error::get_message(errorCode);

	//        JsonValue message;
	//        message = msg;

	error.insert("code", common::JsonValue::Integer(errorCode));
	error.insert("message", msg);

	resp.insert("error", error);
}
}
}
