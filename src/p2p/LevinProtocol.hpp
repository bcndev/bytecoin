// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cassert>
#include "CryptoNote.hpp"
#include "common/MemoryStreams.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

namespace bytecoin {

enum class LevinError : int32_t {
	OK                                   = 0,
	ERROR_CONNECTION                     = -1,
	ERROR_CONNECTION_NOT_FOUND           = -2,
	ERROR_CONNECTION_DESTROYED           = -3,
	ERROR_CONNECTION_TIMEDOUT            = -4,
	ERROR_CONNECTION_NO_DUPLEX_PROTOCOL  = -5,
	ERROR_CONNECTION_HANDLER_NOT_DEFINED = -6,
	ERROR_FORMAT                         = -7,
};

const int32_t LEVIN_PROTOCOL_RETCODE_SUCCESS = 1;

class LevinProtocol {
public:
	template<typename Request>
	static void notify(uint32_t command, const Request &request, int) {
		send_message(command, encode(request), false);
	}

	struct Command {
		uint32_t command = 0;
		bool is_notify   = false;
		bool is_response = false;
		BinaryArray buf;

		bool need_reply() const { return !is_notify && !is_response; }
	};

	static size_t HEADER_SIZE();
	static size_t read_command_header(const BinaryArray &raw_header, Command &cmd, std::string &ban_reason);

	static BinaryArray send_message(uint32_t command, const BinaryArray &out, bool need_response);
	static BinaryArray send_reply(uint32_t command, const BinaryArray &out, int32_t return_code);

	template<typename T>
	static bool decode(const BinaryArray &buf, T &value) {
		try {
			seria::from_binary_key_value(value, buf);
		} catch (std::exception &) {
			return false;
		}
		return true;
	}

	template<typename T>
	static BinaryArray encode(const T &value) {
		return seria::to_binary_key_value(value);
	}
};
}
