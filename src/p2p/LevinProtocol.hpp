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

#include <seria/KVBinaryInputStream.hpp>
#include <seria/KVBinaryOutputStream.hpp>
#include "CryptoNote.hpp"
#include "common/MemoryStreams.hpp"
#include <cassert>

namespace bytecoin {

enum class LevinError : int32_t {
	OK = 0,
	ERROR_CONNECTION = -1,
	ERROR_CONNECTION_NOT_FOUND = -2,
	ERROR_CONNECTION_DESTROYED = -3,
	ERROR_CONNECTION_TIMEDOUT = -4,
	ERROR_CONNECTION_NO_DUPLEX_PROTOCOL = -5,
	ERROR_CONNECTION_HANDLER_NOT_DEFINED = -6,
	ERROR_FORMAT = -7,
};

const int32_t LEVIN_PROTOCOL_RETCODE_SUCCESS = 1;

class LevinProtocol {
public:
	template<typename Request>
	static void notify(uint32_t command, const Request &request, int) {
		sendMessage(command, encode(request), false);
	}

	struct Command {
		uint32_t command = 0;
		bool isNotify = false;
		bool isResponse = false;
		BinaryArray buf;

		bool needReply() const { return !isNotify && !isResponse; }
	};

	static size_t HEADER_SIZE();
	static size_t readCommandHeader(const BinaryArray &raw_header, Command &cmd, std::string &ban_reason);

	static BinaryArray sendMessage(uint32_t command, const BinaryArray &out, bool needResponse);
	static BinaryArray sendReply(uint32_t command, const BinaryArray &out, int32_t returnCode);

	template<typename T>
	static bool decode(const BinaryArray &buf, T &value) {
		try {
			seria::fromBinaryKeyValue(value, buf);
		} catch (std::exception &) {
			return false;
		}
		return true;
	}
	
	template<typename T>
	static BinaryArray encode(const T &value) {
		return seria::toBinaryKeyValue(value);
	}
};

}
