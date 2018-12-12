// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cassert>
#include "CryptoNote.hpp"
#include "common/MemoryStreams.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

namespace cn {

class LevinProtocol {
public:
	enum { RETURN_CODE_SUCCESS = 1 };
	enum CommandType { REQUEST, RESPONSE, NOTIFY };

	static size_t HEADER_SIZE();
	static size_t read_command_header(const BinaryArray &raw_header, CommandType *rrn, uint32_t *command);

	template<typename T>
	static BinaryArray encode(const T &value) {
		return seria::to_binary_kv(value);
	}
	template<typename T>
	static bool decode(const BinaryArray &buf, T &value) {
		try {
			seria::from_binary_kv(value, buf);
		} catch (const std::exception &) {
			return false;
		}
		return true;
	}
	static BinaryArray send(CommandType rrn, uint32_t command, const BinaryArray &out, int32_t return_code);
	template<typename T>
	static BinaryArray send(const T &message) {
		return send(static_cast<CommandType>(T::TYPE), T::ID, seria::to_binary_kv(message), RETURN_CODE_SUCCESS);
	}
};
}  // namespace cn
