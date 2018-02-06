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

#include <cstdint>
#include <string>
#include "common/CommandLine.hpp"

namespace bytecoin {

struct MiningConfig {
	explicit MiningConfig(common::CommandLine & cmd);

	std::string mining_address;
	std::string bytecoind_ip;
	uint16_t bytecoind_port = 0;
	size_t thread_count = 0;
//	size_t scanPeriod; // We are using longpoll now
//	uint8_t log_level;
	size_t blocksLimit = 0; // Mine specified number of blocks, then exit, 0 == indefinetely
//	uint64_t first_block_timestamp;
//	int64_t blockTimestampInterval;
//	bool help;
};

} //namespace bytecoin
