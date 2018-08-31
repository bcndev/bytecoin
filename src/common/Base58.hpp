// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <string>
#include "BinaryArray.hpp"

namespace common {
namespace base58 {

std::string encode(const BinaryArray &data);
bool decode(const std::string &enc, BinaryArray *data);

std::string encode_addr(uint64_t tag, const BinaryArray &data);
bool decode_addr(std::string addr, uint64_t *tag, BinaryArray *data);
}

uint32_t crc32(const uint8_t *data, size_t size, uint32_t crc = 0);
std::string encode_addr_future(std::string prefix, const BinaryArray &addr_data);
bool decode_addr_future(std::string addr, std::string prefix, BinaryArray *addr_data);
void test_addr_future();
}
