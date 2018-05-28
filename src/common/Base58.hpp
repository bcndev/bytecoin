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
}
