// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>

namespace common {

extern const uint32_t crc32_table[];

inline uint32_t crc32_step_zero(uint32_t state) { return (state >> 8) ^ crc32_table[state & 0xff]; }

inline uint32_t crc32_step(uint32_t state, char data) { return crc32_step_zero(state ^ data); }

inline uint32_t crc32(const char *data, size_t size, uint32_t state = 0) {
	for (const char *cur = data; cur != data + size; cur++) {
		state = crc32_step(state, *cur);
	}
	return state;
}

extern const uint32_t crc32_reverse_table[];

inline uint32_t crc32_reverse_step_zero(uint32_t state) { return (state << 8) ^ crc32_reverse_table[state >> 24]; }

}  // namespace common