// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include "BinaryArray.hpp"

namespace common {

template<typename OutputIt, typename T>
typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, void>::type write_varint(
    OutputIt &&dest, T i) {
	while (i >= 0x80) {
		*dest++ = (static_cast<uint8_t>(i) & 0x7f) | 0x80;
		i >>= 7;
	}
	*dest++ = static_cast<uint8_t>(i);
}

template<typename t_type>
BinaryArray get_varint_data(const t_type &v) {
	unsigned char output_index[(sizeof(t_type) * 8 + 6) / 7];
	unsigned char *end = output_index;
	write_varint(end, v);
	return BinaryArray(output_index, end);
}

template<int bits, typename InputIt, typename T>
typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value && 0 <= bits &&
                            bits <= std::numeric_limits<T>::digits,
    int>::type
read_varint(InputIt &&first, InputIt &&last, T &i) {
	int read = 0;
	i        = 0;
	for (int shift = 0;; shift += 7) {
		if (first == last) {
			return read;  // End of input.
		}
		unsigned char byte = *first++;
		++read;
		if (shift + 7 >= bits && byte >= 1 << (bits - shift)) {
			return -1;  // Overflow.
		}
		if (byte == 0 && shift != 0) {
			return -2;  // Non-canonical representation.
		}
		i |= static_cast<T>(byte & 0x7f) << shift;
		if ((byte & 0x80) == 0) {
			break;
		}
	}
	return read;
}

template<typename InputIt, typename T>
int read_varint(InputIt &&first, InputIt &&last, T &i) {
	return read_varint<std::numeric_limits<T>::digits, InputIt, T>(std::move(first), std::move(last), i);
}

// Experimental stuff to reduce integer db indexes
size_t get_varint_sqlite4_size(uint64_t val);
uint64_t read_varint_sqlite4(const unsigned char *&begin, const unsigned char *end);
inline uint64_t read_varint_sqlite4(const char *&begin, const char *end) {
	return read_varint_sqlite4((const unsigned char *&)begin, (const unsigned char *)end);
}

uint64_t read_varint_sqlite4(const std::string &str);
std::string write_varint_sqlite4(uint64_t val);
}
