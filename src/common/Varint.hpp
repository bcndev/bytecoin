// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include "BinaryArray.hpp"

namespace common {

template<typename OutputIt>
void write_varint(OutputIt &&dest, uint64_t v) {
	while (v >= 0x80) {
		*dest++ = (static_cast<uint8_t>(v) & 0x7f) | 0x80;
		v >>= 7;
	}
	*dest++ = static_cast<uint8_t>(v);
}

inline BinaryArray get_varint_data(uint64_t v) {
	unsigned char output_index[(sizeof(uint64_t) * 8 + 6) / 7];
	unsigned char *end = output_index;
	write_varint(end, v);
	return BinaryArray(output_index, end);
}

inline size_t get_varint_data_size(uint64_t v) {
	size_t result = 0;
	while (v >= 0x80) {
		result++;
		v >>= 7;
	}
	return result + 1;
}

template<int bits, typename InputIt, typename T>
typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value && 0 <= bits &&
                            bits <= std::numeric_limits<T>::digits,
    int>::type
read_varint(InputIt &&first, InputIt &&last, T *i) {
	int read = 0;
	*i       = 0;
	for (int shift = 0;; shift += 7) {
		if (first == last)
			return -3;  // End of input.
		unsigned char byte = *first++;
		++read;
		if (shift + 7 >= bits && byte >= 1 << (bits - shift))
			return -1;  // Overflow.
		if (byte == 0 && shift != 0)
			return -2;  // Non-canonical representation.
		*i |= static_cast<T>(byte & 0x7f) << shift;
		if ((byte & 0x80) == 0)
			break;
	}
	return read;
}

template<typename InputIt, typename T>
int read_varint(InputIt &&first, InputIt &&last, T *i) {
	return read_varint<std::numeric_limits<T>::digits, InputIt, T>(
	    std::forward<InputIt>(first), std::forward<InputIt>(last), i);
}

// stupid default varint is mostly useless, because it breaks lexicographic sorting
// we use sqlite4 varint where lexicographic sorting is important (e.g. DB indexes)
size_t get_varint_sqlite4_size(uint64_t val);
uint64_t read_varint_sqlite4(const unsigned char *&begin, const unsigned char *end);
inline uint64_t read_varint_sqlite4(const char *&begin, const char *end) {
	return read_varint_sqlite4(
	    reinterpret_cast<const unsigned char *&>(begin), reinterpret_cast<const unsigned char *>(end));
}

uint64_t read_varint_sqlite4(const std::string &str);
std::string write_varint_sqlite4(uint64_t val);

template<class T>
T uint_be_from_bytes(const unsigned char *buf, size_t si) {
	static_assert(std::is_unsigned<T>::value, "works only with unsigned types");
	T result = 0;
	for (size_t i = 0; i != si; ++i)
		result = (result << 8) + buf[i];
	return result;
}

template<class T>
void uint_be_to_bytes(unsigned char *buf, size_t si, T val) {
	static_assert(std::is_unsigned<T>::value, "works only with unsigned types");
	for (size_t i = si; i-- > 0;) {
		buf[i] = static_cast<unsigned char>(val);
		val >>= 8;
	}
}

template<class T>
T uint_le_from_bytes(const unsigned char *buf, size_t si) {
	static_assert(std::is_unsigned<T>::value, "works only with unsigned types");
	T result = 0;
	for (size_t i = si; i-- > 0;)
		result = (result << 8) + buf[i];
	return result;
}

template<class T>
void uint_le_to_bytes(unsigned char *buf, size_t si, T val) {
	static_assert(std::is_unsigned<T>::value, "works only with unsigned types");
	for (size_t i = 0; i != si; ++i) {
		buf[i] = static_cast<unsigned char>(val);
		val >>= 8;
	}
}
inline void uint_le_to_bytes(unsigned char *buf, size_t si, unsigned char val) {
	for (size_t i = 0; i != si; ++i) {
		buf[i] = val;
		val    = 0;
	}
}
}  // namespace common
