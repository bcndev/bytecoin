// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <string>
#include <type_traits>
#include "BinaryArray.hpp"

namespace common {

std::string as_string(const void *data, size_t size);  // Does not throw
inline std::string as_string(const BinaryArray &data) { return as_string(data.data(), data.size()); }
BinaryArray as_binary_array(const std::string &data);

uint8_t from_hex(char character);  // Returns value of hex 'character', throws on error
bool from_hex(char character,
    uint8_t &value);  // Assigns value of hex 'character' to 'value', returns false on error, does not throw
size_t from_hex(const std::string &text, void *data, size_t buffer_size);  // Assigns values of hex 'text' to buffer
                                                                           // 'data' up to 'buffer_size', returns actual
                                                                           // data size, throws on error
bool from_hex(const std::string &text, void *data, size_t buffer_size,
    size_t &size);  // Assigns values of hex 'text' to buffer 'data' up to 'buffer_size', assigns actual data size to
                    // 'size', returns false on error, does not throw
BinaryArray from_hex(const std::string &text);  // Returns values of hex 'text', throws on error
bool from_hex(const std::string &text,
    BinaryArray &data);  // Appends values of hex 'text' to 'data', returns false on error, does not throw

template<typename T>
bool pod_from_hex(const std::string &text, T &val) {
	static_assert(std::is_standard_layout<T>::value, "T must be Standard Layout");
	size_t out_size;
	return from_hex(text, &val, sizeof(val), out_size) && out_size == sizeof(val);
}

std::string to_hex(const void *data, size_t size);  // Returns hex representation of ('data', 'size'), does not throw
void append_hex(const void *data, size_t size,
    std::string &text);  // Appends hex representation of ('data', 'size') to 'text', does not throw
std::string to_hex(const BinaryArray &data);  // Returns hex representation of 'data', does not throw
void append_hex(
    const BinaryArray &data, std::string &text);  // Appends hex representation of 'data' to 'text', does not throw

template<class T>
std::string pod_to_hex(const T &s) {
	static_assert(std::is_standard_layout<T>::value, "T must be Standard Layout");
	return to_hex(&s, sizeof(s));
}

inline bool split_string_helper(const std::string &str, size_t pos, const std::string &, std::string &head) {
	head = str.substr(pos);
	return true;
}

template<class... Parts>
inline bool split_string_helper(
    const std::string &str, size_t pos, const std::string &separator, std::string &head, Parts &... parts) {
	size_t pos2 = str.find(separator, pos);
	if (pos2 == std::string::npos)
		return false;
	head = str.substr(pos, pos2 - pos);
	return split_string_helper(str, pos2 + 1, separator, parts...);
}

template<class... Parts>
inline bool split_string(const std::string &str, const std::string &separator, Parts &... parts) {
	return split_string_helper(str, 0, separator, parts...);
}
}
