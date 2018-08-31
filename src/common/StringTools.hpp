// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <type_traits>
#include "BinaryArray.hpp"

namespace common {

std::string as_string(const void *data, size_t size);
inline std::string as_string(const BinaryArray &data) { return as_string(data.data(), data.size()); }
BinaryArray as_binary_array(const std::string &data);

uint8_t from_hex(char character);
bool from_hex(char character, uint8_t &value);
void from_hex_or_throw(const std::string &text, void *data, size_t buffer_size);
bool from_hex(const std::string &text, void *data, size_t buffer_size);
BinaryArray from_hex(const std::string &text);  // Returns values of hex 'text', throws on error
bool from_hex(const std::string &text, BinaryArray &data);

template<typename T>
bool pod_from_hex(const std::string &text, T &val) {
	static_assert(std::is_standard_layout<T>::value, "T must be Standard Layout");
	return from_hex(text, &val, sizeof(val));
}

std::string to_hex(const void *data, size_t size);
std::string to_hex(const BinaryArray &data);

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
inline bool split_string_helper(const std::string &str,
    size_t pos,
    const std::string &separator,
    std::string &head,
    Parts &... parts) {
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

// Compile time from_hex
constexpr unsigned char compile_time_parse_digit(char c) {
	return (c == '0')
	           ? 0
	           : (c == '1')
	                 ? 1
	                 : (c == '2')
	                       ? 2
	                       : (c == '3')
	                             ? 3
	                             : (c == '4')
	                                   ? 4
	                                   : (c == '5')
	                                         ? 5
	                                         : (c == '6')
	                                               ? 6
	                                               : (c == '7')
	                                                     ? 7
	                                                     : (c == '8')
	                                                           ? 8
	                                                           : (c == '9')
	                                                                 ? 9
	                                                                 : (c == 'a' || c == 'A')
	                                                                       ? 0xa
	                                                                       : (c == 'b' || c == 'B')
	                                                                             ? 0xb
	                                                                             : (c == 'c' || c == 'C')
	                                                                                   ? 0xc
	                                                                                   : (c == 'd' || c == 'D')
	                                                                                         ? 0xd
	                                                                                         : (c == 'e' || c == 'E')
	                                                                                               ? 0xe
	                                                                                               : (c == 'f' ||
	                                                                                                     c == 'F')
	                                                                                                     ? 0xf
	                                                                                                     : throw std::
	                                                                                                           runtime_error(
	                                                                                                               "bad digit");
}

template<typename T>
constexpr T compile_time_from_hex_impl(const char *str, size_t s, T t) {
	if (s == 0)
		return t;
	char c0       = str[(s - 1) * 2];
	char c1       = str[(s - 1) * 2 + 1];
	t.data[s - 1] = (compile_time_parse_digit(c0) << 4) + compile_time_parse_digit(c1);
	return compile_time_from_hex_impl(str, s - 1, t);
}

template<typename T>
constexpr T pfh(const char (&str)[sizeof(T) * 2 + 1]) {
	static_assert(std::is_standard_layout<T>::value, "T must be Standard Layout");
	return compile_time_from_hex_impl(str, sizeof(T), T{});
}
}
