// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <sstream>
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
bool from_hex(const std::string &text, BinaryArray *data);

template<typename T>
bool pod_from_hex(const std::string &text, T *val) {
	static_assert(std::is_standard_layout<T>::value, "T must be Standard Layout");
	return from_hex(text, val, sizeof(T));
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

inline void to_string_helper(std::stringstream &ss, bool first) {}
template<typename T, typename... Parts>
inline void to_string_helper(std::stringstream &ss, bool first, T &&t, const Parts &... parts) {
	if (!first)
		ss << " ";
	ss << t;
	to_string_helper(ss, false, parts...);
}

template<class... Parts>
std::string to_string(const Parts &... parts) {
	std::stringstream ss;
	to_string_helper(ss, true, parts...);
	return ss.str();
}

// Compile time from_hex, some compilers still do not support switch in constexpr functions
constexpr uint8_t compile_time_parse_digit(char c) {
	return (c == '0')
	           ? uint8_t(0)
	           : (c == '1')
	                 ? uint8_t(1)
	                 : (c == '2')
	                       ? uint8_t(2)
	                       : (c == '3')
	                             ? uint8_t(3)
	                             : (c == '4')
	                                   ? uint8_t(4)
	                                   : (c == '5')
	                                         ? uint8_t(5)
	                                         : (c == '6')
	                                               ? uint8_t(6)
	                                               : (c == '7')
	                                                     ? uint8_t(7)
	                                                     : (c == '8')
	                                                           ? uint8_t(8)
	                                                           : (c == '9')
	                                                                 ? uint8_t(9)
	                                                                 : (c == 'a' || c == 'A')
	                                                                       ? uint8_t(0xa)
	                                                                       : (c == 'b' || c == 'B')
	                                                                             ? uint8_t(0xb)
	                                                                             : (c == 'c' || c == 'C')
	                                                                                   ? uint8_t(0xc)
	                                                                                   : (c == 'd' || c == 'D')
	                                                                                         ? uint8_t(0xd)
	                                                                                         : (c == 'e' || c == 'E')
	                                                                                               ? uint8_t(0xe)
	                                                                                               : (c == 'f' ||
	                                                                                                     c == 'F')
	                                                                                                     ? uint8_t(0xf)
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
}  // namespace common
