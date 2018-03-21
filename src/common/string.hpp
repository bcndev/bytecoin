// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

// Get rid of this header as soon as Google NDK updates its compiler to support std::to_string family of functions

#include <string>

#if defined(__ANDROID__)

#include <sstream>

namespace common {

template<typename T>
inline std::string to_string(T value) {
	std::ostringstream os;
	os << value;
	return os.str();
}

inline long long stoll(const std::string &key) {
	long long val = 0;
	if (sscanf(key.c_str(), "%lld", &val) != 1)
		throw std::runtime_error("stoll failed to convert key=" + key);
	return val;
}
}

#else

namespace common {
template<typename T>
inline std::string to_string(T value) {
	return std::to_string(value);
}

inline long long stoll(const std::string &key) { return std::stoll(key); }
}

#endif
