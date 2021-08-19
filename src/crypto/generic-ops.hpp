// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstring>
#include <functional>
#include "crypto-util.h"

// Put into namespace where type is defined
#define CRYPTO_MAKE_COMPARABLE(type, cmp)                                                                   \
	inline bool operator==(const type &_v1, const type &_v2) { return cmp(&_v1, &_v2, sizeof(type)) == 0; } \
	inline bool operator!=(const type &_v1, const type &_v2) { return cmp(&_v1, &_v2, sizeof(type)) != 0; } \
	inline bool operator<(const type &_v1, const type &_v2) { return cmp(&_v1, &_v2, sizeof(type)) < 0; }   \
	inline bool operator<=(const type &_v1, const type &_v2) { return cmp(&_v1, &_v2, sizeof(type)) <= 0; } \
	inline bool operator>(const type &_v1, const type &_v2) { return cmp(&_v1, &_v2, sizeof(type)) > 0; }   \
	inline bool operator>=(const type &_v1, const type &_v2) { return cmp(&_v1, &_v2, sizeof(type)) >= 0; }

// Put into global namespace
#define CRYPTO_MAKE_HASHABLE(type)                                                               \
	namespace std {                                                                              \
	template<>                                                                                   \
	struct hash<type> {                                                                          \
		size_t operator()(const type &_v) const { return reinterpret_cast<const size_t &>(_v); } \
	};                                                                                           \
	}
