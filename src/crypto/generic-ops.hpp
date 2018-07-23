// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstring>
#include <functional>
#include "crypto-util.h"

#define CRYPTO_MAKE_COMPARABLE(na, type, cmp)                                                               \
	namespace na {                                                                                          \
	inline bool operator==(const type &_v1, const type &_v2) { return cmp(&_v1, &_v2, sizeof(type)) == 0; } \
	inline bool operator!=(const type &_v1, const type &_v2) { return cmp(&_v1, &_v2, sizeof(type)) != 0; } \
	inline bool operator<(const type &_v1, const type &_v2) { return cmp(&_v1, &_v2, sizeof(type)) < 0; }   \
	inline bool operator<=(const type &_v1, const type &_v2) { return cmp(&_v1, &_v2, sizeof(type)) <= 0; } \
	inline bool operator>(const type &_v1, const type &_v2) { return cmp(&_v1, &_v2, sizeof(type)) > 0; }   \
	inline bool operator>=(const type &_v1, const type &_v2) { return cmp(&_v1, &_v2, sizeof(type)) >= 0; } \
	}

#define CRYPTO_MAKE_HASHABLE(na, type)                                                                  \
	namespace na {                                                                                      \
	static_assert(sizeof(size_t) <= sizeof(type), "Size of " #type " must be at least that of size_t"); \
	inline size_t hash_value(const type &_v) { return reinterpret_cast<const size_t &>(_v); }           \
	}                                                                                                   \
	namespace std {                                                                                     \
	template<>                                                                                          \
	struct hash<na::type> {                                                                             \
		size_t operator()(const na::type &_v) const { return reinterpret_cast<const size_t &>(_v); }    \
	};                                                                                                  \
	}
