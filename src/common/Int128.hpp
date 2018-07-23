// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <iosfwd>
#include <tuple>

namespace common {

struct Uint128 {
	uint64_t lo = 0;
	uint64_t hi = 0;

	Uint128() {}
	Uint128(uint64_t d) : lo(d) {}  // implicit

	Uint128 &operator+=(Uint128 other) {
		hi += other.hi;
		uint64_t was_lo = lo;
		lo += other.lo;
		if (lo < was_lo)  // carry is PLATFORM-DEPENDENT
			hi += 1;
		return *this;
	}
	Uint128 &operator-=(Uint128 other) {
		hi -= other.hi;
		if (lo < other.lo)
			hi -= 1;
		lo -= other.lo;  // carry is PLATFORM-DEPENDENT
		return *this;
	}

	bool operator<(const Uint128 &other) const { return std::tie(hi, lo) < std::tie(other.hi, other.lo); }
	bool operator>(const Uint128 &other) const { return std::tie(hi, lo) > std::tie(other.hi, other.lo); }
	bool operator<=(const Uint128 &other) const { return std::tie(hi, lo) <= std::tie(other.hi, other.lo); }
	bool operator>=(const Uint128 &other) const { return std::tie(hi, lo) >= std::tie(other.hi, other.lo); }
	bool operator==(const Uint128 &other) const { return std::tie(hi, lo) == std::tie(other.hi, other.lo); }
	bool operator!=(const Uint128 &other) const { return std::tie(hi, lo) != std::tie(other.hi, other.lo); }
};

inline Uint128 operator+(Uint128 a, Uint128 b) { return a += b; }
inline Uint128 operator-(Uint128 a, Uint128 b) { return a -= b; }

std::ostream &operator<<(std::ostream &out, const Uint128 &v);
}
