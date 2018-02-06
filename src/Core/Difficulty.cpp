// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "crypto/int-util.h"
#include "crypto/hash.hpp"
#include "Difficulty.hpp"

namespace bytecoin {

static bool cadd(uint64_t a, uint64_t b) {
	return a + b < a;
}

static bool cadc(uint64_t a, uint64_t b, bool c) {
	return a + b < a || (c && a + b == (uint64_t) -1);
}

bool check_hash(const crypto::Hash &hash, Difficulty difficulty) {
	uint64_t low, high, top, cur;
	// First check the highest word, this will most likely fail for a random hash.
	top = mul128(swap64le(((const uint64_t *) &hash)[3]), difficulty, &high);
	if (high != 0) {
		return false;
	}
	low = mul128(swap64le(((const uint64_t *) &hash)[0]), difficulty, &cur); // TODO - low is not used
	low = mul128(swap64le(((const uint64_t *) &hash)[1]), difficulty, &high);
	bool carry = cadd(cur, low);
	cur = high;
	low = mul128(swap64le(((const uint64_t *) &hash)[2]), difficulty, &high);
	carry = cadc(cur, low, carry);
	carry = cadc(high, top, carry);
	return !carry;
}
}
