// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "Currency.hpp"
#include "Difficulty.hpp"
#include "crypto/hash.hpp"
#include "crypto/int-util.h"
#include "seria/ISeria.hpp"

using namespace bytecoin;

// carry is PLATFORM-DEPENDENT
static bool cadd(uint64_t a, uint64_t b) { return a + b < a; }

static bool cadc(uint64_t a, uint64_t b, bool c) { return a + b < a || (c && a + b == (uint64_t)-1); }

bool bytecoin::check_hash(const crypto::Hash &hash, Difficulty difficulty) {
	uint64_t low, high, top, cur;
	// First check the highest word, this will most likely fail for a random hash.
	top = mul128(swap64le(((const uint64_t *)&hash)[3]), difficulty, &high);
	if (high != 0) {
		return false;
	}
	low        = mul128(swap64le(((const uint64_t *)&hash)[0]), difficulty, &cur);  // TODO - low is not used
	low        = mul128(swap64le(((const uint64_t *)&hash)[1]), difficulty, &high);
	bool carry = cadd(cur, low);
	cur        = high;
	low        = mul128(swap64le(((const uint64_t *)&hash)[2]), difficulty, &high);
	carry      = cadc(cur, low, carry);
	carry      = cadc(high, top, carry);
	return !carry;
}
