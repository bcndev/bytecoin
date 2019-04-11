// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "Difficulty.hpp"
#include "common/Varint.hpp"
#include "crypto/hash.hpp"
#include "crypto/int-util.h"
#include "seria/ISeria.hpp"

using namespace cn;

// C99 6.2.5.9 - this is actually good working code by C standard
// static bool cadd(uint64_t a, uint64_t b) { return a + b < a; }
static bool cadc(uint64_t a, uint64_t b, bool c) { return a + b < a || (c && a + b == (uint64_t)-1); }

bool cn::check_hash(const crypto::Hash &hash, Difficulty difficulty) {
	uint64_t hash64[4];
	for (size_t i = 0; i != 4; ++i)
		hash64[i] = common::uint_le_from_bytes<uint64_t>(hash.data + 8 * i, 8);
	// First check the highest word, this will most likely fail for a random hash.
	uint64_t r4;
	uint64_t r3s = mul128(hash64[3], difficulty, &r4);
	//	uint64_t low, high, top, cur; //
	//	top = r3s; //
	//	high = r4; //
	if (r4 != 0)
		return false;
	//	low        = mul128(swap64le(((const uint64_t *)&hash)[0]), difficulty, &cur); //
	//	low        = mul128(swap64le(((const uint64_t *)&hash)[1]), difficulty, &high); //
	//	bool carry = cadd(cur, low); //
	//	cur        = high; //
	//	low        = mul128(swap64le(((const uint64_t *)&hash)[2]), difficulty, &high); //
	//	carry      = cadc(cur, low, carry); //
	//	carry      = cadc(high, top, carry); //
	uint64_t r1, r2, r3;
	mul128(hash64[0], difficulty, &r1);
	uint64_t r1s = mul128(hash64[1], difficulty, &r2);
	uint64_t r2s = mul128(hash64[2], difficulty, &r3);
	bool carry   = cadc(r1, r1s, false);
	carry        = cadc(r2, r2s, carry);
	carry        = cadc(r3, r3s, carry);
	return !carry;
}
