// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// TODO - if possible, get rid of this crap

#if defined(_MSC_VER)
#include <stdlib.h>
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define BYTE_ORDER LITTLE_ENDIAN
#define inline __inline

#if defined(__cplusplus)
extern "C" {
#endif
inline uint32_t rol32(uint32_t x, int r) {
	static_assert(sizeof(uint32_t) == sizeof(unsigned int), "this code assumes 32-bit integers");
	return _rotl(x, r);
}

inline uint64_t rol64(uint64_t x, int r) { return _rotl64(x, r); }
#if defined(__cplusplus)
}
#endif

#else
#include <sys/param.h>

#if defined(__cplusplus)
extern "C" {
#endif
static inline uint32_t rol32(uint32_t x, int r) { return (x << (r & 31)) | (x >> (-r & 31)); }

static inline uint64_t rol64(uint64_t x, int r) { return (x << (r & 63)) | (x >> (-r & 63)); }
#if defined(__cplusplus)
}
#endif

#endif

#if defined(__cplusplus)
extern "C" {
#endif

static inline uint64_t hi_dword(uint64_t val) { return val >> 32; }

static inline uint64_t lo_dword(uint64_t val) { return val & 0xFFFFFFFF; }

static inline uint64_t mul128(uint64_t multiplier, uint64_t multiplicand, uint64_t *product_hi) {
#if defined(__GNUC__) && defined(__x86_64__)
	uint64_t hi, lo;
	__asm__("mulq %3\n\t" : "=d"(hi), "=a"(lo) : "%a"(multiplier), "rm"(multiplicand) : "cc");
	*product_hi = hi;
	return lo;
#elif defined(__SIZEOF_INT128__)
	typedef unsigned __int128 uint128_t;
	uint128_t res = (uint128_t)multiplier * (uint128_t)multiplicand;
	*product_hi   = (uint64_t)(res >> 64);
	return (uint64_t)res;
#else
	// multiplier   = ab = a * 2^32 + b
	// multiplicand = cd = c * 2^32 + d
	// ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
	uint64_t a = hi_dword(multiplier);
	uint64_t b = lo_dword(multiplier);
	uint64_t c = hi_dword(multiplicand);
	uint64_t d = lo_dword(multiplicand);

	uint64_t ac = a * c;
	uint64_t ad = a * d;
	uint64_t bc = b * c;
	uint64_t bd = b * d;

	uint64_t adbc       = ad + bc;
	uint64_t adbc_carry = adbc < ad ? 1 : 0;

	// multiplier * multiplicand = product_hi * 2^64 + product_lo
	uint64_t product_lo       = bd + (adbc << 32);
	uint64_t product_lo_carry = product_lo < bd ? 1 : 0;
	*product_hi               = ac + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;
	assert(ac <= *product_hi);

	return product_lo;
#endif
}

static inline uint64_t div_with_reminder(uint64_t dividend, uint32_t divisor, uint32_t *remainder) {
	dividend |= ((uint64_t)*remainder) << 32;
	*remainder = dividend % divisor;
	return dividend / divisor;
}

// Long division with 2^32 base
static inline uint32_t div128_32(uint64_t dividend_hi,
    uint64_t dividend_lo,
    uint32_t divisor,
    uint64_t *quotient_hi,
    uint64_t *quotient_lo) {
	uint64_t dividend_dwords[4];
	uint32_t remainder = 0;

	dividend_dwords[3] = hi_dword(dividend_hi);
	dividend_dwords[2] = lo_dword(dividend_hi);
	dividend_dwords[1] = hi_dword(dividend_lo);
	dividend_dwords[0] = lo_dword(dividend_lo);

	*quotient_hi = div_with_reminder(dividend_dwords[3], divisor, &remainder) << 32;
	*quotient_hi |= div_with_reminder(dividend_dwords[2], divisor, &remainder);
	*quotient_lo = div_with_reminder(dividend_dwords[1], divisor, &remainder) << 32;
	*quotient_lo |= div_with_reminder(dividend_dwords[0], divisor, &remainder);

	return remainder;
}

#define IDENT32(x) ((uint32_t)(x))

#define SWAP32(x)                                                                                                 \
	((((uint32_t)(x)&0x000000ff) << 24) | (((uint32_t)(x)&0x0000ff00) << 8) | (((uint32_t)(x)&0x00ff0000) >> 8) | \
	    (((uint32_t)(x)&0xff000000) >> 24))

#if !defined(BYTE_ORDER) || !defined(LITTLE_ENDIAN) || !defined(BIG_ENDIAN)
// static_assert(false, "BYTE_ORDER is undefined. Perhaps, GNU extensions are not enabled");
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
#define SWAP32LE IDENT32
#endif

#if BYTE_ORDER == BIG_ENDIAN
#define SWAP32LE SWAP32
#endif

#if defined(__cplusplus)
}
#endif
