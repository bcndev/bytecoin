// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <assert.h>
#include <stdint.h>

#include "fe.h"

typedef unsigned __int128 uint128_t;

/* Predeclarations */

/* Common functions */

static inline void STORE64_LE(uint8_t dst[8], uint64_t w) {
	dst[0] = (uint8_t) w; w >>= 8;
	dst[1] = (uint8_t) w; w >>= 8;
	dst[2] = (uint8_t) w; w >>= 8;
	dst[3] = (uint8_t) w; w >>= 8;
	dst[4] = (uint8_t) w; w >>= 8;
	dst[5] = (uint8_t) w; w >>= 8;
	dst[6] = (uint8_t) w; w >>= 8;
	dst[7] = (uint8_t) w;
}

static inline uint64_t LOAD64_LE(const uint8_t src[4]) {
	uint64_t w = (uint64_t) src[0];
	w |= (uint64_t) src[1] <<  8;
	w |= (uint64_t) src[2] << 16;
	w |= (uint64_t) src[3] << 24;
	w |= (uint64_t) src[4] << 32;
	w |= (uint64_t) src[5] << 40;
	w |= (uint64_t) src[6] << 48;
	w |= (uint64_t) src[7] << 56;
	return w;
}
/* From fe_0.c */

/*
h = 0
*/

void fe_0(fe h) {
  h[0] = 0;
  h[1] = 0;
  h[2] = 0;
  h[3] = 0;
  h[4] = 0;
}

/* From fe_1.c */

/*
h = 1
*/

void fe_1(fe h) {
  h[0] = 1;
  h[1] = 0;
  h[2] = 0;
  h[3] = 0;
  h[4] = 0;
}

/* From fe_add.c */

/*
h = f + g
Can overlap h with f or g.

Preconditions:
   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
   |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

Postconditions:
   |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
*/

void fe_add(fe h, const fe f, const fe g) {
	uint64_t h0 = f[0] + g[0];
	uint64_t h1 = f[1] + g[1];
	uint64_t h2 = f[2] + g[2];
	uint64_t h3 = f[3] + g[3];
	uint64_t h4 = f[4] + g[4];

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
}

/* From fe_cmov.c */

/*
Replace (f,g) with (g,g) if b == 1;
replace (f,g) with (f,g) if b == 0.

Preconditions: b in {0,1}.
*/

void fe_cmov(fe f, const fe g, unsigned int b) {
	const uint64_t mask = (uint64_t) (-(int64_t) b);

	uint64_t f0 = f[0];
	uint64_t f1 = f[1];
	uint64_t f2 = f[2];
	uint64_t f3 = f[3];
	uint64_t f4 = f[4];

	uint64_t x0 = f0 ^ g[0];
	uint64_t x1 = f1 ^ g[1];
	uint64_t x2 = f2 ^ g[2];
	uint64_t x3 = f3 ^ g[3];
	uint64_t x4 = f4 ^ g[4];

	x0 &= mask;
	x1 &= mask;
	x2 &= mask;
	x3 &= mask;
	x4 &= mask;

	f[0] = f0 ^ x0;
	f[1] = f1 ^ x1;
	f[2] = f2 ^ x2;
	f[3] = f3 ^ x3;
	f[4] = f4 ^ x4;
}

/* From fe_copy.c */

/*
h = f
*/

void fe_copy(fe h, const fe f) {
  uint64_t f0 = f[0];
  uint64_t f1 = f[1];
  uint64_t f2 = f[2];
  uint64_t f3 = f[3];
  uint64_t f4 = f[4];
  h[0] = f0;
  h[1] = f1;
  h[2] = f2;
  h[3] = f3;
  h[4] = f4;
}

/* From fe_invert.c */

void fe_invert(fe out, const fe z) {
  fe t0;
  fe t1;
  fe t2;
  fe t3;
  int i;

  fe_sq(t0, z);
  fe_sq(t1, t0);
  fe_sq(t1, t1);
  fe_mul(t1, z, t1);
  fe_mul(t0, t0, t1);
  fe_sq(t2, t0);
  fe_mul(t1, t1, t2);
  fe_sq(t2, t1);
  for (i = 0; i < 4; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t1, t2, t1);
  fe_sq(t2, t1);
  for (i = 0; i < 9; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t2, t2, t1);
  fe_sq(t3, t2);
  for (i = 0; i < 19; ++i) {
    fe_sq(t3, t3);
  }
  fe_mul(t2, t3, t2);
  fe_sq(t2, t2);
  for (i = 0; i < 9; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t1, t2, t1);
  fe_sq(t2, t1);
  for (i = 0; i < 49; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t2, t2, t1);
  fe_sq(t3, t2);
  for (i = 0; i < 99; ++i) {
    fe_sq(t3, t3);
  }
  fe_mul(t2, t3, t2);
  fe_sq(t2, t2);
  for (i = 0; i < 49; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t1, t2, t1);
  fe_sq(t1, t1);
  for (i = 0; i < 4; ++i) {
    fe_sq(t1, t1);
  }
  fe_mul(out, t1, t0);

  return;
}

/* From fe_isnegative.c */

/*
return 1 if f is in {1,3,5,...,q-2}
return 0 if f is in {0,2,4,...,q-1}

Preconditions:
   |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
*/

int fe_isnegative(const fe f) {
  unsigned char s[32];
  fe_tobytes(s, f);
  return s[0] & 1;
}

/* From fe_isnonzero.c, modified */

int fe_isnonzero(const fe f) {
  unsigned char s[32];
  fe_tobytes(s, f);
  return (((int) (s[0] | s[1] | s[2] | s[3] | s[4] | s[5] | s[6] | s[7] | s[8] |
    s[9] | s[10] | s[11] | s[12] | s[13] | s[14] | s[15] | s[16] | s[17] |
    s[18] | s[19] | s[20] | s[21] | s[22] | s[23] | s[24] | s[25] | s[26] |
    s[27] | s[28] | s[29] | s[30] | s[31]) - 1) >> 8) + 1;
}

/* From fe_mul.c */

/*
h = f * g
Can overlap h with f or g.

Preconditions:
   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
   |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

Postconditions:
   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
*/

/*
Notes on implementation strategy:

Using schoolbook multiplication.
Karatsuba would save a little in some cost models.

Most multiplications by 2 and 19 are 32-bit precomputations;
cheaper than 64-bit postcomputations.

There is one remaining multiplication by 19 in the carry chain;
one *19 precomputation can be merged into this,
but the resulting data flow is considerably less clean.

There are 12 carries below.
10 of them are 2-way parallelizable and vectorizable.
Can get away with 11 carries, but then data flow is much deeper.

With tighter constraints on inputs can squeeze carries into int32.
*/

void fe_mul(fe h, const fe f, const fe g) {
	const uint64_t mask = 0x7ffffffffffffULL;
	uint128_t r0, r1, r2, r3, r4, carry;
	uint64_t  f0, f1, f2, f3, f4;
	uint64_t  f1_19, f2_19, f3_19, f4_19;
	uint64_t  g0, g1, g2, g3, g4;
	uint64_t  r00, r01, r02, r03, r04;

	f0 = f[0];
	f1 = f[1];
	f2 = f[2];
	f3 = f[3];
	f4 = f[4];

	g0 = g[0];
	g1 = g[1];
	g2 = g[2];
	g3 = g[3];
	g4 = g[4];

	f1_19 = 19ULL * f1;
	f2_19 = 19ULL * f2;
	f3_19 = 19ULL * f3;
	f4_19 = 19ULL * f4;

	r0  = ((uint128_t) f0   ) * ((uint128_t) g0);
	r0 += ((uint128_t) f1_19) * ((uint128_t) g4);
	r0 += ((uint128_t) f2_19) * ((uint128_t) g3);
	r0 += ((uint128_t) f3_19) * ((uint128_t) g2);
	r0 += ((uint128_t) f4_19) * ((uint128_t) g1);

	r1  = ((uint128_t) f0   ) * ((uint128_t) g1);
	r1 += ((uint128_t) f1   ) * ((uint128_t) g0);
	r1 += ((uint128_t) f2_19) * ((uint128_t) g4);
	r1 += ((uint128_t) f3_19) * ((uint128_t) g3);
	r1 += ((uint128_t) f4_19) * ((uint128_t) g2);

	r2  = ((uint128_t) f0   ) * ((uint128_t) g2);
	r2 += ((uint128_t) f1   ) * ((uint128_t) g1);
	r2 += ((uint128_t) f2   ) * ((uint128_t) g0);
	r2 += ((uint128_t) f3_19) * ((uint128_t) g4);
	r2 += ((uint128_t) f4_19) * ((uint128_t) g3);

	r3  = ((uint128_t) f0   ) * ((uint128_t) g3);
	r3 += ((uint128_t) f1   ) * ((uint128_t) g2);
	r3 += ((uint128_t) f2   ) * ((uint128_t) g1);
	r3 += ((uint128_t) f3   ) * ((uint128_t) g0);
	r3 += ((uint128_t) f4_19) * ((uint128_t) g4);

	r4  = ((uint128_t) f0   ) * ((uint128_t) g4);
	r4 += ((uint128_t) f1   ) * ((uint128_t) g3);
	r4 += ((uint128_t) f2   ) * ((uint128_t) g2);
	r4 += ((uint128_t) f3   ) * ((uint128_t) g1);
	r4 += ((uint128_t) f4   ) * ((uint128_t) g0);

	r00    = ((uint64_t) r0) & mask;
	carry  = r0 >> 51;
	r1    += carry;
	r01    = ((uint64_t) r1) & mask;
	carry  = r1 >> 51;
	r2    += carry;
	r02    = ((uint64_t) r2) & mask;
	carry  = r2 >> 51;
	r3    += carry;
	r03    = ((uint64_t) r3) & mask;
	carry  = r3 >> 51;
	r4    += carry;
	r04    = ((uint64_t) r4) & mask;
	carry  = r4 >> 51;
	r00   += 19ULL * (uint64_t) carry;
	carry  = r00 >> 51;
	r00   &= mask;
	r01   += (uint64_t) carry;
	carry  = r01 >> 51;
	r01   &= mask;
	r02   += (uint64_t) carry;

	h[0] = r00;
	h[1] = r01;
	h[2] = r02;
	h[3] = r03;
	h[4] = r04;
}

/* From fe_neg.c */

/*
h = -f

Preconditions:
   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

Postconditions:
   |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
*/

void fe_neg(fe h, const fe f) {
	fe zero;

	fe_0(zero);
	fe_sub(h, zero, f);
}

/* From fe_sq.c */

/*
h = f * f
Can overlap h with f.

Preconditions:
   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

Postconditions:
   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
*/

/*
See fe_mul.c for discussion of implementation strategy.
*/

void fe_sq(fe h, const fe f) {
	const uint64_t mask = 0x7ffffffffffffULL;
	uint128_t r0, r1, r2, r3, r4, carry;
	uint64_t  f0, f1, f2, f3, f4;
	uint64_t  f0_2, f1_2, f1_38, f2_38, f3_38, f3_19, f4_19;
	uint64_t  r00, r01, r02, r03, r04;

	f0 = f[0];
	f1 = f[1];
	f2 = f[2];
	f3 = f[3];
	f4 = f[4];

	f0_2 = f0 << 1;
	f1_2 = f1 << 1;

	f1_38 = 38ULL * f1;
	f2_38 = 38ULL * f2;
	f3_38 = 38ULL * f3;

	f3_19 = 19ULL * f3;
	f4_19 = 19ULL * f4;

	r0  = ((uint128_t) f0   ) * ((uint128_t) f0);
	r0 += ((uint128_t) f1_38) * ((uint128_t) f4);
	r0 += ((uint128_t) f2_38) * ((uint128_t) f3);

	r1  = ((uint128_t) f0_2 ) * ((uint128_t) f1);
	r1 += ((uint128_t) f2_38) * ((uint128_t) f4);
	r1 += ((uint128_t) f3_19) * ((uint128_t) f3);

	r2  = ((uint128_t) f0_2 ) * ((uint128_t) f2);
	r2 += ((uint128_t) f1   ) * ((uint128_t) f1);
	r2 += ((uint128_t) f3_38) * ((uint128_t) f4);

	r3  = ((uint128_t) f0_2 ) * ((uint128_t) f3);
	r3 += ((uint128_t) f1_2 ) * ((uint128_t) f2);
	r3 += ((uint128_t) f4_19) * ((uint128_t) f4);

	r4  = ((uint128_t) f0_2 ) * ((uint128_t) f4);
	r4 += ((uint128_t) f1_2 ) * ((uint128_t) f3);
	r4 += ((uint128_t) f2   ) * ((uint128_t) f2);

	r00    = ((uint64_t) r0) & mask;
	carry  = r0 >> 51;
	r1    += carry;
	r01    = ((uint64_t) r1) & mask;
	carry  = r1 >> 51;
	r2    += carry;
	r02    = ((uint64_t) r2) & mask;
	carry  = r2 >> 51;
	r3    += carry;
	r03    = ((uint64_t) r3) & mask;
	carry  = r3 >> 51;
	r4    += carry;
	r04    = ((uint64_t) r4) & mask;
	carry  = r4 >> 51;
	r00   += 19ULL * (uint64_t) carry;
	carry  = r00 >> 51;
	r00   &= mask;
	r01   += (uint64_t) carry;
	carry  = r01 >> 51;
	r01   &= mask;
	r02   += (uint64_t) carry;

	h[0] = r00;
	h[1] = r01;
	h[2] = r02;
	h[3] = r03;
	h[4] = r04;
}

/* From fe_sq2.c */

/*
h = 2 * f * f
Can overlap h with f.

Preconditions:
   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

Postconditions:
   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
*/

/*
See fe_mul.c for discussion of implementation strategy.
*/

void fe_sq2(fe h, const fe f) {
	const uint64_t mask = 0x7ffffffffffffULL;
	uint128_t r0, r1, r2, r3, r4, carry;
	uint64_t  f0, f1, f2, f3, f4;
	uint64_t  f0_2, f1_2, f1_38, f2_38, f3_38, f3_19, f4_19;
	uint64_t  r00, r01, r02, r03, r04;

	f0 = f[0];
	f1 = f[1];
	f2 = f[2];
	f3 = f[3];
	f4 = f[4];

	f0_2 = f0 << 1;
	f1_2 = f1 << 1;

	f1_38 = 38ULL * f1;
	f2_38 = 38ULL * f2;
	f3_38 = 38ULL * f3;

	f3_19 = 19ULL * f3;
	f4_19 = 19ULL * f4;

	r0  = ((uint128_t) f0   ) * ((uint128_t) f0);
	r0 += ((uint128_t) f1_38) * ((uint128_t) f4);
	r0 += ((uint128_t) f2_38) * ((uint128_t) f3);

	r1  = ((uint128_t) f0_2 ) * ((uint128_t) f1);
	r1 += ((uint128_t) f2_38) * ((uint128_t) f4);
	r1 += ((uint128_t) f3_19) * ((uint128_t) f3);

	r2  = ((uint128_t) f0_2 ) * ((uint128_t) f2);
	r2 += ((uint128_t) f1   ) * ((uint128_t) f1);
	r2 += ((uint128_t) f3_38) * ((uint128_t) f4);

	r3  = ((uint128_t) f0_2 ) * ((uint128_t) f3);
	r3 += ((uint128_t) f1_2 ) * ((uint128_t) f2);
	r3 += ((uint128_t) f4_19) * ((uint128_t) f4);

	r4  = ((uint128_t) f0_2 ) * ((uint128_t) f4);
	r4 += ((uint128_t) f1_2 ) * ((uint128_t) f3);
	r4 += ((uint128_t) f2   ) * ((uint128_t) f2);

	r0 <<= 1;
	r1 <<= 1;
	r2 <<= 1;
	r3 <<= 1;
	r4 <<= 1;

	r00    = ((uint64_t) r0) & mask;
	carry  = r0 >> 51;
	r1    += carry;
	r01    = ((uint64_t) r1) & mask;
	carry  = r1 >> 51;
	r2    += carry;
	r02    = ((uint64_t) r2) & mask;
	carry  = r2 >> 51;
	r3    += carry;
	r03    = ((uint64_t) r3) & mask;
	carry  = r3 >> 51;
	r4    += carry;
	r04    = ((uint64_t) r4) & mask;
	carry  = r4 >> 51;
	r00   += 19ULL * (uint64_t) carry;
	carry  = r00 >> 51;
	r00   &= mask;
	r01   += (uint64_t) carry;
	carry  = r01 >> 51;
	r01   &= mask;
	r02   += (uint64_t) carry;

	h[0] = r00;
	h[1] = r01;
	h[2] = r02;
	h[3] = r03;
	h[4] = r04;
}

/* From fe_sub.c */

/*
h = f - g
Can overlap h with f or g.

Preconditions:
   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
   |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

Postconditions:
   |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
*/

void fe_sub(fe h, const fe f, const fe g) {
	const uint64_t mask = 0x7ffffffffffffULL;
	uint64_t h0, h1, h2, h3, h4;

	h0 = g[0];
	h1 = g[1];
	h2 = g[2];
	h3 = g[3];
	h4 = g[4];

	h1 += h0 >> 51;
	h0 &= mask;
	h2 += h1 >> 51;
	h1 &= mask;
	h3 += h2 >> 51;
	h2 &= mask;
	h4 += h3 >> 51;
	h3 &= mask;
	h0 += 19ULL * (h4 >> 51);
	h4 &= mask;

	h0 = (f[0] + 0xfffffffffffdaULL) - h0;
	h1 = (f[1] + 0xffffffffffffeULL) - h1;
	h2 = (f[2] + 0xffffffffffffeULL) - h2;
	h3 = (f[3] + 0xffffffffffffeULL) - h3;
	h4 = (f[4] + 0xffffffffffffeULL) - h4;

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
}

/* From fe_tobytes.c */

/*
Preconditions:
  |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.

Write p=2^255-19; q=floor(h/p).
Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).

Proof:
  Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
  Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.

  Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
  Then 0<y<1.

  Write r=h-pq.
  Have 0<=r<=p-1=2^255-20.
  Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.

  Write x=r+19(2^-255)r+y.
  Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.

  Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
  so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
*/

static void
fe_reduce(fe h, const fe f)
{
	const uint64_t mask = 0x7ffffffffffffULL;
	uint128_t t[5];

	t[0] = f[0];
	t[1] = f[1];
	t[2] = f[2];
	t[3] = f[3];
	t[4] = f[4];

	t[1] += t[0] >> 51;
	t[0] &= mask;
	t[2] += t[1] >> 51;
	t[1] &= mask;
	t[3] += t[2] >> 51;
	t[2] &= mask;
	t[4] += t[3] >> 51;
	t[3] &= mask;
	t[0] += 19 * (t[4] >> 51);
	t[4] &= mask;

	t[1] += t[0] >> 51;
	t[0] &= mask;
	t[2] += t[1] >> 51;
	t[1] &= mask;
	t[3] += t[2] >> 51;
	t[2] &= mask;
	t[4] += t[3] >> 51;
	t[3] &= mask;
	t[0] += 19 * (t[4] >> 51);
	t[4] &= mask;

	/* now t is between 0 and 2^255-1, properly carried. */
	/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */

	t[0] += 19ULL;

	t[1] += t[0] >> 51;
	t[0] &= mask;
	t[2] += t[1] >> 51;
	t[1] &= mask;
	t[3] += t[2] >> 51;
	t[2] &= mask;
	t[4] += t[3] >> 51;
	t[3] &= mask;
	t[0] += 19ULL * (t[4] >> 51);
	t[4] &= mask;

	/* now between 19 and 2^255-1 in both cases, and offset by 19. */

	t[0] += 0x8000000000000 - 19ULL;
	t[1] += 0x8000000000000 - 1ULL;
	t[2] += 0x8000000000000 - 1ULL;
	t[3] += 0x8000000000000 - 1ULL;
	t[4] += 0x8000000000000 - 1ULL;

	/* now between 2^255 and 2^256-20, and offset by 2^255. */

	t[1] += t[0] >> 51;
	t[0] &= mask;
	t[2] += t[1] >> 51;
	t[1] &= mask;
	t[3] += t[2] >> 51;
	t[2] &= mask;
	t[4] += t[3] >> 51;
	t[3] &= mask;
	t[4] &= mask;

	h[0] = t[0];
	h[1] = t[1];
	h[2] = t[2];
	h[3] = t[3];
	h[4] = t[4];
}

void fe_tobytes(unsigned char *s, const fe h) {
	fe  t;
	uint64_t t0, t1, t2, t3;

	fe_reduce(t, h);
	t0 = t[0] | (t[1] << 51);
	t1 = (t[1] >> 13) | (t[2] << 38);
	t2 = (t[2] >> 26) | (t[3] << 25);
	t3 = (t[3] >> 39) | (t[4] << 12);
	STORE64_LE(s +  0, t0);
	STORE64_LE(s +  8, t1);
	STORE64_LE(s + 16, t2);
	STORE64_LE(s + 24, t3);
}

int fe_frombytes_vartime(fe h, const unsigned char s[32]) {

	/* From fe_frombytes.c */

	const uint64_t mask = 0x7ffffffffffffULL;
	uint64_t h0, h1, h2, h3, h4;

	h0 = (LOAD64_LE(s     )      ) & mask;
	h1 = (LOAD64_LE(s +  6) >>  3) & mask;
	h2 = (LOAD64_LE(s + 12) >>  6) & mask;
	h3 = (LOAD64_LE(s + 19) >>  1) & mask;
	h4 = (LOAD64_LE(s + 24) >> 12) & mask;

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;

	/* Validate the number to be canonical */
	if (h4 == mask && h3 == mask && h2 == mask && h1 == mask && h0 >= mask - 18) {
		return -1;
	}
	return 0;
}

void fe_fromfe_frombytes_vartime(fe h, const unsigned char s[32]) {
	const uint64_t mask = 0x7ffffffffffffULL;
	uint64_t h0, h1, h2, h3, h4;

	h0 = (LOAD64_LE(s     )      ) & mask;
	h1 = (LOAD64_LE(s +  6) >>  3) & mask;
	h2 = (LOAD64_LE(s + 12) >>  6) & mask;
	h3 = (LOAD64_LE(s + 19) >>  1) & mask;
	h4 = (LOAD64_LE(s + 24) >> 12);

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;

//	fe_reduce(h, u); <- not required, fe_sq will reduce
}
