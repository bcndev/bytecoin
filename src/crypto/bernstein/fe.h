// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "c_types.h"
#include <stdint.h>
#if defined(__cplusplus)
extern "C" {
#endif

/* From fe.h */
#if crypto_CRYPTO128
#define FE25519_COUNT 5
typedef uint64_t fe[FE25519_COUNT];
#else
#define FE25519_COUNT 10
typedef int32_t fe[FE25519_COUNT];
#endif

void fe_copy(fe h, const fe f);
void fe_0(fe h);
void fe_1(fe h);
void fe_add(fe h, const fe f, const fe g);
void fe_cmov(fe f, const fe g, unsigned int b);
void fe_invert(fe out, const fe z);
int fe_isnegative(const fe f);
int fe_isnonzero(const fe f);
void fe_neg(fe h, const fe f);

void fe_mul(fe, const fe, const fe);
void fe_sq(fe, const fe);
void fe_sq2(fe h, const fe f);
void fe_tobytes(unsigned char *, const fe);
void fe_divpowm1(fe, const fe, const fe);
void fe_sub(fe h, const fe f, const fe g);

int fe_frombytes_vartime(fe h, const unsigned char s[32]);
void fe_fromfe_frombytes_vartime(fe u, const unsigned char s[32]);

#if defined(__cplusplus)
}
#endif
