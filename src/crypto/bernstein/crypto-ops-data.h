// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "crypto-ops.h"
#if defined(__cplusplus)
namespace crypto { extern "C" {
#endif


/* From ge_double_scalarmult.c, modified */
extern const ge_precomp ge_Bi[8];

/* From ge_frombytes.c, modified */

extern const fe fe_sqrtm1;
extern const fe fe_d;

/* From ge_p3_to_cached.c */

extern const fe fe_d2;

/* From ge_scalarmult_base.c */

extern const ge_precomp ge_base[32][8];

/* New code */

extern const fe fe_ma2;
extern const fe fe_ma;
extern const fe fe_fffb1;
extern const fe fe_fffb2;
extern const fe fe_fffb3;
extern const fe fe_fffb4;

#if defined(__cplusplus)
}}
#endif
