// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "c_types.h"
#if defined(__cplusplus)
namespace crypto { extern "C" {
#endif

/* From fe.h */

typedef int32_t fe[10];

/* From ge.h */

typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p1p1;

typedef struct {
  fe yplusx;
  fe yminusx;
  fe xy2d;
} ge_precomp;

typedef struct {
  fe YplusX;
  fe YminusX;
  fe Z;
  fe T2d;
} ge_cached;

/* From ge_add.c */

void ge_add(ge_p1p1 *, const ge_p3 *, const ge_cached *);

/* From ge_double_scalarmult.c, modified */

typedef ge_cached ge_dsmp[8];
void ge_dsm_precomp(ge_dsmp r, const ge_p3 *s);
void ge_double_scalarmult_base_vartime(ge_p2 *, const struct EllipticCurveScalar *, const ge_p3 *, const struct EllipticCurveScalar *);

/* From ge_frombytes.c, modified */

int ge_frombytes_vartime(ge_p3 *, const struct EllipticCurvePoint *);

/* From ge_p1p1_to_p2.c */

void ge_p1p1_to_p2(ge_p2 *, const ge_p1p1 *);

/* From ge_p1p1_to_p3.c */

void ge_p1p1_to_p3(ge_p3 *, const ge_p1p1 *);

/* From ge_p2_dbl.c */

void ge_p2_dbl(ge_p1p1 *, const ge_p2 *);

/* From ge_p3_to_cached.c */

void ge_p3_to_cached(ge_cached *, const ge_p3 *);

/* From ge_p3_to_p2.c */

void ge_p3_to_p2(ge_p2 *, const ge_p3 *);

/* From ge_p3_tobytes.c */

void ge_p3_tobytes(struct EllipticCurvePoint *, const ge_p3 *);

/* From ge_scalarmult_base.c */

void ge_scalarmult_base(ge_p3 *, const struct EllipticCurveScalar *);

/* From ge_sub.c */

void ge_sub(ge_p1p1 *, const ge_p3 *, const ge_cached *);

/* From ge_tobytes.c */

void ge_tobytes(struct EllipticCurvePoint *, const ge_p2 *);

/* From sc_reduce.c */

void sc_reduce(struct EllipticCurveScalar *, const unsigned char[64]);

/* New code */

void ge_scalarmult(ge_p2 *, const struct EllipticCurveScalar *, const ge_p3 *);
void ge_double_scalarmult_precomp_vartime(ge_p2 *, const struct EllipticCurveScalar *, const ge_p3 *, const struct EllipticCurveScalar *, const ge_dsmp);
int ge_check_subgroup_precomp_vartime(const ge_dsmp);
void ge_mul8(ge_p1p1 *, const ge_p2 *);
void ge_fromfe_frombytes_vartime(ge_p2 *, const unsigned char[32]);
void sc_0(struct EllipticCurveScalar *);
void sc_reduce32(struct EllipticCurveScalar *, const unsigned char[32]);
void sc_add(struct EllipticCurveScalar *, const struct EllipticCurveScalar *, const struct EllipticCurveScalar *);
void sc_sub(struct EllipticCurveScalar *, const struct EllipticCurveScalar *, const struct EllipticCurveScalar *);
void sc_mulsub(struct EllipticCurveScalar *, const struct EllipticCurveScalar *, const struct EllipticCurveScalar *, const struct EllipticCurveScalar *);
int sc_isvalid_vartime(const struct EllipticCurveScalar *);
int sc_iszero(const struct EllipticCurveScalar *); // Doesn't normalize

#if defined(__cplusplus)
}}
#endif
