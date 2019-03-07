// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "bernstein/crypto-ops.h"
#include "crypto.hpp"
#include "hash.hpp"

// Helpers that allow to write normal "x = f(y)" code instead of stupid f(&x, &y)

// Experimental helpers that allow to write normal a = b * c + d

namespace crypto {

struct P3MulResult {
	const ge_p3 &p3;
	const EllipticCurveScalar &s;
	P3MulResult(const ge_p3 &p3, const EllipticCurveScalar &s) : p3(p3), s(s) {}
};
struct P3MulResultG {
	const EllipticCurveScalar &s;
	explicit P3MulResultG(const EllipticCurveScalar &s) : s(s) {}
};

struct G3_type {};

constexpr ge_p3 G_p3{
    {-14297830, -7645148, 16144683, -16471763, 27570974, -2696100, -26142465, 8378389, 20764389, 8758491},
    {-26843541, -6710886, 13421773, -13421773, 26843546, 6710886, -13421773, 13421773, -26843546, -6710886},
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {28827062, -6116119, -27349572, 244363, 8635006, 11264893, 19351346, 13413597, 16611511, -6414980}};

struct P3 {
	ge_p3 p3;

	constexpr P3() : p3{{0}, {1, 0}, {1, 0}, {0}} {  // identity point
	}
	constexpr P3(const ge_p3 &other) : p3(other) {}
	P3(const G3_type &other) : p3(G_p3) {}
	explicit P3(const EllipticCurvePoint &other) {
		if (ge_frombytes_vartime(&p3, &other) != 0)
			throw Error("Public Key Invalid");
	}
	P3(const P3MulResult &other) { ge_scalarmult3(&p3, &other.s, &other.p3); }
	P3(const P3MulResultG &other) { ge_scalarmult_base(&p3, &other.s); }
};

inline PublicKey to_bytes(const P3 &other) {
	PublicKey result;
	ge_p3_tobytes(&result, &other.p3);
	return result;
}
template<typename T>
T to_bytes(const P3 &other) {
	T result;
	ge_p3_tobytes(&result, &other.p3);
	return result;
}

constexpr G3_type G{};
constexpr P3 I{ge_p3{{0}, {1, 0}, {1, 0}, {0}}};
constexpr P3 H{ge_p3{{7329926, -15101362, 31411471, 7614783, 27996851, -3197071, -11157635, -6878293, 466949, -7986503},
    {5858699, 5096796, 21321203, -7536921, -5553480, -11439507, -5627669, 15045946, 19977121, 5275251},
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {23443568, -5110398, -8776029, -4345135, 6889568, -14710814, 7474843, 3279062, 14550766, -7453428}}};

inline P3 &operator*=(P3 &point_base, const EllipticCurveScalar &sec) {
	point_base = P3MulResult(point_base.p3, sec);
	return point_base;
}
inline P3MulResultG operator*(const G3_type &, const EllipticCurveScalar &sec) { return P3MulResultG(sec); }
inline P3MulResultG operator*(const EllipticCurveScalar &sec, const G3_type &) { return P3MulResultG(sec); }

inline P3MulResult operator*(const P3 &point_base, const EllipticCurveScalar &sec) {
	return P3MulResult(point_base.p3, sec);
}
inline P3MulResult operator*(const EllipticCurveScalar &sec, const P3 &point_base) {
	return P3MulResult(point_base.p3, sec);
}
inline P3 operator-(const P3 &a, const P3 &b) {
	ge_cached b_cached;
	ge_p3_to_cached(&b_cached, &b.p3);
	ge_p1p1 result_p1p1;
	ge_sub(&result_p1p1, &a.p3, &b_cached);
	P3 result;
	ge_p1p1_to_p3(&result.p3, &result_p1p1);
	return result;
}
inline P3 &operator-=(P3 &a, const P3 &b) {
	a = a - b;
	return a;
}
inline P3 operator+(const P3 &a, const P3 &b) {
	ge_cached b_cached;
	ge_p3_to_cached(&b_cached, &b.p3);
	ge_p1p1 result_p1p1;
	ge_add(&result_p1p1, &a.p3, &b_cached);
	P3 result;
	ge_p1p1_to_p3(&result.p3, &result_p1p1);
	return result;
}
inline P3 &operator+=(P3 &a, const P3 &b) {
	a = a + b;
	return a;
}
inline P3 operator+(const P3MulResult &r1, const P3MulResult &r2) {
	return P3(r1) + P3(r2);
	//	ge_dsmp dsm;
	//	ge_dsm_precomp(&dsm, &r2.p3);
	//	P3 res_p3;
	//	ge_double_scalarmult_precomp_vartime3(&res_p3.p3, &r1.s, &r1.p3, &r2.s, &dsm);
	//	return res_p3;
}
inline P3 operator+(const P3MulResultG &r1, const P3MulResult &r2) {
	return P3(r1) + P3(r2);
	//	P3 res_p3;
	//	ge_double_scalarmult_base_vartime3(&res_p3.p3, &r2.s, &r2.p3, &r1.s);
	//	return res_p3;
}
inline P3 operator+(const P3MulResult &r1, const P3MulResultG &r2) { return r2 + r1; }

struct ScalarMulResult {
	const EllipticCurveScalar &a;
	const EllipticCurveScalar &b;
	ScalarMulResult(const EllipticCurveScalar &a, const EllipticCurveScalar &b) : a(a), b(b) {}
	operator SecretKey() {
		SecretKey result;
		sc_mul(&result, &a, &b);
		return result;
	}
};
inline ScalarMulResult operator*(const EllipticCurveScalar &a, const EllipticCurveScalar &b) {
	return ScalarMulResult(a, b);
}
inline EllipticCurveScalar &operator*=(EllipticCurveScalar &a, const EllipticCurveScalar &b) {
	a = ScalarMulResult(a, b);
	return a;
}

inline SecretKey operator-(const EllipticCurveScalar &c, const ScalarMulResult &ab) {
	SecretKey result;
	sc_mulsub(&result, &ab.a, &ab.b, &c);
	return result;
}
inline EllipticCurveScalar &operator-=(EllipticCurveScalar &c, const ScalarMulResult &ab) {
	c = c - ab;
	return c;
}
inline SecretKey operator-(const EllipticCurveScalar &a, const EllipticCurveScalar &b) {
	SecretKey result;
	sc_sub(&result, &a, &b);
	return result;
}
inline EllipticCurveScalar &operator-=(EllipticCurveScalar &a, const EllipticCurveScalar &b) {
	a = a - b;
	return a;
}
inline SecretKey operator+(const EllipticCurveScalar &a, const EllipticCurveScalar &b) {
	SecretKey result;
	sc_add(&result, &a, &b);
	return result;
}
inline EllipticCurveScalar &operator+=(EllipticCurveScalar &a, const EllipticCurveScalar &b) {
	a = a + b;
	return a;
}

PublicKey get_G();       // slow, for reference only
PublicKey get_H();       // slow, for reference only
PublicKey test_get_H();  // performs actual steps to calc H_p3

inline SecretKey sc_invert(const EllipticCurveScalar &sec) {
	SecretKey result;
	sc_invert(&result, &sec);
	return result;
}

inline ge_p3 ge_scalarmult_base(const EllipticCurveScalar &sec) {
	ge_p3 point;
	ge_scalarmult_base(&point, &sec);
	return point;
}

inline PublicKey ge_tobytes(const ge_p3 &point3) {
	PublicKey result;
	ge_p3_tobytes(&result, &point3);
	return result;
}

inline PublicKey ge_tobytes(const ge_p2 &point2) {
	PublicKey result;
	ge_tobytes(&result, &point2);
	return result;
}

inline void check_scalar(const EllipticCurveScalar &scalar) {
	if (!sc_isvalid_vartime(&scalar))
		throw Error("Secret Key Invalid");
}

inline ge_p3 ge_frombytes_vartime(const EllipticCurvePoint &point) {
	ge_p3 result_p3;
	if (ge_frombytes_vartime(&result_p3, &point) != 0)
		throw Error("Public Key Invalid");
	return result_p3;
}

inline ge_p3 ge_scalarmult3(const EllipticCurveScalar &sec, const ge_p3 &point_base) {
	ge_p3 point3;
	ge_scalarmult3(&point3, &sec, &point_base);
	return point3;
}

inline ge_p3 ge_double_scalarmult_base_vartime3(
    const EllipticCurveScalar &a, const ge_p3 &A, const EllipticCurveScalar &b) {
	ge_p3 tmp3;
	ge_double_scalarmult_base_vartime3(&tmp3, &a, &A, &b);
	return tmp3;
}

inline ge_p3 ge_double_scalarmult_precomp_vartime3(
    const EllipticCurveScalar &a, const ge_p3 &A, const EllipticCurveScalar &b, const ge_dsmp &B) {
	ge_p3 tmp3;
	ge_double_scalarmult_precomp_vartime3(&tmp3, &a, &A, &b, &B);
	return tmp3;
}

inline bool ge_dsm_frombytes_vartime(ge_dsmp *image_dsm, const EllipticCurvePoint &image) {
	ge_p3 image_p3;
	if (ge_frombytes_vartime(&image_p3, &image) != 0)
		return false;
	ge_dsm_precomp(image_dsm, &image_p3);
	return true;
}
inline ge_p1p1 ge_mul8(const ge_p3 &p3) {
	ge_p1p1 p1;
	ge_mul8(&p1, &p3);
	return p1;
}
inline ge_p1p1 ge_mul8_p2(const ge_p2 &p2) {
	ge_p1p1 p1;
	ge_mul8_p2(&p1, &p2);
	return p1;
}

inline ge_p2 ge_p1p1_to_p2(const ge_p1p1 &p1) {
	ge_p2 p2;
	ge_p1p1_to_p2(&p2, &p1);
	return p2;
}

inline ge_p3 ge_p1p1_to_p3(const ge_p1p1 &p1) {
	ge_p3 p3;
	ge_p1p1_to_p3(&p3, &p1);
	return p3;
}

inline ge_p2 ge_p3_to_p2(const ge_p3 &p3) {
	ge_p2 p2;
	ge_p3_to_p2(&p2, &p3);
	return p2;
}

inline ge_cached ge_p3_to_cached(const ge_p3 &p3) {
	ge_cached ca;
	ge_p3_to_cached(&ca, &p3);
	return ca;
}

inline ge_p3 bytes_to_good_point_p3(const Hash &h) {
	ge_p2 point_p2;
	ge_fromfe_frombytes_vartime(&point_p2, h.data);
	return ge_p1p1_to_p3(ge_mul8_p2(point_p2));
}

inline ge_p3 hash_to_good_point_p3(const void *data, size_t length) {
	const Hash h = cn_fast_hash(data, length);
	return bytes_to_good_point_p3(h);
}

inline ge_p3 hash_to_good_point_p3(const EllipticCurvePoint &key) {
	return hash_to_good_point_p3(key.data, sizeof(key.data));
}

inline ge_p3 ge_add(const ge_p3 &a, const ge_p3 &b) {
	ge_cached b_cached = ge_p3_to_cached(b);
	ge_p1p1 result;
	ge_add(&result, &a, &b_cached);
	return ge_p1p1_to_p3(result);
}

inline ge_p3 ge_sub(const ge_p3 &a, const ge_p3 &b) {
	ge_cached b_cached = ge_p3_to_cached(b);
	ge_p1p1 result;
	ge_sub(&result, &a, &b_cached);
	return ge_p1p1_to_p3(result);
}

void generate_ring_signature_amethyst_loop1(size_t i, const P3 &image_p3, const P3 &p_p3, const P3 &G_plus_B_p3,
    size_t sec_index, const std::vector<PublicKey> &pubs, std::vector<EllipticCurveScalar> *rr, EllipticCurvePoint *y,
    EllipticCurvePoint *z, const Hash *random_seed = nullptr);

void generate_ring_signature_amethyst_loop2(size_t i, const P3 &image_p3, const P3 &p_p3, const P3 &G_plus_B_p3,
    size_t sec_index, const std::vector<PublicKey> &pubs, std::vector<EllipticCurveScalar> *rr,
    EllipticCurveScalar *next_c, const Hash *random_seed = nullptr);

}  // namespace crypto
