// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "bernstein/crypto-ops.h"
#include "crypto.hpp"
#include "hash.hpp"

// Experimental helpers that allow to write normal a = b * c + d

namespace crypto {

struct P3MulResult {
	const ge_p3 &p3;
	const EllipticCurveScalar &s;
};
struct P3MulResultG {
	const EllipticCurveScalar &s;
};

struct G3_type {};

struct P3 {
	ge_p3 p3;

	constexpr P3() : p3{{0}, {1, 0}, {1, 0}, {0}} {  // identity point
	}
	constexpr P3(const ge_p3 &other) : p3(other) {}
	P3(const G3_type &other);
	explicit P3(const EllipticCurvePoint &other) {
		if (ge_frombytes_vartime(&p3, &other) != 0)
			throw Error("Public Key Invalid");
	}
	P3(const P3MulResult &other) { ge_scalarmult3(&p3, &other.s, &other.p3); }
	P3(const P3MulResultG &other) { ge_scalarmult_base(&p3, &other.s); }
	bool frombytes_vartime(const EllipticCurvePoint &other);
	bool in_main_subgroup() const;
	P3 mul8() const;
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

#if crypto_CRYPTO128
constexpr G3_type G{};
constexpr P3 I{ge_p3{{0}, {1, 0}, {1, 0}, {0}}};
constexpr P3 H{ge_p3{{1238364572342387, 511019468147982, 2037248038744755, 1790205373038460, 1715834670489604},
    {342040195458443, 1746005628638707, 1484107488641719, 1009716338237674, 354016121901985}, {1, 0, 0, 0, 0},
    {1908846832760925, 1960202731132578, 1264573804519519, 220054133280410, 1751608742250222}}};
constexpr P3 G_p3{ge_p3{{1738742601995546, 1146398526822698, 2070867633025821, 562264141797630, 587772402128613},
    {1801439850948184, 1351079888211148, 450359962737049, 900719925474099, 1801439850948198}, {1, 0, 0, 0, 0},
    {1841354044333475, 16398895984059, 755974180946558, 900171276175154, 1821297809914039}}};
#else
constexpr G3_type G{};
constexpr P3 I{ge_p3{{0}, {1, 0}, {1, 0}, {0}}};
constexpr P3 H{ge_p3{{7329926, -15101362, 31411471, 7614783, 27996851, -3197071, -11157635, -6878293, 466949, -7986503},
    {5858699, 5096796, 21321203, -7536921, -5553480, -11439507, -5627669, 15045946, 19977121, 5275251},
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {23443568, -5110398, -8776029, -4345135, 6889568, -14710814, 7474843, 3279062, 14550766, -7453428}}};
constexpr P3 G_p3{
    ge_p3{{-14297830, -7645148, 16144683, -16471763, 27570974, -2696100, -26142465, 8378389, 20764389, 8758491},
        {-26843541, -6710886, 13421773, -13421773, 26843546, 6710886, -13421773, 13421773, -26843546, -6710886},
        {1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {28827062, -6116119, -27349572, 244363, 8635006, 11264893, 19351346, 13413597, 16611511, -6414980}}};
#endif

inline P3::P3(const G3_type &other) : p3(G_p3.p3) {}  // here, due to order of definitions

inline P3 &operator*=(P3 &point_base, const EllipticCurveScalar &sec) {
	point_base = P3MulResult{point_base.p3, sec};
	return point_base;
}
inline P3MulResultG operator*(const G3_type &, const EllipticCurveScalar &sec) { return P3MulResultG{sec}; }
inline P3MulResultG operator*(const EllipticCurveScalar &sec, const G3_type &) { return P3MulResultG{sec}; }

inline P3MulResult operator*(const P3 &point_base, const EllipticCurveScalar &sec) {
	return P3MulResult{point_base.p3, sec};
}
inline P3MulResult operator*(const EllipticCurveScalar &sec, const P3 &point_base) {
	return P3MulResult{point_base.p3, sec};
}
P3 operator-(const P3 &a, const P3 &b);
inline P3 &operator-=(P3 &a, const P3 &b) {
	a = a - b;
	return a;
}
P3 operator+(const P3 &a, const P3 &b);
inline P3 &operator+=(P3 &a, const P3 &b) {
	a = a + b;
	return a;
}
// + is fixed time by default
inline P3 operator+(const P3MulResult &r1, const P3MulResult &r2) { return P3(r1) + P3(r2); }
inline P3 operator+(const P3MulResultG &r1, const P3MulResult &r2) { return P3(r1) + P3(r2); }
inline P3 operator+(const P3MulResult &r1, const P3MulResultG &r2) { return r2 + r1; }

inline P3 vartime_add(const P3MulResult &r1, const P3MulResult &r2) {
	ge_dsmp dsm;
	ge_dsm_precomp(&dsm, &r2.p3);
	P3 res_p3;
	ge_double_scalarmult_precomp_vartime3(&res_p3.p3, &r1.s, &r1.p3, &r2.s, &dsm);
	return res_p3;
}
inline P3 vartime_add(const P3MulResultG &r1, const P3MulResult &r2) {
	P3 res_p3;
	ge_double_scalarmult_base_vartime3(&res_p3.p3, &r2.s, &r2.p3, &r1.s);
	return res_p3;
}
inline P3 vartime_add(const P3MulResult &r1, const P3MulResultG &r2) { return r2 + r1; }

struct ScalarMulResult {
	const EllipticCurveScalar &a;
	const EllipticCurveScalar &b;
	operator SecretKey() {
		SecretKey result;
		sc_mul(&result, &a, &b);
		return result;
	}
};
inline ScalarMulResult operator*(const EllipticCurveScalar &a, const EllipticCurveScalar &b) {
	return ScalarMulResult{a, b};
}
inline EllipticCurveScalar &operator*=(EllipticCurveScalar &a, const EllipticCurveScalar &b) {
	a = ScalarMulResult{a, b};
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

PublicKey get_G();  // slow, for reference only
PublicKey get_H();  // slow, for reference only

inline SecretKey sc_invert(const EllipticCurveScalar &sec) {
	SecretKey result;
	sc_invert(&result, &sec);
	return result;
}

inline void check_scalar(const EllipticCurveScalar &scalar) {
	if (!sc_isvalid_vartime(&scalar))
		throw Error("Secret Key Invalid");
}

P3 bytes_to_good_point_p3(const Hash &h);

inline P3 hash_to_good_point_p3(const void *data, size_t length) {
	return bytes_to_good_point_p3(cn_fast_hash(data, length));
}

inline P3 hash_to_good_point_p3(const EllipticCurvePoint &key) {
	return hash_to_good_point_p3(key.data, sizeof(key.data));
}

void generate_ring_signature_amethyst_loop1(size_t i, const P3 &image_p3, const P3 &p_p3, const P3 &G_plus_B_p3,
    size_t sec_index, const std::vector<PublicKey> &pubs, std::vector<EllipticCurveScalar> *rr, EllipticCurvePoint *y,
    EllipticCurvePoint *z, const Hash *random_seed = nullptr);

void generate_ring_signature_amethyst_loop2(size_t i, const P3 &image_p3, const P3 &p_p3, const P3 &G_plus_B_p3,
    size_t sec_index, const std::vector<PublicKey> &pubs, std::vector<EllipticCurveScalar> *rr,
    EllipticCurveScalar *next_c, const Hash *random_seed = nullptr);

}  // namespace crypto
