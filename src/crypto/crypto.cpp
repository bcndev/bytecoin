// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>

#include "crypto-ops.h"
#include "crypto.hpp"
#include "hash.hpp"
#include "random.h"

namespace crypto {

static std::mutex random_lock;

void generate_random_bytes(size_t n, void *result) {
	std::lock_guard<std::mutex> lock(random_lock);
	unsafe_generate_random_bytes(n, result);
}

// - potentially optimize by acquireing lock once
void random_scalar(EllipticCurveScalar &res) {
	unsigned char tmp[64];
	generate_random_bytes(64, tmp);
	sc_reduce(&res, tmp);
}

void hash_to_scalar(const void *data, size_t length, EllipticCurveScalar &res) {
	Hash h = cn_fast_hash(data, length);
	sc_reduce32(&res, h.data);
}

void random_keypair(PublicKey &pub, SecretKey &sec) {
	ge_p3 point;
	random_scalar(sec);
	ge_scalarmult_base(&point, &sec);
	ge_p3_tobytes(&pub, &point);
}
bool key_isvalid(const PublicKey &key) {
	ge_p3 point;
	return ge_frombytes_vartime(&point, &key) == 0;
}
bool keys_match(const SecretKey &secret_key, const PublicKey &expected_public_key) {
	PublicKey pub;
	bool r = secret_key_to_public_key(secret_key, pub);
	return r && expected_public_key == pub;
}
bool secret_key_to_public_key(const SecretKey &sec, PublicKey &pub) {
	ge_p3 point;
	if (!sc_isvalid_vartime(&sec)) {
		return false;
	}
	ge_scalarmult_base(&point, &sec);
	ge_p3_tobytes(&pub, &point);
	return true;
}

bool generate_key_derivation(const PublicKey &key1, const SecretKey &key2, KeyDerivation &derivation) {
	ge_p3 point;
	ge_p2 point2;
	ge_p1p1 point3;
	assert(sc_isvalid_vartime(&key2));
	if (ge_frombytes_vartime(&point, &key1) != 0) {
		return false;
	}
	ge_scalarmult(&point2, &key2, &point);
	ge_mul8(&point3, &point2);
	ge_p1p1_to_p2(&point2, &point3);
	ge_tobytes(&derivation, &point2);
	return true;
}

// template<typename OutputIt, typename T>
// typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, void>::type
static void write_varint(uint8_t *&dest, size_t i) {
	while (i >= 0x80) {
		*dest++ = (static_cast<uint8_t>(i) & 0x7f) | 0x80;
		i >>= 7;
	}
	*dest++ = static_cast<uint8_t>(i);
}
static void derivation_to_scalar(const KeyDerivation &derivation, size_t output_index, EllipticCurveScalar &res) {
	struct {
		KeyDerivation derivation;
		uint8_t output_index[(sizeof(size_t) * 8 + 6) / 7];
	} buf;
	uint8_t *end   = buf.output_index;
	buf.derivation = derivation;
	write_varint(end, output_index);
	assert(end <= buf.output_index + sizeof buf.output_index);
	hash_to_scalar(&buf, end - reinterpret_cast<uint8_t *>(&buf), res);
}

static void derivation_to_scalar(const KeyDerivation &derivation, size_t output_index, const uint8_t *suffix,
    size_t suffix_length, EllipticCurveScalar &res) {
	assert(suffix_length <= 32);
	struct {
		KeyDerivation derivation;
		uint8_t output_index[(sizeof(size_t) * 8 + 6) / 7 + 32];
	} buf;
	uint8_t *end   = buf.output_index;
	buf.derivation = derivation;
	write_varint(end, output_index);
	assert(end <= buf.output_index + sizeof buf.output_index);
	size_t buf_size = end - reinterpret_cast<uint8_t *>(&buf);
	memcpy(end, suffix, suffix_length);
	hash_to_scalar(&buf, buf_size + suffix_length, res);
}

bool derive_public_key(
    const KeyDerivation &derivation, size_t output_index, const PublicKey &base, PublicKey &derived_key) {
	EllipticCurveScalar scalar;
	ge_p3 point1;
	ge_p3 point2;
	ge_cached point3;
	ge_p1p1 point4;
	ge_p2 point5;
	if (ge_frombytes_vartime(&point1, &base) != 0) {
		return false;
	}
	derivation_to_scalar(derivation, output_index, scalar);
	ge_scalarmult_base(&point2, &scalar);
	ge_p3_to_cached(&point3, &point2);
	ge_add(&point4, &point1, &point3);
	ge_p1p1_to_p2(&point5, &point4);
	ge_tobytes(&derived_key, &point5);
	return true;
}

bool derive_public_key(const KeyDerivation &derivation, size_t output_index, const PublicKey &base,
    const uint8_t *suffix, size_t suffix_length, PublicKey &derived_key) {
	EllipticCurveScalar scalar;
	ge_p3 point1;
	ge_p3 point2;
	ge_cached point3;
	ge_p1p1 point4;
	ge_p2 point5;
	if (ge_frombytes_vartime(&point1, &base) != 0) {
		return false;
	}
	derivation_to_scalar(derivation, output_index, suffix, suffix_length, scalar);
	ge_scalarmult_base(&point2, &scalar);
	ge_p3_to_cached(&point3, &point2);
	ge_add(&point4, &point1, &point3);
	ge_p1p1_to_p2(&point5, &point4);
	ge_tobytes(&derived_key, &point5);
	return true;
}

bool underive_public_key_and_get_scalar(const KeyDerivation &derivation, size_t output_index,
    const PublicKey &derived_key, PublicKey &base, EllipticCurveScalar &hashed_derivation) {
	ge_p3 point1;
	ge_p3 point2;
	ge_cached point3;
	ge_p1p1 point4;
	ge_p2 point5;
	if (ge_frombytes_vartime(&point1, &derived_key) != 0) {
		return false;
	}
	derivation_to_scalar(derivation, output_index, hashed_derivation);
	ge_scalarmult_base(&point2, &hashed_derivation);
	ge_p3_to_cached(&point3, &point2);
	ge_sub(&point4, &point1, &point3);
	ge_p1p1_to_p2(&point5, &point4);
	ge_tobytes(&base, &point5);
	return true;
}

void derive_secret_key(
    const KeyDerivation &derivation, size_t output_index, const SecretKey &base, SecretKey &derived_key) {
	EllipticCurveScalar scalar;
	assert(sc_isvalid_vartime(&base));
	derivation_to_scalar(derivation, output_index, scalar);
	sc_add(&derived_key, &base, &scalar);
}

void derive_secret_key(const KeyDerivation &derivation, size_t output_index, const SecretKey &base,
    const uint8_t *suffix, size_t suffix_length, SecretKey &derived_key) {
	EllipticCurveScalar scalar;
	assert(sc_isvalid_vartime(&base));
	derivation_to_scalar(derivation, output_index, suffix, suffix_length, scalar);
	sc_add(&derived_key, &base, &scalar);
}

bool underive_public_key(
    const KeyDerivation &derivation, size_t output_index, const PublicKey &derived_key, PublicKey &base) {
	EllipticCurveScalar scalar;
	ge_p3 point1;
	ge_p3 point2;
	ge_cached point3;
	ge_p1p1 point4;
	ge_p2 point5;
	if (ge_frombytes_vartime(&point1, &derived_key) != 0) {
		return false;
	}
	derivation_to_scalar(derivation, output_index, scalar);
	ge_scalarmult_base(&point2, &scalar);
	ge_p3_to_cached(&point3, &point2);
	ge_sub(&point4, &point1, &point3);
	ge_p1p1_to_p2(&point5, &point4);
	ge_tobytes(&base, &point5);
	return true;
}

bool underive_public_key(const KeyDerivation &derivation, size_t output_index, const PublicKey &derived_key,
    const uint8_t *suffix, size_t suffix_length, PublicKey &base) {
	EllipticCurveScalar scalar;
	ge_p3 point1;
	ge_p3 point2;
	ge_cached point3;
	ge_p1p1 point4;
	ge_p2 point5;
	if (ge_frombytes_vartime(&point1, &derived_key) != 0) {
		return false;
	}

	derivation_to_scalar(derivation, output_index, suffix, suffix_length, scalar);
	ge_scalarmult_base(&point2, &scalar);
	ge_p3_to_cached(&point3, &point2);
	ge_sub(&point4, &point1, &point3);
	ge_p1p1_to_p2(&point5, &point4);
	ge_tobytes(&base, &point5);
	return true;
}

#pragma pack(push, 1)
struct s_comm {
	Hash h;
	EllipticCurvePoint key;
	EllipticCurvePoint comm;
};
#pragma pack(pop)
static_assert(sizeof(s_comm) == 96, "Layout of s_comm structure is wrong");

void generate_signature(const Hash &prefix_hash, const PublicKey &pub, const SecretKey &sec, Signature &sig) {
	ge_p3 tmp3;
	EllipticCurveScalar k;
	s_comm buf;
#if !defined(NDEBUG)
	{
		ge_p3 t;
		PublicKey t2;
		assert(sc_isvalid_vartime(&sec));
		ge_scalarmult_base(&t, &sec);
		ge_p3_tobytes(&t2, &t);
		assert(pub == t2);
	}
#endif
	buf.h   = prefix_hash;
	buf.key = static_cast<const EllipticCurvePoint &>(pub);
	random_scalar(k);
	ge_scalarmult_base(&tmp3, &k);
	ge_p3_tobytes(&buf.comm, &tmp3);
	hash_to_scalar(&buf, sizeof(s_comm), sig.c);
	sc_mulsub(&sig.r, &sig.c, &sec, &k);
}

bool check_signature(const Hash &prefix_hash, const PublicKey &pub, const Signature &sig, bool *key_corrupted) {
	if (key_corrupted)
		*key_corrupted = false;
	ge_p2 tmp2;
	ge_p3 tmp3;
	EllipticCurveScalar c;
	s_comm buf;
	buf.h   = prefix_hash;
	buf.key = static_cast<const EllipticCurvePoint &>(pub);
	if (ge_frombytes_vartime(&tmp3, &pub) != 0) {
		if (key_corrupted)
			*key_corrupted = true;
		assert(false);
		return false;
	}
	if (!sc_isvalid_vartime(&sig.c) || !sc_isvalid_vartime(&sig.r)) {
		return false;
	}
	ge_double_scalarmult_base_vartime(&tmp2, &sig.c, &tmp3, &sig.r);
	ge_tobytes(&buf.comm, &tmp2);
	hash_to_scalar(&buf, sizeof(s_comm), c);
	sc_sub(&c, &c, &sig.c);
	return sc_iszero(&c);
}

static void hash_to_ec(const PublicKey &key, ge_p3 &res) {
	ge_p2 point;
	ge_p1p1 point2;
	Hash h = cn_fast_hash(&key, sizeof(PublicKey));
	ge_fromfe_frombytes_vartime(&point, h.data);
	ge_mul8(&point2, &point);
	ge_p1p1_to_p3(&res, &point2);
}
void hash_to_point_for_tests(const Hash &h, EllipticCurvePoint &res) {
	ge_p2 point;
	ge_fromfe_frombytes_vartime(&point, h.data);
	ge_tobytes(&res, &point);
}
void hash_to_ec(const PublicKey &key, EllipticCurvePoint &res) {
	ge_p3 tmp;
	hash_to_ec(key, tmp);
	ge_p3_tobytes(&res, &tmp);
}
/*void hash_data_to_ec(const uint8_t* data, std::size_t len, EllipticCurvePoint & key) {
    ge_p2 point;
    ge_p1p1 point2;
    Hash h = cn_fast_hash(data, len);
    ge_fromfe_frombytes_vartime(&point, h.data);
    ge_mul8(&point2, &point);
    ge_p1p1_to_p2(&point, &point2);
    ge_tobytes(&key, &point);
}*/

void generate_key_image(const PublicKey &pub, const SecretKey &sec, KeyImage &image) {
	ge_p3 point;
	ge_p2 point2;
	assert(sc_isvalid_vartime(&sec));
	hash_to_ec(pub, point);
	ge_scalarmult(&point2, &sec, &point);
	ge_tobytes(&image, &point2);
}

// void generate_incomplete_key_image(const PublicKey &pub, EllipticCurvePoint &incomplete_key_image) {
//	ge_p3 point;
//	hash_to_ec(pub, point);
//	ge_p3_tobytes(&incomplete_key_image, &point);
//}

#pragma pack(push, 1)
struct rs_comm {
	Hash h;
	struct {
		EllipticCurvePoint a, b;
	} ab[1];  // This structure is never instantiated, so instead of [0] we use standard-compliant [1]
};
#pragma pack(pop)

static size_t rs_comm_size(size_t pubs_count) { return sizeof(Hash) + pubs_count * 2 * sizeof(EllipticCurvePoint); }

bool generate_ring_signature(const Hash &prefix_hash, const KeyImage &image, const PublicKey *const pubs[],
    size_t pubs_count, const SecretKey &sec, size_t sec_index, Signature sigs[]) {
	if (sec_index >= pubs_count)
		return false;
	ge_p3 image_unp;
	ge_dsmp image_pre;
	EllipticCurveScalar sum, k, h;
	const size_t buf_size = rs_comm_size(pubs_count);
	rs_comm *const buf    = reinterpret_cast<rs_comm *>(alloca(buf_size));
#if !defined(NDEBUG)
	{
		ge_p3 t;
		PublicKey t2;
		KeyImage t3;
		assert(sc_isvalid_vartime(&sec));
		ge_scalarmult_base(&t, &sec);
		ge_p3_tobytes(&t2, &t);
		assert(*pubs[sec_index] == t2);
		generate_key_image(*pubs[sec_index], sec, t3);
		assert(image == t3);
	}
#endif
	if (ge_frombytes_vartime(&image_unp, &image) != 0) {
		return false;
	}
	ge_dsm_precomp(image_pre, &image_unp);
	sc_0(&sum);
	buf->h = prefix_hash;
	for (size_t i = 0; i < pubs_count; i++) {
		ge_p2 tmp2;
		ge_p3 tmp3;
		if (i == sec_index) {
			random_scalar(k);
			ge_scalarmult_base(&tmp3, &k);
			ge_p3_tobytes(&buf->ab[i].a, &tmp3);
			hash_to_ec(*pubs[i], tmp3);
			ge_scalarmult(&tmp2, &k, &tmp3);
			ge_tobytes(&buf->ab[i].b, &tmp2);
		} else {
			random_scalar(sigs[i].c);
			random_scalar(sigs[i].r);
			if (ge_frombytes_vartime(&tmp3, pubs[i]) != 0) {
				assert(false);
				return false;
			}
			ge_double_scalarmult_base_vartime(&tmp2, &sigs[i].c, &tmp3, &sigs[i].r);
			ge_tobytes(&buf->ab[i].a, &tmp2);
			hash_to_ec(*pubs[i], tmp3);
			ge_double_scalarmult_precomp_vartime(&tmp2, &sigs[i].r, &tmp3, &sigs[i].c, image_pre);
			ge_tobytes(&buf->ab[i].b, &tmp2);
			sc_add(&sum, &sum, &sigs[i].c);
		}
	}
	hash_to_scalar(buf, buf_size, h);
	sc_sub(&sigs[sec_index].c, &h, &sum);
	sc_mulsub(&sigs[sec_index].r, &sigs[sec_index].c, &sec, &k);
	return true;
}

bool check_ring_signature(const Hash &prefix_hash, const KeyImage &image, const PublicKey *const pubs[],
    size_t pubs_count, const Signature sigs[], bool check_key_image, bool *key_corrupted) {
	if (key_corrupted)
		*key_corrupted = false;
	ge_p3 image_unp;
	ge_dsmp image_pre;
	EllipticCurveScalar sum, h;
	const size_t buf_size = rs_comm_size(pubs_count);
	rs_comm *const buf    = reinterpret_cast<rs_comm *>(alloca(buf_size));
	if (ge_frombytes_vartime(&image_unp, &image) != 0) {
		return false;
	}
	ge_dsm_precomp(image_pre, &image_unp);
	if (check_key_image && ge_check_subgroup_precomp_vartime(image_pre) != 0) {
		// Example of key_images that fail subgroup check
		// c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
		// c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
		// 0000000000000000000000000000000000000000000000000000000000000080
		// 0000000000000000000000000000000000000000000000000000000000000000
		// 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
		// 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
		// ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
		return false;
	}
	sc_0(&sum);
	buf->h = prefix_hash;
	for (size_t i = 0; i < pubs_count; i++) {
		ge_p2 tmp2;
		ge_p3 tmp3;
		if (!sc_isvalid_vartime(&sigs[i].c) || !sc_isvalid_vartime(&sigs[i].r)) {
			return false;
		}
		if (ge_frombytes_vartime(&tmp3, pubs[i]) != 0) {
			if (key_corrupted)
				*key_corrupted = true;
			assert(false);
			return false;
		}
		ge_double_scalarmult_base_vartime(&tmp2, &sigs[i].c, &tmp3, &sigs[i].r);
		ge_tobytes(&buf->ab[i].a, &tmp2);
		hash_to_ec(*pubs[i], tmp3);
		ge_double_scalarmult_precomp_vartime(&tmp2, &sigs[i].r, &tmp3, &sigs[i].c, image_pre);
		ge_tobytes(&buf->ab[i].b, &tmp2);
		sc_add(&sum, &sum, &sigs[i].c);
	}
	hash_to_scalar(buf, buf_size, h);
	sc_sub(&h, &h, &sum);
	return sc_iszero(&h);
}

#pragma pack(push, 1)
struct sp_comm {
	Hash message_hash;
	PublicKey txkey, receiver_view_key;
	KeyDerivation derivation;
	EllipticCurvePoint a, b;
};
#pragma pack(pop)
static_assert(sizeof(sp_comm) == 192, "Layout of sp_comm structure is wrong");

bool generate_sendproof(const PublicKey &txkey_pub, const SecretKey &txkey_sec, const PublicKey &receiver_view_key_pub,
    const KeyDerivation &derivation, const Hash &message_hash, Signature &proof) {
	ge_p1p1 tmp1;
	ge_p2 tmp2;
	ge_p3 tmp3;
	EllipticCurveScalar k;
	sp_comm comm;
	if (ge_frombytes_vartime(&tmp3, &receiver_view_key_pub) != 0) {
		return false;
	}
	comm.message_hash      = message_hash;
	comm.txkey             = txkey_pub;
	comm.receiver_view_key = receiver_view_key_pub;
	comm.derivation        = derivation;
	random_scalar(k);
	ge_scalarmult(&tmp2, &k, &tmp3);
	ge_scalarmult_base(&tmp3, &k);
	ge_p3_tobytes(&comm.a, &tmp3);
	ge_mul8(&tmp1, &tmp2);
	ge_p1p1_to_p2(&tmp2, &tmp1);
	ge_tobytes(&comm.b, &tmp2);
	hash_to_scalar(&comm, sizeof(sp_comm), proof.c);
	sc_mulsub(&proof.r, &proof.c, &txkey_sec, &k);
	return true;
}

bool check_sendproof(const PublicKey &txkey_pub, const PublicKey &receiver_view_key_pub,
    const KeyDerivation &derivation, const Hash &message_hash, const Signature &proof) {
	ge_p1p1 tmp1;
	ge_p2 tmp2;
	ge_p3 tmp3;
	ge_dsmp dsmp;
	EllipticCurveScalar h;
	sp_comm comm;
	if (!sc_isvalid_vartime(&proof.c) || !sc_isvalid_vartime(&proof.r)) {
		return false;
	}
	comm.message_hash      = message_hash;
	comm.txkey             = txkey_pub;
	comm.receiver_view_key = receiver_view_key_pub;
	comm.derivation        = derivation;
	if (ge_frombytes_vartime(&tmp3, &txkey_pub) != 0) {
		return false;
	}
	ge_double_scalarmult_base_vartime(&tmp2, &proof.c, &tmp3, &proof.r);
	ge_tobytes(&comm.a, &tmp2);
	if (ge_frombytes_vartime(&tmp3, &derivation) != 0) {
		return false;
	}
	ge_dsm_precomp(dsmp, &tmp3);
	if (ge_check_subgroup_precomp_vartime(dsmp) != 0) {
		return false;
	}
	if (ge_frombytes_vartime(&tmp3, &receiver_view_key_pub) != 0) {
		return false;
	}
	ge_p3_to_p2(&tmp2, &tmp3);
	ge_mul8(&tmp1, &tmp2);
	ge_p1p1_to_p3(&tmp3, &tmp1);
	ge_double_scalarmult_precomp_vartime(&tmp2, &proof.r, &tmp3, &proof.c, dsmp);
	ge_tobytes(&comm.b, &tmp2);
	hash_to_scalar(&comm, sizeof(sp_comm), h);
	sc_sub(&h, &h, &proof.c);
	return sc_iszero(&h);
}

static std::string to_hex(const void *data, size_t size) {
	std::string text(size * 2, ' ');
	for (size_t i = 0; i < size; ++i) {
		text[i * 2]     = "0123456789abcdef"[static_cast<const uint8_t *>(data)[i] >> 4];
		text[i * 2 + 1] = "0123456789abcdef"[static_cast<const uint8_t *>(data)[i] & 15];
	}
	return text;
}

std::ostream &operator<<(std::ostream &out, const EllipticCurvePoint &v) {
	return out << to_hex(v.data, sizeof(v.data));
}
std::ostream &operator<<(std::ostream &out, const EllipticCurveScalar &v) {
	return out << to_hex(v.data, sizeof(v.data));
}
std::ostream &operator<<(std::ostream &out, const Hash &v) { return out << to_hex(v.data, sizeof(v.data)); }
}
