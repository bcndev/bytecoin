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

#include "bernstein/crypto-ops.h"
#include "crypto.hpp"
#include "hash.hpp"
#include "random.h"

namespace crypto {

static bool paranoid_checks = false;  // instead of stupid NDEBUG
// Helpers that allow to write normal "x = f(y)" code instead of stupid f(&x, &y)

static SecretKey sc_invert(const EllipticCurveScalar &sec) {
	SecretKey result;
	sc_invert(&result, &sec);
	return result;
}

static ge_p3 ge_scalarmult_base(const EllipticCurveScalar &sec) {
	ge_p3 point;
	ge_scalarmult_base(&point, &sec);
	return point;
}

static PublicKey ge_tobytes(const ge_p3 &point3) {
	PublicKey result;
	ge_p3_tobytes(&result, &point3);
	return result;
}

static PublicKey ge_tobytes(const ge_p2 &point2) {
	PublicKey result;
	ge_tobytes(&result, &point2);
	return result;
}

static void check_scalar(const EllipticCurveScalar &scalar) {
	if (!sc_isvalid_vartime(&scalar))
		throw Error("Secret Key Invalid");
}

static ge_p3 ge_frombytes_vartime(const EllipticCurvePoint &point) {
	ge_p3 result_p3;
	if (ge_frombytes_vartime(&result_p3, &point) != 0)
		throw Error("Public Key Invalid");
	return result_p3;
}

static ge_p2 ge_scalarmult(const EllipticCurveScalar &sec, const ge_p3 &point_base) {
	ge_p2 point2;
	ge_scalarmult(&point2, &sec, &point_base);
	return point2;
}

static ge_p2 ge_double_scalarmult_base_vartime(
    const EllipticCurveScalar &a, const ge_p3 &A, const EllipticCurveScalar &b) {
	ge_p2 tmp2;
	ge_double_scalarmult_base_vartime(&tmp2, &a, &A, &b);
	return tmp2;
}

static ge_p2 ge_double_scalarmult_precomp_vartime(
    const EllipticCurveScalar &a, const ge_p3 &A, const EllipticCurveScalar &b, const ge_dsmp B) {
	ge_p2 tmp2;
	ge_double_scalarmult_precomp_vartime(&tmp2, &a, &A, &b, B);
	return tmp2;
}

static bool ge_dsm_frombytes_vartime(ge_dsmp image_dsm, const EllipticCurvePoint &image) {
	ge_p3 image_p3;
	if (ge_frombytes_vartime(&image_p3, &image) != 0)
		return false;
	ge_dsm_precomp(image_dsm, &image_p3);
	return true;
}
static ge_p1p1 ge_mul8(const ge_p2 &p2) {
	ge_p1p1 p1;
	ge_mul8(&p1, &p2);
	return p1;
}

static ge_p2 ge_p1p1_to_p2(const ge_p1p1 &p1) {
	ge_p2 p2;
	ge_p1p1_to_p2(&p2, &p1);
	return p2;
}

static ge_p3 ge_p1p1_to_p3(const ge_p1p1 &p1) {
	ge_p3 p3;
	ge_p1p1_to_p3(&p3, &p1);
	return p3;
}

static ge_p2 ge_p3_to_p2(const ge_p3 &p3) {
	ge_p2 p2;
	ge_p3_to_p2(&p2, &p3);
	return p2;
}
ge_cached ge_p3_to_cached(const ge_p3 &p3) {
	ge_cached ca;
	ge_p3_to_cached(&ca, &p3);
	return ca;
}

// Integer parameters of all funs in crypto.cpp are size_t
enum { max_varint_size = (std::numeric_limits<size_t>::digits + 6) / 7 };

struct MiniBuffer {
	MiniBuffer(uint8_t *buf, size_t max_size) : buf(buf), max_size(max_size) {}
	uint8_t *const buf;
	const size_t max_size;
	size_t pos = 0;
	void check_overflow(size_t size) {
		if (pos + size > max_size)
			throw Error("FixedBuffer overflow");
	}
	void append(const void *ptr, size_t size) {
		check_overflow(size);
		memcpy(buf + pos, ptr, size);
		pos += size;
	}
	template<size_t S>
	void append(const char (&h)[S]) {
		append(h, S - 1);
	}
	void append(const Hash &h) { append(h.data, sizeof(h.data)); }
	void append(const EllipticCurvePoint &h) { append(h.data, sizeof(h.data)); }
	void append(const EllipticCurveScalar &h) { append(h.data, sizeof(h.data)); }
	void append(size_t i) {  // varint
		check_overflow(max_varint_size);
		for (; i >= 0x80; i >>= 7)
			buf[pos++] = static_cast<uint8_t>((i & 0x7f) | 0x80);
		buf[pos++] = static_cast<uint8_t>(i);
		check_overflow(0);  // cheap paranoid check
	}
	SecretKey hash_to_scalar() const { return crypto::hash_to_scalar(buf, pos); }
	SecretKey hash_to_scalar64() const { return crypto::hash_to_scalar64(buf, pos); }
};

template<size_t S>
struct FixedBuffer : MiniBuffer {
	uint8_t space[S]{};
	FixedBuffer() : MiniBuffer{space, S} {}
};

static std::mutex random_lock;

void generate_random_bytes(void *result, size_t n) {
	std::lock_guard<std::mutex> lock(random_lock);
	crypto_unsafe_generate_random_bytes(result, n);
}

// - potentially optimize by acquiring lock once
SecretKey random_scalar() {
	uint8_t tmp[64]{};
	generate_random_bytes(tmp, sizeof(tmp));
	SecretKey result;
	sc_reduce(&result, tmp);
	return result;
}

SecretKey hash_to_scalar(const void *data, size_t length) {
	Hash h = cn_fast_hash(data, length);
	SecretKey result;
	sc_reduce32(&result, h.data);
	return result;
}

SecretKey hash_to_scalar64(const void *data, size_t length) {
	uint8_t buf[64]{};
	crypto_cn_fast_hash64(data, length, buf);
	SecretKey result;
	sc_reduce(&result, buf);
	return result;
}

void random_keypair(PublicKey &pub, SecretKey &sec) {
	sec = random_scalar();
	pub = ge_tobytes(ge_scalarmult_base(sec));
}

bool key_isvalid(const PublicKey &key) {
	ge_p3 point;
	return ge_frombytes_vartime(&point, &key) == 0;
}

bool keys_match(const SecretKey &secret_key, const PublicKey &expected_public_key) {
	PublicKey pub;
	bool r = secret_key_to_public_key(secret_key, &pub);
	return r && expected_public_key == pub;
}

bool secret_key_to_public_key(const SecretKey &sec, PublicKey *pub) {
	if (!sc_isvalid_vartime(&sec))
		return false;
	*pub = ge_tobytes(ge_scalarmult_base(sec));
	return true;
}

KeyDerivation generate_key_derivation(const PublicKey &tx_public_key, const SecretKey &view_secret_key) {
	check_scalar(view_secret_key);
	const ge_p3 tx_public_key_p3 = ge_frombytes_vartime(tx_public_key);
	const ge_p2 point2           = ge_scalarmult(view_secret_key, tx_public_key_p3);
	KeyDerivation derivation;
	static_cast<EllipticCurvePoint &>(derivation) = ge_tobytes(ge_p1p1_to_p2(ge_mul8(point2)));
	return derivation;
}

static SecretKey derivation_to_scalar(const KeyDerivation &derivation, size_t output_index) {
	FixedBuffer<sizeof(KeyDerivation) + max_varint_size> buf;
	buf.append(derivation);
	buf.append(output_index);
	return buf.hash_to_scalar();
}

PublicKey derive_public_key(const KeyDerivation &derivation, size_t output_index, const PublicKey &spend_public_key) {
	const ge_p3 spend_public_key_g3  = ge_frombytes_vartime(spend_public_key);
	const EllipticCurveScalar scalar = derivation_to_scalar(derivation, output_index);
	const ge_cached point3           = ge_p3_to_cached(ge_scalarmult_base(scalar));
	ge_p1p1 point_sum;
	ge_add(&point_sum, &spend_public_key_g3, &point3);
	return ge_tobytes(ge_p1p1_to_p2(point_sum));
}

SecretKey derive_secret_key(const KeyDerivation &derivation, size_t output_index, const SecretKey &spend_secret_key) {
	check_scalar(spend_secret_key);
	const EllipticCurveScalar scalar = derivation_to_scalar(derivation, output_index);
	SecretKey output_secret_key;
	sc_add(&output_secret_key, &spend_secret_key, &scalar);
	return output_secret_key;
}

PublicKey underive_public_key(
    const KeyDerivation &derivation, size_t output_index, const PublicKey &output_public_key) {
	const ge_p3 output_public_key_p3 = ge_frombytes_vartime(output_public_key);
	const EllipticCurveScalar scalar = derivation_to_scalar(derivation, output_index);
	const ge_cached point3           = ge_p3_to_cached(ge_scalarmult_base(scalar));
	ge_p1p1 point_diff;
	ge_sub(&point_diff, &output_public_key_p3, &point3);
	return ge_tobytes(ge_p1p1_to_p2(point_diff));
}

Signature generate_signature(const Hash &prefix_hash, const PublicKey &pub, const SecretKey &sec) {
	if (paranoid_checks && !keys_match(sec, pub))
		throw Error("Keys do not match in generate_signature");
	const EllipticCurveScalar k = random_scalar();

	FixedBuffer<sizeof(Hash) + sizeof(PublicKey) + sizeof(EllipticCurvePoint)> buf;
	buf.append(prefix_hash);
	buf.append(pub);
	buf.append(ge_tobytes(ge_scalarmult_base(k)));

	Signature sig;
	sig.c = buf.hash_to_scalar();
	sc_mulsub(&sig.r, &sig.c, &sec, &k);
	return sig;
}

bool check_signature(const Hash &prefix_hash, const PublicKey &pub, const Signature &sig) {
	if (!sc_isvalid_vartime(&sig.c) || !sc_isvalid_vartime(&sig.r))
		return false;
	const ge_p3 pub_p3 = ge_frombytes_vartime(pub);

	FixedBuffer<sizeof(Hash) + sizeof(PublicKey) + sizeof(EllipticCurvePoint)> buf;
	buf.append(prefix_hash);
	buf.append(pub);
	buf.append(ge_tobytes(ge_double_scalarmult_base_vartime(sig.c, pub_p3, sig.r)));

	EllipticCurveScalar c = buf.hash_to_scalar();
	sc_sub(&c, &c, &sig.c);
	return sc_iszero(&c) != 0;
}

static ge_p3 hash_to_ec_p3(const PublicKey &key) {
	ge_p2 point_p2;
	const Hash h = cn_fast_hash(&key, sizeof(PublicKey));
	ge_fromfe_frombytes_vartime(&point_p2, h.data);
	return ge_p1p1_to_p3(ge_mul8(point_p2));
}

EllipticCurvePoint hash_to_point_for_tests(const Hash &h) {
	ge_p2 point;
	ge_fromfe_frombytes_vartime(&point, h.data);
	return ge_tobytes(point);
}

PublicKey hash_to_ec(const PublicKey &key) { return ge_tobytes(hash_to_ec_p3(key)); }

KeyImage generate_key_image(const PublicKey &pub, const SecretKey &sec) {
	check_scalar(sec);
	const ge_p3 pub_hash_p3 = hash_to_ec_p3(pub);
	KeyImage image;
	static_cast<EllipticCurvePoint &>(image) = ge_tobytes(ge_scalarmult(sec, pub_hash_p3));
	return image;
}

static size_t rs_comm_size(size_t pubs_count) { return sizeof(Hash) + pubs_count * 2 * sizeof(EllipticCurvePoint); }

RingSignature generate_ring_signature(const Hash &prefix_hash, const KeyImage &image, const PublicKey pubs[],
    size_t pubs_count, const SecretKey &sec, size_t sec_index) {
	if (sec_index >= pubs_count)
		throw Error("sec_index >= pubs_count in generate_ring_signature");
	check_scalar(sec);
	RingSignature sig;
	sig.resize(pubs_count);
	if (paranoid_checks && !keys_match(sec, pubs[sec_index]))
		throw Error("Keys do not match in generate_ring_signature");
	if (paranoid_checks && generate_key_image(pubs[sec_index], sec) != image)
		throw Error("Keyimage does not match keys in generate_ring_signature");
	ge_dsmp image_dsm;
	if (!ge_dsm_frombytes_vartime(image_dsm, image))
		throw Error("Keyimage is invalid");
	const size_t buf_size = rs_comm_size(pubs_count);
	MiniBuffer buf(reinterpret_cast<uint8_t *>(alloca(buf_size)), buf_size);
	EllipticCurveScalar sum, k;
	sc_0(&sum);
	buf.append(prefix_hash);
	for (size_t i = 0; i < pubs_count; i++) {
		const ge_p3 hash_pubs_i_p3 = hash_to_ec_p3(pubs[i]);
		if (i == sec_index) {
			k = random_scalar();
			buf.append(ge_tobytes(ge_scalarmult_base(k)));
			buf.append(ge_tobytes(ge_scalarmult(k, hash_pubs_i_p3)));
		} else {
			const ge_p3 pubs_i_p3 = ge_frombytes_vartime(pubs[i]);
			sig[i].c              = random_scalar();
			sig[i].r              = random_scalar();
			buf.append(ge_tobytes(ge_double_scalarmult_base_vartime(sig[i].c, pubs_i_p3, sig[i].r)));
			buf.append(ge_tobytes(ge_double_scalarmult_precomp_vartime(sig[i].r, hash_pubs_i_p3, sig[i].c, image_dsm)));
			sc_add(&sum, &sum, &sig[i].c);
		}
	}
	const EllipticCurveScalar h = buf.hash_to_scalar();
	sc_sub(&sig[sec_index].c, &h, &sum);
	sc_mulsub(&sig[sec_index].r, &sig[sec_index].c, &sec, &k);
	return sig;
}

bool check_ring_signature(const Hash &prefix_hash, const KeyImage &image, const PublicKey pubs[], size_t pubs_count,
    const RingSignature &sig, bool key_image_subgroup_check) {
	ge_dsmp image_dsm;
	if (!ge_dsm_frombytes_vartime(image_dsm, image))
		return false;  // key_image is considered part of signature, we do not throw if it is invalid
	if (key_image_subgroup_check && ge_check_subgroup_precomp_vartime(image_dsm) != 0) {
		// Example of key_images that fail subgroup check
		// c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa (in tx
		// 56da63a36a60cc2151e322528f8685c927fdad9578a5678af8023f87dd27430c)
		// c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a (in tx
		// f5e6754d7859ff4abf7a9733d5852d5ba35a77cab3dff4bb929c626cf1737b5a)
		// 0000000000000000000000000000000000000000000000000000000000000080 (in tx
		// 17320545c428fe7d67ff2c8140eef5c970adfc5eecab978986ac8b4b12a1dd84)
		// 0100000000000000000000000000000000000000000000000000000000000000 (in tx
		// 5a3db49ef69e1f9dd9b740cabea7328cd3499c29fc4f3295bac3fa5e55384626)
		// 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05 (in tx
		// cef289d7fab6e35ac123db8a3f06f7675b48067e0dff185c72b140845b8b3b23)
		// 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85 (in tx
		// 7e418cc77935cc349f007cd5409d2b6908e4130321fa6f97ee0fee64b000ff85)
		// ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f (in tx
		// 74298d301eb4b4da30c06989e0f7ff24a26c90bf4ffc4f2c18f34b7a22cf1136)
		return false;
	}
	const size_t buf_size = rs_comm_size(pubs_count);
	MiniBuffer buf(reinterpret_cast<uint8_t *>(alloca(buf_size)), buf_size);
	EllipticCurveScalar sum;
	sc_0(&sum);
	buf.append(prefix_hash);
	for (size_t i = 0; i < pubs_count; i++) {
		if (!sc_isvalid_vartime(&sig[i].c) || !sc_isvalid_vartime(&sig[i].r))
			return false;
		const ge_p3 pubs_i_p3      = ge_frombytes_vartime(pubs[i]);
		const ge_p3 hash_pubs_i_p3 = hash_to_ec_p3(pubs[i]);

		buf.append(ge_tobytes(ge_double_scalarmult_base_vartime(sig[i].c, pubs_i_p3, sig[i].r)));
		buf.append(ge_tobytes(ge_double_scalarmult_precomp_vartime(sig[i].r, hash_pubs_i_p3, sig[i].c, image_dsm)));
		sc_add(&sum, &sum, &sig[i].c);
	}
	EllipticCurveScalar h = buf.hash_to_scalar();
	sc_sub(&h, &h, &sum);
	return sc_iszero(&h) != 0;
}

RingSignature3 generate_ring_signature3(const Hash &prefix_hash, const std::vector<KeyImage> &images,
    const std::vector<std::vector<PublicKey>> &pubs, const std::vector<SecretKey> &secs,
    const std::vector<size_t> &sec_indexes, const SecretKey &view_secret_key) {
	if (images.empty() || images.size() != pubs.size() || images.size() != secs.size())
		throw Error("inconsistent images/pubs/secs size in generate_ring_signature3");
	RingSignature3 sig;
	sig.r.resize(images.size());
	// std::cout << "generate_ring_signature3" << std::endl;

	const size_t buf_size = sizeof(Hash) + images.size() * 2 * sizeof(EllipticCurvePoint);
	MiniBuffer buf(reinterpret_cast<uint8_t *>(alloca(buf_size)), buf_size);
	buf.append(prefix_hash);
	for (size_t i = 0; i != images.size(); ++i) {
		const size_t sec_index = sec_indexes[i];
		if (pubs[i].empty() || sec_index >= pubs[i].size())
			throw Error("sec_index >= pubs_count in generate_ring_signature3");
		check_scalar(secs[i]);
		if (paranoid_checks && !keys_match(secs[i], pubs[i][sec_index]))
			throw Error("Keys do not match in generate_ring_signature");
		if (paranoid_checks && generate_key_image(pubs[i][sec_index], secs[i]) != images[i])
			throw Error("Keyimage does not match keys in generate_ring_signature");
		ge_dsmp image_dsm;  // TODO - do not unpack image if it is not needed in this loop
		if (!ge_dsm_frombytes_vartime(image_dsm, images[i]))
			throw Error("Keyimage is invalid");
		sig.r[i].resize(pubs[i].size());
		FixedBuffer<sizeof(Hash) + sizeof(SecretKey)> k_buf;
		k_buf.append(prefix_hash);
		k_buf.append(secs.at(i));
		const EllipticCurveScalar k = k_buf.hash_to_scalar64();
		// std::cout << "k[" << i << "]=" << k << std::endl;
		EllipticCurvePoint a = ge_tobytes(ge_scalarmult_base(k));
		// std::cout << "a[" << i << ", " << sec_index[i] << "]=" << a << std::endl;
		const ge_p3 hash_pubs_sec_p3 = hash_to_ec_p3(pubs[i][sec_index]);
		EllipticCurvePoint b         = ge_tobytes(ge_scalarmult(k, hash_pubs_sec_p3));
		// std::cout << "b[" << i << ", " << sec_index[i] << "]=" << b << std::endl;
		for (size_t j = sec_indexes[i] + 1; j < pubs[i].size(); ++j) {
			const ge_p3 pubs_i_p3      = ge_frombytes_vartime(pubs[i][j]);
			const ge_p3 hash_pubs_i_p3 = hash_to_ec_p3(pubs[i][j]);

			EllipticCurveScalar &r = sig.r[i][j];
			FixedBuffer<sizeof(Hash) + sizeof(SecretKey) + 2 * max_varint_size> r_buf;
			r_buf.append(view_secret_key);
			r_buf.append(prefix_hash);
			r_buf.append(i);
			r_buf.append(j);
			r = r_buf.hash_to_scalar64();
			// std::cout << "r[" << i << ", " << j << "]=" << r << std::endl;

			FixedBuffer<sizeof(Hash) + 2 * sizeof(EllipticCurvePoint)> c_buf;
			c_buf.append(prefix_hash);
			c_buf.append(a);
			c_buf.append(b);
			const EllipticCurveScalar c = c_buf.hash_to_scalar();
			// std::cout << "c[" << i << ", " << j << "]=" << c << std::endl;

			a = ge_tobytes(ge_double_scalarmult_base_vartime(c, pubs_i_p3, r));
			b = ge_tobytes(ge_double_scalarmult_precomp_vartime(r, hash_pubs_i_p3, c, image_dsm));
			// std::cout << "a[" << i << ", " << j << "]=" << a << std::endl;
			// std::cout << "b[" << i << ", " << j << "]=" << b << std::endl;
		}
		buf.append(a);
		buf.append(b);
	}
	sig.c0 = buf.hash_to_scalar();
	// std::cout << "c0=" << sigs[0].c0 << std::endl;
	for (size_t i = 0; i != images.size(); ++i) {
		const size_t sec_index = sec_indexes[i];
		ge_dsmp image_dsm;  // TODO - do not unpack image if it is not needed in this loop
		if (!ge_dsm_frombytes_vartime(image_dsm, images[i]))
			throw Error("Keyimage is invalid");
		FixedBuffer<sizeof(Hash) + sizeof(SecretKey)> k_buf;
		k_buf.append(prefix_hash);
		k_buf.append(secs.at(i));
		const EllipticCurveScalar k = k_buf.hash_to_scalar64();
		// std::cout << "k[" << i << "]=" << k << std::endl;
		EllipticCurveScalar next_c = sig.c0;
		for (size_t j = 0; j != sec_index; ++j) {
			const ge_p3 pubs_i_p3      = ge_frombytes_vartime(pubs[i][j]);
			const ge_p3 hash_pubs_i_p3 = hash_to_ec_p3(pubs[i][j]);

			EllipticCurveScalar &r = sig.r[i][j];
			FixedBuffer<2 * sizeof(Hash) + sizeof(KeyImage) + max_varint_size> r_buf;
			r_buf.append(view_secret_key);
			r_buf.append(prefix_hash);
			r_buf.append(i);
			r_buf.append(j);
			r = r_buf.hash_to_scalar64();
			// std::cout << "r[" << i << ", " << j << "]=" << r << std::endl;

			const auto a = ge_tobytes(ge_double_scalarmult_base_vartime(next_c, pubs_i_p3, r));
			const auto b = ge_tobytes(ge_double_scalarmult_precomp_vartime(r, hash_pubs_i_p3, next_c, image_dsm));
			// std::cout << "a[" << i << ", " << j << "]=" << a << std::endl;
			// std::cout << "b[" << i << ", " << j << "]=" << b << std::endl;

			FixedBuffer<sizeof(Hash) + 2 * sizeof(EllipticCurvePoint)> c_buf;
			c_buf.append(prefix_hash);
			c_buf.append(a);
			c_buf.append(b);
			next_c = c_buf.hash_to_scalar();
			// std::cout << "next_c[" << i << ", " << j << "]=" << next_c << std::endl;
		}
		sc_mulsub(&sig.r[i][sec_index], &next_c, &secs[i], &k);
		// std::cout << "r[" << i << ", " << sec_index[i] << "]=" << sigs[i].r[sec_index[i]] << std::endl;
	}
	return sig;
}

bool check_ring_signature3(const Hash &prefix_hash, const std::vector<KeyImage> &images,
    const std::vector<std::vector<PublicKey>> &pubs, const RingSignature3 &sig) {
	if (images.empty() || images.size() != pubs.size() || images.size() != sig.r.size())
		throw Error("inconsistent images/pubs/sigs size in check_ring_signature3");
	// std::cout << "check_ring_signature3" << std::endl;
	const size_t buf_size = sizeof(Hash) + images.size() * 2 * sizeof(EllipticCurvePoint);
	MiniBuffer buf(reinterpret_cast<uint8_t *>(alloca(buf_size)), buf_size);
	buf.append(prefix_hash);
	for (size_t i = 0; i != images.size(); ++i) {
		if (pubs[i].empty() || pubs[i].size() != sig.r[i].size())
			throw Error("inconsistent pubs/sigs size in check_ring_signature3");
		ge_dsmp image_dsm;
		if (!ge_dsm_frombytes_vartime(image_dsm, images[i]))
			return false;  // key_image is considered part of signature, we do not throw if it is invalid
		if (ge_check_subgroup_precomp_vartime(image_dsm) != 0)
			return false;
		auto next_c = sig.c0;
		for (size_t j = 0; j != pubs[i].size(); ++j) {
			// std::cout << "c[" << i << ", " << j << "]=" << next_c << std::endl;
			const ge_p3 pubs_i_p3        = ge_frombytes_vartime(pubs[i][j]);
			const ge_p3 hash_pubs_i_p3   = hash_to_ec_p3(pubs[i][j]);
			const EllipticCurveScalar &r = sig.r[i][j];
			// std::cout << "r[" << i << ", " << j << "]=" << r << std::endl;

			const auto a = ge_tobytes(ge_double_scalarmult_base_vartime(next_c, pubs_i_p3, r));
			const auto b = ge_tobytes(ge_double_scalarmult_precomp_vartime(r, hash_pubs_i_p3, next_c, image_dsm));
			// std::cout << "a[" << i << ", " << j << "]=" << a << std::endl;
			// std::cout << "b[" << i << ", " << j << "]=" << b << std::endl;

			if (j == pubs[i].size() - 1) {
				buf.append(a);
				buf.append(b);
			} else {
				FixedBuffer<sizeof(Hash) + 2 * sizeof(EllipticCurvePoint)> c_buf;
				c_buf.append(prefix_hash);
				c_buf.append(a);
				c_buf.append(b);
				next_c = c_buf.hash_to_scalar();
			}
		}
	}
	auto c = buf.hash_to_scalar();
	sc_sub(&c, &c, &sig.c0);
	return sc_iszero(&c) != 0;
}

size_t find_deterministic_input3(const Hash &prefix_hash, size_t input_index, const std::vector<EllipticCurveScalar> &r,
    const SecretKey &view_secret_key) {
	size_t bad_index = r.size();
	for (size_t i = 0; i < r.size(); i++) {
		FixedBuffer<sizeof(Hash) + sizeof(SecretKey) + 2 * max_varint_size> r_buf;
		r_buf.append(view_secret_key);
		r_buf.append(prefix_hash);
		r_buf.append(input_index);
		r_buf.append(i);
		const SecretKey must_be_r = r_buf.hash_to_scalar64();
		if (must_be_r != r[i]) {
			if (bad_index != r.size())  // second bad index
				return r.size();
			bad_index = i;
		}
	}
	return bad_index;
}

Signature generate_sendproof(const PublicKey &txkey_pub, const SecretKey &txkey_sec,
    const PublicKey &receiver_view_key_pub, const KeyDerivation &derivation, const Hash &message_hash) {
	const ge_p3 receiver_view_key_pub_p3 = ge_frombytes_vartime(receiver_view_key_pub);
	const EllipticCurveScalar k          = random_scalar();
	FixedBuffer<sizeof(Hash) + 2 * sizeof(PublicKey) + sizeof(KeyDerivation) + 2 * sizeof(EllipticCurvePoint)> cr_comm;
	cr_comm.append(message_hash);
	cr_comm.append(txkey_pub);
	cr_comm.append(receiver_view_key_pub);
	cr_comm.append(derivation);
	cr_comm.append(ge_tobytes(ge_scalarmult_base(k)));

	const ge_p2 tmp2 = ge_scalarmult(k, receiver_view_key_pub_p3);
	cr_comm.append(ge_tobytes(ge_p1p1_to_p2(ge_mul8(tmp2))));

	Signature proof;
	proof.c = cr_comm.hash_to_scalar();
	sc_mulsub(&proof.r, &proof.c, &txkey_sec, &k);
	return proof;
}

bool check_sendproof(const PublicKey &txkey_pub, const PublicKey &receiver_view_key_pub,
    const KeyDerivation &derivation, const Hash &message_hash, const Signature &proof) {
	if (!sc_isvalid_vartime(&proof.c) || !sc_isvalid_vartime(&proof.r))
		return false;
	ge_p3 txkey_pub_p3;
	if (ge_frombytes_vartime(&txkey_pub_p3, &txkey_pub) != 0)
		return false;  // tx public keys are not checked by daemon and can be invalid
	const ge_p3 receiver_view_key_pub_g3 = ge_frombytes_vartime(receiver_view_key_pub);  // checked as part of address
	ge_dsmp derivation_dsmp;
	if (!ge_dsm_frombytes_vartime(derivation_dsmp, derivation))
		return false;
	if (ge_check_subgroup_precomp_vartime(derivation_dsmp) != 0)
		return false;
	FixedBuffer<sizeof(Hash) + 2 * sizeof(PublicKey) + sizeof(KeyDerivation) + 2 * sizeof(EllipticCurvePoint)> cr_comm;
	cr_comm.append(message_hash);
	cr_comm.append(txkey_pub);
	cr_comm.append(receiver_view_key_pub);
	cr_comm.append(derivation);
	cr_comm.append(ge_tobytes(ge_double_scalarmult_base_vartime(proof.c, txkey_pub_p3, proof.r)));
	ge_p3 tmp3 = ge_p1p1_to_p3(ge_mul8(ge_p3_to_p2(receiver_view_key_pub_g3)));
	cr_comm.append(ge_tobytes(ge_double_scalarmult_precomp_vartime(proof.r, tmp3, proof.c, derivation_dsmp)));
	EllipticCurveScalar h = cr_comm.hash_to_scalar();
	sc_sub(&h, &h, &proof.c);
	return sc_iszero(&h) != 0;
}

void generate_hd_spendkeys(
    const KeyPair &base, const Hash &keys_generation_seed, size_t index, std::vector<KeyPair> *result) {
	const ge_p3 point_base            = ge_frombytes_vartime(base.public_key);
	const ge_cached point_base_cached = ge_p3_to_cached(point_base);
	for (size_t d = 0; d != result->size(); ++d) {
		KeyPair &res = result->at(d);

		FixedBuffer<sizeof(Hash) + 7 + max_varint_size> cr_comm;
		cr_comm.append(keys_generation_seed);
		cr_comm.append("address");
		cr_comm.append(index + d);
		SecretKey delta_secret_key = cr_comm.hash_to_scalar();
		ge_p3 delta_public_key_g3;
		ge_scalarmult_base(&delta_public_key_g3, &delta_secret_key);

		ge_p1p1 point_sum;
		ge_add(&point_sum, &delta_public_key_g3, &point_base_cached);
		res.public_key = ge_tobytes(ge_p1p1_to_p2(point_sum));

		if (base.secret_key == SecretKey{}) {
			res.secret_key = SecretKey{};
		} else {
			sc_add(&res.secret_key, &delta_secret_key, &base.secret_key);
			if (paranoid_checks && !keys_match(res.secret_key, res.public_key))
				throw Error("Invariant failed dring hd address beneration");
		}
	}
}

PublicKey generate_address_s_v(const PublicKey &spend_public_key, const SecretKey &view_secret_key) {
	const ge_p3 spend_public_key_p3 = ge_frombytes_vartime(spend_public_key);
	check_scalar(view_secret_key);
	return ge_tobytes(ge_scalarmult(view_secret_key, spend_public_key_p3));
}

static_assert(sizeof(PublicKey) == sizeof(Hash), "We are going to XOR them");

// create map s*G -> WalletRecord

// In tx, there is 2 values per output T (encrypted output secret) and P (output public key)

// T = k xor inv(H(k|inputs|#o))*v*s*G
// P = inv(H(k|inputs|#o))*s*G)

// look for our output
// k' = P*v xor T
// lookup H(k'|inputs|#o)*P in map

// if found, then secret output key
// p = inv(H(k|inputs|#o))*s

// send_proof

// q = deterministic(wallet_seed_special_for_k | inputs | #o)
// Q = q*G
// k = Q or H(Q)

// proof of send to address s*G is (Q, txid, message, s*G, v*s*G), signed by q

PublicKey unlinkable_underive_public_key(const SecretKey &view_secret_key, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &output_public_key, const Hash &encrypted_output_secret,
    SecretKey *spend_scalar) {
	check_scalar(view_secret_key);
	// TODO - When passing to ledger, check that no crypto attacks possible
	const ge_p3 output_public_key_p3 = ge_frombytes_vartime(output_public_key);
	const PublicKey p_v              = ge_tobytes(ge_scalarmult(view_secret_key, output_public_key_p3));
	Hash output_secret;
	for (size_t i = 0; i != sizeof(output_secret.data); ++i)
		output_secret.data[i] = p_v.data[i] ^ encrypted_output_secret.data[i];
	FixedBuffer<2 * sizeof(Hash) + max_varint_size> cr_comm;
	cr_comm.append(output_secret);
	cr_comm.append(tx_inputs_hash);
	cr_comm.append(output_index);
	*spend_scalar = cr_comm.hash_to_scalar();
	return ge_tobytes(ge_scalarmult(*spend_scalar, output_public_key_p3));
}

SecretKey unlinkable_derive_secret_key(const SecretKey &spend_secret_key, const SecretKey &spend_scalar) {
	check_scalar(spend_secret_key);
	check_scalar(spend_scalar);
	const SecretKey inv_spend_scalar = sc_invert(spend_scalar);
	SecretKey output_secret_key;
	sc_mul(&output_secret_key, &inv_spend_scalar, &spend_secret_key);
	return output_secret_key;
}

PublicKey unlinkable_derive_public_key(const Hash &output_secret, const Hash &tx_inputs_hash, size_t output_index,
    const PublicKey &spend_public_key, const PublicKey &vs_public_key, Hash *encrypted_output_secret) {
	const ge_p3 spend_public_key_p3 = ge_frombytes_vartime(spend_public_key);
	const ge_p3 vs_public_key_p3    = ge_frombytes_vartime(vs_public_key);

	FixedBuffer<2 * sizeof(Hash) + max_varint_size> cr_comm;
	cr_comm.append(output_secret);
	cr_comm.append(tx_inputs_hash);
	cr_comm.append(output_index);
	const SecretKey spend_scalar     = cr_comm.hash_to_scalar();
	const SecretKey inv_spend_scalar = sc_invert(spend_scalar);
	PublicKey output_public_key      = ge_tobytes(ge_scalarmult(inv_spend_scalar, spend_public_key_p3));
	const PublicKey p_v              = ge_tobytes(ge_scalarmult(inv_spend_scalar, vs_public_key_p3));
	for (size_t i = 0; i != sizeof(output_secret.data); ++i)
		encrypted_output_secret->data[i] = p_v.data[i] ^ output_secret.data[i];
	return output_public_key;
}

bool unlinkable_underive_address(const Hash &output_secret, const Hash &tx_inputs_hash, size_t output_index,
    const PublicKey &output_public_key, const Hash &encrypted_output_secret, PublicKey *spend_public_key,
    PublicKey *vs_public_key) {
	ge_p3 output_public_key_p3;
	if (ge_frombytes_vartime(&output_public_key_p3, &output_public_key) != 0)
		return false;
	FixedBuffer<2 * sizeof(Hash) + max_varint_size> cr_comm;
	cr_comm.append(output_secret);
	cr_comm.append(tx_inputs_hash);
	cr_comm.append(output_index);
	const SecretKey spend_scalar = cr_comm.hash_to_scalar();
	*spend_public_key            = ge_tobytes(ge_scalarmult(spend_scalar, output_public_key_p3));
	PublicKey t;
	for (size_t i = 0; i != sizeof(output_secret.data); ++i)
		t.data[i] = encrypted_output_secret.data[i] ^ output_secret.data[i];
	ge_p3 t_p3;
	if (ge_frombytes_vartime(&t_p3, &t) != 0)
		return false;
	*vs_public_key = ge_tobytes(ge_scalarmult(spend_scalar, t_p3));
	return true;
}

}  // namespace crypto
