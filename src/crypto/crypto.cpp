// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for
// details.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>

#ifndef __EMSCRIPTEN__
#include <mutex>
#endif

#include "bernstein/crypto-ops.h"
#include "crypto.hpp"
#include "crypto_helpers.hpp"
#include "hash.hpp"
#include "random.h"

namespace crypto {

// clang-format off
//#define DEBUG_PRINT(expr) do { expr; } while (0)
#define DEBUG_PRINT(expr)

//#define PARANOID_CHECK(expr, msg) do { if (!(expr)) throw Error(msg); } while (0)
#define PARANOID_CHECK(expr, msg)
// clang-format on

PublicKey get_G() { return to_bytes(G_p3); }  // 5866666666666666666666666666666666666666666666666666666666666666

PublicKey get_H() { return to_bytes(H); }  // 8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94

KeccakStream &KeccakStream::append(size_t i) {  // varint
	enum { max_varint_size = (std::numeric_limits<size_t>::digits + 6) / 7 };
	unsigned char data[max_varint_size];
	unsigned char *p = data;
	for (; i >= 0x80; i >>= 7)
		*p++ = static_cast<uint8_t>((i & 0x7f) | 0x80);
	*p++ = static_cast<uint8_t>(i);
	append(data, p - data);
	return *this;
}

static void append_varint(BinaryArray *ba, size_t i) {
	enum { max_varint_size = (std::numeric_limits<size_t>::digits + 6) / 7 };
	unsigned char data[max_varint_size];
	unsigned char *p = data;
	for (; i >= 0x80; i >>= 7)
		*p++ = static_cast<uint8_t>((i & 0x7f) | 0x80);
	*p++ = static_cast<uint8_t>(i);
	ba->insert(ba->end(), data, p);
}

SecretKey KeccakStream::hash_to_scalar() {
	Hash h = cn_fast_hash();
	return bytes_to_scalar(h);
}

SecretKey KeccakStream::hash_to_scalar64() {
	Hash h = cn_fast_hash();
	crypto_keccak_init(&impl, 256, 1);  // reuse same impl
	crypto_keccak_update(&impl, h.data, sizeof(h.data));
	Hash h2 = cn_fast_hash();
	uint8_t buf[64]{};
	memcpy(buf, h.data, 32);
	memcpy(buf + 32, h2.data, 32);
	SecretKey result;
	sc_reduce64(&result, buf);
	return result;
}

PublicKey KeccakStream::hash_to_good_point() { return bytes_to_good_point(cn_fast_hash()); }

#ifndef __EMSCRIPTEN__
static std::mutex random_lock;
#endif

void generate_random_bytes(unsigned char *result, size_t n) {
#ifndef __EMSCRIPTEN__
	std::lock_guard<std::mutex> lock(random_lock);
#endif
	crypto_unsafe_generate_random_bytes(result, n);
}

SecretKey random_scalar() {
	uint8_t tmp[64]{};
	generate_random_bytes(tmp, sizeof(tmp));
	SecretKey result;
	sc_reduce64(&result, tmp);
	return result;
}

void random_keypair(PublicKey &pub, SecretKey &sec) {
	sec = random_scalar();
	pub = to_bytes(G * sec);
}

SecretKey bytes_to_scalar(const Hash &h) {
	SecretKey result;
	sc_reduce32(&result, h.data);
	return result;
}

PublicKey bytes_to_good_point(const Hash &h) { return to_bytes(bytes_to_good_point_p3(h)); }

PublicKey hash_to_good_point(const void *data, size_t length) { return to_bytes(hash_to_good_point_p3(data, length)); }

SecretKey hash_to_scalar(const void *data, size_t length) {
	return KeccakStream().append(data, length).hash_to_scalar();
}

SecretKey hash_to_scalar64(const void *data, size_t length) {
	return KeccakStream().append(data, length).hash_to_scalar64();
}

PublicKey bytes_to_bad_point(const Hash &h) {
	ge_p2 point;
	ge_fromfe_frombytes_vartime(&point, h.data);
	PublicKey result;
	ge_tobytes(&result, &point);
	return result;
}

bool key_isvalid(const EllipticCurvePoint &key) {
	P3 point;
	return point.frombytes_vartime(key);
}

bool key_in_main_subgroup(const EllipticCurvePoint &key) {
	P3 point;
	return point.frombytes_vartime(key) && point.in_main_subgroup();
	// All historic key images that fail subgroup check
	// c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
	//      in tx 56da63a36a60cc2151e322528f8685c927fdad9578a5678af8023f87dd27430c
	// c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
	//     in tx  f5e6754d7859ff4abf7a9733d5852d5ba35a77cab3dff4bb929c626cf1737b5a
	// 0000000000000000000000000000000000000000000000000000000000000080
	//     in tx 17320545c428fe7d67ff2c8140eef5c970adfc5eecab978986ac8b4b12a1dd84
	// 0100000000000000000000000000000000000000000000000000000000000000
	//     in tx 5a3db49ef69e1f9dd9b740cabea7328cd3499c29fc4f3295bac3fa5e55384626)
	// 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
	//     in tx cef289d7fab6e35ac123db8a3f06f7675b48067e0dff185c72b140845b8b3b23
	// 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
	//     in tx 7e418cc77935cc349f007cd5409d2b6908e4130321fa6f97ee0fee64b000ff85)
	// ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
	//     in tx 74298d301eb4b4da30c06989e0f7ff24a26c90bf4ffc4f2c18f34b7a22cf1136)

	// All historic output public keys that fail subgroup check
	// 9b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd088071
	//     in genesis block, tx
	//     2734b067c7cfc24d68f6bb1049d8b6fb10f9d9e21e31fd9a86b4d6ae5d24fab5
	// 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
	//     in tx 07a09e3c26d8ffc2e890713a69974e943a23ef6ad65b3bcbfc2b0f0da1add8f4
	//     in tx 2eb6eba0c298c9286accc0d9624173e8059bbeb09554aeb7ef1e2b7c373e3adb
	//     in tx 4bf32408756a8c914f2dea12cb17b38400a8d4b9bf6edcced2c03fc23fb27a0d
}

bool keys_match(const SecretKey &secret_key, const PublicKey &expected_public_key) {
	PublicKey pub;
	bool r = secret_key_to_public_key(secret_key, &pub);
	return r && expected_public_key == pub;
}

bool secret_key_to_public_key(const SecretKey &sec, PublicKey *pub) {
	if (!sc_isvalid_vartime(&sec))
		return false;
	*pub = to_bytes(G * sec);
	return true;
}

Signature generate_signature(const Hash &prefix_hash, const PublicKey &pub, const SecretKey &sec) {
	PARANOID_CHECK(keys_match(sec, pub), "Keys do not match in generate_signature");
	const EllipticCurveScalar k = random_scalar();

	KeccakStream buf;
	buf << prefix_hash << pub << to_bytes(G * k);

	Signature sig;
	sig.c = buf.hash_to_scalar();
	sig.r = k - sig.c * sec;
	return sig;
}

bool check_signature(const Hash &prefix_hash, const PublicKey &pub, const Signature &sig) {
	if (!sc_isvalid_vartime(&sig.c) || !sc_isvalid_vartime(&sig.r))
		return false;

	KeccakStream buf;
	buf << prefix_hash << pub << to_bytes(sig.c * P3(pub) + sig.r * G);

	EllipticCurveScalar c = buf.hash_to_scalar() - sig.c;
	return sc_iszero(&c) != 0;
}

Signature generate_proof_H(const SecretKey &s) {
	const EllipticCurveScalar k = random_scalar();

	KeccakStream buf;
	buf << to_bytes(H * s) << to_bytes(H * k);

	Signature sig;
	sig.c = buf.hash_to_scalar();
	sig.r = k - sig.c * s;
	return sig;
}

bool check_proof_H(const PublicKey &sH, const Signature &sig) {
	if (!sc_isvalid_vartime(&sig.c) || !sc_isvalid_vartime(&sig.r))
		return false;
	KeccakStream buf;
	buf << sH << to_bytes(sig.c * P3(sH) + sig.r * H);

	EllipticCurveScalar c = buf.hash_to_scalar() - sig.c;
	return sc_iszero(&c) != 0;
}

KeyImage generate_key_image(const PublicKey &pub, const SecretKey &sec) {
	check_scalar(sec);
	P3 pub_hash_p3 = hash_to_good_point_p3(pub);
	return to_bytes<KeyImage>(pub_hash_p3 * sec);
}

RingSignature generate_ring_signature(const Hash &prefix_hash, const KeyImage &image, const PublicKey pubs[],
    size_t pubs_count, const SecretKey &sec, size_t sec_index) {
	if (sec_index >= pubs_count)
		throw Error("sec_index >= pubs_count in generate_ring_signature");
	check_scalar(sec);
	RingSignature sig;
	sig.resize(pubs_count);
	PARANOID_CHECK(keys_match(sec, pubs[sec_index]), "Keys do not match in generate_ring_signature");
	PARANOID_CHECK(
	    generate_key_image(pubs[sec_index], sec) == image, "Keyimage does not match keys in generate_ring_signature");
	const P3 image_p3(image);
	KeccakStream buf;
	EllipticCurveScalar sum, k;
	sc_0(&sum);
	buf << prefix_hash;
	for (size_t i = 0; i < pubs_count; i++) {
		const P3 hash_pubs_i_p3 = hash_to_good_point_p3(pubs[i]);
		if (i == sec_index) {
			k = random_scalar();
			buf << to_bytes(G * k) << to_bytes(k * hash_pubs_i_p3);
		} else {
			const P3 pubs_i_p3(pubs[i]);
			sig[i].c = random_scalar();
			sig[i].r = random_scalar();
			buf << to_bytes(vartime_add(sig[i].c * pubs_i_p3, sig[i].r * G));
			buf << to_bytes(vartime_add(sig[i].r * hash_pubs_i_p3, sig[i].c * image_p3));
			sum += sig[i].c;
		}
	}
	const EllipticCurveScalar h = buf.hash_to_scalar();
	sig[sec_index].c            = h - sum;
	sig[sec_index].r            = k - sig[sec_index].c * sec;
	return sig;
}

bool check_ring_signature(
    const Hash &prefix_hash, const KeyImage &image, const std::vector<PublicKey> &pubs, const RingSignature &sig) {
	if (sig.size() != pubs.size())
		return false;
	P3 image_p3;
	if (!image_p3.frombytes_vartime(image))
		return false;  // key_image is considered part of signature, we do not throw
		               // if it is invalid
	KeccakStream buf;
	EllipticCurveScalar sum;
	sc_0(&sum);
	buf << prefix_hash;
	for (size_t i = 0; i < pubs.size(); i++) {
		if (!sc_isvalid_vartime(&sig[i].c) || !sc_isvalid_vartime(&sig[i].r))
			return false;
		const P3 pubs_i_p3(pubs[i]);
		const P3 hash_pubs_i_p3 = hash_to_good_point_p3(pubs[i]);

		buf << to_bytes(vartime_add(sig[i].c * pubs_i_p3, sig[i].r * G));
		buf << to_bytes(vartime_add(sig[i].r * hash_pubs_i_p3, sig[i].c * image_p3));
		sum += sig[i].c;
	}
	EllipticCurveScalar h = buf.hash_to_scalar() - sum;
	return sc_iszero(&h) != 0;
}

static SecretKey generate_sign_secret(
    size_t i, const Hash &random_seed1, const SecretKey &random_seed2, const char secret_name[2]) {
	KeccakStream k_buf;
	k_buf << random_seed1 << random_seed2;
	k_buf.append_byte(secret_name[0]).append_byte(secret_name[1]);
	k_buf << i;
	SecretKey b = k_buf.hash_to_scalar64();
	DEBUG_PRINT(std::cout << secret_name[0] << secret_name[1] << "[" << i << "]=" << b << std::endl);
	return b;
}

void generate_ring_signature_amethyst_loop1(size_t i, const P3 &image_p3, const P3 &p_p3, const P3 &G_plus_B_p3,
    size_t sec_index, const std::vector<PublicKey> &pubs, std::vector<EllipticCurveScalar> *rr, EllipticCurvePoint *y,
    EllipticCurvePoint *z, const Hash *random_seed) {
	rr->resize(pubs.size());
	for (size_t j = sec_index + 1; j < pubs.size(); ++j) {
		DEBUG_PRINT(std::cout << "pk[" << i << ", " << j << "]=" << pubs[j] << std::endl);
		const P3 pubs_i_p3(pubs[j]);
		const P3 hash_pubs_i_p3(hash_to_good_point_p3(pubs[j]));

		EllipticCurveScalar &r = (*rr)[j];
		if (random_seed) {
			KeccakStream r_buf;
			r_buf << *random_seed << "r" << i << j;
			r = r_buf.hash_to_scalar64();
		} else
			r = random_scalar();
		DEBUG_PRINT(std::cout << "rr[" << i << ", " << j << "]=" << r << std::endl);

		KeccakStream c_buf;
		c_buf << *y << *z;
		const EllipticCurveScalar c = c_buf.hash_to_scalar();
		DEBUG_PRINT(std::cout << "c[" << i << ", " << j << "]=" << c << std::endl);

		*y = to_bytes(c * (pubs_i_p3 - p_p3) + r * G_plus_B_p3);
		*z = to_bytes(c * image_p3 + r * hash_pubs_i_p3);
		DEBUG_PRINT(std::cout << "y[" << i << ", " << j << "]=" << *y << std::endl);
		DEBUG_PRINT(std::cout << "z[" << i << ", " << j << "]=" << *z << std::endl);
	}
}

void generate_ring_signature_amethyst_loop2(size_t i, const P3 &image_p3, const P3 &p_p3, const P3 &G_plus_B_p3,
    size_t sec_index, const std::vector<PublicKey> &pubs, std::vector<EllipticCurveScalar> *rr,
    EllipticCurveScalar *next_c, const Hash *random_seed) {
	for (size_t j = 0; j != sec_index; ++j) {
		DEBUG_PRINT(std::cout << "pk[" << i << ", " << j << "]=" << pubs[j] << std::endl);
		const P3 pubs_i_p3(pubs[j]);
		const P3 hash_pubs_i_p3(hash_to_good_point_p3(pubs[j]));

		EllipticCurveScalar &r = (*rr)[j];
		if (random_seed) {
			KeccakStream r_buf;
			r_buf << *random_seed << "r" << i << j;
			r = r_buf.hash_to_scalar64();
		} else
			r = random_scalar();
		DEBUG_PRINT(std::cout << "rr[" << i << ", " << j << "]=" << r << std::endl);

		const auto y = to_bytes(*next_c * (pubs_i_p3 - p_p3) + r * G_plus_B_p3);
		const auto z = to_bytes(*next_c * image_p3 + r * hash_pubs_i_p3);
		DEBUG_PRINT(std::cout << "y[" << i << ", " << j << "]=" << y << std::endl);
		DEBUG_PRINT(std::cout << "z[" << i << ", " << j << "]=" << z << std::endl);

		KeccakStream c_buf;
		c_buf << y << z;
		*next_c = c_buf.hash_to_scalar();
		DEBUG_PRINT(std::cout << "c[" << i << ", " << j << "]=" << *next_c << std::endl);
	}
}

RingSignatureAmethyst generate_ring_signature_amethyst(const Hash &prefix_hash, const std::vector<KeyImage> &images,
    const std::vector<std::vector<PublicKey>> &pubs, const std::vector<SecretKey> &secs_spend,
    const std::vector<SecretKey> &secs_audit, const std::vector<size_t> &sec_indexes, const Hash *random_seed) {
	// sanity checks
	if (images.empty() || images.size() != pubs.size() || images.size() != secs_spend.size() ||
	    images.size() != secs_audit.size())
		throw Error(
		    "inconsistent images/pubs/secs size in "
		    "generate_ring_signature_amethyst");
	DEBUG_PRINT(std::cout << "generate_ring_signature_amethyst" << std::endl);

	RingSignatureAmethyst sig;
	sig.pp.resize(images.size());
	sig.rr.resize(images.size());
	sig.rs.resize(images.size());
	sig.ra.resize(images.size());
	std::vector<PublicKey> b_coins(images.size());

	const Hash random_seed1      = random_seed ? *random_seed : crypto::rand<Hash>();
	const SecretKey random_seed2 = secs_spend.at(0);  // protection against owned rng

	KeccakStream buf;
	buf << prefix_hash;

	DEBUG_PRINT(std::cout << "prefix_hash=" << prefix_hash << std::endl);

	for (size_t i = 0; i != images.size(); ++i) {
		const size_t sec_index = sec_indexes[i];
		DEBUG_PRINT(std::cout << "image[" << i << "]=" << images[i] << std::endl);
		// sanity checks
		if (pubs[i].empty() || sec_index >= pubs[i].size())
			throw Error("sec_index >= pubs_count in generate_ring_signature_amethyst");
		check_scalar(secs_spend[i]);
		check_scalar(secs_audit[i]);
		PARANOID_CHECK(secret_keys_to_public_key(secs_audit[i], secs_spend[i]) == pubs[i][sec_index],
		    "Keys do not match in generate_ring_signature_amethyst");
		PARANOID_CHECK(generate_key_image(pubs[i][sec_index], secs_audit[i]) == images[i],
		    "Keyimage does not match keys in generate_ring_signature_amethyst");

		const P3 b_coin_p3(hash_to_good_point_p3(images[i]));
		b_coins[i] = to_bytes(b_coin_p3);
		const P3 hash_pubs_sec_p3(hash_to_good_point_p3(pubs[i][sec_index]));
		DEBUG_PRINT(std::cout << "b_coin[" << i << "]=" << b_coins[i] << std::endl);
		const P3 p_p3 = H * secs_spend[i] - b_coin_p3 * secs_audit[i];
		sig.pp[i]     = to_bytes(p_p3);
		buf << sig.pp[i];
		DEBUG_PRINT(std::cout << "p[" << i << "]=" << sig.pp[i] << std::endl);

		const SecretKey kr = generate_sign_secret(i, random_seed1, random_seed2, "kr");
		const SecretKey ks = generate_sign_secret(i, random_seed1, random_seed2, "ks");
		const SecretKey ka = generate_sign_secret(i, random_seed1, random_seed2, "ka");

		const PublicKey x = to_bytes(ks * H + ka * b_coin_p3);
		buf << x;
		DEBUG_PRINT(std::cout << "x[" << i << "]=" << x << std::endl);

		const P3 G_plus_B_p3 = P3(G) + b_coin_p3;
		DEBUG_PRINT(std::cout << "pk[" << i << ", " << sec_index << "]=" << pubs[i][sec_index] << std::endl);
		EllipticCurvePoint y = to_bytes(kr * G_plus_B_p3);
		DEBUG_PRINT(std::cout << "y[" << i << ", " << sec_index << "]=" << y << std::endl);
		EllipticCurvePoint z = to_bytes(kr * hash_pubs_sec_p3);
		DEBUG_PRINT(std::cout << "z[" << i << ", " << sec_index << "]=" << z << std::endl);

		const P3 image_p3(images[i]);
		generate_ring_signature_amethyst_loop1(
		    i, image_p3, p_p3, G_plus_B_p3, sec_indexes[i], pubs[i], &sig.rr[i], &y, &z, random_seed);
		buf << y << z;
		for (size_t j = 0; j != pubs[i].size(); ++j)
			buf << pubs[i][j];
	}
	// glued point of Borromean ring signature
	sig.c0 = buf.hash_to_scalar();
	DEBUG_PRINT(std::cout << "c0=" << sig.c0 << std::endl);

	for (size_t i = 0; i != images.size(); ++i) {
		const size_t sec_index = sec_indexes[i];
		const P3 image_p3(images[i]);
		DEBUG_PRINT(std::cout << "image[" << i << "]=" << images[i] << std::endl);

		const P3 b_coin_p3(b_coins[i]);
		const P3 G_plus_B_p3 = P3(G) + b_coin_p3;
		const P3 p_p3(sig.pp[i]);

		const SecretKey kr = generate_sign_secret(i, random_seed1, random_seed2, "kr");
		const SecretKey ks = generate_sign_secret(i, random_seed1, random_seed2, "ks");
		const SecretKey ka = generate_sign_secret(i, random_seed1, random_seed2, "ka");

		sig.rs[i] = ks - sig.c0 * secs_spend[i];
		sig.ra[i] = ka + sig.c0 * secs_audit[i];

		DEBUG_PRINT(std::cout << "aha=" << to_bytes(sig.rs[i] * H + sig.ra[i] * b_coin_p3) << " "
		                      << to_bytes(sig.c0 * p_p3) << std::endl);

		DEBUG_PRINT(std::cout << "rs[" << i << "]=" << sig.rs[i] << std::endl);
		DEBUG_PRINT(std::cout << "ra[" << i << "]=" << sig.ra[i] << std::endl);

		EllipticCurveScalar next_c = sig.c0;
		generate_ring_signature_amethyst_loop2(
		    i, image_p3, p_p3, G_plus_B_p3, sec_indexes[i], pubs[i], &sig.rr[i], &next_c, random_seed);
		sig.rr[i][sec_index] = kr - next_c * secs_audit[i];
		DEBUG_PRINT(std::cout << "rr[" << i << ", " << sec_index << "]=" << sig.rr[i][sec_index] << std::endl);
	}
	return sig;
}

bool check_ring_signature_amethyst(const Hash &prefix_hash, const std::vector<KeyImage> &images,
    const std::vector<std::vector<PublicKey>> &pubs, const RingSignatureAmethyst &sig) {
	// sanity checks
	if (images.empty() || images.size() != pubs.size() || images.size() != sig.pp.size() ||
	    images.size() != sig.rr.size() || images.size() != sig.rs.size() || images.size() != sig.ra.size())
		throw Error("inconsistent images/pubs/sigs size in check_ring_signature_amethyst");
	if (!sc_isvalid_vartime(&sig.c0))
		return false;
	DEBUG_PRINT(std::cout << "check_ring_signature_amethyst" << std::endl);

	DEBUG_PRINT(std::cout << "prefix_hash=" << prefix_hash << std::endl);
	KeccakStream buf;
	buf << prefix_hash;
	for (size_t i = 0; i != images.size(); ++i) {
		if (pubs[i].empty() || pubs[i].size() != sig.rr[i].size())
			throw Error("inconsistent pubs/sigs size in check_ring_signature_amethyst");
		DEBUG_PRINT(std::cout << "image[" << i << "]=" << images[i] << std::endl);
		const P3 b_coin_p3(hash_to_good_point_p3(images[i]));
		const P3 G_plus_B_p3 = P3(G) + b_coin_p3;
		if (!key_in_main_subgroup(sig.pp[i]))
			return false;
		if (!sc_isvalid_vartime(&sig.rs[i]) || !sc_isvalid_vartime(&sig.ra[i]))
			return false;

		const P3 p_p3(sig.pp[i]);

		buf << sig.pp[i];
		DEBUG_PRINT(std::cout << "b_coin[" << i << "]=" << to_bytes(b_coin_p3) << std::endl);
		DEBUG_PRINT(std::cout << "p[" << i << "]=" << sig.pp[i] << std::endl);

		const PublicKey x = to_bytes(vartime_add(sig.c0 * p_p3, sig.rs[i] * H) + sig.ra[i] * b_coin_p3);
		DEBUG_PRINT(std::cout << "x[" << i << "]=" << x << std::endl);
		buf << x;

		const P3 image_p3(images[i]);

		auto next_c = sig.c0;
		for (size_t j = 0; j != pubs[i].size(); ++j) {
			DEBUG_PRINT(std::cout << "pk[" << i << ", " << j << "]=" << pubs[i][j] << std::endl);
			DEBUG_PRINT(std::cout << "c[" << i << ", " << j << "]=" << next_c << std::endl);

			const P3 pubs_i_p3(pubs[i][j]);
			const P3 hash_pubs_i_p3(hash_to_good_point_p3(pubs[i][j]));
			const EllipticCurveScalar &rr = sig.rr[i][j];
			if (!sc_isvalid_vartime(&rr))
				return false;
			DEBUG_PRINT(std::cout << "rr[" << i << ", " << j << "]=" << rr << std::endl);

			const auto y = to_bytes(vartime_add(next_c * (pubs_i_p3 - p_p3), rr * G_plus_B_p3));
			const auto z = to_bytes(vartime_add(next_c * image_p3, rr * hash_pubs_i_p3));
			DEBUG_PRINT(std::cout << "y[" << i << ", " << j << "]=" << y << std::endl);
			DEBUG_PRINT(std::cout << "z[" << i << ", " << j << "]=" << z << std::endl);

			if (j == pubs[i].size() - 1) {
				buf << y << z;
			} else {
				KeccakStream c_buf;
				c_buf << y << z;
				next_c = c_buf.hash_to_scalar();
				DEBUG_PRINT(std::cout << "c[" << i << ", " << j << "]=" << next_c << std::endl);
			}
		}
		for (size_t j = 0; j != pubs[i].size(); ++j)
			buf << pubs[i][j];
	}
	const auto c = buf.hash_to_scalar() - sig.c0;
	return sc_iszero(&c) != 0;
}

KeyDerivation generate_key_derivation(const PublicKey &tx_public_key, const SecretKey &view_secret_key) {
	check_scalar(view_secret_key);
	// tx public key is not checked by node, so can be invalid
	// it is convenient to compare derivation with KeyDerivation{} outside this
	// function to detect the fact
	try {
		const P3 tx_public_key_p3(tx_public_key);
		const P3 point3 = view_secret_key * tx_public_key_p3;
		return to_bytes<KeyDerivation>(point3.mul8());
	} catch (const std::exception &) {
	}
	return KeyDerivation{};
}

static SecretKey derivation_to_scalar(const KeyDerivation &derivation, size_t output_index) {
	KeccakStream buf;
	buf << derivation << output_index;
	return buf.hash_to_scalar();
}

PublicKey derive_output_public_key(const KeyDerivation &derivation, size_t output_index, const PublicKey &address_S) {
	const EllipticCurveScalar scalar = derivation_to_scalar(derivation, output_index);
	return to_bytes(scalar * G + P3(address_S));
}

SecretKey derive_output_secret_key(const KeyDerivation &derivation, size_t output_index, const SecretKey &address_s) {
	check_scalar(address_s);
	return derivation_to_scalar(derivation, output_index) + address_s;
}

PublicKey underive_address_S(const KeyDerivation &derivation, size_t output_index, const PublicKey &output_public_key) {
	const EllipticCurveScalar scalar = derivation_to_scalar(derivation, output_index);
	return to_bytes(P3(output_public_key) - scalar * G);
}

Signature generate_sendproof(const PublicKey &txkey_pub,
    const SecretKey &txkey_sec,
    const PublicKey &receiver_address_V,
    const KeyDerivation &derivation,
    const Hash &message_hash) {
	const P3 receiver_address_V_p3(receiver_address_V);
	const EllipticCurveScalar k = random_scalar();

	KeccakStream cr_comm;
	cr_comm << message_hash << txkey_pub << receiver_address_V << derivation << to_bytes(k * G);
	const P3 tmp3 = k * receiver_address_V_p3;
	cr_comm << to_bytes(tmp3.mul8());

	Signature proof;
	proof.c = cr_comm.hash_to_scalar();
	proof.r = k - proof.c * txkey_sec;
	return proof;
}

bool check_sendproof(const PublicKey &txkey_pub, const PublicKey &receiver_address_V, const KeyDerivation &derivation,
    const Hash &message_hash, const Signature &proof) {
	if (!sc_isvalid_vartime(&proof.c) || !sc_isvalid_vartime(&proof.r))
		return false;
	P3 txkey_pub_p3;
	if (!txkey_pub_p3.frombytes_vartime(txkey_pub))
		return false;                                    // tx public keys are not checked by daemon and can be invalid
	const P3 receiver_address_V_g3(receiver_address_V);  // checked as part of address
	P3 derivation_p3;
	if (!derivation_p3.frombytes_vartime(derivation) || !derivation_p3.in_main_subgroup())
		return false;
	KeccakStream cr_comm;
	cr_comm << message_hash << txkey_pub << receiver_address_V << derivation;
	cr_comm << to_bytes(vartime_add(proof.c * txkey_pub_p3, proof.r * G));
	const P3 tmp3 = receiver_address_V_g3.mul8();
	cr_comm << to_bytes(vartime_add(proof.r * tmp3, proof.c * derivation_p3));
	EllipticCurveScalar h = cr_comm.hash_to_scalar() - proof.c;
	return sc_iszero(&h) != 0;
}

void generate_hd_spendkeys(
    const SecretKey &a0, const PublicKey &A_plus_SH, size_t index, std::vector<KeyPair> *result) {
	const P3 A_plus_SH_p3(A_plus_SH);
	for (size_t d = 0; d != result->size(); ++d) {
		KeyPair &res = result->at(d);

		KeccakStream cr_comm;
		cr_comm << A_plus_SH << "address" << (index + d);
		const SecretKey delta_secret_key = cr_comm.hash_to_scalar();
		const P3 delta_public_key_g3     = delta_secret_key * G;

		res.public_key = to_bytes(A_plus_SH_p3 + delta_public_key_g3);

		if (a0 == SecretKey{}) {
			res.secret_key = SecretKey{};
		} else {
			res.secret_key = a0 + delta_secret_key;
		}
	}
}

// base + Hs(seed|index)*mul
PublicKey generate_hd_spendkey(
    const PublicKey &v_mul_A_plus_SH, const PublicKey &A_plus_SH, const PublicKey &V, size_t index) {
	const P3 v_mul_A_plus_SH_p3(v_mul_A_plus_SH);
	const P3 V_p3(V);
	KeccakStream cr_comm;
	cr_comm << A_plus_SH << "address" << index;
	const SecretKey delta_secret_key = cr_comm.hash_to_scalar();
	return to_bytes(v_mul_A_plus_SH_p3 + delta_secret_key * V_p3);
}

SecretKey generate_hd_secretkey(const SecretKey &a0, const PublicKey &A_plus_SH, size_t index) {
	KeccakStream cr_comm;
	cr_comm << A_plus_SH << "address" << index;
	SecretKey delta_secret_key = cr_comm.hash_to_scalar();
	return a0 + delta_secret_key;
}

PublicKey secret_keys_to_public_key(const SecretKey &a, const SecretKey &s) { return to_bytes(a * G + s * H); }

BinaryArray get_output_secret_hash_arg(
    const PublicKey &output_shared_secret, const Hash &tx_inputs_hash, size_t output_index) {
	BinaryArray result = output_shared_secret.as_binary_array();
	result.insert(result.end(), std::begin(tx_inputs_hash.data), std::end(tx_inputs_hash.data));
	append_varint(&result, output_index);
	return result;
}

PublicKey linkable_derive_output_public_key(const SecretKey &output_secret, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &address_S, const PublicKey &address_V, PublicKey *encrypted_output_secret,
    PublicKey *output_shared_secret) {
	check_scalar(output_secret);
	const P3 address_V_p3(address_V);
	*encrypted_output_secret = to_bytes(output_secret * address_V_p3);

	const PublicKey derivation = to_bytes(output_secret * G);
	*output_shared_secret      = derivation;

	KeccakStream cr_comm;
	cr_comm << derivation << tx_inputs_hash << output_index;
	const EllipticCurveScalar derivation_hash = cr_comm.hash_to_scalar();

	return to_bytes(derivation_hash * G + P3(address_S));
}

PublicKey linkable_underive_address_S(const SecretKey &inv_view_secret_key, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &output_public_key, const PublicKey &encrypted_output_secret,
    PublicKey *output_shared_secret) {
	check_scalar(inv_view_secret_key);
	const P3 encrypted_output_secret_p3(encrypted_output_secret);
	const PublicKey derivation = to_bytes(inv_view_secret_key * encrypted_output_secret_p3);
	*output_shared_secret      = derivation;

	KeccakStream cr_comm;
	cr_comm << derivation << tx_inputs_hash << output_index;
	SecretKey output_secret_hash = cr_comm.hash_to_scalar();

	return to_bytes(P3(output_public_key) - output_secret_hash * G);
}

SecretKey linkable_derive_output_secret_key(const SecretKey &address_s, const SecretKey &output_secret_hash) {
	check_scalar(address_s);
	check_scalar(output_secret_hash);
	return address_s + output_secret_hash;
}

void linkable_underive_address(const SecretKey &output_secret, const Hash &tx_inputs_hash, size_t output_index,
    const PublicKey &output_public_key, const PublicKey &encrypted_output_secret, PublicKey *address_S,
    PublicKey *address_V, PublicKey *output_shared_secret) {
	check_scalar(output_secret);
	const PublicKey derivation = to_bytes(output_secret * G);
	*output_shared_secret      = derivation;
	KeccakStream cr_comm;
	cr_comm << derivation << tx_inputs_hash << output_index;
	const EllipticCurveScalar derivation_hash = cr_comm.hash_to_scalar();
	*address_S                                = to_bytes(P3(output_public_key) - derivation_hash * G);

	const SecretKey inv_output_secret = sc_invert(output_secret);
	*address_V                        = to_bytes(inv_output_secret * P3(encrypted_output_secret));
}

PublicKey unlinkable_derive_output_public_key(const PublicKey &output_secret, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &address_S, const PublicKey &address_SV, PublicKey *encrypted_output_secret,
    PublicKey *output_shared_secret) {
	DEBUG_PRINT(std::cout << "output_secret=" << output_secret << std::endl);
	const P3 address_s_p3(address_S);
	const P3 address_sv_p3(address_SV);
	const P3 output_secret_p3(output_secret);

	*output_shared_secret = output_secret;
	KeccakStream cr_comm;
	cr_comm << output_secret << tx_inputs_hash << output_index;
	const SecretKey output_secret_hash = cr_comm.hash_to_scalar();
	DEBUG_PRINT(std::cout << "output_secret_hash=" << output_secret_hash << std::endl);

	const SecretKey inv_output_secret_hash = sc_invert(output_secret_hash);
	DEBUG_PRINT(std::cout << "inv_output_secret_hash=" << inv_output_secret_hash << std::endl);
	PublicKey output_public_key = to_bytes(inv_output_secret_hash * address_s_p3);

	*encrypted_output_secret = to_bytes(output_secret_p3 + inv_output_secret_hash * address_sv_p3);
	return output_public_key;
}

PublicKey unlinkable_underive_address_S(const SecretKey &view_secret_key, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &output_public_key, const PublicKey &encrypted_output_secret,
    PublicKey *output_shared_secret) {
	check_scalar(view_secret_key);
	const P3 output_public_key_p3(output_public_key);
	const P3 encrypted_output_secret_p3(encrypted_output_secret);

	const PublicKey output_secret = to_bytes(encrypted_output_secret_p3 - view_secret_key * output_public_key_p3);
	*output_shared_secret         = output_secret;
	DEBUG_PRINT(std::cout << "output_secret=" << output_secret << std::endl);

	KeccakStream cr_comm;
	cr_comm << output_secret << tx_inputs_hash << output_index;

	SecretKey output_secret_hash = cr_comm.hash_to_scalar();
	DEBUG_PRINT(std::cout << "output_secret_hash=" << output_secret_hash << std::endl);

	PublicKey result = to_bytes(output_secret_hash * output_public_key_p3);
	return result;
}

PublicKey unlinkable_underive_address_S_step1(const SecretKey &view_secret_key, const PublicKey &output_public_key) {
	check_scalar(view_secret_key);
	return to_bytes(view_secret_key * P3(output_public_key));
}

PublicKey unlinkable_underive_address_S_step2(const PublicKey &Pv, const Hash &tx_inputs_hash, size_t output_index,
    const PublicKey &output_public_key, const PublicKey &encrypted_output_secret, PublicKey *output_shared_secret) {
	const P3 Pv_p3(Pv);
	const P3 output_public_key_p3(output_public_key);
	const P3 encrypted_output_secret_p3(encrypted_output_secret);

	const PublicKey output_secret = to_bytes(encrypted_output_secret_p3 - Pv_p3);
	*output_shared_secret         = output_secret;
	KeccakStream cr_comm;
	cr_comm << output_secret << tx_inputs_hash << output_index;
	SecretKey output_secret_hash = cr_comm.hash_to_scalar();

	return to_bytes(output_secret_hash * output_public_key_p3);
}

SecretKey unlinkable_derive_output_secret_key(const SecretKey &address_secret, const SecretKey &output_secret_hash) {
	check_scalar(address_secret);
	check_scalar(output_secret_hash);
	const SecretKey inv_output_secret_hash = sc_invert(output_secret_hash);
	return inv_output_secret_hash * address_secret;
}

void unlinkable_underive_address(PublicKey *address_S, PublicKey *address_Sv, const PublicKey &output_secret,
    const Hash &tx_inputs_hash, size_t output_index, const PublicKey &output_public_key,
    const PublicKey &encrypted_output_secret, PublicKey *output_shared_secret) {
	*output_shared_secret = output_secret;
	const P3 output_public_key_p3(output_public_key);
	const P3 output_secret_p3(output_secret);
	const P3 encrypted_output_secret_p3(encrypted_output_secret);

	KeccakStream cr_comm;
	cr_comm << output_secret << tx_inputs_hash << output_index;
	const SecretKey output_secret_hash = cr_comm.hash_to_scalar();

	*address_S = to_bytes(output_secret_hash * output_public_key_p3);

	const P3 t_minus_k = encrypted_output_secret_p3 - output_secret_p3;

	*address_Sv = to_bytes(output_secret_hash * t_minus_k);
}

// from crypto_helpers

bool P3::frombytes_vartime(const EllipticCurvePoint &other) {
	ge_p3 p3_tmp;  // ge_frombytes_vartime returns random result if false
	if (ge_frombytes_vartime(&p3_tmp, &other) != 0)
		return false;
	p3 = p3_tmp;
	return true;
}

bool P3::in_main_subgroup() const {
	ge_dsmp image_dsm;
	ge_dsm_precomp(&image_dsm, &p3);
	return ge_check_subgroup_precomp_vartime(&image_dsm) == 0;
}

P3 P3::mul8() const {
	ge_p1p1 p1;
	ge_mul8(&p1, &p3);
	P3 result;
	ge_p1p1_to_p3(&result.p3, &p1);
	return result;
}

P3 operator-(const P3 &a, const P3 &b) {
	ge_cached b_cached;
	ge_p3_to_cached(&b_cached, &b.p3);
	ge_p1p1 result_p1p1;
	ge_sub(&result_p1p1, &a.p3, &b_cached);
	P3 result;
	ge_p1p1_to_p3(&result.p3, &result_p1p1);
	return result;
}

P3 operator+(const P3 &a, const P3 &b) {
	ge_cached b_cached;
	ge_p3_to_cached(&b_cached, &b.p3);
	ge_p1p1 result_p1p1;
	ge_add(&result_p1p1, &a.p3, &b_cached);
	P3 result;
	ge_p1p1_to_p3(&result.p3, &result_p1p1);
	return result;
}

P3 bytes_to_good_point_p3(const Hash &h) {
	ge_p2 point_p2;
	ge_fromfe_frombytes_vartime(&point_p2, h.data);
	ge_p1p1 p1;
	ge_mul8_p2(&p1, &point_p2);
	ge_p3 p3;
	ge_p1p1_to_p3(&p3, &p1);
	return P3(p3);
}

// copy verbatim from common/Varint.hpp, we do not wish dependency
template<class T>
T uint_le_from_bytes(const unsigned char *buf, size_t si) {
	static_assert(std::is_unsigned<T>::value, "works only with unsigned types");
	T result = 0;
	for (size_t i = si; i-- > 0;)
		result = (result << 8) + buf[i];
	return result;
}

template<class T>
void uint_le_to_bytes(unsigned char *buf, size_t si, T val) {
	static_assert(std::is_unsigned<T>::value, "works only with unsigned types");
	for (size_t i = 0; i != si; ++i) {
		buf[i] = static_cast<unsigned char>(val);
		val >>= 8;
	}
}

SecretKey sc_from_uint64(uint64_t val) {
	SecretKey result;
	uint_le_to_bytes(result.data, 8, val);
	return result;
}

}  // namespace crypto
