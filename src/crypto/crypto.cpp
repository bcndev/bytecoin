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
#include "crypto_helpers.hpp"
#include "hash.hpp"
#include "random.h"

namespace crypto {

//#define DEBUG_PRINT(expr) do {         		expr;             	} while (0)
#define DEBUG_PRINT(expr)

//#define PARANOID_CHECK(expr, msg) 	do { 	if (!(expr))  throw Error(msg);	} while (0)
#define PARANOID_CHECK(expr, msg)

const ge_p3 H_p3 = {{7329926, -15101362, 31411471, 7614783, 27996851, -3197071, -11157635, -6878293, 466949, -7986503},
    {5858699, 5096796, 21321203, -7536921, -5553480, -11439507, -5627669, 15045946, 19977121, 5275251},
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {23443568, -5110398, -8776029, -4345135, 6889568, -14710814, 7474843, 3279062, 14550766, -7453428}};

PublicKey get_G() {  // 5866666666666666666666666666666666666666666666666666666666666666
	SecretKey one;
	sc_1(&one);
	return ge_tobytes(ge_scalarmult_base(one));
}

PublicKey get_H() { return ge_tobytes(H_p3); }  // 8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94

const ge_p3 &get_H_p3() { return H_p3; }

PublicKey test_get_H() {
	PublicKey G = get_G();
	Hash hash   = cn_fast_hash(G.data, sizeof(G.data));
	PublicKey hash_as_pk;
	memcpy(hash_as_pk.data, hash.data, 32);  // reintrepret hash as a point :)
	return ge_tobytes(ge_p1p1_to_p3(ge_mul8(ge_frombytes_vartime(hash_as_pk))));
}

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

SecretKey KeccakStream::hash_to_scalar() {
	Hash h = cn_fast_hash();
	SecretKey result;
	sc_reduce32(&result, h.data);
	return result;
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

PublicKey KeccakStream::hash_to_point() {
	const Hash h = cn_fast_hash();
	ge_p2 point_p2;
	ge_fromfe_frombytes_vartime(&point_p2, h.data);
	return ge_tobytes(ge_p1p1_to_p3(ge_mul8_p2(point_p2)));
}

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
	sc_reduce64(&result, tmp);
	return result;
}

PublicKey hash_to_good_point(const void *data, size_t length) {
	return ge_tobytes(hash_to_good_point_p3(data, length));
}

SecretKey hash_to_scalar(const void *data, size_t length) {
	return KeccakStream().append(data, length).hash_to_scalar();
}

// TODO - check security of this approach.
SecretKey hash_to_scalar64(const void *data, size_t length) {
	return KeccakStream().append(data, length).hash_to_scalar64();
}

PublicKey bytes_to_bad_point(const Hash &h) {
	ge_p2 point;
	ge_fromfe_frombytes_vartime(&point, h.data);
	return ge_tobytes(point);
}

PublicKey hash_to_bad_point(const void *data, size_t length) { return bytes_to_bad_point(cn_fast_hash(data, length)); }

void random_keypair(PublicKey &pub, SecretKey &sec) {
	sec = random_scalar();
	pub = ge_tobytes(ge_scalarmult_base(sec));
}

bool key_isvalid(const PublicKey &key) {
	ge_p3 point;
	return ge_frombytes_vartime(&point, &key) == 0;
}

bool key_in_main_subgroup(const EllipticCurvePoint &key) {
	ge_dsmp key_dsm;
	if (!ge_dsm_frombytes_vartime(&key_dsm, key))
		return false;
	return ge_check_subgroup_precomp_vartime(&key_dsm) == 0;
	// All historic key images that fail subgroup check
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
	// All historic output public keys that fail subgroup check
	// 9b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd088071 (in tx
	// 2734b067c7cfc24d68f6bb1049d8b6fb10f9d9e21e31fd9a86b4d6ae5d24fab5)
	// 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05 (in tx
	// 07a09e3c26d8ffc2e890713a69974e943a23ef6ad65b3bcbfc2b0f0da1add8f4,
	// 2eb6eba0c298c9286accc0d9624173e8059bbeb09554aeb7ef1e2b7c373e3adb,
	// 4bf32408756a8c914f2dea12cb17b38400a8d4b9bf6edcced2c03fc23fb27a0d)
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

Signature generate_signature(const Hash &prefix_hash, const PublicKey &pub, const SecretKey &sec) {
	PARANOID_CHECK(keys_match(sec, pub), "Keys do not match in generate_signature");
	const EllipticCurveScalar k = random_scalar();

	KeccakStream buf;
	//	buf << prefix_hash << pub << ge_tobytes(ge_scalarmult_base(k));
	buf << prefix_hash << pub << to_bytes(G * k);

	Signature sig;
	sig.c = buf.hash_to_scalar();
	//	sc_mulsub(&sig.r, &sig.c, &sec, &k);
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

Signature generate_signature_H(const Hash &prefix_hash, const PublicKey &sec_H, const SecretKey &sec) {
	const EllipticCurveScalar k = random_scalar();

	KeccakStream buf;
	buf << prefix_hash << sec_H << to_bytes(H * k);

	Signature sig;
	sig.c = buf.hash_to_scalar();
	sig.r = k - sig.c * sec;
	return sig;
}

bool check_signature_H(const Hash &prefix_hash, const PublicKey &sec_H, const Signature &sig) {
	if (!sc_isvalid_vartime(&sig.c) || !sc_isvalid_vartime(&sig.r))
		return false;
	KeccakStream buf;
	buf << prefix_hash << sec_H << to_bytes(sig.c * P3(sec_H) + sig.r * H);

	EllipticCurveScalar c = buf.hash_to_scalar() - sig.c;
	return sc_iszero(&c) != 0;
}

KeyImage generate_key_image(const PublicKey &pub, const SecretKey &sec) {
	check_scalar(sec);
	//	const ge_p3 pub_hash_p3 = hash_to_good_point_p3(pub);
	//	KeyImage image;
	//	static_cast<EllipticCurvePoint &>(image) = ge_tobytes(ge_scalarmult(sec, pub_hash_p3));
	//	return image;

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
	ge_dsmp image_dsm;
	if (!ge_dsm_frombytes_vartime(&image_dsm, image))
		throw Error("Keyimage is invalid");
	KeccakStream buf;
	EllipticCurveScalar sum, k;
	sc_0(&sum);
	buf << prefix_hash;
	for (size_t i = 0; i < pubs_count; i++) {
		const ge_p3 hash_pubs_i_p3 = hash_to_good_point_p3(pubs[i]);
		if (i == sec_index) {
			k = random_scalar();
			buf << ge_tobytes(ge_scalarmult_base(k)) << ge_tobytes(ge_scalarmult3(k, hash_pubs_i_p3));
		} else {
			const ge_p3 pubs_i_p3 = ge_frombytes_vartime(pubs[i]);
			sig[i].c              = random_scalar();
			sig[i].r              = random_scalar();
			buf << ge_tobytes(ge_double_scalarmult_base_vartime3(sig[i].c, pubs_i_p3, sig[i].r));
			buf << ge_tobytes(ge_double_scalarmult_precomp_vartime3(sig[i].r, hash_pubs_i_p3, sig[i].c, image_dsm));
			sc_add(&sum, &sum, &sig[i].c);
		}
	}
	const EllipticCurveScalar h = buf.hash_to_scalar();
	sc_sub(&sig[sec_index].c, &h, &sum);
	sc_mulsub(&sig[sec_index].r, &sig[sec_index].c, &sec, &k);
	return sig;
}

bool check_ring_signature(const Hash &prefix_hash, const KeyImage &image, const PublicKey pubs[], size_t pubs_count,
    const RingSignature &sig) {
	ge_dsmp image_dsm;
	if (!ge_dsm_frombytes_vartime(&image_dsm, image))
		return false;  // key_image is considered part of signature, we do not throw if it is invalid
	KeccakStream buf;
	EllipticCurveScalar sum;
	sc_0(&sum);
	buf << prefix_hash;
	for (size_t i = 0; i < pubs_count; i++) {
		if (!sc_isvalid_vartime(&sig[i].c) || !sc_isvalid_vartime(&sig[i].r))
			return false;
		const ge_p3 pubs_i_p3      = ge_frombytes_vartime(pubs[i]);
		const ge_p3 hash_pubs_i_p3 = hash_to_good_point_p3(pubs[i]);

		buf << ge_tobytes(ge_double_scalarmult_base_vartime3(sig[i].c, pubs_i_p3, sig[i].r));
		buf << ge_tobytes(ge_double_scalarmult_precomp_vartime3(sig[i].r, hash_pubs_i_p3, sig[i].c, image_dsm));
		sc_add(&sum, &sum, &sig[i].c);
	}
	EllipticCurveScalar h = buf.hash_to_scalar();
	sc_sub(&h, &h, &sum);
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

void generate_ring_signature_auditable_loop1(size_t i, const Hash &prefix_hash, const P3 &image_p3, const P3 &p_p3,
    const P3 &G_plus_B_p3, size_t sec_index, const std::vector<PublicKey> &pubs, std::vector<EllipticCurveScalar> *ra,
    EllipticCurvePoint *x, EllipticCurvePoint *y) {
	ra->resize(pubs.size());
	for (size_t j = sec_index + 1; j < pubs.size(); ++j) {
		DEBUG_PRINT(std::cout << "pk[" << i << ", " << j << "]=" << pubs[j] << std::endl);
		const P3 pubs_i_p3(pubs[j]);
		const P3 hash_pubs_i_p3(hash_to_good_point_p3(pubs[j]));

		EllipticCurveScalar &r = (*ra)[j];
		r                      = random_scalar();
		//		FixedBuffer<sizeof(Hash) + 1 + 2 * max_varint_size> r_buf;
		//		r_buf << mega_random_seed << "r" << i << j;
		//		r = r_buf.hash_to_scalar64();
		DEBUG_PRINT(std::cout << "ra[" << i << ", " << j << "]=" << r << std::endl);

		KeccakStream c_buf;
		c_buf << prefix_hash << *x << *y;
		const EllipticCurveScalar c = c_buf.hash_to_scalar();
		DEBUG_PRINT(std::cout << "c[" << i << ", " << j << "]=" << c << std::endl);

		*x = to_bytes(c * (pubs_i_p3 - p_p3) + r * G_plus_B_p3);
		*y = to_bytes(c * image_p3 + r * hash_pubs_i_p3);
		DEBUG_PRINT(std::cout << "x[" << i << ", " << j << "]=" << *x << std::endl);
		DEBUG_PRINT(std::cout << "y[" << i << ", " << j << "]=" << *y << std::endl);
	}
}

void generate_ring_signature_auditable_loop2(size_t i, const Hash &prefix_hash, const P3 &image_p3, const P3 &p_p3,
    const P3 &G_plus_B_p3, size_t sec_index, const std::vector<PublicKey> &pubs, std::vector<EllipticCurveScalar> *ra,
    EllipticCurveScalar *next_c) {
	for (size_t j = 0; j != sec_index; ++j) {
		DEBUG_PRINT(std::cout << "pk[" << i << ", " << j << "]=" << pubs[j] << std::endl);
		const P3 pubs_i_p3(pubs[j]);
		const P3 hash_pubs_i_p3(hash_to_good_point_p3(pubs[j]));

		EllipticCurveScalar &r = (*ra)[j];
		r                      = random_scalar();
		//		FixedBuffer<sizeof(Hash) + 1 + 2 * max_varint_size> r_buf;
		//		r_buf << mega_random_seed << "r" << i << j;
		//		r = r_buf.hash_to_scalar64();
		DEBUG_PRINT(std::cout << "ra[" << i << ", " << j << "]=" << r << std::endl);

		const auto x = to_bytes(*next_c * (pubs_i_p3 - p_p3) + r * G_plus_B_p3);
		const auto y = to_bytes(*next_c * image_p3 + r * hash_pubs_i_p3);
		DEBUG_PRINT(std::cout << "x[" << i << ", " << j << "]=" << x << std::endl);
		DEBUG_PRINT(std::cout << "y[" << i << ", " << j << "]=" << y << std::endl);

		KeccakStream c_buf;
		c_buf << prefix_hash << x << y;
		*next_c = c_buf.hash_to_scalar();
		DEBUG_PRINT(std::cout << "c[" << i << ", " << j << "]=" << *next_c << std::endl);
	}
}

RingSignatureAmethyst generate_ring_signature_auditable(const Hash &prefix_hash, const std::vector<KeyImage> &images,
    const std::vector<std::vector<PublicKey>> &pubs, const std::vector<SecretKey> &secs_spend,
    const std::vector<SecretKey> &secs_audit, const std::vector<size_t> &sec_indexes) {
	// sanity checks
	if (images.empty() || images.size() != pubs.size() || images.size() != secs_spend.size() ||
	    images.size() != secs_audit.size())
		throw Error("inconsistent images/pubs/secs size in generate_ring_signature_auditable");
	DEBUG_PRINT(std::cout << "generate_ring_signature_auditable" << std::endl);

	RingSignatureAmethyst sig;
	sig.p.resize(images.size());
	sig.ra.resize(images.size());
	sig.rb.resize(images.size());
	sig.rc.resize(images.size());
	std::vector<PublicKey> b_coins(images.size());

	const Hash random_seed1      = Hash{};            // crypto::rand<Hash>(); TODO - uncomment in final code
	const SecretKey random_seed2 = secs_spend.at(0);  // protection against owned rng

	KeccakStream buf;
	buf << prefix_hash;

	DEBUG_PRINT(std::cout << "prefix_hash=" << prefix_hash << std::endl);

	for (size_t i = 0; i != images.size(); ++i) {
		const size_t sec_index = sec_indexes[i];
		DEBUG_PRINT(std::cout << "image[" << i << "]=" << images[i] << std::endl);
		// sanity checks
		if (pubs[i].empty() || sec_index >= pubs[i].size())
			throw Error("sec_index >= pubs_count in generate_ring_signature_auditable");
		check_scalar(secs_spend[i]);
		check_scalar(secs_audit[i]);
		PARANOID_CHECK(secret_keys_to_public_key(secs_audit[i], secs_spend[i]) == pubs[i][sec_index],
		    "Keys do not match in generate_ring_signature_auditable");
		PARANOID_CHECK(generate_key_image(pubs[i][sec_index], secs_audit[i]) == images[i],
		    "Keyimage does not match keys in generate_ring_signature_auditable");

		const P3 b_coin_p3(hash_to_good_point_p3(images[i]));
		b_coins[i] = to_bytes(b_coin_p3);
		const P3 hash_pubs_sec_p3(hash_to_good_point_p3(pubs[i][sec_index]));
		DEBUG_PRINT(std::cout << "b_coin[" << i << "]=" << b_coins[i] << std::endl);
		const P3 p_p3 = H * secs_spend[i] - b_coin_p3 * secs_audit[i];
		sig.p[i]      = to_bytes(p_p3);
		buf << sig.p[i];
		DEBUG_PRINT(std::cout << "p[" << i << "]=" << sig.p[i] << std::endl);

		const SecretKey ka = generate_sign_secret(i, random_seed1, random_seed2, "ka");
		const SecretKey kb = generate_sign_secret(i, random_seed1, random_seed2, "kb");
		const SecretKey kc = generate_sign_secret(i, random_seed1, random_seed2, "kc");

		const PublicKey z = to_bytes(kb * H + kc * b_coin_p3);
		buf << z;
		DEBUG_PRINT(std::cout << "z[" << i << "]=" << z << std::endl);

		const P3 G_plus_B_p3 = P3(G) + b_coin_p3;
		DEBUG_PRINT(std::cout << "pk[" << i << ", " << sec_index << "]=" << pubs[i][sec_index] << std::endl);
		EllipticCurvePoint x = to_bytes(ka * G_plus_B_p3);
		DEBUG_PRINT(std::cout << "x[" << i << ", " << sec_index << "]=" << x << std::endl);
		EllipticCurvePoint y = to_bytes(ka * hash_pubs_sec_p3);
		DEBUG_PRINT(std::cout << "y[" << i << ", " << sec_index << "]=" << y << std::endl);

		const P3 image_p3(images[i]);
		generate_ring_signature_auditable_loop1(
		    i, prefix_hash, image_p3, p_p3, G_plus_B_p3, sec_indexes[i], pubs[i], &sig.ra[i], &x, &y);
		buf << x << y;
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
		const P3 p_p3(sig.p[i]);

		const SecretKey ka = generate_sign_secret(i, random_seed1, random_seed2, "ka");
		const SecretKey kb = generate_sign_secret(i, random_seed1, random_seed2, "kb");
		const SecretKey kc = generate_sign_secret(i, random_seed1, random_seed2, "kc");

		sig.rb[i] = kb - sig.c0 * secs_spend[i];
		sig.rc[i] = kc + sig.c0 * secs_audit[i];

		DEBUG_PRINT(std::cout << "aha=" << to_bytes(sig.rb[i] * H + sig.rc[i] * b_coin_p3) << " " << to_bytes(sig.c0 * p_p3)
		          << std::endl);

		DEBUG_PRINT(std::cout << "rb[" << i << "]=" << sig.rb[i] << std::endl);
		DEBUG_PRINT(std::cout << "rc[" << i << "]=" << sig.rc[i] << std::endl);

		EllipticCurveScalar next_c = sig.c0;
		generate_ring_signature_auditable_loop2(
		    i, prefix_hash, image_p3, p_p3, G_plus_B_p3, sec_indexes[i], pubs[i], &sig.ra[i], &next_c);
		sig.ra[i][sec_index] = ka - next_c * secs_audit[i];
		DEBUG_PRINT(std::cout << "ra[" << i << ", " << sec_index << "]=" << sig.ra[i][sec_index] << std::endl);
	}
	return sig;
}

bool check_ring_signature_auditable(const Hash &prefix_hash, const std::vector<KeyImage> &images,
    const std::vector<std::vector<PublicKey>> &pubs, const RingSignatureAmethyst &sig) {
	// sanity checks
	if (images.empty() || images.size() != pubs.size() || images.size() != sig.p.size() ||
	    images.size() != sig.ra.size() || images.size() != sig.rb.size() || images.size() != sig.rc.size())
		throw Error("inconsistent images/pubs/sigs size in check_ring_signature_auditable");
	if (!sc_isvalid_vartime(&sig.c0))
		return false;
	DEBUG_PRINT(std::cout << "check_ring_signature_auditable" << std::endl);

	DEBUG_PRINT(std::cout << "prefix_hash=" << prefix_hash << std::endl);
	KeccakStream buf;
	buf << prefix_hash;
	for (size_t i = 0; i != images.size(); ++i) {
		if (pubs[i].empty() || pubs[i].size() != sig.ra[i].size())
			throw Error("inconsistent pubs/sigs size in check_ring_signature_auditable");
		DEBUG_PRINT(std::cout << "image[" << i << "]=" << images[i] << std::endl);
		const P3 b_coin_p3(hash_to_good_point_p3(images[i]));
		const P3 G_plus_B_p3 = P3(G) + b_coin_p3;
		if (!key_in_main_subgroup(sig.p[i]))
			return false;
		if (!sc_isvalid_vartime(&sig.rb[i]) || !sc_isvalid_vartime(&sig.rc[i]))
			return false;

		const P3 p_p3(sig.p[i]);

		buf << sig.p[i];
		DEBUG_PRINT(std::cout << "b_coin[" << i << "]=" << to_bytes(b_coin_p3) << std::endl);
		DEBUG_PRINT(std::cout << "p[" << i << "]=" << sig.p[i] << std::endl);

		const PublicKey z = to_bytes(P3(sig.c0 * p_p3) + P3(sig.rb[i] * H) + P3(sig.rc[i] * b_coin_p3));
		DEBUG_PRINT(std::cout << "z[" << i << "]=" << z << std::endl);
		buf << z;

		const P3 image_p3(images[i]);

		auto next_c = sig.c0;
		for (size_t j = 0; j != pubs[i].size(); ++j) {
			DEBUG_PRINT(std::cout << "pk[" << i << ", " << j << "]=" << pubs[i][j] << std::endl);
			DEBUG_PRINT(std::cout << "c[" << i << ", " << j << "]=" << next_c << std::endl);

			const P3 pubs_i_p3(pubs[i][j]);
			const P3 hash_pubs_i_p3(hash_to_good_point_p3(pubs[i][j]));
			const EllipticCurveScalar &ra = sig.ra[i][j];
			if (!sc_isvalid_vartime(&ra))
				return false;
			DEBUG_PRINT(std::cout << "ra[" << i << ", " << j << "]=" << ra << std::endl);

			const auto x = to_bytes(next_c * (pubs_i_p3 - p_p3) + ra * G_plus_B_p3);
			const auto y = to_bytes(next_c * image_p3 + ra * hash_pubs_i_p3);
			DEBUG_PRINT(std::cout << "x[" << i << ", " << j << "]=" << x << std::endl);
			DEBUG_PRINT(std::cout << "y[" << i << ", " << j << "]=" << y << std::endl);

			if (j == pubs[i].size() - 1) {
				buf << x << y;
			} else {
				KeccakStream c_buf;
				c_buf << prefix_hash << x << y;
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

SendproofSignatureAmethyst generate_sendproof_signature_auditable(
    const Hash &prefix_hash, const KeyImage &image, const SecretKey &sec_spend, const SecretKey &sec_audit) {
	check_scalar(sec_spend);
	check_scalar(sec_audit);
	DEBUG_PRINT(std::cout << "generate_sendproof_signature_auditable" << std::endl);

	KeccakStream buf;
	buf << prefix_hash;

	DEBUG_PRINT(std::cout << "prefix_hash=" << prefix_hash << std::endl);

	DEBUG_PRINT(std::cout << "image=" << image << std::endl);

	const P3 b_coin_p3(hash_to_good_point_p3(image));
	//	b_coins[i] = to_bytes(b_coin_p3);
	//	DEBUG_PRINT(std::cout << "b_coin[" << i << "]=" << b_coins[i] << std::endl);
	const P3 p_p3 = H * sec_spend - b_coin_p3 * sec_audit;
	auto ps       = to_bytes(p_p3);
	buf << ps;
	DEBUG_PRINT(std::cout << "p[" << i << "]=" << ps << std::endl);

	const EllipticCurveScalar kb = random_scalar();
	const EllipticCurveScalar kc = random_scalar();

	const PublicKey z = to_bytes(kb * H + kc * b_coin_p3);
	buf << z;
	DEBUG_PRINT(std::cout << "z[" << i << "]=" << z << std::endl);

	SendproofSignatureAmethyst result;
	result.c0 = buf.hash_to_scalar();
	DEBUG_PRINT(std::cout << "c0=" << result.c0 << std::endl);

	result.rb = kb - result.c0 * sec_spend;
	result.rc = kc + result.c0 * sec_audit;

	DEBUG_PRINT(std::cout << "rb[" << i << "]=" << result.rb << std::endl);
	DEBUG_PRINT(std::cout << "rc[" << i << "]=" << result.rc << std::endl);

	return result;
}

bool check_sendproof_signature_auditable(
    const Hash &prefix_hash, const KeyImage &image, const PublicKey &ps, const SendproofSignatureAmethyst &sig) {
	// sanity checks
	if (!sc_isvalid_vartime(&sig.c0) || !sc_isvalid_vartime(&sig.rb) || !sc_isvalid_vartime(&sig.rc))
		return false;
	DEBUG_PRINT(std::cout << "check_sendproof_signature_auditable" << std::endl);

	DEBUG_PRINT(std::cout << "prefix_hash=" << prefix_hash << std::endl);
	KeccakStream buf;
	buf << prefix_hash << ps;
	const P3 b_coin_p3(hash_to_good_point_p3(image));
	const PublicKey z = to_bytes(P3(sig.c0 * P3(ps)) + P3(sig.rb * H) + P3(sig.rc * b_coin_p3));
	DEBUG_PRINT(std::cout << "z[" << i << "]=" << z << std::endl);
	buf << z;
	const auto c = buf.hash_to_scalar() - sig.c0;
	return sc_iszero(&c) != 0;
}

KeyDerivation generate_key_derivation(const PublicKey &tx_public_key, const SecretKey &view_secret_key) {
	check_scalar(view_secret_key);
	const ge_p3 tx_public_key_p3 = ge_frombytes_vartime(tx_public_key);
	const ge_p3 point3           = ge_scalarmult3(view_secret_key, tx_public_key_p3);
	KeyDerivation derivation;
	static_cast<EllipticCurvePoint &>(derivation) = ge_tobytes(ge_p1p1_to_p2(ge_mul8(point3)));
	return derivation;
}

static SecretKey derivation_to_scalar(const KeyDerivation &derivation, size_t output_index) {
	KeccakStream buf;
	buf << derivation << output_index;
	return buf.hash_to_scalar();
}

PublicKey derive_output_public_key(const KeyDerivation &derivation, size_t output_index, const PublicKey &address_S) {
	const ge_p3 address_S_g3         = ge_frombytes_vartime(address_S);
	const EllipticCurveScalar scalar = derivation_to_scalar(derivation, output_index);
	const ge_cached point3           = ge_p3_to_cached(ge_scalarmult_base(scalar));
	ge_p1p1 point_sum;
	ge_add(&point_sum, &address_S_g3, &point3);
	return ge_tobytes(ge_p1p1_to_p2(point_sum));
}

SecretKey derive_output_secret_key(const KeyDerivation &derivation, size_t output_index, const SecretKey &address_s) {
	check_scalar(address_s);
	const EllipticCurveScalar scalar = derivation_to_scalar(derivation, output_index);
	SecretKey output_secret_key;
	sc_add(&output_secret_key, &address_s, &scalar);
	return output_secret_key;
}

PublicKey underive_address_S(const KeyDerivation &derivation, size_t output_index, const PublicKey &output_public_key) {
	const ge_p3 output_public_key_p3 = ge_frombytes_vartime(output_public_key);
	const EllipticCurveScalar scalar = derivation_to_scalar(derivation, output_index);
	const ge_cached point3           = ge_p3_to_cached(ge_scalarmult_base(scalar));
	ge_p1p1 point_diff;
	ge_sub(&point_diff, &output_public_key_p3, &point3);
	return ge_tobytes(ge_p1p1_to_p2(point_diff));
}

Signature generate_sendproof(const PublicKey &txkey_pub, const SecretKey &txkey_sec,
    const PublicKey &receiver_address_V, const KeyDerivation &derivation, const Hash &message_hash) {
	const ge_p3 receiver_address_V_p3 = ge_frombytes_vartime(receiver_address_V);
	const EllipticCurveScalar k       = random_scalar();

	KeccakStream cr_comm;
	cr_comm << message_hash << txkey_pub << receiver_address_V << derivation << ge_tobytes(ge_scalarmult_base(k));
	const ge_p3 tmp3 = ge_scalarmult3(k, receiver_address_V_p3);
	cr_comm.append(ge_tobytes(ge_p1p1_to_p2(ge_mul8(tmp3))));

	Signature proof;
	proof.c = cr_comm.hash_to_scalar();
	sc_mulsub(&proof.r, &proof.c, &txkey_sec, &k);
	return proof;
}

bool check_sendproof(const PublicKey &txkey_pub, const PublicKey &receiver_address_V, const KeyDerivation &derivation,
    const Hash &message_hash, const Signature &proof) {
	if (!sc_isvalid_vartime(&proof.c) || !sc_isvalid_vartime(&proof.r))
		return false;
	ge_p3 txkey_pub_p3;
	if (ge_frombytes_vartime(&txkey_pub_p3, &txkey_pub) != 0)
		return false;  // tx public keys are not checked by daemon and can be invalid
	const ge_p3 receiver_address_V_g3 = ge_frombytes_vartime(receiver_address_V);  // checked as part of address
	ge_dsmp derivation_dsmp;
	if (!ge_dsm_frombytes_vartime(&derivation_dsmp, derivation))
		return false;
	if (ge_check_subgroup_precomp_vartime(&derivation_dsmp) != 0)
		return false;
	KeccakStream cr_comm;
	cr_comm << message_hash << txkey_pub << receiver_address_V << derivation;
	cr_comm << ge_tobytes(ge_double_scalarmult_base_vartime3(proof.c, txkey_pub_p3, proof.r));
	ge_p3 tmp3 = ge_p1p1_to_p3(ge_mul8(receiver_address_V_g3));
	cr_comm << ge_tobytes(ge_double_scalarmult_precomp_vartime3(proof.r, tmp3, proof.c, derivation_dsmp));
	EllipticCurveScalar h = cr_comm.hash_to_scalar();
	sc_sub(&h, &h, &proof.c);
	return sc_iszero(&h) != 0;
}

void generate_hd_spendkeys(
    const SecretKey &a0, const PublicKey &A_plus_SH, size_t index, std::vector<KeyPair> *result) {
	const ge_p3 A_plus_SH_p3         = ge_frombytes_vartime(A_plus_SH);
	const ge_cached A_plus_SH_cached = ge_p3_to_cached(A_plus_SH_p3);
	for (size_t d = 0; d != result->size(); ++d) {
		KeyPair &res = result->at(d);

		KeccakStream cr_comm;
		cr_comm << A_plus_SH << "address" << (index + d);
		const SecretKey delta_secret_key = cr_comm.hash_to_scalar();
		const ge_p3 delta_public_key_g3  = ge_scalarmult_base(delta_secret_key);

		ge_p1p1 point_sum;
		ge_add(&point_sum, &delta_public_key_g3, &A_plus_SH_cached);
		res.public_key = ge_tobytes(ge_p1p1_to_p2(point_sum));

		if (a0 == SecretKey{}) {
			res.secret_key = SecretKey{};
		} else {
			sc_add(&res.secret_key, &delta_secret_key, &a0);
		}
	}
}

// base + Hs(seed|index)*mul
PublicKey generate_hd_spendkey(
    const PublicKey &v_mul_A_plus_SH, const PublicKey &A_plus_SH, const PublicKey &V, size_t index) {
	const ge_p3 v_mul_A_plus_SH_p3 = ge_frombytes_vartime(v_mul_A_plus_SH);
	const ge_p3 V_p3               = ge_frombytes_vartime(V);
	KeccakStream cr_comm;
	cr_comm << A_plus_SH << "address" << index;
	const SecretKey delta_secret_key = cr_comm.hash_to_scalar();
	return ge_tobytes(ge_add(v_mul_A_plus_SH_p3, ge_scalarmult3(delta_secret_key, V_p3)));
}

SecretKey generate_hd_secretkey(const SecretKey &a0, const PublicKey &A_plus_SH, size_t index) {
	KeccakStream cr_comm;
	cr_comm << A_plus_SH << "address" << index;
	SecretKey delta_secret_key = cr_comm.hash_to_scalar();
	SecretKey result;
	sc_add(&result, &delta_secret_key, &a0);
	return result;
}

PublicKey A_plus_b_H(const PublicKey &A, const SecretKey &b) {
	const ge_p3 A_p3 = ge_frombytes_vartime(A);
	return ge_tobytes(ge_add(A_p3, ge_scalarmult3(b, H_p3)));
}

PublicKey A_plus_B(const PublicKey &A, const PublicKey &B) { return to_bytes(P3(A) + P3(B)); }

PublicKey A_minus_B(const PublicKey &A, const PublicKey &B) { return to_bytes(P3(A) - P3(B)); }

PublicKey A_minus_b_H(const PublicKey &A, const SecretKey &b) {
	const ge_p3 A_p3 = ge_frombytes_vartime(A);
	return ge_tobytes(ge_sub(A_p3, ge_scalarmult3(b, H_p3)));
}

PublicKey A_mul_b(const PublicKey &A, const SecretKey &b) {
	const ge_p3 A_p3 = ge_frombytes_vartime(A);
	check_scalar(b);
	return ge_tobytes(ge_scalarmult3(b, A_p3));
}

PublicKey secret_keys_to_public_key(const SecretKey &a, const SecretKey &s) {
	return ge_tobytes(ge_add(ge_scalarmult_base(a), ge_scalarmult3(s, H_p3)));
}

// v, s - common for all addresses        *** v common for all addresses, s = 0
// S(i) = (a(i)*G+s*H)                    *** S(i) = a(i) * G
// V(i) = S(I)*v                          *** V(i) = v * G
// create map S -> WalletRecord

// In tx we generate per-output deterministic secret
// q = deterministic(wallet_seed_special_for_k | inputs | #o)
// Q = q*G
// K = Hp(Q)                              *** k = Hs(Q)

// P.S. If we need more secret bytes, we do k(suffix) = H(Q | suffix)

// In tx, there is 2 values per output T (encrypted output secret) and P (output public key)

// T = K + inv(H(K|inputs|#o))*V(i)       ***  T = k * V(i)
// P = inv(H(K|inputs|#o))*S(i)           ***  P = S(i) + H(k*G|inputs|#o)*G

// look for our output
// K' = T - P*v                           ***  D = inv(v) * T
// S' = H(K'|inputs|#o)*P in map          ***  S' = P - H(D|inputs|#o)*G

// if found in map, then secret output key(s)
// p_s = inv(H(K'|inputs|#o))*s           ***  p_s = 0
// p_a = inv(H(K'|inputs|#o))*a(i)        ***  p_a = a(i) + H(D|inputs|#o)

// send_proof

// proof of send to address s*G is array of
// (Q, txid, message, address)         *** (Q, txid, message, address)
// plus count of records (so that proof cannot be split)
// signed by q

PublicKey linkable_derive_output_public_key(const SecretKey &output_secret, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &address_S, const PublicKey &address_V, PublicKey *encrypted_output_secret) {
	check_scalar(output_secret);
	const ge_p3 view_secret_key_p3 = ge_frombytes_vartime(address_V);
	*encrypted_output_secret       = ge_tobytes(ge_scalarmult3(output_secret, view_secret_key_p3));

	const EllipticCurvePoint derivation = ge_tobytes(ge_scalarmult_base(output_secret));
	//	std::cout << "derivation=" << derivation << std::endl;

	KeccakStream cr_comm;
	cr_comm << derivation << tx_inputs_hash << output_index;
	const EllipticCurveScalar derivation_hash = cr_comm.hash_to_scalar();
	//	std::cout << "derivation_hash=" << derivation_hash << std::endl;

	const ge_cached point3 = ge_p3_to_cached(ge_scalarmult_base(derivation_hash));

	const ge_p3 address_s_g3 = ge_frombytes_vartime(address_S);
	ge_p1p1 point_sum;
	ge_add(&point_sum, &address_s_g3, &point3);
	return ge_tobytes(ge_p1p1_to_p2(point_sum));
}

PublicKey linkable_underive_address_S(const SecretKey &inv_view_secret_key, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &output_public_key, const PublicKey &encrypted_output_secret,
    SecretKey *spend_scalar) {
	check_scalar(inv_view_secret_key);
	const ge_p3 encrypted_output_secret_p3 = ge_frombytes_vartime(encrypted_output_secret);
	const EllipticCurvePoint derivation = ge_tobytes(ge_scalarmult3(inv_view_secret_key, encrypted_output_secret_p3));
	//	std::cout << "derivation=" << derivation << std::endl;

	KeccakStream cr_comm;
	cr_comm << derivation << tx_inputs_hash << output_index;
	*spend_scalar = cr_comm.hash_to_scalar();
	//	std::cout << "derivation_hash=" << *spend_scalar << std::endl;

	const ge_p3 output_public_key_g3 = ge_frombytes_vartime(output_public_key);
	const ge_cached point3           = ge_p3_to_cached(ge_scalarmult_base(*spend_scalar));
	ge_p1p1 point_diff;
	ge_sub(&point_diff, &output_public_key_g3, &point3);
	return ge_tobytes(ge_p1p1_to_p2(point_diff));
}

SecretKey linkable_derive_output_secret_key(const SecretKey &address_s, const SecretKey &spend_scalar) {
	check_scalar(address_s);
	check_scalar(spend_scalar);
	SecretKey output_secret_key;
	sc_add(&output_secret_key, &address_s, &spend_scalar);
	return output_secret_key;
}

void linkable_underive_address(const SecretKey &output_secret, const Hash &tx_inputs_hash, size_t output_index,
    const PublicKey &output_public_key, const PublicKey &encrypted_output_secret, PublicKey *address_S,
    PublicKey *address_V) {
	check_scalar(output_secret);
	const EllipticCurvePoint derivation = ge_tobytes(ge_scalarmult_base(output_secret));

	KeccakStream cr_comm;
	cr_comm << derivation << tx_inputs_hash << output_index;
	const EllipticCurveScalar derivation_hash = cr_comm.hash_to_scalar();

	const ge_cached point3 = ge_p3_to_cached(ge_scalarmult_base(derivation_hash));

	const ge_p3 output_public_key_g3 = ge_frombytes_vartime(output_public_key);
	ge_p1p1 point_diff;
	ge_sub(&point_diff, &output_public_key_g3, &point3);
	*address_S = ge_tobytes(ge_p1p1_to_p2(point_diff));

	const SecretKey inv_output_secret = sc_invert(output_secret);

	const ge_p3 encrypted_output_secret_g3 = ge_frombytes_vartime(encrypted_output_secret);
	*address_V                             = ge_tobytes(ge_scalarmult3(inv_output_secret, encrypted_output_secret_g3));
}

void test_linkable() {
	const SecretKey output_secret       = random_scalar();
	const Hash tx_inputs_hash           = rand<Hash>();
	const size_t output_index           = rand<size_t>();
	const KeyPair spend_keypair         = random_keypair();
	const KeyPair view_keypair          = random_keypair();
	const SecretKey inv_view_secret_key = sc_invert(view_keypair.secret_key);

	PublicKey encrypted_output_secret;
	PublicKey output_public_key = linkable_derive_output_public_key(output_secret, tx_inputs_hash, output_index,
	    spend_keypair.public_key, view_keypair.public_key, &encrypted_output_secret);

	SecretKey spend_scalar;
	PublicKey address_S2 = linkable_underive_address_S(
	    inv_view_secret_key, tx_inputs_hash, output_index, output_public_key, encrypted_output_secret, &spend_scalar);
	if (address_S2 != spend_keypair.public_key)
		throw Error("Aha");
	SecretKey output_secret_key2 = linkable_derive_output_secret_key(spend_keypair.secret_key, spend_scalar);
	PublicKey output_public_key2;
	if (!secret_key_to_public_key(output_secret_key2, &output_public_key2) || output_public_key2 != output_public_key)
		throw Error("Oho");
	PublicKey address_S3;
	PublicKey address_V3;
	linkable_underive_address(output_secret, tx_inputs_hash, output_index, output_public_key, encrypted_output_secret,
	    &address_S3, &address_V3);
	if (address_S3 != spend_keypair.public_key || address_V3 != view_keypair.public_key)
		throw Error("Uhu");
}

PublicKey unlinkable_derive_output_public_key(const PublicKey &output_secret, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &address_S, const PublicKey &address_SV, PublicKey *encrypted_output_secret) {
	DEBUG_PRINT(std::cout << "output_secret=" << output_secret << std::endl);
	const ge_p3 address_s_p3     = ge_frombytes_vartime(address_S);
	const ge_p3 address_sv_p3    = ge_frombytes_vartime(address_SV);
	const ge_p3 output_secret_p3 = ge_frombytes_vartime(output_secret);

	KeccakStream cr_comm;
	cr_comm << output_secret << tx_inputs_hash << output_index;
	const SecretKey spend_scalar = cr_comm.hash_to_scalar();
	DEBUG_PRINT(std::cout << "spend_scalar=" << spend_scalar << std::endl);

	const SecretKey inv_spend_scalar = sc_invert(spend_scalar);
	DEBUG_PRINT(std::cout << "inv_spend_scalar=" << inv_spend_scalar << std::endl);
	PublicKey output_public_key = ge_tobytes(ge_scalarmult3(inv_spend_scalar, address_s_p3));

	*encrypted_output_secret = ge_tobytes(ge_add(output_secret_p3, ge_scalarmult3(inv_spend_scalar, address_sv_p3)));
	return output_public_key;
}

// T = K + inv(H(K|inputs|#o))*(v*s*G)    ***  T = k * (v*G)
// P = inv(H(K|inputs|#o))*s*G            ***  P = S + H(k*G|inputs|#o)*G

// look for our output
// K' = T - P*v                           ***  D = inv(v) * T
// S' = H(K'|inputs|#o)*P in map          ***  S' = P - H(D|inputs|#o)*G

PublicKey unlinkable_underive_address_S(const SecretKey &view_secret_key, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &output_public_key, const PublicKey &encrypted_output_secret,
    SecretKey *spend_scalar) {
	check_scalar(view_secret_key);
	const ge_p3 output_public_key_p3       = ge_frombytes_vartime(output_public_key);
	const ge_p3 encrypted_output_secret_p3 = ge_frombytes_vartime(encrypted_output_secret);
	//	const ge_cached p_v_cached             = ge_p3_to_cached();
	//	ge_p1p1 point_diff;
	//	ge_sub(&point_diff, &encrypted_output_secret_p3, &p_v_cached);

	const PublicKey output_secret =
	    ge_tobytes(ge_sub(encrypted_output_secret_p3, ge_scalarmult3(view_secret_key, output_public_key_p3)));
	DEBUG_PRINT(std::cout << "output_secret=" << output_secret << std::endl);

	KeccakStream cr_comm;
	cr_comm << output_secret << tx_inputs_hash << output_index;
	*spend_scalar = cr_comm.hash_to_scalar();
	DEBUG_PRINT(std::cout << "spend_scalar=" << *spend_scalar << std::endl);

	PublicKey result = ge_tobytes(ge_scalarmult3(*spend_scalar, output_public_key_p3));
	{
		PublicKey P_v2 = unlinkable_underive_address_S_step1(view_secret_key, output_public_key);
		SecretKey spend_scalar2;
		PublicKey result2 = unlinkable_underive_address_S_step2(
		    P_v2, tx_inputs_hash, output_index, output_public_key, encrypted_output_secret, &spend_scalar2);
		if (result != result2 || *spend_scalar != spend_scalar2)
			throw Error("unlinkable_underive_public_key steps error");
	}
	return result;
}

PublicKey unlinkable_underive_address_S_step1(const SecretKey &view_secret_key, const PublicKey &output_public_key) {
	check_scalar(view_secret_key);
	const ge_p3 output_public_key_p3 = ge_frombytes_vartime(output_public_key);
	return ge_tobytes(ge_scalarmult3(view_secret_key, output_public_key_p3));
}

PublicKey unlinkable_underive_address_S_step2(const PublicKey &P_v, const Hash &tx_inputs_hash, size_t output_index,
    const PublicKey &output_public_key, const PublicKey &encrypted_output_secret, SecretKey *spend_scalar) {
	const ge_p3 p_v_p3                     = ge_frombytes_vartime(P_v);
	const ge_p3 output_public_key_p3       = ge_frombytes_vartime(output_public_key);
	const ge_p3 encrypted_output_secret_p3 = ge_frombytes_vartime(encrypted_output_secret);
	const ge_cached p_v_cached             = ge_p3_to_cached(p_v_p3);
	ge_p1p1 point_diff;
	ge_sub(&point_diff, &encrypted_output_secret_p3, &p_v_cached);

	const PublicKey output_secret = ge_tobytes(ge_p1p1_to_p2(point_diff));
	//	std::cout << "output_secret=" << output_secret << std::endl;

	KeccakStream cr_comm;
	cr_comm << output_secret << tx_inputs_hash << output_index;
	*spend_scalar = cr_comm.hash_to_scalar();
	//	std::cout << "spend_scalar=" << *spend_scalar << std::endl;

	return ge_tobytes(ge_scalarmult3(*spend_scalar, output_public_key_p3));
}

SecretKey unlinkable_derive_output_secret_key(const SecretKey &address_secret, const SecretKey &spend_scalar) {
	check_scalar(address_secret);
	check_scalar(spend_scalar);
	const SecretKey inv_spend_scalar = sc_invert(spend_scalar);
	return sc_mul(inv_spend_scalar, address_secret);
}

void unlinkable_underive_address(PublicKey *address_S, PublicKey *address_Sv, const PublicKey &output_secret,
    const Hash &tx_inputs_hash, size_t output_index, const PublicKey &output_public_key,
    const PublicKey &encrypted_output_secret) {
	const ge_p3 output_public_key_p3       = ge_frombytes_vartime(output_public_key);
	const ge_p3 output_secret_p3           = ge_frombytes_vartime(output_secret);
	const ge_p3 encrypted_output_secret_p3 = ge_frombytes_vartime(encrypted_output_secret);

	KeccakStream cr_comm;
	cr_comm << output_secret << tx_inputs_hash << output_index;
	const SecretKey spend_scalar = cr_comm.hash_to_scalar();

	*address_S = ge_tobytes(ge_scalarmult3(spend_scalar, output_public_key_p3));

	const ge_cached p_v = ge_p3_to_cached(output_secret_p3);
	ge_p1p1 point_diff;
	ge_sub(&point_diff, &encrypted_output_secret_p3, &p_v);

	const ge_p3 t_minus_k = ge_p1p1_to_p3(point_diff);

	*address_Sv = ge_tobytes(ge_scalarmult3(spend_scalar, t_minus_k));
}

void test_unlinkable() {
	const PublicKey output_secret = random_keypair().public_key;
	const Hash tx_inputs_hash     = rand<Hash>();
	const size_t output_index     = rand<size_t>() % 100;
	const KeyPair spend_keypair   = random_keypair();
	//	KeyPair spend_keypair;
	//	secret_key_to_public_key(spend_keypair.secret_key, &spend_keypair.public_key);
	const KeyPair view_keypair        = random_keypair();
	const KeyPair audit_key_base_pair = random_keypair();

	//	auto A_plus_SH = A_plus_b_H(audit_key_base_pair.public_key, spend_keypair.secret_key);

	//	std::vector<KeyPair> key_result;
	//	key_result.resize(result.size());
	//	crypto::generate_hd_spendkeys(m_audit_key_base.secret_key, m_A_plus_SH, counter, &key_result);

	const PublicKey address_S  = A_plus_b_H(audit_key_base_pair.public_key, spend_keypair.secret_key);
	const PublicKey address_Sv = A_mul_b(address_S, view_keypair.secret_key);

	std::cout << "address_S=" << address_S << std::endl;
	std::cout << "address_Sv=" << address_Sv << std::endl;

	PublicKey encrypted_output_secret;
	PublicKey output_public_key = unlinkable_derive_output_public_key(
	    output_secret, tx_inputs_hash, output_index, address_S, address_Sv, &encrypted_output_secret);

	SecretKey spend_scalar;
	PublicKey address_S2 = unlinkable_underive_address_S(view_keypair.secret_key, tx_inputs_hash, output_index,
	    output_public_key, encrypted_output_secret, &spend_scalar);
	std::cout << "address_s2=" << address_S2 << std::endl;
	if (address_S2 != address_S)
		throw Error("Aha");
	SecretKey output_secret_key2_s = unlinkable_derive_output_secret_key(spend_keypair.secret_key, spend_scalar);
	SecretKey output_secret_key2_a = unlinkable_derive_output_secret_key(audit_key_base_pair.secret_key, spend_scalar);
	PublicKey output_public_key2   = secret_keys_to_public_key(output_secret_key2_a, output_secret_key2_s);
	if (output_public_key2 != output_public_key)
		throw Error("Oho");
	const auto keyimage = generate_key_image(output_public_key, output_secret_key2_a);
	PublicKey address_S3;
	PublicKey address_Sv3;
	unlinkable_underive_address(&address_S3, &address_Sv3, output_secret, tx_inputs_hash, output_index,
	    output_public_key, encrypted_output_secret);
	if (address_S3 != address_S || address_Sv3 != address_Sv)
		throw Error("Uhu");
	std::vector<KeyImage> images{keyimage};
	std::vector<std::vector<PublicKey>> pubs(1);
	pubs.back().push_back(random_keypair().public_key);
	pubs.back().push_back(random_keypair().public_key);
	pubs.back().push_back(output_public_key);
	pubs.back().push_back(random_keypair().public_key);

	std::vector<SecretKey> sec_s{output_secret_key2_s};
	std::vector<SecretKey> sec_a{output_secret_key2_a};
	std::vector<size_t> sec_indexes{2};

	const Hash tx_prefix_hash = rand<Hash>();
	auto sig = generate_ring_signature_auditable(tx_prefix_hash, images, pubs, sec_s, sec_a, sec_indexes);
	if (!check_ring_signature_auditable(tx_prefix_hash, images, pubs, sig))
		throw Error("Yhy");
	sig.ra.back().back().data[0] += 1;
	if (check_ring_signature_auditable(tx_prefix_hash, images, pubs, sig))
		throw Error("Xhx");
}

// outputs_count protects against splitting proof into valid proofs with smaller amounts
// of course, send proof creator can choose to include any set of outputs
/*Signature amethyst_generate_sendproof(const KeyPair &output_det_keys, const Hash &tid, const Hash &message_hash,
    const std::string &address, size_t outputs_count) {
    KeccakStream cr_comm;
    cr_comm << tid << message_hash << outputs_count;
    cr_comm.append(address.data(), address.size());
    const Hash hash = cr_comm.cn_fast_hash();
    return generate_signature(hash, output_det_keys.public_key, output_det_keys.secret_key);
}

bool amethyst_check_sendproof(const PublicKey &output_det_key, const Hash &tid, const Hash &message_hash,
    const std::string &address, size_t outputs_count, const Signature &sig) {
    KeccakStream cr_comm;
    cr_comm << tid << message_hash << outputs_count;
    cr_comm.append(address.data(), address.size());
    const Hash hash = cr_comm.cn_fast_hash();
    return check_signature(hash, output_det_key, sig);
}*/

}  // namespace crypto
