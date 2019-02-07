// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for
// details.

//#include <cstddef>
//#include <cstring>
#include <fstream>
#include <map>
#include <vector>
#include "common/Invariant.hpp"
#include "crypto/bernstein/crypto-ops.h"

#include "test_crypto.hpp"

#include "../io.hpp"
#include "benchmarks.hpp"
#include "common/StringTools.hpp"
#include "crypto/bernstein/crypto-ops.h"
#include "crypto/crypto.hpp"
#include "crypto/crypto_helpers.hpp"
#include "crypto/hash.hpp"
#include "crypto/random.h"

static void check(bool expr, size_t test) {
	if (expr)
		return;
	std::cerr << "Wrong result on test " << test << std::endl;
	throw std::runtime_error("test_crypto failed");
}

using namespace crypto;

void test_check_scalar(std::fstream &input, size_t test) {
	EllipticCurveScalar scalar;
	bool expected = false;
	get(input, scalar, expected);
	const bool actual = sc_isvalid_vartime(&scalar) != 0;
	check(expected == actual, test);
}

void test_hash_to_scalar(std::fstream &input, size_t test) {
	std::vector<char> data;
	EllipticCurveScalar expected;
	get(input, data, expected);
	const auto actual = hash_to_scalar(data.data(), data.size());
	check(expected == actual, test);
}

void test_random_scalar(std::fstream &input, size_t test) {
	EllipticCurveScalar expected, actual;
	get(input, expected);
	actual = random_scalar();
	check(expected == actual, test);

	// We do not have separate tests for inversions, so perform it on
	// random_scalars
	EllipticCurveScalar inv_actual, inv_inv_actual;
	EllipticCurveScalar b, inv_b, inv_inv_b, a_b, inv_a_inv_b, inv_a_b;
	b = hash_to_scalar(actual.data, sizeof(actual.data));
	// FIXME move inversion tests to separate function
	sc_invert(&inv_actual, &actual);
	sc_invert(&inv_inv_actual, &inv_actual);
	sc_invert(&inv_b, &b);
	sc_invert(&inv_inv_b, &inv_b);
	invariant(actual == inv_inv_actual, "");
	invariant(b == inv_inv_b, "");
	sc_mul(&a_b, &actual, &b);
	sc_mul(&inv_a_inv_b, &inv_actual, &inv_b);
	sc_invert(&inv_a_b, &a_b);
	invariant(inv_a_inv_b == inv_a_b, "");

	EllipticCurveScalar one, inv_one, real_one;
	sc_1(&real_one);
	sc_mul(&one, &actual, &inv_actual);
	invariant(one == real_one, "");
	sc_mul(&one, &b, &inv_b);
	invariant(one == real_one, "");
	sc_invert(&inv_one, &one);
	invariant(one == inv_one, "");
}

void test_generate_keys(std::fstream &input, size_t test) {
	PublicKey expected1, actual1;
	SecretKey expected2, actual2;
	get(input, expected1, expected2);
	random_keypair(actual1, actual2);
	check(expected1 == actual1, test);
	check(expected2 == actual2, test);
}

void test_check_key(std::fstream &input, size_t test) {
	PublicKey key;
	bool expected = false;
	get(input, key, expected);
	const bool actual = key_isvalid(key);
	check(expected == actual, test);
}

void test_secret_key_to_public_key(std::fstream &input, size_t test) {
	SecretKey sec;
	bool expected1 = false;
	PublicKey expected2, actual2;
	get(input, sec, expected1);
	if (expected1) {
		get(input, expected2);
	}
	const bool actual1 = secret_key_to_public_key(sec, &actual2);
	check(!(expected1 != actual1 || (expected1 && expected2 != actual2)), test);
}

void test_generate_key_derivation(std::fstream &input, size_t test) {
	PublicKey key1;
	SecretKey key2;
	bool expected1 = false;
	KeyDerivation expected2;
	get(input, key1, key2, expected1);
	if (expected1) {
		get(input, expected2);
	}
	try {
		const auto actual2 = generate_key_derivation(key1, key2);
		check(actual2 == expected2, test);
	} catch (const std::exception &) {
		check(!expected1, test);
	}
}

void test_derive_public_key(std::fstream &input, size_t test) {
	KeyDerivation derivation;
	size_t output_index;
	PublicKey base;
	bool expected1 = false;
	PublicKey expected2;
	get(input, derivation, output_index, base, expected1);
	if (expected1) {
		get(input, expected2);
	}
	try {
		const auto actual2 = derive_output_public_key(derivation, output_index, base);
		check(actual2 == expected2, test);
	} catch (const std::exception &) {
		check(!expected1, test);
	}
}

void test_derive_secret_key(std::fstream &input, size_t test) {
	KeyDerivation derivation;
	size_t output_index;
	SecretKey base;
	SecretKey expected, actual;
	get(input, derivation, output_index, base, expected);
	//			try {
	actual = derive_output_secret_key(derivation, output_index, base);
	//			}catch(const std::exception &){
	//			}
	check(expected == actual, test);
}

void test_underive_public_key(std::fstream &input, size_t test) {
	KeyDerivation derivation;
	size_t output_index;
	PublicKey derived_key;
	bool expected1 = false;
	PublicKey expected2;
	get(input, derivation, output_index, derived_key, expected1);
	if (expected1) {
		get(input, expected2);
	}
	try {
		const auto actual2 = underive_address_S(derivation, output_index, derived_key);
		check(actual2 == expected2, test);
	} catch (const std::exception &) {
		check(!expected1, test);
	}
}

void test_generate_signature(std::fstream &input, size_t test) {
	Hash prefix_hash;
	PublicKey pub;
	SecretKey sec;
	Signature expected;
	get(input, prefix_hash, pub, sec, expected);
	const auto actual = generate_signature(prefix_hash, pub, sec);
	check(expected == actual, test);
}

void test_check_signature(std::fstream &input, size_t test) {
	Hash prefix_hash;
	PublicKey pub;
	Signature sig;
	bool expected = false;
	get(input, prefix_hash, pub, sig, expected);
	const bool actual = check_signature(prefix_hash, pub, sig);
	check(expected == actual, test);
}

void test_hash_to_point(std::fstream &input, size_t test) {
	Hash h;
	EllipticCurvePoint expected;
	get(input, h, expected);
	const auto actual = bytes_to_bad_point(h);
	check(expected == actual, test);
}

void test_hash_to_ec(std::fstream &input, size_t test) {
	PublicKey key;
	EllipticCurvePoint expected;
	get(input, key, expected);
	const auto actual = hash_to_good_point(key);
	check(expected == actual, test);
}

void test_generate_key_image(std::fstream &input, size_t test) {
	PublicKey pub;
	SecretKey sec;
	KeyImage expected;
	get(input, pub, sec, expected);
	const auto actual = generate_key_image(pub, sec);
	check(expected == actual, test);
}

void test_generate_ring_signature(std::fstream &input, size_t test) {
	Hash prefix_hash;
	KeyImage image;
	std::vector<PublicKey> vpubs;
	//			std::vector<const crypto::PublicKey *> pubs;
	size_t pubs_count;
	SecretKey sec;
	size_t sec_index;
	RingSignature expected;
	get(input, prefix_hash, image, pubs_count);
	vpubs.resize(pubs_count);
	//			pubs.resize(pubs_count);
	for (size_t i = 0; i < pubs_count; i++) {
		get(input, vpubs[i]);
		//				pubs[i] = &vpubs[i];
	}
	get(input, sec, sec_index);
	expected.resize(pubs_count);
	getvar(input, pubs_count * sizeof(Signature), expected.data());
	const auto actual = generate_ring_signature(prefix_hash, image, vpubs.data(), vpubs.size(), sec, sec_index);
	check(expected == actual, test);
	// TODO - better tests for half-size ring signatures

	/*			We started to use rng in borromean and auditable signatures, so we cannot
	            pass tests that rely on deterministic rng
	            static std::vector<crypto::KeyImage> images;
	            static std::vector<crypto::SecretKey> secs;
	            static std::vector<std::vector<crypto::PublicKey>> pubss;
	            static std::vector<size_t> sec_indexes;
	            images.push_back(image);
	            secs.push_back(sec);
	            pubss.push_back(vpubs);
	            sec_indexes.push_back(sec_index);
	            if (images.size() > 32) {
	                crypto::RingSignatureBorromean sig3 =
	                    crypto::generate_ring_signature_borromean(prefix_hash, images, pubss, secs, sec_indexes);
	                bool checked = crypto::check_ring_signature_borromean(prefix_hash, images, pubss, sig3);
	                sig3.r.at(0).at(0).data[13] += 1;
	                bool checked2 = crypto::check_ring_signature_borromean(prefix_hash, images, pubss, sig3);
	                invariant(checked && !checked2, "");

	                images.clear();
	                secs.clear();
	                pubss.clear();
	                sec_indexes.clear();
	            }*/
}

void test_check_ring_signature(std::fstream &input, size_t test) {
	Hash prefix_hash;
	KeyImage image;
	std::vector<PublicKey> vpubs;
	//			std::vector<const crypto::PublicKey *> pubs;
	size_t pubs_count;
	RingSignature sigs;
	bool expected = false;
	size_t i;
	get(input, prefix_hash, image, pubs_count);
	vpubs.resize(pubs_count);
	for (i = 0; i < pubs_count; i++) {
		get(input, vpubs[i]);
	}
	sigs.resize(pubs_count);
	getvar(input, pubs_count * sizeof(Signature), sigs.data());
	get(input, expected);
	const bool actual = check_ring_signature(prefix_hash, image, vpubs.data(), vpubs.size(), sigs);
	check(expected == actual, test);
}

void strange_add() {
	SecretKey a, b, c;
	PublicKey A, B, C;
	invariant(common::pod_from_hex("3930bd5216d5e7fe00625982026b40553457870474fd3466b4454a7b49398d0a", &a), "");
	invariant(common::pod_from_hex("f303536f2dee4b4f38232f41b12411eeb02d3fc76e0536fc23f81b2630489f0d", &b), "");
	invariant(common::pod_from_hex("1cbd29783c1ccf7868c888319717fc5fe76fc83b251a057fe8eef19750ac8b0f", &c), "");
	check_scalar(a);
	check_scalar(b);
	check_scalar(c);

	invariant(common::pod_from_hex("4c7335be6898dcd7a3c8c5b9436b93bace5209f53486a732bc4ec00a2db5d6ee", &A), "");
	invariant(common::pod_from_hex("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94", &B), "");
	invariant(common::pod_from_hex("d3ed97a11ce0d238382ed8ee60064d5fbcef928988c658e7c1ca42ec8b1a1a2e", &C), "");
	invariant(key_in_main_subgroup(A), "");
	invariant(key_in_main_subgroup(B), "");
	invariant(key_in_main_subgroup(C), "");

	const ge_p3 A_p3 = ge_frombytes_vartime(A);
	const ge_p3 B_p3 = ge_frombytes_vartime(B);  // or get_H_p3();
	const ge_p3 C_p3 = ge_frombytes_vartime(C);

	const ge_p3 tmp_a_A = ge_scalarmult3(a, A_p3);
	const ge_p3 tmp_b_B = ge_scalarmult3(b, B_p3);
	const ge_p3 tmp_c_C = ge_scalarmult3(c, C_p3);
	invariant(key_in_main_subgroup(ge_tobytes(tmp_a_A)), "");
	invariant(key_in_main_subgroup(ge_tobytes(tmp_b_B)), "");
	invariant(key_in_main_subgroup(ge_tobytes(tmp_c_C)), "");
	{
		ge_dsmp dsm;
		ge_dsm_precomp(&dsm, &B_p3);
		ge_p3 tmp1    = ge_double_scalarmult_precomp_vartime3(a, A_p3, b, dsm);
		ge_p3 result1 = ge_add(tmp1, tmp_c_C);
		std::cout << "result1=" << ge_tobytes(result1) << std::endl;
		std::cout << "tmp1=" << ge_tobytes(tmp1) << std::endl;
		std::cout << "a_A + b_B =" << ge_tobytes(ge_add(tmp_a_A, tmp_b_B)) << std::endl;
		tmp1    = ge_frombytes_vartime(ge_tobytes(tmp1));
		result1 = ge_add(tmp1, tmp_c_C);
		std::cout << "result1(to-from)=" << ge_tobytes(result1) << std::endl;
	}
	{
		ge_dsmp dsm;
		ge_dsm_precomp(&dsm, &C_p3);
		ge_p3 tmp2    = ge_double_scalarmult_precomp_vartime3(b, B_p3, c, dsm);
		ge_p3 result2 = ge_add(tmp_a_A, tmp2);
		std::cout << "result2=" << ge_tobytes(result2) << std::endl;
		std::cout << "tmp2=" << ge_tobytes(tmp2) << std::endl;
		std::cout << "b_B + c_C =" << ge_tobytes(ge_add(tmp_b_B, tmp_c_C)) << std::endl;
		tmp2    = ge_frombytes_vartime(ge_tobytes(tmp2));
		result2 = ge_add(tmp_a_A, tmp2);
		std::cout << "result1(to-from)=" << ge_tobytes(result2) << std::endl;
	}
	{
		ge_p3 result3 = ge_add(ge_add(tmp_a_A, tmp_b_B), tmp_c_C);
		std::cout << "result3=" << ge_tobytes(result3) << std::endl;
	}
}

void test_crypto(const std::string &test_vectors_filename) {
	//	strange_add();
	std::cout << "G=" << crypto::get_G() << std::endl;
	std::cout << "H=" << crypto::get_H() << std::endl;
	invariant(crypto::get_H() == crypto::test_get_H(), "");

	//	SecretKey sk;
	//	sk.data[0] = 8;
	//	std::cout << ge_tobytes(ge_scalarmult_base(sk)) << std::endl;
	PublicKey pk = common::pfh<PublicKey>("409c2e98dfebfd5ea008ecd4b60b4535fb553a63175396e0f37811c6e84ff134");

	std::cout << "cn_fast_hash(pk): " << crypto::cn_fast_hash(pk.data, sizeof(pk.data)) << std::endl;
	std::cout << "hash_to_scalar(pk)" << crypto::hash_to_scalar(pk.data, sizeof(pk.data)) << std::endl;
	Hash h  = cn_fast_hash(pk.data, sizeof(pk.data));
	Hash h2 = cn_fast_hash(h.data, sizeof(h.data));
	std::cout << "cn_fast_hash(pk):               " << h << std::endl;
	std::cout << "cn_fast_hash(cn_fast_hash(pk)): " << h2 << std::endl;

	uint8_t buf[64]{};
	memcpy(buf, h.data, 32);
	memcpy(buf + 32, h2.data, 32);
	SecretKey result;
	sc_reduce64(&result, buf);
	std::cout << result << std::endl;
	//	std::cout << crypto::hash_to_scalar64(pk.data, sizeof(pk.data)) << std::endl;

	P3 p1        = crypto::hash_to_good_point_p3(pk);
	P3 p2        = crypto::hash_to_good_point_p3(pk);
	SecretKey s1 = crypto::hash_to_scalar(pk.data, sizeof(pk.data));
	SecretKey s2 = crypto::hash_to_scalar(pk.data, sizeof(pk.data));

	std::cout << "Identity group element as EllipticCurvePoint: " << to_bytes(I) << std::endl;

	SecretKey s3 = s1 - s2;
	s3 -= s2;
	SecretKey s5 = s1 + s2;
	s5 += s2;
	SecretKey s4 = s1 - s2 * s3;
	s4 -= s3 * s4;

	P3 r1 = s1 * G + s2 * p2;
	P3 r2 = s1 * p1 + s2 * p2;
	P3 r3 = s1 * p1 + s2 * G;
	P3 r4 = p1 + s2 * G;
	P3 r5 = s1 * p1 + p2;
	P3 r6 = p1 + s1 * G + s2 * p2;
	P3 r7 = s1 * p1 + s2 * G + p2;
	P3 r8 = s1 * (p1 + p2) + s2 * G;

	r2 += r3 + G;
	r4 += r5;
	r6 *= s1;

	P3 zero_point(PublicKey{});
	std::cout << key_in_main_subgroup(PublicKey{}) << std::endl;
	zero_point = P3();
	std::cout << "Zero EllipticCurvePoint is in main subgroup: " << key_in_main_subgroup(PublicKey{}) << std::endl;

	std::cout << "Sum of two zero EllipticCurvePoint's: " << to_bytes(zero_point + zero_point) << std::endl;
	std::cout << "Sum of two identity elements: " << to_bytes(I + I) << std::endl;
	std::cout << to_bytes(r1) << " " << to_bytes(r7) << " " << to_bytes(r8) << std::endl;

	crypto::test_unlinkable();

	std::map<std::string, void (*)(std::fstream &, size_t)> test_function;
	test_function["check_scalar"]             = test_check_scalar;
	test_function["random_scalar"]            = test_random_scalar;
	test_function["hash_to_scalar"]           = test_hash_to_scalar;
	test_function["generate_keys"]            = test_generate_keys;
	test_function["check_key"]                = test_check_key;
	test_function["secret_key_to_public_key"] = test_secret_key_to_public_key;
	test_function["generate_key_derivation"]  = test_generate_key_derivation;
	test_function["derive_public_key"]        = test_derive_public_key;
	test_function["derive_secret_key"]        = test_derive_secret_key;
	test_function["underive_public_key"]      = test_underive_public_key;
	test_function["generate_signature"]       = test_generate_signature;
	test_function["check_signature"]          = test_check_signature;
	test_function["hash_to_point"]            = test_hash_to_point;
	test_function["hash_to_ec"]               = test_hash_to_ec;
	test_function["generate_key_image"]       = test_generate_key_image;
	test_function["generate_ring_signature"]  = test_generate_ring_signature;
	test_function["check_ring_signature"]     = test_check_ring_signature;

	std::fstream input;
	std::string cmd;
	crypto_initialize_random_for_tests();

	std::map<std::string, int> test_counts;
	input.open(test_vectors_filename, std::ios_base::in);
	for (size_t test = 1;; ++test) {
		input.exceptions(std::ios_base::badbit);
		if (!(input >> cmd)) {
			break;
		}
		input.exceptions(std::ios_base::badbit | std::ios_base::failbit | std::ios_base::eofbit);
		if (test_function.count(cmd)) {
			test_function[cmd](input, test);
			test_counts[cmd] += 1;
		} else {
			throw std::ios_base::failure("Unknown function: " + cmd);
		}
	}

	std::cout << "Passed successfully:" << std::endl;
	for (auto &item : test_counts) {
		std::string name;
		int count;
		std::tie(name, count) = item;
		std::cout << "    " << name << ": " << count << " tests;" << std::endl;
	}

	crypto::KeyPair test_keypair1 = crypto::random_keypair();
	crypto::KeyPair test_keypair2 = crypto::random_keypair();
	crypto::SecretKey actual;
	int COUNT       = 1000;
	auto idea_start = std::chrono::high_resolution_clock::now();
	for (int count = 0; count != COUNT; ++count) {
		crypto::KeyDerivation der = generate_key_derivation(test_keypair1.public_key, test_keypair2.secret_key);
		test_keypair2.secret_key  = derive_output_secret_key(der, 0, test_keypair1.secret_key);
	}
	auto idea_ms =
	    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - idea_start);
	if (idea_ms.count() != 0)
		std::cout << "Benchmark generate_derivation+derive_secret_key result=" << test_keypair2.secret_key
		          << " ops/sec=" << COUNT * 1000 / idea_ms.count() << std::endl;
	else
		std::cout << "Benchmark generate_derivation+derive_secret_key result=" << test_keypair2.secret_key
		          << " ops/sec=inf" << std::endl;
	crypto::Signature test_sig;
	test_keypair1 = crypto::random_keypair();
	COUNT         = 1000;
	idea_start    = std::chrono::high_resolution_clock::now();
	for (int count = 0; count != COUNT; ++count) {
		test_sig = crypto::generate_signature(
		    *(const crypto::Hash *)(&test_sig.c), test_keypair1.public_key, test_keypair1.secret_key);
	}
	idea_ms =
	    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - idea_start);
	if (idea_ms.count() != 0)
		std::cout << "Benchmark generate_signature result=" << test_sig.c
		          << " ops/sec=" << COUNT * 1000 / idea_ms.count() << std::endl;
	else
		std::cout << "Benchmark generate_signature result=" << test_sig.r << " ops/sec=inf" << std::endl;
}
