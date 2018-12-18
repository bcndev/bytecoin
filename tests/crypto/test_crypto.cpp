// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for
// details.

//#include <cstddef>
//#include <cstring>
#include <fstream>
#include <vector>
#include "common/Invariant.hpp"
#include "crypto/bernstein/crypto-ops.h"

#include "test_crypto.hpp"

#include "../io.hpp"
#include "common/StringTools.hpp"
#include "crypto/bernstein/crypto-ops.h"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "crypto/random.h"

static void check(bool expr, size_t test) {
	if (expr)
		return;
	std::cerr << "Wrong result on test " << test << std::endl;
	throw std::runtime_error("test_crypto failed");
}

using namespace crypto;

class FastHashStream {
public:
	void append(const void *data, size_t size) {}
	Hash cn_fast_hash() const { return Hash{}; }
};

class LedgerProxy {
	PublicKey m_view_public_key;
	SecretKey m_view_secret_key;
	Hash m_seed;
	Hash m_tx_derivation_seed;

public:
	ge_p3 unlinkable_underive_public_key_step1(const PublicKey &output_public_key) {
		//		const ge_p3 output_public_key_p3 = ge_frombytes_vartime(output_public_key);
		//		const ge_cached p_v = ge_p3_to_cached(ge_scalarmult3(view_secret_key, output_public_key_p3));
		//		ge_p1p1 point_diff;
		//		ge_sub(&point_diff, &encrypted_output_secret_p3, &p_v);
		return ge_p3{};
	}
};

void generate_ring_signature3(const Hash &prefix_hash, const std::vector<KeyImage> &images,
    const std::vector<std::vector<PublicKey>> &pubs, const std::vector<SecretKey> &secs,
    const std::vector<size_t> &sec_indexes, const SecretKey &view_secret_key);

RingSignature3 create_signature();

void test_crypto(const std::string &test_vectors_filename) {
	std::fstream input;
	std::string cmd;
	size_t test = 0;
	crypto_initialize_random_for_tests();
	input.open(test_vectors_filename, std::ios_base::in);
	for (;;) {
		++test;
		input.exceptions(std::ios_base::badbit);
		if (!(input >> cmd)) {
			break;
		}
		input.exceptions(std::ios_base::badbit | std::ios_base::failbit | std::ios_base::eofbit);
		if (cmd == "check_scalar") {
			crypto::EllipticCurveScalar scalar;
			bool expected = false;
			get(input, scalar, expected);
			const bool actual = sc_isvalid_vartime(&scalar) != 0;
			check(expected == actual, test);
		} else if (cmd == "random_scalar") {
			crypto::EllipticCurveScalar expected, actual;
			get(input, expected);
			actual = crypto::random_scalar();
			check(expected == actual, test);

			// We do not have separate tests for inversions, so perform it on
			// random_scalars
			crypto::EllipticCurveScalar inv_actual, inv_inv_actual;
			crypto::EllipticCurveScalar b, inv_b, inv_inv_b, a_b, inv_a_inv_b, inv_a_b;
			b = crypto::hash_to_scalar(actual.data, sizeof(actual.data));

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

			crypto::EllipticCurveScalar one, inv_one, real_one;
			sc_1(&real_one);
			sc_mul(&one, &actual, &inv_actual);
			invariant(one == real_one, "");
			sc_mul(&one, &b, &inv_b);
			invariant(one == real_one, "");
			sc_invert(&inv_one, &one);
			invariant(one == inv_one, "");
		} else if (cmd == "hash_to_scalar") {
			std::vector<char> data;
			crypto::EllipticCurveScalar expected;
			get(input, data, expected);
			const auto actual = crypto::hash_to_scalar(data.data(), data.size());
			check(expected == actual, test);
		} else if (cmd == "generate_keys") {
			crypto::PublicKey expected1, actual1;
			crypto::SecretKey expected2, actual2;
			get(input, expected1, expected2);
			random_keypair(actual1, actual2);
			check(expected1 == actual1, test);
			check(expected2 == actual2, test);
		} else if (cmd == "check_key") {
			crypto::PublicKey key;
			bool expected = false;
			get(input, key, expected);
			const bool actual = key_isvalid(key);
			check(expected == actual, test);
		} else if (cmd == "secret_key_to_public_key") {
			crypto::SecretKey sec;
			bool expected1 = false;
			crypto::PublicKey expected2, actual2;
			get(input, sec, expected1);
			if (expected1) {
				get(input, expected2);
			}
			const bool actual1 = secret_key_to_public_key(sec, &actual2);
			check(!(expected1 != actual1 || (expected1 && expected2 != actual2)), test);
		} else if (cmd == "generate_key_derivation") {
			crypto::PublicKey key1;
			crypto::SecretKey key2;
			bool expected1 = false;
			crypto::KeyDerivation expected2;
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
		} else if (cmd == "derive_public_key") {
			crypto::KeyDerivation derivation;
			size_t output_index;
			crypto::PublicKey base;
			bool expected1 = false;
			crypto::PublicKey expected2;
			get(input, derivation, output_index, base, expected1);
			if (expected1) {
				get(input, expected2);
			}
			try {
				const auto actual2 = derive_public_key(derivation, output_index, base);
				check(actual2 == expected2, test);
			} catch (const std::exception &) {
				check(!expected1, test);
			}
		} else if (cmd == "derive_secret_key") {
			crypto::KeyDerivation derivation;
			size_t output_index;
			crypto::SecretKey base;
			crypto::SecretKey expected, actual;
			get(input, derivation, output_index, base, expected);
			//			try {
			actual = derive_secret_key(derivation, output_index, base);
			//			}catch(const std::exception &){
			//			}
			check(expected == actual, test);
		} else if (cmd == "underive_public_key") {
			crypto::KeyDerivation derivation;
			size_t output_index;
			crypto::PublicKey derived_key;
			bool expected1 = false;
			crypto::PublicKey expected2;
			get(input, derivation, output_index, derived_key, expected1);
			if (expected1) {
				get(input, expected2);
			}
			try {
				const auto actual2 = underive_public_key(derivation, output_index, derived_key);
				check(actual2 == expected2, test);
			} catch (const std::exception &) {
				check(!expected1, test);
			}
		} else if (cmd == "generate_signature") {
			crypto::Hash prefix_hash;
			crypto::PublicKey pub;
			crypto::SecretKey sec;
			crypto::Signature expected;
			get(input, prefix_hash, pub, sec, expected);
			const auto actual = generate_signature(prefix_hash, pub, sec);
			check(expected == actual, test);
		} else if (cmd == "check_signature") {
			crypto::Hash prefix_hash;
			crypto::PublicKey pub;
			crypto::Signature sig;
			bool expected = false;
			get(input, prefix_hash, pub, sig, expected);
			const bool actual = check_signature(prefix_hash, pub, sig);
			check(expected == actual, test);
		} else if (cmd == "hash_to_point") {
			crypto::Hash h;
			crypto::EllipticCurvePoint expected;
			get(input, h, expected);
			const auto actual = hash_to_point_for_tests(h);
			check(expected == actual, test);
		} else if (cmd == "hash_to_ec") {
			crypto::PublicKey key;
			crypto::EllipticCurvePoint expected;
			get(input, key, expected);
			const auto actual = hash_to_ec(key);
			check(expected == actual, test);
		} else if (cmd == "generate_key_image") {
			crypto::PublicKey pub;
			crypto::SecretKey sec;
			crypto::KeyImage expected;
			get(input, pub, sec, expected);
			const auto actual = generate_key_image(pub, sec);
			check(expected == actual, test);
		} else if (cmd == "generate_ring_signature") {
			crypto::Hash prefix_hash;
			crypto::KeyImage image;
			std::vector<crypto::PublicKey> vpubs;
			//			std::vector<const crypto::PublicKey *> pubs;
			size_t pubs_count;
			crypto::SecretKey sec;
			size_t sec_index;
			crypto::RingSignature expected;
			get(input, prefix_hash, image, pubs_count);
			vpubs.resize(pubs_count);
			//			pubs.resize(pubs_count);
			for (size_t i = 0; i < pubs_count; i++) {
				get(input, vpubs[i]);
				//				pubs[i] = &vpubs[i];
			}
			get(input, sec, sec_index);
			expected.resize(pubs_count);
			getvar(input, pubs_count * sizeof(crypto::Signature), expected.data());
			crypto::SecretKey view_secret_key;
			const auto actual = generate_ring_signature(prefix_hash, image, vpubs.data(), vpubs.size(), sec, sec_index);
			check(expected == actual, test);
			// TODO - better tests for half-size ring signatures

			static std::vector<crypto::KeyImage> images;
			static std::vector<crypto::SecretKey> secs;
			static std::vector<std::vector<crypto::PublicKey>> pubss;
			static std::vector<size_t> sec_indexes;
			images.push_back(image);
			secs.push_back(sec);
			pubss.push_back(vpubs);
			sec_indexes.push_back(sec_index);
			if (images.size() > 32) {
				crypto::RingSignature3 sig3 =
				    crypto::generate_ring_signature3(prefix_hash, images, pubss, secs, sec_indexes, view_secret_key);
				bool checked = crypto::check_ring_signature3(prefix_hash, images, pubss, sig3);
				//				for (size_t i = 0; i != images.size(); ++i) {
				//					size_t found_sec_index =
				//					    crypto::find_deterministic_input3(prefix_hash, i, sig3.r.at(i),
				// view_secret_key); 					invariant(sec_indexes[i] == found_sec_index, "");
				//				}
				sig3.r.at(0).at(0).data[13] += 1;
				bool checked2 = crypto::check_ring_signature3(prefix_hash, images, pubss, sig3);
				invariant(checked && !checked2, "");

				images.clear();
				secs.clear();
				pubss.clear();
				sec_indexes.clear();
			}
		} else if (cmd == "check_ring_signature") {
			crypto::Hash prefix_hash;
			crypto::KeyImage image;
			std::vector<crypto::PublicKey> vpubs;
			//			std::vector<const crypto::PublicKey *> pubs;
			size_t pubs_count;
			crypto::RingSignature sigs;
			bool expected = false;
			size_t i;
			get(input, prefix_hash, image, pubs_count);
			vpubs.resize(pubs_count);
			for (i = 0; i < pubs_count; i++) {
				get(input, vpubs[i]);
			}
			sigs.resize(pubs_count);
			getvar(input, pubs_count * sizeof(crypto::Signature), sigs.data());
			get(input, expected);
			const bool actual = check_ring_signature(prefix_hash, image, vpubs.data(), vpubs.size(), sigs, true);
			check(expected == actual, test);
		} else {
			throw std::ios_base::failure("Unknown function: " + cmd);
		}
	}
	crypto::KeyPair test_keypair1 = crypto::random_keypair();
	crypto::KeyPair test_keypair2 = crypto::random_keypair();
	crypto::SecretKey actual;
	int COUNT       = 1000;
	auto idea_start = std::chrono::high_resolution_clock::now();
	for (int count = 0; count != COUNT; ++count) {
		crypto::KeyDerivation der = crypto::generate_key_derivation(test_keypair1.public_key, test_keypair2.secret_key);
		test_keypair2.secret_key  = derive_secret_key(der, 0, test_keypair1.secret_key);
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
