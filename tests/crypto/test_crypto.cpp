// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

//#include <cstddef>
//#include <cstring>
#include <fstream>
#include <vector>

#include "test_crypto.hpp"

#include "../io.hpp"
#include "crypto/crypto-ops.h"
#include "crypto/crypto.hpp"
#include "crypto/hash.hpp"
#include "crypto/random.h"

static void check(bool expr, size_t test) {
	if (expr)
		return;
	std::cerr << "Wrong result on test " << test << std::endl;
	throw std::runtime_error("test_crypto failed");
}

void test_crypto(const std::string &test_vectors_filename) {
	std::fstream input;
	std::string cmd;
	size_t test = 0;
	crypto::initialize_random_for_tests();
	//  if (argc != 2) {
	//    cerr << "invalid arguments" << endl;
	//    return 1;
	//  }
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
			bool expected = false, actual;
			get(input, scalar, expected);
			actual = sc_isvalid_vartime(&scalar);
			check(expected == actual, test);
		} else if (cmd == "random_scalar") {
			crypto::EllipticCurveScalar expected, actual;
			get(input, expected);
			crypto::random_scalar(actual);
			check(expected == actual, test);
		} else if (cmd == "hash_to_scalar") {
			std::vector<char> data;
			crypto::EllipticCurveScalar expected, actual;
			get(input, data, expected);
			crypto::hash_to_scalar(data.data(), data.size(), actual);
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
			bool expected = false, actual;
			get(input, key, expected);
			actual = key_isvalid(key);
			check(expected == actual, test);
		} else if (cmd == "secret_key_to_public_key") {
			crypto::SecretKey sec;
			bool expected1 = false, actual1;
			crypto::PublicKey expected2, actual2;
			get(input, sec, expected1);
			if (expected1) {
				get(input, expected2);
			}
			actual1 = secret_key_to_public_key(sec, actual2);
			check(!(expected1 != actual1 || (expected1 && expected2 != actual2)), test);
		} else if (cmd == "generate_key_derivation") {
			crypto::PublicKey key1;
			crypto::SecretKey key2;
			bool expected1 = false, actual1;
			crypto::KeyDerivation expected2, actual2;
			get(input, key1, key2, expected1);
			if (expected1) {
				get(input, expected2);
			}
			actual1 = generate_key_derivation(key1, key2, actual2);
			check(!(expected1 != actual1 || (expected1 && expected2 != actual2)), test);
		} else if (cmd == "derive_public_key") {
			crypto::KeyDerivation derivation;
			size_t output_index;
			crypto::PublicKey base;
			bool expected1 = false, actual1;
			crypto::PublicKey expected2, actual2;
			get(input, derivation, output_index, base, expected1);
			if (expected1) {
				get(input, expected2);
			}
			actual1 = derive_public_key(derivation, output_index, base, actual2);
			check(!(expected1 != actual1 || (expected1 && expected2 != actual2)), test);
		} else if (cmd == "derive_secret_key") {
			crypto::KeyDerivation derivation;
			size_t output_index;
			crypto::SecretKey base;
			crypto::SecretKey expected, actual;
			get(input, derivation, output_index, base, expected);
			derive_secret_key(derivation, output_index, base, actual);
			check(expected == actual, test);
		} else if (cmd == "underive_public_key") {
			crypto::KeyDerivation derivation;
			size_t output_index;
			crypto::PublicKey derived_key;
			bool expected1 = false, actual1;
			crypto::PublicKey expected2, actual2;
			get(input, derivation, output_index, derived_key, expected1);
			if (expected1) {
				get(input, expected2);
			}
			actual1 = underive_public_key(derivation, output_index, derived_key, actual2);
			check(!(expected1 != actual1 || (expected1 && expected2 != actual2)), test);
		} else if (cmd == "generate_signature") {
			crypto::Hash prefix_hash;
			crypto::PublicKey pub;
			crypto::SecretKey sec;
			crypto::Signature expected, actual;
			get(input, prefix_hash, pub, sec, expected);
			generate_signature(prefix_hash, pub, sec, actual);
			check(expected == actual, test);
		} else if (cmd == "check_signature") {
			crypto::Hash prefix_hash;
			crypto::PublicKey pub;
			crypto::Signature sig;
			bool expected = false, actual;
			get(input, prefix_hash, pub, sig, expected);
			actual = check_signature(prefix_hash, pub, sig);
			check(expected == actual, test);
		} else if (cmd == "hash_to_point") {
			crypto::Hash h;
			crypto::EllipticCurvePoint expected, actual;
			get(input, h, expected);
			hash_to_point_for_tests(h, actual);
			check(expected == actual, test);
		} else if (cmd == "hash_to_ec") {
			crypto::PublicKey key;
			crypto::EllipticCurvePoint expected, actual;
			get(input, key, expected);
			hash_to_ec(key, actual);
			check(expected == actual, test);
		} else if (cmd == "generate_key_image") {
			crypto::PublicKey pub;
			crypto::SecretKey sec;
			crypto::KeyImage expected, actual;
			get(input, pub, sec, expected);
			generate_key_image(pub, sec, actual);
			check(expected == actual, test);
		} else if (cmd == "generate_ring_signature") {
			crypto::Hash prefix_hash;
			crypto::KeyImage image;
			std::vector<crypto::PublicKey> vpubs;
			std::vector<const crypto::PublicKey *> pubs;
			size_t pubs_count;
			crypto::SecretKey sec;
			size_t sec_index;
			std::vector<crypto::Signature> expected, actual;
			size_t i;
			get(input, prefix_hash, image, pubs_count);
			vpubs.resize(pubs_count);
			pubs.resize(pubs_count);
			for (i = 0; i < pubs_count; i++) {
				get(input, vpubs[i]);
				pubs[i] = &vpubs[i];
			}
			get(input, sec, sec_index);
			expected.resize(pubs_count);
			getvar(input, pubs_count * sizeof(crypto::Signature), expected.data());
			actual.resize(pubs_count);
			generate_ring_signature(prefix_hash, image, pubs.data(), pubs_count, sec, sec_index, actual.data());
			check(expected == actual, test);
		} else if (cmd == "check_ring_signature") {
			crypto::Hash prefix_hash;
			crypto::KeyImage image;
			std::vector<crypto::PublicKey> vpubs;
			std::vector<const crypto::PublicKey *> pubs;
			size_t pubs_count;
			std::vector<crypto::Signature> sigs;
			bool expected = false, actual;
			size_t i;
			get(input, prefix_hash, image, pubs_count);
			vpubs.resize(pubs_count);
			pubs.resize(pubs_count);
			for (i = 0; i < pubs_count; i++) {
				get(input, vpubs[i]);
				pubs[i] = &vpubs[i];
			}
			sigs.resize(pubs_count);
			getvar(input, pubs_count * sizeof(crypto::Signature), sigs.data());
			get(input, expected);
			actual = check_ring_signature(prefix_hash, image, pubs.data(), pubs_count, sigs.data(), true);
			check(expected == actual, test);  // TODO - check 2.*
		} else {
			throw std::ios_base::failure("Unknown function: " + cmd);
		}
	}
}
