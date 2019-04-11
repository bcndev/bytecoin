// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for
// details.

//#include <cstddef>
//#include <cstring>
//#include <sys/param.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <common/MemoryStreams.hpp>
#include <fstream>
#include <map>

#include "../io.hpp"
#include "common/Invariant.hpp"
#include "common/Varint.hpp"
#include "crypto/bernstein/crypto-ops.h"
#include "crypto/crypto.hpp"
#include "crypto/crypto_helpers.hpp"
#include "seria/BinaryInputStream.hpp"
#include "test_crypto.hpp"

std::vector<std::string> select_tests_to_run(const std::vector<std::string> &selected_test_cases,
    const std::map<std::string, test_case> &test_function);

using namespace crypto;

void test_unlinkable() {
	const PublicKey output_secret     = random_keypair().public_key;
	const Hash tx_inputs_hash         = rand<Hash>();
	const size_t output_index         = rand<size_t>() % 100;
	const KeyPair spend_keypair       = random_keypair();
	const KeyPair view_keypair        = random_keypair();
	const KeyPair audit_key_base_pair = random_keypair();

	const PublicKey address_S  = to_bytes(P3(audit_key_base_pair.public_key) + spend_keypair.secret_key * H);
	const PublicKey address_Sv = to_bytes(P3(address_S) * view_keypair.secret_key);

	PublicKey encrypted_output_secret;
	PublicKey output_public_key = unlinkable_derive_output_public_key(
	    output_secret, tx_inputs_hash, output_index, address_S, address_Sv, &encrypted_output_secret);

	BinaryArray output_secret_hash_arg;
	PublicKey address_S2         = unlinkable_underive_address_S(view_keypair.secret_key, tx_inputs_hash, output_index,
        output_public_key, encrypted_output_secret, &output_secret_hash_arg);
	SecretKey output_secret_hash = hash_to_scalar(output_secret_hash_arg.data(), output_secret_hash_arg.size());
	if (address_S2 != address_S)
		throw Error("Aha");
	SecretKey output_secret_key2_s = unlinkable_derive_output_secret_key(spend_keypair.secret_key, output_secret_hash);
	SecretKey output_secret_key2_a =
	    unlinkable_derive_output_secret_key(audit_key_base_pair.secret_key, output_secret_hash);
	PublicKey output_public_key2 = secret_keys_to_public_key(output_secret_key2_a, output_secret_key2_s);
	if (output_public_key2 != output_public_key)
		throw Error("Oho");
	PublicKey address_S3;
	PublicKey address_Sv3;
	unlinkable_underive_address(&address_S3, &address_Sv3, output_secret, tx_inputs_hash, output_index,
	    output_public_key, encrypted_output_secret);
	if (address_S3 != address_S || address_Sv3 != address_Sv)
		throw Error("Uhu");
}

void test_linkable() {
	const SecretKey output_secret       = random_scalar();
	const Hash tx_inputs_hash           = rand<Hash>();
	const auto output_index             = rand<size_t>();
	const KeyPair spend_keypair         = random_keypair();
	const KeyPair view_keypair          = random_keypair();
	const SecretKey inv_view_secret_key = sc_invert(view_keypair.secret_key);

	PublicKey encrypted_output_secret;
	PublicKey output_public_key = linkable_derive_output_public_key(output_secret, tx_inputs_hash, output_index,
	    spend_keypair.public_key, view_keypair.public_key, &encrypted_output_secret);

	BinaryArray output_secret_hash_arg;
	PublicKey address_S2         = linkable_underive_address_S(inv_view_secret_key, tx_inputs_hash, output_index,
        output_public_key, encrypted_output_secret, &output_secret_hash_arg);
	SecretKey output_secret_hash = hash_to_scalar(output_secret_hash_arg.data(), output_secret_hash_arg.size());
	if (address_S2 != spend_keypair.public_key)
		throw Error("Aha");
	SecretKey output_secret_key2 = linkable_derive_output_secret_key(spend_keypair.secret_key, output_secret_hash);
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

PublicKey test_get_H() {
	PublicKey G = get_G();
	Hash hash   = cn_fast_hash(G.data, sizeof(G.data));
	PublicKey hash_as_pk;
	memcpy(hash_as_pk.data, hash.data, 32);  // reintrepret hash as a point :)
	return to_bytes(bytes_to_good_point_p3(hash));
	//	return ge_tobytes(ge_p1p1_to_p3(ge_mul8(ge_frombytes_vartime(hash_as_pk))));
}

// FIXME

struct VarInt {
	size_t value{};

	VarInt() = default;

	operator size_t() const { return value; }
};

template<typename T>
std::istream &operator>>(std::istream &stream, std::vector<T> &value);

std::istream &getvalue(std::istream &stream, bool &value) {
	std::string data;
	stream >> data;
	value = (data == "True");
	return stream;
}

std::istream &operator>>(std::istream &stream, VarInt &value) {
	std::string data;
	stream >> data;
	seria::from_binary(value.value, common::from_hex(data));
	return stream;
}

std::istream &operator>>(std::istream &stream, EllipticCurvePoint &value) {
	get(stream, value);
	return stream;
}

std::istream &operator>>(std::istream &stream, EllipticCurveScalar &value) {
	get(stream, value);
	return stream;
}

std::istream &operator>>(std::istream &stream, Hash &value) {
	get(stream, value);
	return stream;
}

std::istream &operator>>(std::istream &stream, RingSignatureAmethyst &value) {
	stream >> value.c0 >> value.ra >> value.rs >> value.pp >> value.rr;
	return stream;
}

std::istream &operator>>(std::istream &stream, Signature &value) {
	stream >> value.c >> value.r;
	return stream;
}

template<typename T>
std::istream &operator>>(std::istream &stream, std::vector<T> &value) {
	VarInt vector_size;
	stream >> vector_size;
	if (vector_size.value > 200)  // likely parsing error
		throw std::string("Vector size too big.");
	for (size_t i = 0; i < vector_size.value; ++i) {
		T item;
		stream >> item;
		value.push_back(item);
	}
	return stream;
}

// FIXME

bool test_check_ring_signature_amethyst(std::istream &input) {
	Hash prefix_hash;
	std::vector<std::vector<PublicKey>> inputs;
	std::vector<KeyImage> images;
	RingSignatureAmethyst signature;
	bool expected;
	get(input, prefix_hash);
	input >> inputs >> images >> signature;
	getvalue(input, expected);
	const auto actual = check_ring_signature_amethyst(prefix_hash, images, inputs, signature);
	return expected == actual;
}

bool test_generate_ring_signature_amethyst(std::istream &input) {
	Hash prefix_hash;
	std::vector<std::vector<PublicKey>> inputs;
	std::vector<KeyImage> images;
	std::vector<SecretKey> audit_keys;
	std::vector<SecretKey> spend_keys;
	std::vector<VarInt> secret_indices_varint;
	RingSignatureAmethyst signature;
	Hash seed{};  // zeroes
	get(input, prefix_hash);
	input >> inputs >> images >> audit_keys >> spend_keys >> secret_indices_varint >> signature;
	std::vector<size_t> secret_indices(secret_indices_varint.begin(), secret_indices_varint.end());
	auto actual =
	    generate_ring_signature_amethyst(prefix_hash, images, inputs, spend_keys, audit_keys, secret_indices, &seed);
	bool result = (signature.c0 == actual.c0) && (signature.ra == actual.ra) && (signature.rs == actual.rs) &&
	              (signature.rr == actual.rr) && (signature.pp == actual.pp);
	return result;
}

bool test_random_scalar(std::istream &input) {
	EllipticCurveScalar expected, actual;
	get(input, expected);
	actual = random_scalar();
	return expected == actual;
}

bool test_random_keypair(std::istream &input) {
	PublicKey expected_pub, actual_pub;
	SecretKey expected_sec, actual_sec;
	input >> expected_sec >> expected_pub;
	random_keypair(actual_pub, actual_sec);
	return (expected_pub == actual_pub) && (expected_sec == actual_sec);
}

bool test_check_scalar(std::istream &input) {
	EllipticCurveScalar scalar;
	bool expected = false;
	get(input, scalar, expected);
	const bool actual = sc_isvalid_vartime(&scalar) != 0;
	return expected == actual;
}

bool test_hash_to_scalar(std::istream &input) {
	std::vector<char> data;
	EllipticCurveScalar expected;
	get(input, data, expected);
	const auto actual = hash_to_scalar(data.data(), data.size());
	return expected == actual;
}

bool test_check_key(std::istream &input) {
	PublicKey key;
	bool expected = false;
	get(input, key, expected);
	const bool actual = key_isvalid(key);
	return expected == actual;
}

bool test_secret_key_to_public_key(std::istream &input) {
	SecretKey sec;
	bool expected1 = false;
	PublicKey expected2, actual2;
	get(input, sec, expected1);
	if (expected1) {
		get(input, expected2);
	}
	const bool actual1 = secret_key_to_public_key(sec, &actual2);
	return !(expected1 != actual1 || (expected1 && expected2 != actual2));
}

bool test_generate_key_derivation(std::istream &input) {
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
		return actual2 == expected2;
	} catch (const std::exception &) {
		return !expected1;
	}
}

bool test_derive_public_key(std::istream &input) {
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
		return actual2 == expected2;
	} catch (const std::exception &) {
		return !expected1;
	}
}

bool test_derive_secret_key(std::istream &input) {
	KeyDerivation derivation;
	size_t output_index;
	SecretKey base;
	SecretKey expected, actual;
	get(input, derivation, output_index, base, expected);
	//			try {
	actual = derive_output_secret_key(derivation, output_index, base);
	//			}catch(const std::exception &){
	//			}
	return expected == actual;
}

bool test_underive_public_key(std::istream &input) {
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
		return actual2 == expected2;
	} catch (const std::exception &) {
		return !expected1;
	}
}

bool test_generate_signature(std::istream &input) {
	Hash prefix_hash;
	PublicKey public_key;
	SecretKey secret_key;
	Signature expected;
	get(input, prefix_hash, secret_key, public_key, expected);
	const auto actual = generate_signature(prefix_hash, public_key, secret_key);
	return (actual.c == expected.c) && (actual.r == expected.r);
}

bool test_check_signature(std::istream &input) {
	Hash prefix_hash;
	PublicKey public_key;
	Signature signature;
	bool expected = false;

	get(input, prefix_hash);
	input >> public_key >> signature >> expected;
	const bool actual = check_signature(prefix_hash, public_key, signature);
	return expected == actual;
}

bool test_hash_to_point(std::istream &input) {
	Hash h;
	EllipticCurvePoint expected;
	get(input, h, expected);
	const auto actual = bytes_to_bad_point(h);
	return expected == actual;
}

bool test_hash_to_subgroup(std::istream &input) {
	PublicKey key;
	EllipticCurvePoint expected;
	get(input, key, expected);
	const auto actual = hash_to_good_point(key);
	return expected == actual;
}

bool test_generate_key_image(std::istream &input) {
	crypto::SecretKey spend_sec, audit_sec;
	crypto::PublicKey public_key;
	crypto::KeyImage image_expected;
	input >> audit_sec >> spend_sec >> public_key >> image_expected;
	const auto actual = crypto::generate_key_image(public_key, audit_sec);
	return image_expected == actual;
}

bool test_generate_ring_signature(std::istream &input) {
	Hash prefix_hash;
	KeyImage image;
	std::vector<PublicKey> mixins;
	crypto::SecretKey secret_key;
	VarInt secret_index{};
	RingSignature signature;

	get(input, prefix_hash);
	input >> mixins >> image >> secret_key >> secret_index >> signature;
	auto actual =
	    crypto::generate_ring_signature(prefix_hash, image, mixins.data(), mixins.size(), secret_key, secret_index);
	bool result = true;
	for (size_t i = 0; i < actual.size(); ++i) {
		result &= (actual[i].c == signature[i].c) && (actual[i].r == signature[i].r);
	}
	return result;
}

bool test_check_ring_signature(std::istream &input) {
	Hash prefix_hash;
	std::vector<PublicKey> mixins;
	KeyImage image;
	RingSignature signature;
	bool expected;

	get(input, prefix_hash);
	input >> mixins >> image >> signature;
	getvalue(input, expected);
	const bool actual = check_ring_signature(prefix_hash, image, mixins, signature);
	return expected == actual;
}

size_t max_length(const std::vector<std::string> &strings) {
	size_t max_name_size = 0;
	for (auto &name : strings) {
		auto length = name.length();
		if (length > max_name_size)
			max_name_size = length;
	}
	return max_name_size;
}

void run_test_suite(const std::string &name, std::fstream &input, std::map<std::string, test_case> &test_function,
    const bool break_on_failure, std::vector<size_t> &passed_tests, std::vector<size_t> &failed_tests) {
	crypto_initialize_random_for_tests();
	std::string line;
	for (size_t i = 1; getline(input, line); ++i) {
		std::stringstream line_stream(line);
		bool result = test_function[name](line_stream);
		if (!result && break_on_failure) {
			std::cerr << "Failure on test " << i << " in test suite \"" << name << "\".";
			break;
		}
		if (result)
			passed_tests.emplace_back(i);
		else
			failed_tests.emplace_back(i);
	}
}

static const size_t FAILED_TEST_COUNT_PRINT_LIMIT = 40;

void test_crypto(const std::string &test_vectors_folder,
    const std::vector<std::string> &selected_test_cases = std::vector<std::string>(),
    const std::string &test_results_log = "", const bool break_on_failure = false) {
	std::map<std::string, test_case> test_function;
	test_function["check_key"]                            = test_check_key;
	test_function["check_ring_signature"]                 = test_check_ring_signature;
	test_function["check_ring_signature_amethyst"]        = test_check_ring_signature_amethyst;
	test_function["check_ring_signature_amethyst_big"]    = test_check_ring_signature_amethyst;
	test_function["check_scalar"]                         = test_check_scalar;
	test_function["check_signature"]                      = test_check_signature;
	test_function["derive_public_key"]                    = test_derive_public_key;
	test_function["derive_secret_key"]                    = test_derive_secret_key;
	test_function["generate_key_derivation"]              = test_generate_key_derivation;
	test_function["generate_key_image"]                   = test_generate_key_image;
	test_function["generate_ring_signature"]              = test_generate_ring_signature;
	test_function["generate_ring_signature_amethyst"]     = test_generate_ring_signature_amethyst;
	test_function["generate_ring_signature_amethyst_big"] = test_generate_ring_signature_amethyst;
	test_function["generate_ring_signature_big"]          = test_generate_ring_signature;
	test_function["generate_signature"]                   = test_generate_signature;
	test_function["hash_to_scalar"]                       = test_hash_to_scalar;
	test_function["hash_to_subgroup"]                     = test_hash_to_subgroup;
	test_function["random_keypair"]                       = test_random_keypair;
	test_function["random_scalar"]                        = test_random_scalar;
	test_function["secret_key_to_public_key"]             = test_secret_key_to_public_key;
	test_function["underive_public_key"]                  = test_underive_public_key;

	std::vector<std::string> test_cases = select_tests_to_run(selected_test_cases, test_function);

	size_t max_name_size = max_length(test_cases);
	for (auto &name : test_cases) {
		std::stringstream test_file_path_buf;
		test_file_path_buf << test_vectors_folder << "/"
		                   << "test_" << name << ".txt";
		auto test_file_path = test_file_path_buf.str();
		std::fstream input(test_file_path, std::ios_base::in);
		if (!input.is_open()) {
			std::cerr << "Could not open test vectors with name \"" << test_file_path << "\" for test \"" << name
			          << "\"." << std::endl;
			continue;
		}
		input.exceptions(std::ios_base::badbit);

		std::vector<size_t> passed_tests, failed_tests;
		run_test_suite(name, input, test_function, break_on_failure, passed_tests, failed_tests);

		std::stringstream name_buf;
		name_buf << "\"" << name << "\": ";
		std::cout << "In test suite " << std::left << std::setfill(' ')
		          << std::setw(static_cast<int>(max_name_size + 4)) << name_buf.str() << passed_tests.size()
		          << " passed, " << failed_tests.size() << " failed." << std::endl;

		if (!failed_tests.empty()) {
			std::cout << "\tFailed tests: ";
			std::cout << failed_tests[0];
			size_t i = 1;
			for (; i < std::min<size_t>(failed_tests.size(), FAILED_TEST_COUNT_PRINT_LIMIT); ++i)
				std::cout << ", " << failed_tests[i];
			std::cout << (i < failed_tests.size() ? ", ..." : ".") << std::endl;
		}
	}
}

std::vector<std::string> select_tests_to_run(const std::vector<std::string> &selected_test_cases,
    const std::map<std::string, test_case> &test_function) {
	std::vector<std::string> test_cases;
	std::vector<std::string> error_test_cases;
	if (selected_test_cases.empty()) {
		for (auto &test : test_function) {
			std::string name;
			test_case func;
			tie(name, func) = test;
			test_cases.emplace_back(name);
		}
	} else {
		for (auto &name : selected_test_cases) {
			if (test_function.count(name))
				test_cases.emplace_back(name);
			else
				error_test_cases.emplace_back(name);
		}
		if (!error_test_cases.empty()) {
			std::cerr << "Invalid arguments. The following test cases are unknown: ";
			for (auto &name : error_test_cases)
				std::cerr << "\t" << name << std::endl;
			exit(1);
		}
	}
	return test_cases;
}
