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
#include <vector>

#include "../io.hpp"
#include "benchmarks.hpp"
#include "common/Invariant.hpp"
#include "common/StringTools.hpp"
#include "crypto/bernstein/crypto-ops.h"
#include "crypto/crypto.hpp"
#include "crypto/crypto_helpers.hpp"
#include "crypto/hash.hpp"
#include "crypto/random.h"
#include "test_crypto.hpp"

std::vector<std::string> select_tests_to_run(const std::vector<std::string> &selected_test_cases,
    const std::map<std::string, test_case> &test_function);

using namespace crypto;

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
	//	crypto::generate_hd_spendkeys(m_audit_key_base.secret_key, m_A_plus_sH, counter, &key_result);

	const PublicKey address_S  = A_plus_b_H(audit_key_base_pair.public_key, spend_keypair.secret_key);
	const PublicKey address_Sv = A_mul_b(address_S, view_keypair.secret_key);

	std::cout << "address_S=" << address_S << std::endl;
	std::cout << "address_Sv=" << address_Sv << std::endl;

	PublicKey encrypted_output_secret;
	PublicKey output_public_key = unlinkable_derive_output_public_key(
	    output_secret, tx_inputs_hash, output_index, address_S, address_Sv, &encrypted_output_secret);

	BinaryArray output_secret_hash_arg;
	PublicKey address_S2         = unlinkable_underive_address_S(view_keypair.secret_key, tx_inputs_hash, output_index,
        output_public_key, encrypted_output_secret, &output_secret_hash_arg);
	SecretKey output_secret_hash = hash_to_scalar(output_secret_hash_arg.data(), output_secret_hash_arg.size());
	std::cout << "address_s2=" << address_S2 << std::endl;
	if (address_S2 != address_S)
		throw Error("Aha");
	SecretKey output_secret_key2_s = unlinkable_derive_output_secret_key(spend_keypair.secret_key, output_secret_hash);
	SecretKey output_secret_key2_a =
	    unlinkable_derive_output_secret_key(audit_key_base_pair.secret_key, output_secret_hash);
	PublicKey output_public_key2 = secret_keys_to_public_key(output_secret_key2_a, output_secret_key2_s);
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
	auto sig = generate_ring_signature_amethyst(tx_prefix_hash, images, pubs, sec_s, sec_a, sec_indexes);
	if (!check_ring_signature_amethyst(tx_prefix_hash, images, pubs, sig))
		throw Error("Yhy");
	sig.rr.back().back().data[0] += 1;
	if (check_ring_signature_amethyst(tx_prefix_hash, images, pubs, sig))
		throw Error("Xhx");
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

// FIXME

std::istream &getvalue(std::istream &stream, bool &value) {
	std::string data;
	stream >> data;
	value = (data == "True");
	return stream;
}

size_t hexstr_to_int(std::string &s) {
    size_t value = 0;
    for (auto &c: s) {
        value <<= 4;
        value += common::from_hex(c);
    }
    return value;
}
std::istream &getvalue(std::istream &stream, size_t &value) {
	std::string data;
	stream >> data;
    value = hexstr_to_int(data);
//    value = 0;
//    for (auto &c: data) {
//        value <<= 4;
//        value += common::from_hex(c);
//    }
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

std::istream &operator>>(std::istream &stream, std::vector<size_t> &value) {
    size_t vector_size;
    getvalue(stream, vector_size);
    for (size_t i = 0; i < vector_size; ++i) {
        size_t item;
        getvalue(stream, item);
        value.push_back(item);
    }
    return stream;
}

template<typename T>
std::istream &operator>>(std::istream &stream, std::vector<T> &value) {
	size_t vector_size;
	getvalue(stream, vector_size);
	for (size_t i = 0; i < vector_size; ++i) {
		T item;
		stream >> item;
		value.push_back(item);
	}
	return stream;
}

std::istream &operator>>(std::istream &stream, RingSignatureAmethyst &value) {
	stream >> value.c0 >> value.ra >> value.rs >> value.pp >> value.rr;
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
	std::vector<size_t> secret_indices;
	RingSignatureAmethyst signature;
	Hash seed{};  // zeroes
	get(input, prefix_hash);
	input >> inputs >> images >> audit_keys >> spend_keys >> secret_indices >> signature;
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

bool test_generate_keys(std::istream &input) {
	PublicKey expected1, actual1;
	SecretKey expected2, actual2;
	get(input, expected1, expected2);
	random_keypair(actual1, actual2);
	return (expected1 == actual1) && (expected2 == actual2);
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
	PublicKey pub;
	SecretKey sec;
	Signature expected;
	get(input, prefix_hash, pub, sec, expected);
	const auto actual = generate_signature(prefix_hash, pub, sec);
	return expected == actual;
}

bool test_check_signature(std::istream &input) {
	Hash prefix_hash;
	PublicKey pub;
	Signature sig;
	bool expected = false;
	get(input, prefix_hash, pub, sig, expected);
	const bool actual = check_signature(prefix_hash, pub, sig);
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
	PublicKey pub;
	SecretKey sec;
	KeyImage expected;
	get(input, pub, sec, expected);
	const auto actual = generate_key_image(pub, sec);
	return expected == actual;
}

bool test_generate_ring_signature(std::istream &input) {
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
	return expected == actual;
	// TODO - better tests for half-size ring signatures

	/*			We started to use rng in amethyst signatures, so we cannot
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

bool test_check_ring_signature(std::istream &input) {
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
	return expected == actual;
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
	const ge_p3 B_p3 = ge_frombytes_vartime(B);
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

void reduce64_alt(struct cryptoEllipticCurveScalar *aa, const unsigned char s[64]) {
	SecretKey sk1;
	sk1.data[31] = 8;
	SecretKey sk2;
	sk2.data[0]      = 32;
	SecretKey s2_256 = sk1 * sk2;
	std::cout << "skk " << s2_256 << std::endl;

	SecretKey left;
	sc_reduce32(&left, s);
	SecretKey right;
	sc_reduce32(&right, s + 32);

	SecretKey mu;
	sc_mul(&mu, &right, &s2_256);
	sc_add(aa, &mu, &left);
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
    const bool break_on_failure, std::vector<int> &passed_tests, std::vector<int> &failed_tests) {
	crypto_initialize_random_for_tests();
	std::string line;
	for (size_t i = 1; getline(input, line); ++i) {
        if (i > 40) break;
		std::stringstream line_stream(line);
		bool result = test_function[name](line_stream);
		if (!result && break_on_failure) {
			std::cerr << "Failure on test " << i << " in test suite \"" << name << "\".";
			break;
		}
		if (result)
			passed_tests.emplace_back(static_cast<int>(i));
		else
			failed_tests.emplace_back(static_cast<int>(i));
	}
}

void test_crypto(const std::string &test_vectors_folder,
    const std::vector<std::string> &selected_test_cases = std::vector<std::string>(),
    const std::string &test_results_log = "", const bool break_on_failure = false) {
	std::map<std::string, test_case> test_function;
	test_function["check_key"]                     = test_check_key;
	test_function["check_ring_signature"]          = test_check_ring_signature;
	test_function["check_ring_signature_amethyst"] = test_check_ring_signature_amethyst;
    test_function["check_ring_signature_amethyst_big"] = test_check_ring_signature_amethyst;
	test_function["check_scalar"]                  = test_check_scalar;
	test_function["check_signature"]               = test_check_signature;
	test_function["derive_public_key"]             = test_derive_public_key;
	test_function["derive_secret_key"]             = test_derive_secret_key;
	test_function["generate_key_derivation"]       = test_generate_key_derivation;
	test_function["generate_key_image"]            = test_generate_key_image;
	//    test_function["generate_keys"] = test_generate_keys;  // FIXME tests depend on through random generator, need
	//    new tests test_function["generate_ring_signature"] = test_generate_ring_signature; // FIXME tests depend on
	//    through random generator, need new tests
	test_function["generate_ring_signature_amethyst"] = test_generate_ring_signature_amethyst;
    test_function["generate_ring_signature_amethyst_big"] = test_generate_ring_signature_amethyst;
//    test_function["generate_signature"] = test_generate_signature; // FIXME tests depend on through random//    generator, need new tests test_function["hash_to_curve"] = test_hash_to_point;
	test_function["hash_to_scalar"]           = test_hash_to_scalar;
	test_function["hash_to_subgroup"]         = test_hash_to_subgroup;
	test_function["random_scalar"]            = test_random_scalar;
	test_function["secret_key_to_public_key"] = test_secret_key_to_public_key;
	test_function["underive_public_key"]      = test_underive_public_key;

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

		std::vector<int> passed_tests, failed_tests;
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
            for (; i < std::min<size_t>(failed_tests.size(), 200); ++i)
				std::cout << ", " << failed_tests[i];
			std::cout << (i < failed_tests.size() ? ", ..." : ".") << std::endl;
		}
	}

	//	strange_add();
	//    std::cout << "G=" << crypto::get_G() << std::endl;
	//    std::cout << "H=" << crypto::get_H() << std::endl;
	//    invariant(crypto::get_H() == crypto::test_get_H(), "");
	//
	//    uint8_t tmp[64]{};
	//    generate_random_bytes(tmp, sizeof(tmp));
	//
	//    SecretKey res1;
	//    SecretKey res2;
	//    sc_reduce64(&res1, tmp);
	//    reduce64_alt(&res2, tmp);
	//    std::cout << "res1=" << res1 << std::endl;
	//    std::cout << "res2=" << res2 << std::endl;

	//	SecretKey sk;
	//	sk.data[0] = 8;
	//	std::cout << ge_tobytes(ge_scalarmult_base(sk)) << std::endl;
	//    PublicKey pk = common::pfh<PublicKey>("409c2e98dfebfd5ea008ecd4b60b4535fb553a63175396e0f37811c6e84ff134");
	//
	//    std::cout << "cn_fast_hash(pk): " << crypto::cn_fast_hash(pk.data, sizeof(pk.data)) << std::endl;
	//    std::cout << "hash_to_scalar(pk)" << crypto::hash_to_scalar(pk.data, sizeof(pk.data)) << std::endl;
	//    Hash h = cn_fast_hash(pk.data, sizeof(pk.data));
	//    Hash h2 = cn_fast_hash(h.data, sizeof(h.data));
	//    std::cout << "cn_fast_hash(pk):               " << h << std::endl;
	//    std::cout << "cn_fast_hash(cn_fast_hash(pk)): " << h2 << std::endl;
	//
	//    uint8_t buf[64]{};
	//    memcpy(buf, h.data, 32);
	//    memcpy(buf + 32, h2.data, 32);
	//    SecretKey result;
	//    sc_reduce64(&result, buf);
	//    std::cout << result << std::endl;
	//    //	std::cout << crypto::hash_to_scalar64(pk.data, sizeof(pk.data)) << std::endl;
	//
	//    P3 p1 = crypto::hash_to_good_point_p3(pk);
	//    P3 p2 = crypto::hash_to_good_point_p3(pk);
	//    SecretKey s1 = crypto::hash_to_scalar(pk.data, sizeof(pk.data));
	//    SecretKey s2 = crypto::hash_to_scalar(pk.data, sizeof(pk.data));
	//
	//    std::cout << "Identity group element as EllipticCurvePoint: " << to_bytes(I) << std::endl;
	//
	//    SecretKey s3 = s1 - s2;
	//    s3 -= s2;
	//    SecretKey s5 = s1 + s2;
	//    s5 += s2;
	//    SecretKey s4 = s1 - s2 * s3;
	//    s4 -= s3 * s4;
	//
	//    P3 r1 = s1 * G + s2 * p2;
	//    P3 r2 = s1 * p1 + s2 * p2;
	//    P3 r3 = s1 * p1 + s2 * G;
	//    P3 r4 = p1 + s2 * G;
	//    P3 r5 = s1 * p1 + p2;
	//    P3 r6 = p1 + s1 * G + s2 * p2;
	//    P3 r7 = s1 * p1 + s2 * G + p2;
	//    P3 r8 = s1 * (p1 + p2) + s2 * G;
	//
	//    r2 += r3 + G;
	//    r4 += r5;
	//    r6 *= s1;
	//
	//    P3 zero_point(PublicKey{});
	//    std::cout << key_in_main_subgroup(PublicKey{}) << std::endl;
	//    zero_point = P3();
	//    std::cout << "Zero EllipticCurvePoint is in main subgroup: " << key_in_main_subgroup(PublicKey{}) <<
	//    std::endl;
	//
	//    std::cout << "Sum of two zero EllipticCurvePoint's: " << to_bytes(zero_point + zero_point) << std::endl;
	//    std::cout << "Sum of two identity elements: " << to_bytes(I + I) << std::endl;
	//    std::cout << to_bytes(r1) << " " << to_bytes(r7) << " " << to_bytes(r8) << std::endl;

	test_unlinkable();
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
