// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "test_hash.hpp"

#include <cstddef>
#include <fstream>
#include <iomanip>
#include <ios>
#include <string>

#include "../io.hpp"
#include "common/StringTools.hpp"
#include "crypto/hash-impl.h"
#include "crypto/hash.hpp"

using namespace std;

static crypto::CryptoNightContext context;

extern "C" {
#ifdef _MSC_VER
#pragma warning(disable : 4297)
#endif

static void hash_tree(const void *data, size_t length, unsigned char *hash) {
	if ((length & 31) != 0) {
		throw ios_base::failure("Invalid input length for tree_hash");
	}
	crypto::tree_hash((const unsigned char(*)[32])data, length >> 5, hash);
}

static void slow_hash(const void *data, size_t length, unsigned char *hash) {
	context.cn_slow_hash(data, length, hash);
}
}

extern "C" typedef void hash_f(const void *, size_t, unsigned char *);

struct hash_func {
	const string name;
	hash_f &f;
} hashes[] = {{"fast", crypto::cn_fast_hash}, {"slow", slow_hash}, {"tree", hash_tree},
    {"extra-blake", crypto::hash_extra_blake}, {"extra-groestl", crypto::hash_extra_groestl},
    {"extra-jh", crypto::hash_extra_jh}, {"extra-skein", crypto::hash_extra_skein}};

void test_hash(const char *test_fun_name, const std::string &test_vectors_filename) {
	hash_f *f = nullptr;
	fstream input;
	vector<char> data;
	crypto::Hash expected, actual;
	size_t test = 0;
	for (hash_func *hf = hashes;; hf++) {
		if (hf >= &hashes[sizeof(hashes) / sizeof(hash_func)]) {
			cerr << "Unknown function" << endl;
			throw std::runtime_error("test_hash failed");
		}
		if (test_fun_name == hf->name) {
			f = &hf->f;
			break;
		}
	}
	//  if (f == slow_hash) {
	//    context = new Crypto::cn_context();
	//  }
	input.open(test_vectors_filename, ios_base::in);
	for (;;) {
		++test;
		input.exceptions(ios_base::badbit);
		get(input, expected);
		if (input.rdstate() & ios_base::eofbit) {
			break;
		}
		input.exceptions(ios_base::badbit | ios_base::failbit | ios_base::eofbit);
		input.clear(input.rdstate());
		get(input, data);
		f(data.data(), data.size(), actual.data);
		if (expected != actual) {
			cerr << "Hash mismatch on test " << test << endl;
			//      	cerr << "Input: " << common::pod_to_hex(data) << endl;
			cerr << "Expected hash: " << common::pod_to_hex(expected) << endl;
			cerr << "Actual hash: " << common::pod_to_hex(actual) << endl;
			;
			throw std::runtime_error("test_hash failed");
		}
	}
}

void test_hashes(const std::string &test_vectors_folder) {
	test_hash("extra-blake", test_vectors_folder + "/tests-extra-blake.txt");
	test_hash("extra-groestl", test_vectors_folder + "/tests-extra-groestl.txt");
	test_hash("extra-jh", test_vectors_folder + "/tests-extra-jh.txt");
	test_hash("extra-skein", test_vectors_folder + "/tests-extra-skein.txt");
	test_hash("fast", test_vectors_folder + "/tests-fast.txt");
	test_hash("slow", test_vectors_folder + "/tests-slow.txt");
	test_hash("tree", test_vectors_folder + "/tests-tree.txt");
}
