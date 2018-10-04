// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "test_hash.hpp"

//#include <cstddef>
#include <fstream>
//#include <iomanip>
//#include <ios>
//#include <string>

#include "../io.hpp"
#include "common/Invariant.hpp"
#include "common/StringTools.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.h"
#include "crypto/hash.hpp"

static crypto::CryptoNightContext context;

//#ifdef _MSC_VER
//#pragma warning(disable : 4297)
//#endif

static void hash_tree(const void *vdata, size_t vlength, crypto::CHash *hash) {
	if (vlength % 32 != 0)
		throw std::ios_base::failure("Invalid input length for tree_hash");
	const struct crypto::CHash *data = (const struct crypto::CHash *)vdata;
	size_t length                    = vlength / 32;
	crypto::tree_hash(data, length, hash);
	std::vector<crypto::CHash> branch(crypto::coinbase_tree_depth(length) + 1);
	crypto::coinbase_tree_branch(data, length, branch.data());
	invariant(branch.back() == crypto::CHash{}, "");  // No output array overwrite
	crypto::CHash hash2;
	crypto::tree_hash_from_branch(branch.data(), branch.size() - 1, data, nullptr, &hash2);
	invariant(*hash == hash2, "");
}

static void slow_hash(const void *data, size_t length, crypto::CHash *hash) {
	context.cn_slow_hash(data, length, hash);
	crypto::CHash hash2;
	crypto::cn_slow_hash_platform_independent(context.get_data(), data, length, &hash2);
	invariant(*hash == hash2, "");
}

extern "C" typedef void hash_f(const void *, size_t, crypto::CHash *);

struct hash_func {
	const std::string name;
	hash_f &f;
} hashes[] = {{"fast", crypto::cn_fast_hash}, {"slow", slow_hash}, {"tree", hash_tree},
    {"extra-blake", crypto::hash_extra_blake}, {"extra-groestl", crypto::hash_extra_groestl},
    {"extra-jh", crypto::hash_extra_jh}, {"extra-skein", crypto::hash_extra_skein}};

void test_hash(const char *test_fun_name, const std::string &test_vectors_filename) {
	hash_f *f = nullptr;
	std::fstream input;
	std::vector<char> data;
	crypto::Hash expected, actual;
	size_t test = 0;
	for (hash_func *hf = hashes;; hf++) {
		if (hf >= &hashes[sizeof(hashes) / sizeof(hash_func)]) {
			std::cerr << "Unknown function" << std::endl;
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
	input.open(test_vectors_filename, std::ios_base::in);
	for (;;) {
		++test;
		input.exceptions(std::ios_base::badbit);
		get(input, expected);
		if (input.rdstate() & std::ios_base::eofbit) {
			break;
		}
		input.exceptions(std::ios_base::badbit | std::ios_base::failbit | std::ios_base::eofbit);
		input.clear(input.rdstate());
		get(input, data);
		f(data.data(), data.size(), &actual);
		if (expected != actual) {
			std::cerr << "Hash mismatch on test " << test << std::endl;
			//      	cerr << "Input: " << common::pod_to_hex(data) << endl;
			std::cerr << "Expected hash: " << expected << std::endl;
			std::cerr << "Actual hash: " << actual << std::endl;
			;
			throw std::runtime_error("test_hash failed");
		}
	}
}

void test_hashes(const std::string &test_vectors_folder) {
	size_t depths[17] = {0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4};
	for (size_t i = 1; i < sizeof(depths) / sizeof(*depths); ++i)
		invariant(crypto::coinbase_tree_depth(i) == depths[i], "");
	test_hash("extra-blake", test_vectors_folder + "/tests-extra-blake.txt");
	test_hash("extra-groestl", test_vectors_folder + "/tests-extra-groestl.txt");
	test_hash("extra-jh", test_vectors_folder + "/tests-extra-jh.txt");
	test_hash("extra-skein", test_vectors_folder + "/tests-extra-skein.txt");
	test_hash("fast", test_vectors_folder + "/tests-fast.txt");
	test_hash("slow", test_vectors_folder + "/tests-slow.txt");
	test_hash("tree", test_vectors_folder + "/tests-tree.txt");

	for (size_t si = 1; si != 34; ++si) {
		std::vector<crypto::MergeMiningItem> mm_items(si);
		for (auto &item : mm_items) {
			item.leaf = crypto::rand<crypto::Hash>();
			item.path = crypto::rand<crypto::Hash>();
			if (si > 20) {
				item.path.data[0] = (si % 2) ? 0 : 0xff;
				item.path.data[1] = (si % 2) ? 0 : 0xff;
			}
		}
		crypto::Hash root = crypto::fill_merge_mining_branches(mm_items.data(), mm_items.size());
		for (auto &item : mm_items) {
			crypto::Hash root2 =
			    crypto::tree_hash_from_branch(item.branch.data(), item.branch.size(), item.leaf, &item.path);
			invariant(root == root2, "");
		}
	}
	crypto::Hash test_hash;
	int COUNT       = 100000;
	auto idea_start = std::chrono::high_resolution_clock::now();
	for (int count = 0; count != COUNT; ++count) {
		test_hash = crypto::cn_fast_hash(test_hash.data, sizeof(test_hash.data));
	}
	auto idea_ms =
	    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - idea_start);
	if (idea_ms.count() != 0)
		std::cout << "Benchmart cn_fast_hash result=" << test_hash << " hashes/sec=" << COUNT * 1000 / idea_ms.count()
		          << std::endl;
	else
		std::cout << "Benchmart cn_fast_hash result=" << test_hash << " hashes/sec=inf" << std::endl;
	test_hash  = crypto::Hash{};
	COUNT      = 100;
	idea_start = std::chrono::high_resolution_clock::now();
	for (int count = 0; count != COUNT; ++count) {
		test_hash = context.cn_slow_hash(test_hash.data, sizeof(test_hash.data));
	}
	idea_ms =
	    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - idea_start);
	if (idea_ms.count() != 0)
		std::cout << "Benchmart cn_slow_hash result=" << test_hash << " hashes/sec=" << COUNT * 1000 / idea_ms.count()
		          << std::endl;
	else
		std::cout << "Benchmart cn_slow_hash result=" << test_hash << " hashes/sec=inf" << std::endl;
}
