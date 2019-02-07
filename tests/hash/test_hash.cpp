// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for
// details.

#include "test_hash.hpp"

#include <fstream>

#include "../io.hpp"
#include "common/Invariant.hpp"
#include "common/StringTools.hpp"
#include "crypto/crypto.hpp"
#include "crypto/hash.h"
#include "crypto/hash.hpp"

static crypto::CryptoNightContext context;

static void hash_tree(const void *vdata, size_t vlength, cryptoHash *hash) {
	if (vlength % 32 != 0)
		throw std::ios_base::failure("Invalid input length for tree_hash");
	const struct cryptoHash *data = (const struct cryptoHash *)vdata;
	size_t length                 = vlength / 32;
	crypto_tree_hash(data, length, hash);
	std::vector<crypto::Hash> branch(crypto_coinbase_tree_depth(length) + 1);
	crypto_coinbase_tree_branch(data, length, branch.data());
	invariant(branch.back() == crypto::Hash{}, "");  // No output array overwrite
	crypto::Hash hash2;
	crypto_tree_hash_from_branch(branch.data(), branch.size() - 1, data, nullptr, &hash2);
	crypto::Hash chash;
	static_cast<cryptoHash &>(chash) = *hash;
	invariant(chash == hash2, "");
}

static void slow_hash(const void *data, size_t length, cryptoHash *hash) {
	context.cn_slow_hash(data, length, hash);
	crypto::Hash hash2;
	crypto_cn_slow_hash_platform_independent(context.get_data(), data, length, &hash2);
	crypto::Hash chash;
	static_cast<cryptoHash &>(chash) = *hash;
	invariant(chash == hash2, "");
}

extern "C" typedef void hash_f(const void *, size_t, cryptoHash *);

struct hash_func {
	const std::string name;
	hash_f &f;
} hashes[] = {{"fast", crypto_cn_fast_hash}, {"slow", slow_hash}, {"tree", hash_tree},
    {"extra-blake", crypto_hash_extra_blake}, {"extra-groestl", crypto_hash_extra_groestl},
    {"extra-jh", crypto_hash_extra_jh}, {"extra-skein", crypto_hash_extra_skein}};

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

void keccak_any(const void *in, size_t inlen, unsigned char *md, size_t mdlen, uint8_t delim) {
	cryptoKeccakHasher hasher;
	crypto_keccak_init(&hasher, mdlen, delim);
	crypto_keccak_update(&hasher, in, inlen);
	crypto_keccak_final(&hasher, md, mdlen / 8);
}
void test_hashes(const std::string &test_vectors_folder) {
	std::string any_string("Keccak family)");
	unsigned char md[64];
	keccak_any(any_string.data(), any_string.size(), md, 128, 0x1f);
	invariant(common::to_hex(md, 16) == "db647745ba790814315c70e0768eb9db", "");
	keccak_any(any_string.data(), any_string.size(), md, 256, 0x1f);
	invariant(common::to_hex(md, 32) == "65e6c908348094fe28ac73387c6975edccaf31eb69ff69c78051203c088e7af9", "");

	keccak_any(any_string.data(), any_string.size(), md, 224, 0x01);
	invariant(common::to_hex(md, 28) == "4275c0dde3fd65def5e4e3073b48e4a8a4e7d54f40967f144e2bc222", "");
	keccak_any(any_string.data(), any_string.size(), md, 256, 0x01);
	invariant(common::to_hex(md, 32) == "24c9a98982d55a9c0012e751f7fb3c745d4c99b1a16318f828f58fd342bed3d0", "");
	keccak_any(any_string.data(), any_string.size(), md, 384, 0x01);
	invariant(common::to_hex(md, 48) ==
	              "bd3b8b6548e9a450d160a019b7fadb23ed61f0ac2ecbecd5458ba40af3a67dc9c01cbae9b962e4e76836f7642d3468f3",
	    "");
	keccak_any(any_string.data(), any_string.size(), md, 512, 0x01);
	invariant(
	    common::to_hex(md, 64) ==
	        "45e07a8ad2f7da730573cea596d232dd1b2cfe7ac6ef1ec610732bada98464d99513dfb0712705963f82c998e529d185aff2368b68e12f8e6228d72bc8b58f3f",
	    "");

	keccak_any(any_string.data(), any_string.size(), md, 224, 0x06);
	invariant(common::to_hex(md, 28) == "92d1903aec6144f655d8a169398c36425db0260184a58ea32a0d79e2", "");
	keccak_any(any_string.data(), any_string.size(), md, 256, 0x06);
	invariant(common::to_hex(md, 32) == "e9492b5c4fed0ee624e8bddc79ac1a998493fd8c222e54f65555a6ba4c9539e8", "");
	keccak_any(any_string.data(), any_string.size(), md, 384, 0x06);
	invariant(common::to_hex(md, 48) ==
	              "fcb0edcb07f67859ce296b53731602d974dc0ff4e355e696a8c3a3cb0cfef6fdc7d9d600089eacad240879a238b8362f",
	    "");
	keccak_any(any_string.data(), any_string.size(), md, 512, 0x06);
	invariant(
	    common::to_hex(md, 64) ==
	        "53fdfee3ee9f749c8132df285e2ab5ef31cda10b9ad36dab70d75bb6ea79d3325b63662e9ef054167827f41468877a37cf2099a5ec40fd5619c199c1b4c99c31",
	    "");

	size_t depths[17] = {0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4};
	for (size_t i = 1; i < sizeof(depths) / sizeof(*depths); ++i)
		invariant(crypto_coinbase_tree_depth(i) == depths[i], "");
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
		std::cout << "Benchmark cn_fast_hash result=" << test_hash << " hashes/sec=" << COUNT * 1000 / idea_ms.count()
		          << std::endl;
	else
		std::cout << "Benchmark cn_fast_hash result=" << test_hash << " hashes/sec=inf" << std::endl;
	test_hash  = crypto::Hash{};
	COUNT      = 100;
	idea_start = std::chrono::high_resolution_clock::now();
	for (int count = 0; count != COUNT; ++count) {
		test_hash = context.cn_slow_hash(test_hash.data, sizeof(test_hash.data));
	}
	idea_ms =
	    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - idea_start);
	if (idea_ms.count() != 0)
		std::cout << "Benchmark cn_slow_hash result=" << test_hash << " hashes/sec=" << COUNT * 1000 / idea_ms.count()
		          << std::endl;
	else
		std::cout << "Benchmark cn_slow_hash result=" << test_hash << " hashes/sec=inf" << std::endl;
}
