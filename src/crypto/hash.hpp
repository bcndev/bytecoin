// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <stddef.h>

#include "hash.h"
#include "tree-hash.h"
#include "types.hpp"
#include "hash-ops.h"

namespace crypto {
// Cryptonight hash functions

inline Hash cn_fast_hash(const void *data, size_t length) {
	Hash h;
	crypto_cn_fast_hash(data, length, &h);
	return h;
}
inline Hash cn_fast_hash(const std::vector<uint8_t> &data) {
	Hash h;
	crypto_cn_fast_hash(data.data(), data.size(), &h);
	return h;
}

class CryptoNightContext {
public:
	CryptoNightContext();
	~CryptoNightContext();

	CryptoNightContext(const CryptoNightContext &) = delete;
	void operator=(const CryptoNightContext &) = delete;

	inline void cn_slow_hash(const void *src_data, size_t length, cryptoHash *hash) {
        //crypto_cn_slow_hash(data, src_data, length, hash);
        crypto::cn_slow_hash(src_data, length, hash->data, 3, 0/*prehashed*/);
	}
	inline Hash cn_slow_hash(const void *src_data, size_t length) {
		Hash hash;
        //crypto_cn_slow_hash(data, src_data, length, &hash);
        crypto::cn_slow_hash(src_data, length, hash.data, 3, 0/*prehashed*/);
		return hash;
	}
	void *get_data() const { return data; }

private:
	void *data;
};

inline Hash tree_hash(const Hash hashes[], size_t count) {
	Hash root_hash;
	crypto_tree_hash(hashes, count, &root_hash);
	return root_hash;
}

inline Hash tree_hash_from_branch(const Hash branch[], size_t depth, const Hash &leaf, const Hash *path) {
	Hash root_hash;
	crypto_tree_hash_from_branch(branch, depth, &leaf, path, &root_hash);
	return root_hash;
}

struct MergeMiningItem {
	Hash leaf;
	Hash path;
	std::vector<Hash> branch;
};
struct CMTreeItem {
	Hash leaf;
	Hash path;
	std::vector<CMBranchElement> branch;
};

Hash fill_merge_mining_branches(MergeMiningItem items[], size_t count);
Hash fill_cm_branches(CMTreeItem items[], size_t count);

bool cm_branch_valid(const std::vector<CMBranchElement> &branch);
Hash tree_hash_from_cm_branch(const std::vector<CMBranchElement> &branch, const Hash &leaf, const Hash &path);

}  // namespace crypto
