// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "tree-hash.h"
#include <assert.h>
#include <stddef.h>
#include <string.h>
#ifdef _WIN32
#include <malloc.h>
#define alloca _alloca
#else
#include <alloca.h>
#endif

void crypto_tree_hash(const struct cryptoHash hashes[], size_t count, struct cryptoHash *root_hash) {
	assert(count > 0);
	if (count == 1) {
		*root_hash = *hashes;
		return;
	}
	if (count == 2) {
		crypto_cn_fast_hash(hashes, 2 * sizeof(struct cryptoHash), root_hash);
		return;
	}
	size_t i, j;
	size_t cnt = 1;
	while (cnt * 2 < count)
		cnt *= 2;
	//    size_t cnt = count - 1;
	//    for (i = 1; i < 8 * sizeof(size_t); i <<= 1) {
	//      cnt |= cnt >> i;
	//    }
	//    cnt &= ~(cnt >> 1);
	struct cryptoHash *ints = (struct cryptoHash *)alloca(cnt * sizeof(struct cryptoHash));
	memcpy(ints, hashes, (2 * cnt - count) * sizeof(struct cryptoHash));
	for (i = 2 * cnt - count, j = 2 * cnt - count; j < cnt; i += 2, ++j) {
		crypto_cn_fast_hash(hashes + i, 2 * sizeof(struct cryptoHash), ints + j);
	}
	assert(i == count);
	while (cnt > 2) {
		cnt /= 2;
		for (j = 0; j < cnt; ++j) {
			crypto_cn_fast_hash(ints + 2 * j, 2 * sizeof(struct cryptoHash), ints + j);
		}
	}
	crypto_cn_fast_hash(ints, 2 * sizeof(struct cryptoHash), root_hash);
}

size_t crypto_coinbase_tree_depth(size_t count) {
	assert(count > 0);
	size_t depth = 0;
	while ((1ULL << (depth + 1)) <= count)
		depth += 1;
	//  for (i = sizeof(size_t) << 2; i > 0; i >>= 1) {
	//    if (count >> i > 0) {
	//      count >>= i;
	//      depth += i;
	//    }
	//  }
	return depth;
}

void crypto_coinbase_tree_branch(const struct cryptoHash hashes[], size_t count, struct cryptoHash branch[]) {
	assert(count > 0);
	size_t i, j;
	size_t depth = crypto_coinbase_tree_depth(count);
	size_t cnt   = (size_t)1U << depth;
	//  for (i = sizeof(size_t) << 2; i > 0; i >>= 1) {
	//    if (cnt << i <= count) {
	//      cnt <<= i;
	//      depth += i;
	//    }
	//  }
	//  assert(cnt == 1ULL << depth);
	//  assert(depth == coinbase_tree_depth(count));
	struct cryptoHash *ints = (struct cryptoHash *)alloca((cnt - 1) * sizeof(struct cryptoHash));
	memcpy(ints, hashes + 1, (2 * cnt - count - 1) * sizeof(struct cryptoHash));
	for (i = 2 * cnt - count, j = 2 * cnt - count - 1; j < cnt - 1; i += 2, ++j) {
		crypto_cn_fast_hash(hashes + i, 2 * sizeof(struct cryptoHash), ints + j);
	}
	assert(i == count);
	while (depth > 0) {
		assert(cnt == (size_t)1U << depth);
		cnt >>= 1;
		--depth;
		branch[depth] = ints[0];
		for (i = 1, j = 0; j < cnt - 1; i += 2, ++j) {
			crypto_cn_fast_hash(ints + i, 2 * sizeof(struct cryptoHash), ints + j);
		}
	}
}

void crypto_tree_hash_from_branch(const struct cryptoHash branch[], size_t depth, const struct cryptoHash *leaf,
    const struct cryptoHash *path, struct cryptoHash *root_hash) {
	if (depth == 0) {
		*root_hash = *leaf;
		return;
	}
	struct cryptoHash buffer[2];
	int from_leaf = 1;
	struct cryptoHash *leaf_path, *branch_path;
	while (depth > 0) {
		--depth;
		if (path && (path->data[depth >> 3] & (1 << (depth & 7))) != 0) {
			leaf_path   = buffer + 1;
			branch_path = buffer + 0;
		} else {
			leaf_path   = buffer + 0;
			branch_path = buffer + 1;
		}
		if (from_leaf) {
			*leaf_path = *leaf;
			from_leaf  = 0;
		} else {
			crypto_cn_fast_hash(buffer, 2 * sizeof(struct cryptoHash), leaf_path);
		}
		*branch_path = branch[depth];
	}
	crypto_cn_fast_hash(buffer, 2 * sizeof(struct cryptoHash), root_hash);
}
