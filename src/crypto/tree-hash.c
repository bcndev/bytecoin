// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "tree-hash.h"
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// We defined funs for count == 0 to avoid special cases

void crypto_tree_hash(const struct cryptoHash hashes[], size_t count, struct cryptoHash *root_hash) {
	if (count == 0) {
		memset(root_hash->data, 0, sizeof(root_hash->data));
		return;
	}
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
	struct cryptoHash *ints = (struct cryptoHash *)malloc(cnt * sizeof(struct cryptoHash));
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
	free(ints);
}

size_t crypto_coinbase_tree_depth(size_t count) {
	if (count == 0)
		return 0;
	size_t depth = 0;
	while (depth < 63 && (1ULL << (depth + 1)) <= count)
		depth += 1;
	return depth;
}

void crypto_coinbase_tree_branch(const struct cryptoHash hashes[], size_t count, struct cryptoHash branch[]) {
	if (count == 0)
		return;
	size_t i, j;
	size_t depth            = crypto_coinbase_tree_depth(count);
	size_t cnt              = (size_t)1U << depth;
	struct cryptoHash *ints = (struct cryptoHash *)malloc((cnt - 1) * sizeof(struct cryptoHash));
	memcpy(ints, hashes + 1, (2 * cnt - count - 1) * sizeof(struct cryptoHash));
	for (i = 2 * cnt - count, j = 2 * cnt - count - 1; j < cnt - 1; i += 2, ++j) {
		crypto_cn_fast_hash(hashes + i, 2 * sizeof(struct cryptoHash), ints + j);
	}
	assert(i == count);
	while (depth > 0) {
		assert(cnt == (size_t)1U << depth);
		cnt >>= 1U;
		--depth;
		branch[depth] = ints[0];
		for (i = 1, j = 0; j < cnt - 1; i += 2, ++j) {
			crypto_cn_fast_hash(ints + i, 2 * sizeof(struct cryptoHash), ints + j);
		}
	}
	free(ints);
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
		if (path && (path->data[depth >> 3U] & (1U << (depth & 7U))) != 0) {
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
