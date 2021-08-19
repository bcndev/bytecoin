// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "hash.h"

#if defined(__cplusplus)
extern "C" {
#endif

void crypto_tree_hash(const struct cryptoHash hashes[], size_t count, struct cryptoHash *root_hash);
size_t crypto_coinbase_tree_depth(size_t count);
void crypto_coinbase_tree_branch(const struct cryptoHash hashes[], size_t count, struct cryptoHash branch[]);
void crypto_tree_hash_from_branch(const struct cryptoHash branch[], size_t depth, const struct cryptoHash *leaf,
    const struct cryptoHash *path, struct cryptoHash *root_hash);

#if defined(__cplusplus)
}
#endif
