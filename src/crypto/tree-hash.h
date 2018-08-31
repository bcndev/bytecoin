// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "hash.h"

#if defined(__cplusplus)
namespace crypto {
extern "C" {
#endif

void tree_hash(const struct CHash hashes[], size_t count, struct CHash *root_hash);
size_t coinbase_tree_depth(size_t count);
void coinbase_tree_branch(const struct CHash hashes[], size_t count, struct CHash branch[]);
void tree_hash_from_branch(const struct CHash branch[], size_t depth, const struct CHash *leaf,
    const struct CHash *path, struct CHash *root_hash);

#if defined(__cplusplus)
}
}

#endif
