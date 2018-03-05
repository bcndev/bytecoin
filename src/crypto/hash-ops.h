// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#if defined(__cplusplus)
namespace crypto { extern "C" {
#endif

enum {
  HASH_SIZE = 32,
  HASH_DATA_AREA = 136,
  SLOW_HASH_CONTEXT_SIZE = 2097552
};

void cn_fast_hash(const void *data, size_t length, unsigned char *hash);

void cn_slow_hash(void *, const void *, size_t, void *);

void tree_hash(const unsigned char (*hashes)[HASH_SIZE], size_t count, unsigned char *root_hash);
size_t tree_depth(size_t count);
void tree_branch(const unsigned char (*hashes)[HASH_SIZE], size_t count, unsigned char (*branch)[HASH_SIZE]);
void tree_hash_from_branch(const unsigned char (*branch)[HASH_SIZE], size_t depth, const unsigned char *leaf, const void *path, unsigned char *root_hash);

#if defined(__cplusplus)
}}
#endif
