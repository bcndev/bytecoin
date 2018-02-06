// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

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
