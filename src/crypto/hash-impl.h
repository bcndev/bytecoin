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

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "int-util.h"
#include "hash-ops.h"

#if defined(__cplusplus)
namespace crypto { extern "C" {
#endif

inline void *padd(void *p, size_t i) {
  return (char *) p + i;
}

inline const void *cpadd(const void *p, size_t i) {
  return (const char *) p + i;
}

#pragma pack(push, 1)
union hash_state {
  uint8_t b[200];
  uint64_t w[25];
};
#pragma pack(pop)
static_assert(sizeof(union hash_state) == 200, "Invalid structure size");

void hash_permutation(union hash_state *state);
void hash_process(union hash_state *state, const uint8_t *buf, size_t count);

void hash_extra_blake(const void *data, size_t length, unsigned char *hash);
void hash_extra_groestl(const void *data, size_t length, unsigned char *hash);
void hash_extra_jh(const void *data, size_t length, unsigned char *hash);
void hash_extra_skein(const void *data, size_t length, unsigned char *hash);

#if defined(__cplusplus)
}}
#endif
