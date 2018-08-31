// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
#include "generic-ops.hpp"
namespace crypto {
extern "C" {
#endif

#pragma pack(push, 1)
struct CHash {
	unsigned char data[32];
};
#pragma pack(pop)

enum { HASH_DATA_AREA = 136, SLOW_HASH_CONTEXT_SIZE = 2097552 };

void cn_fast_hash(const void *data, size_t length, struct CHash *hash);

void cn_slow_hash(void *scratchpad, const void *data, size_t length, struct CHash *hash);
void cn_slow_hash_platform_independent(void *scratchpad, const void *data, size_t length, struct CHash *hash);

struct keccak_state {
	uint8_t b[200];
};

static_assert(sizeof(struct keccak_state) == 200, "Invalid structure size");

void keccak_permutation(struct keccak_state *state);
void keccak_into_state(const uint8_t *buf, size_t count, struct keccak_state *state);

void hash_extra_blake(const void *data, size_t length, struct CHash *hash);
void hash_extra_groestl(const void *data, size_t length, struct CHash *hash);
void hash_extra_jh(const void *data, size_t length, struct CHash *hash);
void hash_extra_skein(const void *data, size_t length, struct CHash *hash);

#if defined(__cplusplus)
}
}

CRYPTO_MAKE_COMPARABLE(crypto, CHash, std::memcmp)

#endif
