// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#pragma pack(push, 1)
struct cryptoHash {
	unsigned char data[32];
};
#pragma pack(pop)

enum { HASH_DATA_AREA = 136, SLOW_HASH_CONTEXT_SIZE = 2097552 };

void crypto_cn_fast_hash(const void *data, size_t length, struct cryptoHash *hash);
void crypto_cn_fast_hash64(const void *data, size_t length, unsigned char hash[64]);

void crypto_cn_slow_hash(void *scratchpad, const void *data, size_t length, struct cryptoHash *hash);
void crypto_cn_slow_hash_platform_independent(
    void *scratchpad, const void *data, size_t length, struct cryptoHash *hash);

struct cryptoKeccakState {
	uint8_t b[200];
};

void crypto_keccak_permutation(struct cryptoKeccakState *state);
void crypto_keccak_into_state(const uint8_t *buf, size_t count, struct cryptoKeccakState *state);

void crypto_hash_extra_blake(const void *data, size_t length, struct cryptoHash *hash);
void crypto_hash_extra_groestl(const void *data, size_t length, struct cryptoHash *hash);
void crypto_hash_extra_jh(const void *data, size_t length, struct cryptoHash *hash);
void crypto_hash_extra_skein(const void *data, size_t length, struct cryptoHash *hash);

#if defined(__cplusplus)
}

#endif
