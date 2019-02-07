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
// void crypto_cn_fast_hash64(const void *data, size_t length, unsigned char hash[64]);

void crypto_cn_slow_hash(void *scratchpad, const void *data, size_t length, struct cryptoHash *hash);
void crypto_cn_slow_hash_platform_independent(
    void *scratchpad, const void *data, size_t length, struct cryptoHash *hash);

struct cryptoKeccakState {
	uint8_t b[200];
};

struct cryptoKeccakHasher {
	struct cryptoKeccakState state;
	size_t offset;
	size_t rate;
	uint8_t delim;
};

void crypto_keccak_permutation(struct cryptoKeccakState *state);
void crypto_keccak_into_state(const uint8_t *buf, size_t count, struct cryptoKeccakState *state);

// shake128:  128, 0x1f
// shake256:  256, 0x1f
// keccak224: 224, 0x01
// keccak256: 256, 0x01 <-- cn_fast_hash
// keccak384: 384, 0x01
// keccak512: 512, 0x01
// sha3_224:  224, 0x06
// sha3_256:  256, 0x06
// sha3_384:  384, 0x06
// sha3_512:  512, 0x06
void crypto_keccak_init(struct cryptoKeccakHasher *, size_t mdlen, uint8_t delim);
void crypto_keccak_update(struct cryptoKeccakHasher *, const void *buf, size_t count);
void crypto_keccak_final(struct cryptoKeccakHasher *, uint8_t *result, size_t count);

void crypto_hash_extra_blake(const void *data, size_t length, struct cryptoHash *hash);
void crypto_hash_extra_groestl(const void *data, size_t length, struct cryptoHash *hash);
void crypto_hash_extra_jh(const void *data, size_t length, struct cryptoHash *hash);
void crypto_hash_extra_skein(const void *data, size_t length, struct cryptoHash *hash);

#if defined(__cplusplus)
}

#endif
