// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"

void KeccakF1600_StatePermute(void *state);  // Forward declarations from keccak/ folder

// Our Non Standard variant
static int keccak(const uint8_t *in, size_t inlen, uint8_t *md, size_t mdlen) {
	struct cryptoKeccakState st;
	uint8_t temp[144];
	size_t rsiz = sizeof(struct cryptoKeccakState) == mdlen ? HASH_DATA_AREA : 200 - 2 * mdlen;

	memset(st.b, 0, sizeof(st));

	for (; inlen >= rsiz; inlen -= rsiz, in += rsiz) {
		for (size_t i = 0; i < rsiz; i++)
			st.b[i] ^= in[i];
		KeccakF1600_StatePermute(st.b);
	}

	// last block and padding
	memcpy(temp, in, inlen);
	temp[inlen++] = 1;
	memset(temp + inlen, 0, rsiz - inlen);
	temp[rsiz - 1] |= 0x80;

	for (size_t i = 0; i < rsiz; i++)
		st.b[i] ^= temp[i];

	KeccakF1600_StatePermute(st.b);

	memcpy(md, st.b, mdlen);

	return 0;
}

void crypto_keccak_permutation(struct cryptoKeccakState *state) { KeccakF1600_StatePermute(state); }

void crypto_keccak_into_state(const uint8_t *buf, size_t count, struct cryptoKeccakState *state) {
	keccak(buf, count, state->b, sizeof(struct cryptoKeccakState));
}

void crypto_cn_fast_hash(const void *data, size_t length, struct cryptoHash *hash) {
	//	struct cryptoHash hash2;
	struct cryptoKeccakHasher hasher;
	crypto_keccak_init(&hasher, 256, 1);
	crypto_keccak_update(&hasher, data, length);
	crypto_keccak_final(&hasher, hash->data, sizeof(hash->data));

	//	struct cryptoKeccakState state;
	//	crypto_keccak_into_state(data, length, &state);
	//	memcpy(hash->data, &state, sizeof(struct cryptoHash));

	//	if (memcmp(hash->data, hash2.data, sizeof(hash2.data)) != 0) {
	//		fprintf(stderr, "keccak stream failure for data length %d", (int)length);
	//		exit(-1);
	//	}
}

void crypto_keccak_init(struct cryptoKeccakHasher *hasher, size_t mdlen, uint8_t delim) {
	hasher->rate   = 200 - 2 * mdlen / 8;
	hasher->delim  = delim;
	hasher->offset = 0;
	memset(hasher->state.b, 0, sizeof(hasher->state.b));
}

void crypto_keccak_update(struct cryptoKeccakHasher *hasher, const void *vin, size_t inlen) {
	const unsigned char *in = (const unsigned char *)vin;
	size_t rsiz             = hasher->rate - hasher->offset;
	size_t offset           = hasher->offset;
	unsigned char *b        = hasher->state.b;

	while (inlen >= rsiz) {
		for (size_t i = 0; i < rsiz; i++)
			b[offset + i] ^= in[i];
		KeccakF1600_StatePermute(b);
		inlen -= rsiz;
		in += rsiz;
		rsiz   = hasher->rate;
		offset = 0;
	}
	for (size_t i = 0; i < inlen; i++)
		b[offset + i] ^= in[i];
	hasher->offset = offset + inlen;
}

void crypto_keccak_final(struct cryptoKeccakHasher *hasher, uint8_t *out, size_t outlen) {
	unsigned char *b = hasher->state.b;
	size_t rate      = hasher->rate;
	b[hasher->offset] ^= hasher->delim;
	b[rate - 1] ^= 0x80;

	KeccakF1600_StatePermute(b);

	for (; outlen >= rate; outlen -= rate, out += rate) {
		for (size_t i = 0; i < rate; i++)
			out[i] = b[i];
		KeccakF1600_StatePermute(b);
	}
	for (size_t i = 0; i < outlen; i++)
		out[i] = b[i];
}

// void crypto_cn_fast_hash64(const void *data, size_t length, unsigned char hash[64]) {
//	struct cryptoKeccakState state;
//	crypto_keccak_into_state(data, length, &state);
//	memcpy(hash, &state, 64);
//}
