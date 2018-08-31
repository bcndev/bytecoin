// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hash.h"

void KeccakF1600_StatePermute(void *state);  // Forward declarations from keccak/ folder

// Our Non Standard variant
static int keccak(const uint8_t *in, size_t inlen, uint8_t *md, size_t mdlen) {
	struct keccak_state st;
	uint8_t temp[144];
	size_t rsiz = sizeof(struct keccak_state) == mdlen ? HASH_DATA_AREA : 200 - 2 * mdlen;

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

void keccak_permutation(struct keccak_state *state) { KeccakF1600_StatePermute(state); }

void keccak_into_state(const uint8_t *buf, size_t count, struct keccak_state *state) {
	keccak(buf, count, state->b, sizeof(struct keccak_state));
}

void cn_fast_hash(const void *data, size_t length, struct CHash *hash) {
	struct keccak_state state;
	keccak_into_state(data, length, &state);
	memcpy(hash->data, &state, sizeof(struct CHash));
}
