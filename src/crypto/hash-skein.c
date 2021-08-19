// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <stddef.h>
#include <stdint.h>

#include "hash.h"
#include "skein/skein.h"

enum {
  HASH_SIZE = 32
};

void crypto_hash_extra_skein(const void *data, size_t length, struct cryptoHash *hash) {
	skein_hash(8 * sizeof(struct cryptoHash), data, 8 * length, hash->data);
}

void hash_extra_skein(const void *data, size_t length, unsigned char *hash) {
  int r = skein_hash(8 * HASH_SIZE, data, 8 * length, hash);
  assert(SKEIN_SUCCESS == r);
}
