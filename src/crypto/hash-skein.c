// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <stddef.h>
#include <stdint.h>

#include "hash.h"
#include "skein/skein.h"

void crypto_hash_extra_skein(const void *data, size_t length, struct cryptoHash *hash) {
	skein_hash(8 * sizeof(struct cryptoHash), data, 8 * length, hash->data);
}
