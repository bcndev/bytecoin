// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <stddef.h>
#include <stdint.h>

#include "hash.h"
#include "skein/skein.h"

void hash_extra_skein(const void *data, size_t length, struct CHash *hash) {
	int r = skein_hash(8 * sizeof(struct CHash), data, 8 * length, hash->data);
	assert(SKEIN_SUCCESS == r);
}
