// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hash.h"
#include "jh/jh.h"

void crypto_hash_extra_jh(const void *data, size_t length, struct cryptoHash *hash) {
	int r = jh_hash(sizeof(struct cryptoHash) * 8, data, 8 * length, hash->data);
	assert(SUCCESS == r);
}
