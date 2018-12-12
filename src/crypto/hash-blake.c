// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <stddef.h>
#include <stdint.h>

#include "blake/blake256.h"
#include "hash.h"

void crypto_hash_extra_blake(const void *data, size_t length, struct cryptoHash *hash) {
	blake256_hash(hash->data, data, length);
}
