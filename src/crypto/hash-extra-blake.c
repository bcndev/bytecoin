// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <stddef.h>
#include <stdint.h>

#include "blake256.h"

void hash_extra_blake(const void *data, size_t length, unsigned char *hash) {
  blake256_hash(hash, data, length);
}
