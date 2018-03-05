// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include <stddef.h>
#include <stdint.h>

#include "hash-impl.h"
#include "skein.h"

void hash_extra_skein(const void *data, size_t length, unsigned char *hash) {
  int r = skein_hash(8 * HASH_SIZE, data, 8 * length, hash);
  assert(SKEIN_SUCCESS == r);
}
