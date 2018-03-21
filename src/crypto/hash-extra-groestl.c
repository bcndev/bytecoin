// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <stddef.h>
#include <stdint.h>

#include "groestl.h"

void hash_extra_groestl(const void *data, size_t length, unsigned char *hash) {
  groestl(data, length * 8, hash);
}
