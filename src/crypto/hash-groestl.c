// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <stddef.h>
#include <stdint.h>

#include "groestl/Groestl-opt.h"
#include "hash.h"

void crypto_hash_extra_groestl(const void *data, size_t length, struct cryptoHash *hash) {
	hashState context;

	Init(&context, 256);
	Update(&context, data, length * 8);
	Final(&context, hash->data);
}

void hash_extra_groestl(const void *data, size_t length, unsigned char *hash) {
	hashState context;

	Init(&context, 256);
	Update(&context, data, length * 8);
	Final(&context, hash);
}
