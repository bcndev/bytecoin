// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

void crypto_unsafe_generate_random_bytes(unsigned char *result, size_t n);  // Not thread-safe
void crypto_initialize_random(void);
void crypto_initialize_random_for_tests(void);

#if defined(__cplusplus)
}
#endif
