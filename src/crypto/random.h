// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#if !defined(__cplusplus)
#include <stddef.h>
#endif

#if defined(__cplusplus)
namespace crypto { extern "C" {
#endif

void unsafe_generate_random_bytes(size_t n, void *result); // Not thread-safe
void initialize_random(void);
void initialize_random_for_tests(void);

#if defined(__cplusplus)
}}
#endif
