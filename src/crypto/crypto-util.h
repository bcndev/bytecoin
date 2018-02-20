// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include <stdint.h>
#include <stddef.h>


#if defined(__cplusplus)
#include <memory.h>
#include <string>
namespace crypto {
extern "C" {
#endif
// We borrow from https://libsodium.org/
void sodium_memzero(void* pnt, size_t length);
int sodium_compare(const void* a1, const void* a2, size_t length);
int sodium_is_zero(const void * data, const size_t nlen);

#if defined(__cplusplus)
}}
#endif
