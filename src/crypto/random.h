// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

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
