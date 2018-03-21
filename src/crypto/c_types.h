// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#if defined(__cplusplus)
#include "generic-ops.hpp"
namespace crypto { extern "C" {
#endif

#pragma pack(push, 1)
struct EllipticCurvePoint {
	unsigned char data[32];
};
struct EllipticCurveScalar {
	unsigned char data[32];
};
#pragma pack(pop)

#if defined(__cplusplus)
}}

CRYPTO_MAKE_COMPARABLE(crypto, EllipticCurvePoint, std::memcmp)
CRYPTO_MAKE_COMPARABLE(crypto, EllipticCurveScalar, std::memcmp)

#endif
