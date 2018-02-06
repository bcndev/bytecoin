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

#include <cstdint>
#include <string>
#include <vector>
#include "c_types.h"
#include "crypto-util.h"

namespace crypto {

#pragma pack(push, 1)
struct Hash {
  uint8_t data[32]{};
};

struct PublicKey : public EllipticCurvePoint {
	PublicKey():EllipticCurvePoint{}{}
};

struct SecretKey : public EllipticCurveScalar {
	SecretKey():EllipticCurveScalar{}{}
	~SecretKey() {
		sodium_memzero(data, sizeof(data));
	}
};

struct KeyDerivation : public EllipticCurvePoint {
	KeyDerivation():EllipticCurvePoint{}{}
};

struct KeyImage : public EllipticCurvePoint {
	KeyImage():EllipticCurvePoint{}{}
};

struct Signature {
    EllipticCurveScalar c, r;
	Signature():c{}, r{}{}
};
#pragma pack(pop)

static_assert(sizeof(EllipticCurvePoint) == 32 && sizeof(EllipticCurveScalar) == 32, "Invalid structure size");

static_assert(sizeof(Hash) == 32 && sizeof(PublicKey) == 32
	&& sizeof(SecretKey) == 32 && sizeof(KeyDerivation) == 32
	&& sizeof(KeyImage) == 32 && sizeof(Signature) == 64, "Invalid structure size");

struct KeyPair { // Never used as a pod
	PublicKey publicKey;
	SecretKey secretKey;
};

}

CRYPTO_MAKE_HASHABLE(crypto, Hash)
CRYPTO_MAKE_COMPARABLE(crypto, Hash, std::memcmp)

CRYPTO_MAKE_HASHABLE(crypto, PublicKey)
CRYPTO_MAKE_COMPARABLE(crypto, PublicKey, std::memcmp)

CRYPTO_MAKE_HASHABLE(crypto, KeyImage)
CRYPTO_MAKE_COMPARABLE(crypto, KeyImage, std::memcmp)

CRYPTO_MAKE_HASHABLE(crypto, SecretKey)
CRYPTO_MAKE_COMPARABLE(crypto, SecretKey, crypto::sodium_compare)

CRYPTO_MAKE_COMPARABLE(crypto, Signature, std::memcmp)

