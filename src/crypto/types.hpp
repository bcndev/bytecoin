// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>
#include "bernstein/c_types.h"
#include "crypto-util.h"
#include "hash.h"

namespace crypto {

#pragma pack(push, 1)
struct Hash : public CHash {
	constexpr Hash() : CHash{} {}
};

struct PublicKey : public EllipticCurvePoint {
	constexpr PublicKey() : EllipticCurvePoint{} {}
};

struct SecretKey : public EllipticCurveScalar {
	constexpr SecretKey() : EllipticCurveScalar{} {}
	~SecretKey() { sodium_memzero(data, sizeof(data)); }
};

struct KeyDerivation : public EllipticCurvePoint {
	constexpr KeyDerivation() : EllipticCurvePoint{} {}
};

struct KeyImage : public EllipticCurvePoint {
	constexpr KeyImage() : EllipticCurvePoint{} {}
};

struct Signature {
	EllipticCurveScalar c, r;
	constexpr Signature() : c{}, r{} {}
};
#pragma pack(pop)

static_assert(sizeof(EllipticCurvePoint) == 32 && sizeof(EllipticCurveScalar) == 32, "Invalid structure size");

static_assert(sizeof(Hash) == 32 && sizeof(PublicKey) == 32 && sizeof(SecretKey) == 32 && sizeof(KeyDerivation) == 32 &&
                  sizeof(KeyImage) == 32 &&
                  sizeof(Signature) == 64,
    "Invalid structure size");

struct KeyPair {  // Never used as a pod
	PublicKey public_key;
	SecretKey secret_key;
};

std::ostream &operator<<(std::ostream &out, const EllipticCurvePoint &v);
std::ostream &operator<<(std::ostream &out, const EllipticCurveScalar &v);
std::ostream &operator<<(std::ostream &out, const Hash &v);
}

CRYPTO_MAKE_HASHABLE(crypto, Hash)
CRYPTO_MAKE_COMPARABLE(crypto, Hash, std::memcmp)

CRYPTO_MAKE_HASHABLE(crypto, PublicKey)
CRYPTO_MAKE_COMPARABLE(crypto, PublicKey, std::memcmp)

CRYPTO_MAKE_HASHABLE(crypto, SecretKey)
CRYPTO_MAKE_COMPARABLE(crypto, SecretKey, crypto::sodium_compare)

CRYPTO_MAKE_HASHABLE(crypto, KeyDerivation)
CRYPTO_MAKE_COMPARABLE(crypto, KeyDerivation, std::memcmp)

CRYPTO_MAKE_HASHABLE(crypto, KeyImage)
CRYPTO_MAKE_COMPARABLE(crypto, KeyImage, std::memcmp)

CRYPTO_MAKE_COMPARABLE(crypto, Signature, std::memcmp)
