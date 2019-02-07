// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>
#include "bernstein/c_types.h"
#include "crypto-util.h"
#include "generic-ops.hpp"
#include "hash.h"

namespace crypto {

#pragma pack(push, 1)
struct Hash : public cryptoHash {
	constexpr Hash() : cryptoHash{} {}

	std::vector<uint8_t> as_binary_array() const { return std::vector<uint8_t>{std::begin(data), std::end(data)}; }
};

struct EllipticCurvePoint : public cryptoEllipticCurvePoint {
	constexpr EllipticCurvePoint() : cryptoEllipticCurvePoint{} {}
	// Default initialisation produces point outside main subgroup
	// Good or bad, this is done so that Point{} can be used as "null value".

	std::vector<uint8_t> as_binary_array() const { return std::vector<uint8_t>{std::begin(data), std::end(data)}; }
};
struct EllipticCurveScalar : public cryptoEllipticCurveScalar {
	constexpr EllipticCurveScalar() : cryptoEllipticCurveScalar{} {}

	std::vector<uint8_t> as_binary_array() const { return std::vector<uint8_t>{std::begin(data), std::end(data)}; }
};

struct PublicKey : public EllipticCurvePoint {};

struct SecretKey : public EllipticCurveScalar {
	~SecretKey() { sodium_memzero(data, sizeof(data)); }
};

struct KeyDerivation : public EllipticCurvePoint {};

struct KeyImage : public EllipticCurvePoint {};

struct Signature {
	EllipticCurveScalar c, r;
};
#pragma pack(pop)

static_assert(sizeof(EllipticCurvePoint) == 32 && sizeof(EllipticCurveScalar) == 32, "Invalid structure size");

static_assert(sizeof(Hash) == 32 && sizeof(PublicKey) == 32 && sizeof(SecretKey) == 32 && sizeof(KeyDerivation) == 32 &&
                  sizeof(KeyImage) == 32 && sizeof(Signature) == 64,
    "Invalid structure size");

// Following structures never used as a pod

struct CMBranchElement {
	uint8_t depth = 0;
	Hash hash;
};

struct KeyPair {
	PublicKey public_key;
	SecretKey secret_key;
};

typedef std::vector<Signature> RingSignature;

struct RingSignatureAmethyst {  // New auditable signatures
	std::vector<PublicKey> p;
	EllipticCurveScalar c0;
	std::vector<std::vector<EllipticCurveScalar>> ra;
	std::vector<EllipticCurveScalar> rb;
	std::vector<EllipticCurveScalar> rc;
};

struct SendproofSignatureAmethyst {
	EllipticCurveScalar c0, rb, rc;
};

std::ostream &operator<<(std::ostream &out, const EllipticCurvePoint &v);
std::ostream &operator<<(std::ostream &out, const EllipticCurveScalar &v);
std::ostream &operator<<(std::ostream &out, const Hash &v);

CRYPTO_MAKE_COMPARABLE(Hash, std::memcmp)
CRYPTO_MAKE_COMPARABLE(EllipticCurveScalar, sodium_compare)
CRYPTO_MAKE_COMPARABLE(EllipticCurvePoint, std::memcmp)
CRYPTO_MAKE_COMPARABLE(PublicKey, std::memcmp)
CRYPTO_MAKE_COMPARABLE(SecretKey, sodium_compare)
CRYPTO_MAKE_COMPARABLE(KeyDerivation, std::memcmp)
CRYPTO_MAKE_COMPARABLE(KeyImage, std::memcmp)
CRYPTO_MAKE_COMPARABLE(Signature, std::memcmp)

}  // namespace crypto

CRYPTO_MAKE_HASHABLE(crypto::Hash)
CRYPTO_MAKE_HASHABLE(crypto::EllipticCurveScalar)
CRYPTO_MAKE_HASHABLE(crypto::EllipticCurvePoint)
CRYPTO_MAKE_HASHABLE(crypto::PublicKey)
CRYPTO_MAKE_HASHABLE(crypto::SecretKey)
CRYPTO_MAKE_HASHABLE(crypto::KeyDerivation)
CRYPTO_MAKE_HASHABLE(crypto::KeyImage)
