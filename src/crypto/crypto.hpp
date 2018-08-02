// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstddef>
#include <limits>
#include <mutex>
#include <type_traits>
#include <vector>

#include "random.h"
#include "types.hpp"

namespace crypto {

void generate_random_bytes(size_t n, void *result);  // thread-safe
void random_scalar(EllipticCurveScalar &res);

template<typename T>
T rand() {
	static_assert(std::is_standard_layout<T>::value, "T must be Standard Layout");
	T res;
	generate_random_bytes(sizeof(T), &res);
	return res;
}

template<typename T>
class random_engine {  // adapter for std:: algorithms
public:
	typedef T result_type;
	constexpr static T min() { return std::numeric_limits<T>::min(); }
	constexpr static T max() { return std::numeric_limits<T>::max(); }
	T operator()() {
		static_assert(std::is_unsigned<T>::value, "random engine is defined only for unsigned types");
		return rand<T>();
	}
};

void random_keypair(PublicKey &pub, SecretKey &sec);

inline KeyPair random_keypair() {
	KeyPair k;
	crypto::random_keypair(k.public_key, k.secret_key);
	return k;
}

// Check a public key. Returns true if it is valid, false otherwise.
bool key_isvalid(const PublicKey &key);
// Checks a private key and computes the corresponding public key.
bool secret_key_to_public_key(const SecretKey &sec, PublicKey &pub);
bool keys_match(const SecretKey &secret_key, const PublicKey &expected_public_key);

// To generate an ephemeral key used to send money to:
// The sender generates a new key pair, which becomes the transaction key. The public transaction key is included in
// "extra" field.
// Both the sender and the receiver generate key derivation from the transaction key and the receivers' "view" key.
// The sender uses key derivation, the output index, and the receivers' "spend" key to derive an ephemeral public key.
// The receiver can either derive the public key (to check that the transaction is addressed to him) or the private key
// (to spend the money).
bool generate_key_derivation(const PublicKey &key1, const SecretKey &key2, KeyDerivation &derivation);

bool derive_public_key(const KeyDerivation &derivation, size_t output_index, const PublicKey &base,
    const uint8_t *prefix, size_t prefix_length, PublicKey &derived_key);

bool derive_public_key(
    const KeyDerivation &derivation, size_t output_index, const PublicKey &base, PublicKey &derived_key);

bool underive_public_key_and_get_scalar(const KeyDerivation &derivation, std::size_t output_index,
    const PublicKey &derived_key, PublicKey &base, EllipticCurveScalar &hashed_derivation);

void derive_secret_key(const KeyDerivation &derivation, std::size_t output_index, const SecretKey &base,
    const uint8_t *prefix, size_t prefix_length, SecretKey &derived_key);

void derive_secret_key(
    const KeyDerivation &derivation, std::size_t output_index, const SecretKey &base, SecretKey &derived_key);

// Inverse function of derive_public_key. It can be used by the receiver to find which "spend" key was used to generate
// a transaction. This may be useful if the receiver used multiple addresses which only differ in "spend" key.
bool underive_public_key(const KeyDerivation &derivation, size_t output_index, const PublicKey &derived_key,
    const uint8_t *prefix, size_t prefix_length, PublicKey &base);

bool underive_public_key(
    const KeyDerivation &derivation, size_t output_index, const PublicKey &derived_key, PublicKey &base);

// returns false if keys are corrupted/invalid
void generate_signature(const Hash &prefix_hash, const PublicKey &pub, const SecretKey &sec, Signature &sig);
bool check_signature(
    const Hash &prefix_hash, const PublicKey &pub, const Signature &sig, bool *key_corrupted = nullptr);

// To send money to a key:
// The sender generates an ephemeral key and includes it in transaction output.
// To spend the money, the receiver generates a key image from it.
// Then he selects a bunch of outputs, including the one he spends, and uses them to generate a ring signature.
// To check the signature, it is necessary to collect all the keys that were used to generate it. To detect double
// spends, it is necessary to check that each key image is used at most once.
void generate_key_image(const PublicKey &pub, const SecretKey &sec, KeyImage &image);

// void hash_data_to_ec(const uint8_t* data, std::size_t len, EllipticCurvePoint& key);

// returns false if keys are corrupted/invalid
bool generate_ring_signature(const Hash &prefix_hash, const KeyImage &image, const PublicKey *const pubs[],
    std::size_t pubs_count, const SecretKey &sec, std::size_t sec_index, Signature sigs[]);
bool check_ring_signature(const Hash &prefix_hash, const KeyImage &image, const PublicKey *const pubs[],
    size_t pubs_count, const Signature sigs[], bool check_key_image, bool *key_corrupted = nullptr);
// TODO - remove one pair of funs
// returns false if keys are corrupted/invalid
inline bool generate_ring_signature(const Hash &prefix_hash, const KeyImage &image,
    const std::vector<const PublicKey *> &pubs, const SecretKey &sec, size_t sec_index, Signature sigs[]) {
	return generate_ring_signature(prefix_hash, image, pubs.data(), pubs.size(), sec, sec_index, sigs);
}
inline bool check_ring_signature(const Hash &prefix_hash, const KeyImage &image,
    const std::vector<const PublicKey *> &pubs, const Signature sigs[], bool check_key_image,
    bool *key_corrupted = nullptr) {
	return check_ring_signature(prefix_hash, image, pubs.data(), pubs.size(), sigs, check_key_image, key_corrupted);
}

bool generate_sendproof(const PublicKey &txkey_pub, const SecretKey &txkey_sec, const PublicKey &receiver_view_key_pub,
    const KeyDerivation &derivation, const Hash &message_hash, Signature &proof);
// Transaction key and the derivation supplied with the proof can be invalid, this just means that the proof is invalid.
bool check_sendproof(const PublicKey &txkey_pub, const PublicKey &receiver_view_key_pub,
    const KeyDerivation &derivation, const Hash &message_hash, const Signature &proof);

void hash_to_scalar(const void *data, size_t length, EllipticCurveScalar &res);
void hash_to_point_for_tests(const Hash &h, EllipticCurvePoint &res);  // Used only in tests
void hash_to_ec(const PublicKey &key, EllipticCurvePoint &res);
}
