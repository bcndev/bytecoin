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

// thrown when invariants a violated
// 1. PublicKey, SecretKey are invalid (except key_isvalid, secret_key_to_public_key, keys_match)
// 2. array sizes mismatch or other logic error

class Error : public std::logic_error {
public:
	explicit Error(const std::string &msg) : std::logic_error(msg) {}
};

void generate_random_bytes(void *result, size_t n);  // thread-safe
SecretKey random_scalar();

template<typename T>
T rand() {
	static_assert(std::is_standard_layout<T>::value, "T must be Standard Layout");
	T res;
	generate_random_bytes(&res, sizeof(T));
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
bool secret_key_to_public_key(const SecretKey &sec, PublicKey *pub);
bool keys_match(const SecretKey &secret_key, const PublicKey &expected_public_key);

// To generate an ephemeral key used to send money to:
// The sender generates a new key pair, which becomes the transaction key. The public transaction key is included in
// "extra" field.
// Both the sender and the receiver generate key derivation from the transaction key and the receivers' "view" key.
// The sender uses key derivation, the output index, and the receivers' "spend" key to derive an ephemeral public key.
// The receiver can either derive the public key (to check that the transaction is addressed to him) or the private key
// (to spend the money).
KeyDerivation generate_key_derivation(const PublicKey &tx_public_key, const SecretKey &view_secret_key);

PublicKey derive_public_key(const KeyDerivation &derivation, size_t output_index, const PublicKey &spend_public_key);

SecretKey derive_secret_key(
    const KeyDerivation &derivation, std::size_t output_index, const SecretKey &spend_secret_key);

// Inverse function of derive_public_key. It can be used by the receiver to find which "spend" key was used to generate
// a transaction. This may be useful if the receiver used multiple addresses which only differ in "spend" key.

PublicKey underive_public_key(const KeyDerivation &derivation, size_t output_index, const PublicKey &output_public_key);

// returns false if keys are corrupted/invalid
Signature generate_signature(const Hash &prefix_hash, const PublicKey &pub, const SecretKey &sec);

bool check_signature(const Hash &prefix_hash, const PublicKey &pub, const Signature &sig);

// To send money to a key:
// The sender generates an ephemeral key and includes it in transaction output.
// To spend the money, the receiver generates a key image from it.
// Then he selects a bunch of outputs, including the one he spends, and uses them to generate a ring signature.
// To check the signature, it is necessary to collect all the keys that were used to generate it. To detect double
// spends, it is necessary to check that each key image is used at most once.
KeyImage generate_key_image(const PublicKey &pub, const SecretKey &sec);

// void hash_data_to_ec(const uint8_t* data, std::size_t len, EllipticCurvePoint& key);

RingSignature generate_ring_signature(const Hash &prefix_hash, const KeyImage &image, const PublicKey pubs[],
    std::size_t pubs_count, const SecretKey &sec, std::size_t sec_index);

bool check_ring_signature(const Hash &prefix_hash, const KeyImage &image, const PublicKey pubs[], size_t pubs_count,
    const RingSignature &sig, bool key_image_subgroup_check);

RingSignature3 generate_ring_signature3(const Hash &prefix_hash, const std::vector<KeyImage> &images,
    const std::vector<std::vector<PublicKey>> &pubs, const std::vector<SecretKey> &secs,
    const std::vector<size_t> &sec_indexes, const SecretKey &view_secret_key);
// returns false if keys are corrupted/invalid

bool check_ring_signature3(const Hash &prefix_hash, const std::vector<KeyImage> &image,
    const std::vector<std::vector<PublicKey>> &pubs, const RingSignature3 &sig);

size_t find_deterministic_input3(const Hash &prefix_hash, size_t input_index, const std::vector<EllipticCurveScalar> &r,
    const SecretKey &view_secret_key);
// returns r.size() if not our input

Signature generate_sendproof(const PublicKey &txkey_pub, const SecretKey &txkey_sec,
    const PublicKey &receiver_view_key_pub, const KeyDerivation &derivation, const Hash &message_hash);
// Transaction key and the derivation supplied with the proof can be invalid, this just means that the proof is invalid.
bool check_sendproof(const PublicKey &txkey_pub, const PublicKey &receiver_view_key_pub,
    const KeyDerivation &derivation, const Hash &message_hash, const Signature &proof);

SecretKey hash_to_scalar(const void *data, size_t length);
SecretKey hash_to_scalar64(const void *data, size_t length);
EllipticCurvePoint hash_to_point_for_tests(const Hash &h);  // Used only in tests
PublicKey hash_to_ec(const PublicKey &key);

// result size should be set to number of desired spend keys
void generate_hd_spendkeys(
    const KeyPair &base, const Hash &keys_generation_seed, size_t index, std::vector<KeyPair> *result);
PublicKey generate_address_s_v(const PublicKey &spend_public_key, const SecretKey &view_secret_key);

// Unlinkable crypto, spend_scalar is temporary value that is expensive to calc, we pass it arounf
PublicKey unlinkable_underive_public_key(const SecretKey &view_secret_key, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &output_public_key, const Hash &encrypted_output_secret,
    SecretKey *spend_scalar);

SecretKey unlinkable_derive_secret_key(const SecretKey &spend_secret_key, const SecretKey &spend_scalar);

PublicKey unlinkable_derive_public_key(const Hash &output_secret, const Hash &tx_inputs_hash, size_t output_index,
    const PublicKey &spend_public_key, const PublicKey &vs_public_key, Hash *encrypted_output_secret);

bool unlinkable_underive_address(const Hash &output_secret, const Hash &tx_inputs_hash, size_t output_index,
    const PublicKey &output_public_key, const Hash &encrypted_output_secret, PublicKey *spend_public_key,
    PublicKey *vs_public_key);

}  // namespace crypto
