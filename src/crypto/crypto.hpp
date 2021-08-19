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

void generate_random_bytes(unsigned char *result, size_t n);  // thread-safe
SecretKey random_scalar();

template<typename T>
T rand() {
	static_assert(std::is_standard_layout<T>::value, "T must be Standard Layout");
	T res;
	generate_random_bytes(reinterpret_cast<unsigned char *>(&res), sizeof(T));
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

class KeccakStream {
	cryptoKeccakHasher impl;

public:
	KeccakStream() { crypto_keccak_init(&impl, 256, 1); }
	KeccakStream &append(const void *buf, size_t count) {
		crypto_keccak_update(&impl, buf, count);
		return *this;
	}
	template<size_t S>
	KeccakStream &append(const char (&h)[S]) {
		append(h, S - 1);
		return *this;
	}
	KeccakStream &append_byte(uint8_t byte) {
		append(&byte, 1);
		return *this;
	}
	KeccakStream &append(size_t i);  // varint
	KeccakStream &append(const Hash &h) { return append(h.data, sizeof(h.data)); }
	KeccakStream &append(const EllipticCurvePoint &h) { return append(h.data, sizeof(h.data)); }
	KeccakStream &append(const EllipticCurveScalar &h) { return append(h.data, sizeof(h.data)); }
	Hash cn_fast_hash() {
		Hash result;
		crypto_keccak_final(&impl, result.data, sizeof(result.data));
		return result;
	}
	SecretKey hash_to_scalar();
	SecretKey hash_to_scalar64();
	PublicKey hash_to_good_point();
};

template<class T>
KeccakStream &operator<<(KeccakStream &buffer, const T &value) {
	buffer.append(value);
	return buffer;
}
template<size_t S>
KeccakStream &operator<<(KeccakStream &buffer, const char (&h)[S]) {
	buffer.append(h);
	return buffer;
}
// Check a public key. Returns true if it is valid, false otherwise.
bool key_isvalid(const EllipticCurvePoint &key);
bool key_in_main_subgroup(const EllipticCurvePoint &key);
// Checks a private key and computes the corresponding public key.
bool secret_key_to_public_key(const SecretKey &sec, PublicKey *pub);
bool keys_match(const SecretKey &secret_key, const PublicKey &expected_public_key);

// returns false if keys are corrupted/invalid
Signature generate_signature(const Hash &prefix_hash, const PublicKey &pub, const SecretKey &sec);
bool check_signature(const Hash &prefix_hash, const PublicKey &pub, const Signature &sig);

Signature generate_proof_H(const SecretKey &s);
bool check_proof_H(const PublicKey &sH, const Signature &sig);

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

bool check_ring_signature(
    const Hash &prefix_hash, const KeyImage &image, const std::vector<PublicKey> &pubs, const RingSignature &sig);

RingSignatureAmethyst generate_ring_signature_amethyst(const Hash &prefix_hash, const std::vector<KeyImage> &images,
    const std::vector<std::vector<PublicKey>> &pubs, const std::vector<SecretKey> &secs_spend,
    const std::vector<SecretKey> &secs_audit, const std::vector<size_t> &sec_indexes,
    const Hash *random_seed = nullptr);
bool check_ring_signature_amethyst(const Hash &prefix_hash, const std::vector<KeyImage> &images,
    const std::vector<std::vector<PublicKey>> &pubs, const RingSignatureAmethyst &sig);

SecretKey bytes_to_scalar(const Hash &h);
SecretKey hash_to_scalar(const void *data, size_t length);
SecretKey hash_to_scalar64(const void *data, size_t length);

// any 32 bytes into valid point (potentially outside main subgroup)
PublicKey bytes_to_bad_point(const Hash &h);

// hash of (data, length) into valid point (inside main subgroup)
PublicKey bytes_to_good_point(const Hash &h);
PublicKey hash_to_good_point(const void *data, size_t length);
inline PublicKey hash_to_good_point(const PublicKey &key) { return hash_to_good_point(key.data, sizeof(key.data)); }

// Legacy crypto
// To generate an ephemeral key used to send money to:
// The sender generates a new key pair, which becomes the transaction key. The public transaction key is included in
// "extra" field.
// Both the sender and the receiver generate key derivation from the transaction key and the receivers' "view" key.
// The sender uses key derivation, the output index, and the receivers' "spend" key to derive an ephemeral public key.
// The receiver can either derive the public key (to check that the transaction is addressed to him) or the private key
// (to spend the money).

// shared secret -
// tx_public_key * view_secret_key for receiver
// tx_secret_key * address_V for sender
KeyDerivation generate_key_derivation(const PublicKey &tx_public_key, const SecretKey &view_secret_key);

PublicKey derive_output_public_key(const KeyDerivation &derivation, size_t output_index, const PublicKey &address_S);

PublicKey underive_address_S(const KeyDerivation &derivation, size_t output_index, const PublicKey &output_public_key);

SecretKey derive_output_secret_key(
    const KeyDerivation &derivation, std::size_t output_index, const SecretKey &address_s);

Signature generate_sendproof(const PublicKey &txkey_pub, const SecretKey &txkey_sec,
    const PublicKey &receiver_address_V, const KeyDerivation &derivation, const Hash &message_hash);

// Transaction key and the derivation supplied with the proof can be invalid, this just means that the proof is invalid.
bool check_sendproof(const PublicKey &txkey_pub, const PublicKey &receiver_address_V, const KeyDerivation &derivation,
    const Hash &message_hash, const Signature &proof);

BinaryArray get_output_secret_hash_arg(
    const PublicKey &output_shared_secret, const Hash &tx_inputs_hash, size_t output_index);

// Linkable crypto, output_secret_hash is temporary value that is expensive to calc, we pass it around
// Old addresses use improved crypto in amethyst, because we need to enforce unique output public keys
// on crypto level. Enforcing on daemon DB index level does not work (each of 2 solutions is vulnerable to attack).

// sender, sending
PublicKey linkable_derive_output_public_key(const SecretKey &output_secret, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &address_S, const PublicKey &address_V, PublicKey *encrypted_output_secret,
    PublicKey *output_shared_secret);

// receiver looking for outputs
PublicKey linkable_underive_address_S(const SecretKey &inv_view_secret_key, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &output_public_key, const PublicKey &encrypted_output_secret,
    PublicKey *output_shared_secret);

// receiver
SecretKey linkable_derive_output_secret_key(const SecretKey &address_s, const SecretKey &output_secret_hash);

// sender, restoring destination address
void linkable_underive_address(const SecretKey &output_secret, const Hash &tx_inputs_hash, size_t output_index,
    const PublicKey &output_public_key, const PublicKey &encrypted_output_secret, PublicKey *address_S,
    PublicKey *address_V, PublicKey *output_shared_secret);

// Unlinkable crypto, output_secret_hash is temporary value that is expensive to calc, we pass it around

// result size should be set to number of desired spend keys
void generate_hd_spendkeys(const SecretKey &a0, const PublicKey &A_plus_SH, size_t index, std::vector<KeyPair> *result);
PublicKey generate_hd_spendkey(
    const PublicKey &v_mul_A_plus_SH, const PublicKey &A_plus_SH, const PublicKey &V, size_t index);
// generate_hd_secretkey function emulate hardware wallet
SecretKey generate_hd_secretkey(const SecretKey &a0, const PublicKey &A_plus_SH, size_t index);

// a*G + s*H
PublicKey secret_keys_to_public_key(const SecretKey &a, const SecretKey &s);

// sender sending
PublicKey unlinkable_derive_output_public_key(const PublicKey &output_secret, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &address_S, const PublicKey &address_SV, PublicKey *encrypted_output_secret,
    PublicKey *output_shared_secret);

// receiver looking for outputs
PublicKey unlinkable_underive_address_S(const SecretKey &view_secret_key, const Hash &tx_inputs_hash,
    size_t output_index, const PublicKey &output_public_key, const PublicKey &encrypted_output_secret,
    PublicKey *output_shared_secret);

// 2-step functions emulate hardware wallet
PublicKey unlinkable_underive_address_S_step1(const SecretKey &view_secret_key, const PublicKey &output_public_key);
PublicKey unlinkable_underive_address_S_step2(const PublicKey &Pv, const Hash &tx_inputs_hash, size_t output_index,
    const PublicKey &output_public_key, const PublicKey &encrypted_output_secret, PublicKey *output_shared_secret);

SecretKey unlinkable_derive_output_secret_key(const SecretKey &address_secret, const SecretKey &output_secret_hash);
// address_secret can be audit_secret_key or spend_secret_key

// sender, restoring destination address
void unlinkable_underive_address(PublicKey *address_S, PublicKey *address_Sv, const PublicKey &output_secret,
    const Hash &tx_inputs_hash, size_t output_index, const PublicKey &output_public_key,
    const PublicKey &encrypted_output_secret, PublicKey *output_shared_secret);

}  // namespace crypto
