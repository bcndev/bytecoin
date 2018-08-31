#pragma once

#include "bernstein/chacha8.h"

#include "crypto-util.h"
#include "hash.hpp"

namespace crypto {

#pragma pack(push, 1)
struct chacha8_key {
	uint8_t data[CHACHA8_KEY_SIZE];

	chacha8_key() : data{} {}
	explicit chacha8_key(const Hash &ha) {
		memcpy(data, ha.data, CHACHA8_KEY_SIZE);  // safe because of static_assert below
	}
	~chacha8_key() { sodium_memzero(data, sizeof(data)); }
};
struct chacha8_iv {
	uint8_t data[CHACHA8_IV_SIZE]{};
};
#pragma pack(pop)

static_assert(
    sizeof(chacha8_key) == CHACHA8_KEY_SIZE && sizeof(chacha8_iv) == CHACHA8_IV_SIZE, "Invalid structure size");
static_assert(sizeof(chacha8_key) <= sizeof(Hash), "Size of hash must be at least that of chacha8_key");

inline void chacha8(const void *data, size_t length, const chacha8_key &key, const chacha8_iv &iv, void *cipher) {
	chacha8(data, length, key.data, iv.data, (char *)cipher);
}

inline chacha8_key generate_chacha8_key(
    crypto::CryptoNightContext &context, const void *password_data, size_t password_size) {
	Hash pwd_hash = context.cn_slow_hash(password_data, password_size);
	return chacha8_key{pwd_hash};
}
inline chacha8_key generate_chacha8_key(crypto::CryptoNightContext &context, const std::string &password) {
	return generate_chacha8_key(context, password.data(), password.size());
}
}
