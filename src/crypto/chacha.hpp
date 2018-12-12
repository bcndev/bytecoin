#pragma once

#include "hash.hpp"

namespace crypto {

#pragma pack(push, 1)
struct chacha_key {
	uint8_t data[32];

	chacha_key() : data{} {}
	explicit chacha_key(const Hash &ha);
	~chacha_key();
};
struct chacha_iv {
	uint8_t data[8]{};
};
#pragma pack(pop)

void chacha(size_t rounds, const void *data, size_t length, const chacha_key &key, const chacha_iv &iv, void *cipher);
inline void chacha8(const void *data, size_t length, const chacha_key &key, const chacha_iv &iv, void *cipher) {
	chacha(8, data, length, key, iv, cipher);
}

// Do not forget to append salt to password before calling this
chacha_key generate_chacha8_key(crypto::CryptoNightContext &context, const void *password_data, size_t password_size);
}  // namespace crypto
