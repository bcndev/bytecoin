#include "chacha.hpp"
#include <algorithm>

#include "crypto-util.h"

#include "bernstein/chacha8.h"

static_assert(sizeof(crypto::chacha_key) == CHACHA8_KEY_SIZE && sizeof(crypto::chacha_iv) == CHACHA8_IV_SIZE,
    "Invalid structure size for chacha8");

crypto::chacha_key::chacha_key(const Hash &ha) { memcpy(data, ha.data, std::min(sizeof(ha), sizeof(chacha_key))); }
crypto::chacha_key::~chacha_key() { sodium_memzero(data, sizeof(data)); }

static_assert(sizeof(crypto::chacha_key) == CHACHA8_KEY_SIZE && sizeof(crypto::chacha_iv) == CHACHA8_IV_SIZE,
    "Invalid structure size");

void crypto::chacha(size_t rounds,
    const void *data,
    size_t length,
    const chacha_key &key,
    const chacha_iv &iv,
    void *cipher) {
	::chacha(rounds, data, length, key.data, iv.data, reinterpret_cast<char *>(cipher));
}

crypto::chacha_key crypto::generate_chacha8_key(crypto::CryptoNightContext &context,
    const void *password_data,
    size_t password_size) {
	Hash pwd_hash = context.cn_slow_hash(password_data, password_size);
	return chacha_key{pwd_hash};
}
