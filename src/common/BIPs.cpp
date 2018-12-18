// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "BIPs.hpp"
#include <iostream>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <algorithm>
#include <crypto/crypto.hpp>
#include <string>
#include <vector>
#include "common/Invariant.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "common/Words.hpp"

struct EC_GROUPw {
	EC_GROUP *pgroup = nullptr;
	EC_GROUPw() : pgroup(EC_GROUP_new_by_curve_name(NID_secp256k1)) {}
	~EC_GROUPw() {
		EC_GROUP_free(pgroup);
		pgroup = nullptr;
	}
};
struct BIGNUMw {
	BIGNUM *pbn = nullptr;
	BIGNUMw() : pbn(BN_new()) {}
	BIGNUMw(const unsigned char *data, size_t size) : pbn(BN_bin2bn(data, static_cast<int>(size), nullptr)) {}
	~BIGNUMw() {
		BN_free(pbn);
		pbn = nullptr;
	}
};
struct BN_CTXw {
	BN_CTX *ctx = nullptr;
	BN_CTXw() : ctx(BN_CTX_new()) {}
	~BN_CTXw() {
		BN_CTX_free(ctx);
		ctx = nullptr;
	}
};
struct EC_POINTw {
	EC_POINT *p = nullptr;
	explicit EC_POINTw(EC_GROUP *pgroup) : p(EC_POINT_new(pgroup)) {}
	~EC_POINTw() {
		EC_POINT_free(p);
		p = nullptr;
	}
};

using namespace cn;

const bool debug_print = false;

void Bip32Key::make_pub() {
	EC_GROUPw group;
	BIGNUMw priv_bn(priv_key.data(), priv_key.size());

	EC_POINTw pkey(group.pgroup);
	invariant(EC_POINT_mul(group.pgroup, pkey.p, priv_bn.pbn, nullptr, nullptr, nullptr), "EC_POINT_mul failed");
	unsigned char pub_buf[128]{};
	size_t si =
	    EC_POINT_point2oct(group.pgroup, pkey.p, POINT_CONVERSION_COMPRESSED, pub_buf, sizeof(pub_buf), nullptr);
	invariant(si != 0, "EC_POINT_point2oct failed");
	pub_key.assign(pub_buf, pub_buf + si);
	if (debug_print)
		std::cout << "   pub_key=" << common::to_hex(pub_key) << std::endl;
}

Bip32Key Bip32Key::create_master_key(const std::string &bip39_mnemonic, const std::string &passphrase) {
	Bip32Key result;
	unsigned char bip39_seed[64];
	std::string hmac_salt    = "mnemonic" + passphrase;
	std::string bitcoin_seed = "Bitcoin seed";
	PKCS5_PBKDF2_HMAC(bip39_mnemonic.data(), static_cast<int>(bip39_mnemonic.size()),
	    reinterpret_cast<const uint8_t *>(hmac_salt.data()), static_cast<int>(hmac_salt.size()), 2048, EVP_sha512(), 64,
	    bip39_seed);
	auto master = HMAC(
	    EVP_sha512(), bitcoin_seed.data(), static_cast<int>(bitcoin_seed.size()), bip39_seed, 64, nullptr, nullptr);
	if (debug_print) {
		std::cout << "bip39 seed=" << common::to_hex(bip39_seed, 64) << std::endl;
		std::cout << "bip39 master chain code=" << common::to_hex(master + 32, 32) << std::endl;
		std::cout << "bip39 master key=" << common::to_hex(master, 32) << std::endl;
	}
	result.chain_code.assign(master + 32, master + 64);
	result.priv_key.assign(master, master + 32);
	result.make_pub();
	return result;
}

static const char *utf8_whitespaces[] = {  // Control characters
    "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08", "\x0E", "\x0F", "\x10", "\x11", "\x12", "\x13",
    "\x14", "\x15", "\x16", "\x17", "\x18", "\x19", "\x1A", "\x1B", "\x1C", "\x1D", "\x1E", "\x1F",
    // Unicode whitespace characters with WSpace=Y
    "\x09", "\x0A", "\x0B", "\x0C", "\x0D", "\x20",
    "\xC2\x85",                                                      // (U+0085)
    "\xC2\xA0",                                                      // (U+00A0)
    "\xE1\x9A\x80",                                                  // (U+1680)
    "\xE2\x80\x80", "\xE2\x80\x81", "\xE2\x80\x82", "\xE2\x80\x83",  // (U+2000 - U+200A)
    "\xE2\x80\x84", "\xE2\x80\x85", "\xE2\x80\x86", "\xE2\x80\x87", "\xE2\x80\x88", "\xE2\x80\x89", "\xE2\x80\x8A",
    "\xE2\x80\xA8",  // (U+2028)
    "\xE2\x80\xA9",  // (U+2029)
    "\xE2\x80\xAF",  // (U+202F)
    "\xE2\x81\x9F",  // (U+205F)
    "\xE3\x80\x80",  // (U+3000)
    // Unicode whitespace characters without WSpace=Y
    "\xE1\xA0\x8E",  // (U+180E)
    "\xE2\x80\x8B",  // (U+200B)
    "\xE2\x80\x8C",  // (U+200C)
    "\xE2\x80\x8D",  // (U+200D)
    "\xE2\x81\xA0",  // (U+2060)
    "\xEF\xBB\xBF"};

static size_t find_any(const std::string &str, std::string *found) {
	size_t best = std::string::npos;
	for (const auto wh : utf8_whitespaces) {
		size_t pos = str.find(wh);
		if (pos < best) {
			*found = wh;
			best   = pos;
		}
	}
	return best;
}

static_assert(common::WORDS_COUNT == 2048, "BIP39 wordlist should be 2048 words");

std::string Bip32Key::create_random_bip39_mnemonic(size_t bits) {
	std::string result;
	if (bits % 32 != 0)
		throw Exception("Mnemonic bits must be multiple of 32");
	if (bits < 128 || bits > 256)
		throw Exception("Mnemonic bits must be between 128 and 256");
	const size_t cs_bits         = bits / 32;
	const size_t should_be_words = (bits + cs_bits) / 11;
	std::vector<uint8_t> ent_data(bits / 8);
	crypto::generate_random_bytes(ent_data.data(), ent_data.size());

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, ent_data.data(), ent_data.size());
	SHA256_Final(hash, &sha256);
	const size_t crc = size_t(hash[0]) >> (8 - cs_bits);
	bool crc_added   = false;

	size_t remaining_value_bits = 0;
	size_t remaining_value      = 0;

	size_t words_added = 0;
	while (words_added < should_be_words) {
		if (remaining_value_bits >= 11) {
			size_t word_num = remaining_value >> (remaining_value_bits - 11);
			if (word_num >= common::WORDS_COUNT)
				throw Exception("Mnemonic creation error - word outside of list");
			if (!result.empty())
				result += " ";
			result += common::raw_words[word_num];
			words_added += 1;
			remaining_value &= (1 << (remaining_value_bits - 11)) - 1;
			remaining_value_bits -= 11;
			continue;
		}
		if (!ent_data.empty()) {
			remaining_value <<= 8;
			remaining_value |= ent_data.at(0);
			remaining_value_bits += 8;
			ent_data.erase(ent_data.begin());
			continue;
		}
		if (!crc_added) {
			remaining_value <<= cs_bits;
			remaining_value |= crc;
			remaining_value_bits += cs_bits;
			crc_added = true;
			continue;
		}
		throw Exception("Mnemonic creation error - run out of entropy");
	}
	return check_bip39_mnemonic(result);
}

std::string Bip32Key::check_bip39_mnemonic(const std::string &bip39_mnemonic) {
	std::string str = bip39_mnemonic;
	// Not the fastest way to split into words by set of strings
	std::vector<size_t> word_bits;
	std::string result;
	while (!str.empty()) {
		std::string found;
		auto wpos = find_any(str, &found);
		if (wpos == 0) {
			str.erase(str.begin(), str.begin() + found.size());
			continue;
		}
		auto word                = str.substr(0, wpos);
		const char *const *begin = common::raw_words;
		const char *const *end   = begin + common::WORDS_COUNT;
		auto fou                 = std::lower_bound(begin, end, word.c_str(),
            [](const char *left, const char *right) -> bool { return strcmp(left, right) < 0; });
		if (fou == end || std::string(*fou) != word)
			throw Exception("Mnemonic word '" + word + "' not in the list");
		if (!result.empty())
			result += " ";
		result += word;
		word_bits.push_back(fou - common::raw_words);
		if (wpos <= str.size())
			str.erase(str.begin(), str.begin() + wpos);
		else
			str.clear();
	}
	if (word_bits.size() % 3 != 0)
		throw Exception("Mnemonic word count is not multiple of 3");
	if (word_bits.size() > 24)
		throw Exception("Mnemonic too many words (max 24)");
	const size_t cs_bits   = word_bits.size() / 3;
	const size_t ent_bytes = 4 * cs_bits;
	common::BinaryArray ent_data;
	size_t remaining_value_bits = 0;
	size_t remaining_value      = 0;
	while (ent_data.size() < ent_bytes) {
		if (remaining_value_bits >= 8) {
			ent_data.push_back(static_cast<uint8_t>((remaining_value >> (remaining_value_bits - 8)) & 0xFF));
			remaining_value &= (1 << (remaining_value_bits - 8)) - 1;
			remaining_value_bits -= 8;
			continue;
		}
		if (word_bits.empty())
			break;
		remaining_value <<= 11;
		remaining_value |= word_bits.front();
		remaining_value_bits += 11;
		word_bits.erase(word_bits.begin());
	}
	//	std::cout << common::to_hex(ent_data) << std::endl;
	if (remaining_value_bits != cs_bits)
		throw Exception("Mnemonic invalid format");
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, ent_data.data(), ent_data.size());
	SHA256_Final(hash, &sha256);
	const size_t crc = size_t(hash[0]) >> (8 - cs_bits);
	if (crc != remaining_value)
		throw Exception("Mnemonic wrong CRC");
	return result;
}

Bip32Key Bip32Key::derive_key(uint32_t child_num) const {
	EC_GROUPw group;
	BN_CTXw bn_ctx;
	unsigned char numbuf[4]{};
	common::uint_be_to_bytes(numbuf, 4, child_num);
	Bip32Key result;
	result.key_num = child_num;
	common::BinaryArray buf;
	if (child_num >= 0x80000000U) {
		buf.push_back(0);
		common::append(buf, priv_key.begin(), priv_key.end());
	} else {
		common::append(buf, pub_key.begin(), pub_key.end());
	}
	common::append(buf, numbuf, numbuf + 4);
	auto master = HMAC(EVP_sha512(), chain_code.data(), static_cast<int>(chain_code.size()), buf.data(),
	    static_cast<int>(buf.size()), nullptr, nullptr);
	result.chain_code.assign(master + 32, master + 64);
	if (debug_print)
		std::cout << "chain code=" << common::to_hex(result.chain_code) << std::endl;
	BIGNUMw priv_bn(master, 32);
	BIGNUMw priv_bn2(priv_key.data(), priv_key.size());
	BIGNUMw priv_order;
	invariant(BN_add(priv_bn.pbn, priv_bn.pbn, priv_bn2.pbn), "BN_add failed");

	invariant(EC_GROUP_get_order(group.pgroup, priv_order.pbn, bn_ctx.ctx), "EC_GROUP_get_order failed");
	invariant(BN_mod(priv_bn.pbn, priv_bn.pbn, priv_order.pbn, bn_ctx.ctx), "BN_mod failed");
	result.priv_key.resize(32);
	invariant(BN_bn2binpad(priv_bn.pbn, result.priv_key.data(), 32), "BN_bn2binpad failed");
	if (debug_print)
		std::cout << "  priv_key=" << common::to_hex(result.priv_key) << std::endl;
	result.make_pub();

	return result;
}
