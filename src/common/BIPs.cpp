// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "BIPs.hpp"
#include <iostream>

#include <hmac_sha2.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <algorithm>
#include <boost/multiprecision/cpp_int.hpp>
#include <string>
#include <vector>
#include "common/Invariant.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "common/Words.hpp"
#include "crypto/crypto.hpp"

void pkcs5_pbkdf2_hmac_sha512(const uint8_t *pass, size_t passlen, const uint8_t *salt, size_t saltlen, size_t iter,
    size_t keylen, uint8_t *out) {
	constexpr size_t hashLen = 64;
	const auto numBlocks     = (keylen + hashLen - 1) / hashLen;
	hmac_sha512_ctx ctx;

	hmac_sha512_init(&ctx, pass, static_cast<int>(passlen));
	memset(out, 0, keylen);
	for (size_t b = 0; b < numBlocks; ++b) {
		hmac_sha512_reinit(&ctx);
		hmac_sha512_update(&ctx, salt, static_cast<int>(saltlen));
		unsigned char bb[4]{};
		common::uint_be_to_bytes(bb, 4, b + 1);
		unsigned char U[hashLen]{};
		hmac_sha512_update(&ctx, bb, 4);
		hmac_sha512_final(&ctx, U, hashLen);
		size_t cou = std::min<size_t>(hashLen, keylen - b * hashLen);
		for (size_t j = 0; j != cou; ++j)
			out[b * hashLen + j] = U[j];
		for (size_t i = 1; i < iter; ++i) {
			hmac_sha512_reinit(&ctx);
			hmac_sha512_update(&ctx, U, hashLen);
			hmac_sha512_final(&ctx, U, hashLen);
			for (size_t j = 0; j != cou; ++j)
				out[b * hashLen + j] ^= U[j];
		}
	}
}

void pkcs5_pbkdf2_hmac_sha512_checked(
    const uint8_t *pass, size_t passlen, const uint8_t *salt, size_t saltlen, size_t iter, uint8_t *out) {
	pkcs5_pbkdf2_hmac_sha512(pass, passlen, salt, saltlen, iter, 64, out);
	unsigned char out2[64]{};
	PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(pass), static_cast<int>(passlen), salt, static_cast<int>(saltlen),
	    static_cast<int>(iter), EVP_sha512(), 64, out2);
	invariant(memcmp(out, out2, 64) == 0, "");
}

void hmac_sha512_checked(
    const uint8_t *key, size_t key_size, const uint8_t *message, size_t message_len, uint8_t *out) {
	hmac_sha512(key, static_cast<int>(key_size), message, static_cast<int>(message_len), out, 64);
	auto out2 = HMAC(EVP_sha512(), reinterpret_cast<const char *>(key), static_cast<int>(key_size), message,
	    message_len, nullptr, nullptr);
	invariant(memcmp(out, out2, 64) == 0, "");
}

void sha256_checked(const unsigned char *message, size_t len, unsigned char *digest) {
	sha256(message, static_cast<int>(len), digest);
	unsigned char digest2[32]{};
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, message, len);
	SHA256_Final(digest2, &sha256);
	invariant(memcmp(digest, digest2, 32) == 0, "");
}

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

namespace mp = boost::multiprecision;

const mp::cpp_int group_p = mp::pow(mp::cpp_int(2), 256) - mp::pow(mp::cpp_int(2), 32) - mp::cpp_int(977);
const mp::cpp_int group_n("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

static mp::cpp_int pos_mod(const mp::cpp_int &val, const mp::cpp_int &p2) {
	mp::cpp_int r = val % p2;
	if (r < 0)
		r += p2;
	return r;
}

static mp::cpp_int inverse(mp::cpp_int x) {
	mp::cpp_int p2 = group_p;
	mp::cpp_int inv1(1);
	mp::cpp_int inv2(0);
	//	std::cout << "x0=" << x << std::endl;
	//	std::cout << "p0=" << p << std::endl;
	while (p2 != mp::cpp_int(1) && p2 != mp::cpp_int(0)) {
		auto inv1prev = inv1;
		auto inv2prev = inv2;
		inv1          = inv2prev;
		inv2          = inv1prev - inv2prev * (x / p2);
		auto xprev    = x;
		auto pprev    = p2;
		x             = pprev;
		p2            = pos_mod(xprev, pprev);
		//		std::cout << "x=" << x << std::endl;
		//		std::cout << "p=" << p << std::endl;
		//		std::cout << "inv1=" << inv1 << std::endl;
		//		std::cout << "inv2=" << inv2 << std::endl;
	}
	return inv2;
}

struct mppoint {
	mp::cpp_int x{0};
	mp::cpp_int y{0};
};

static const mppoint g{mp::cpp_int("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
    mp::cpp_int("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")};

static bool is_zero(const mppoint &pt) { return pt.x == 0 && pt.y == 0; }

static mppoint dblpt(const mppoint &pt) {
	if (is_zero(pt))
		return pt;
	if (pt.y == 0)  // Never on sec256k1
		return mppoint{};
	mp::cpp_int slope = 3 * pt.x * pt.x * inverse(2 * pt.y);
	mp::cpp_int xsum  = slope * slope - 2 * pt.x;
	mp::cpp_int ysum  = slope * (pt.x - xsum) - pt.y;
	return mppoint{pos_mod(xsum, group_p), pos_mod(ysum, group_p)};
}

static mppoint addpt(const mppoint &p1, const mppoint &p2) {
	if (is_zero(p1))
		return p2;
	if (is_zero(p2))
		return p1;
	if (p1.x == p2.x) {
		if (p1.y == p2.y)
			return dblpt(p1);
		return mppoint{};  // (x, y) + (x, -y) = 0
	}
	mp::cpp_int slope = (p1.y - p2.y) * inverse(p1.x - p2.x);
	mp::cpp_int xsum  = slope * slope - (p1.x + p2.x);
	mp::cpp_int ysum  = slope * (p1.x - xsum) - p1.y;
	return mppoint{pos_mod(xsum, group_p), pos_mod(ysum, group_p)};
}

static mppoint ptmul(const mppoint &pt, mp::cpp_int a) {
	mppoint scale = pt;
	mppoint acc;  // pt ^ 0 == 0
	while (a != 0) {
		if (a % 2 == 1) {
			acc = addpt(acc, scale);
		}
		scale = dblpt(scale);
		a /= 2;
	}
	return acc;
}

// https://crypto.stackexchange.com/questions/8914/ecdsa-compressed-public-key-point-back-to-uncompressed-public-key-point
// https://bitcoin.stackexchange.com/questions/3059/what-is-a-compressed-bitcoin-key

static common::BinaryArray bitcoin_Gn(const common::BinaryArray &n) {
	//	std::cout << "p=" << std::hex << p << std::dec << std::endl;
	//	std::cout << "g=" << std::hex << g.x << " " << g.y << std::dec << std::endl;
	//	mppoint g2 = dblpt(g);
	//	std::cout << "g2=" << std::hex << g2.x << " " << g2.y << std::dec << std::endl;
	//	mppoint g3 = addpt(g2, g);

	//	std::cout << "g3=" << std::hex << g3.x << " " << g3.y << std::dec << std::endl;
	//	mp::cpp_int priv_key_mp("0xf8ef380d6c05116dbed78bfdd6e6625e57426af9a082b81c2fa27b06984c11f3");

	//	mppoint pub_key_mp = ptmul(g, priv_key_mp);
	//	std::cout << "pub_key=" << std::hex << pub_key_mp.x << " " << pub_key_mp.y << std::dec << std::endl;

	mp::cpp_int priv_key;
	import_bits(priv_key, std::begin(n), std::end(n));
	if (debug_print)
		std::cout << "priv_key=" << std::hex << priv_key << std::dec << std::endl;
	mppoint pub_key = ptmul(g, priv_key);
	if (debug_print)
		std::cout << "pub_key=" << std::hex << pub_key.x << " " << pub_key.y << std::dec << std::endl;
	if (is_zero(pub_key))
		return common::BinaryArray(1, uint8_t{0});
	const uint8_t first_byte = (pub_key.y % 2) == 1 ? uint8_t(0x03) : uint8_t(0x02);
	common::BinaryArray result(1, first_byte);
	export_bits(pub_key.x, std::back_inserter(result), 8);
	if (result.size() < 33)
		result.insert(result.begin() + 1, 33 - result.size(), uint8_t{0});
	//	std::cout << "pub_key=" << common::to_hex(result) << std::endl;
	return result;
}

static common::BinaryArray bitcoin_sc_add(const common::BinaryArray &a, const common::BinaryArray &b) {
	EC_GROUPw group;
	BN_CTXw bn_ctx;
	BIGNUMw priv_bn(a.data(), a.size());
	BIGNUMw priv_bn2(b.data(), b.size());
	BIGNUMw priv_order;
	invariant(BN_add(priv_bn.pbn, priv_bn.pbn, priv_bn2.pbn), "BN_add failed");

	invariant(EC_GROUP_get_order(group.pgroup, priv_order.pbn, bn_ctx.ctx), "EC_GROUP_get_order failed");
	invariant(BN_mod(priv_bn.pbn, priv_bn.pbn, priv_order.pbn, bn_ctx.ctx), "BN_mod failed");
	common::BinaryArray sum(32);
	//	invariant(BN_bn2binpad(priv_order.pbn, sum.data(), 32), "BN_bn2binpad failed");
	//	std::cout << common::to_hex(sum) << std::endl;
	invariant(BN_bn2binpad(priv_bn.pbn, sum.data(), 32), "BN_bn2binpad failed");

	mp::cpp_int priv_a;
	import_bits(priv_a, std::begin(a), std::end(a));
	mp::cpp_int priv_b;
	import_bits(priv_b, std::begin(b), std::end(b));

	mp::cpp_int priv_sum = pos_mod(priv_a + priv_b, group_n);
	common::BinaryArray sum2;
	export_bits(priv_sum, std::back_inserter(sum2), 8);
	if (sum2.size() < 32)
		sum2.insert(sum2.begin(), 32 - sum2.size(), uint8_t{0});
	invariant(sum == sum2, "");
	return sum;
}

void Bip32Key::make_pub() {
	//	boost::multiprecision::cpp_int pow("8912627233012800753578052027888001981");

	if (debug_print)
		std::cout << "priv_key=" << common::to_hex(priv_key) << std::endl;

	//	common::BinaryArray priv_key_zero(priv_key.size());
	EC_GROUPw group;
	BIGNUMw priv_bn(priv_key.data(), priv_key.size());

	EC_POINTw pkey(group.pgroup);
	invariant(EC_POINT_mul(group.pgroup, pkey.p, priv_bn.pbn, nullptr, nullptr, nullptr), "EC_POINT_mul failed");
	unsigned char pub_buf[128]{};
	size_t si =
	    EC_POINT_point2oct(group.pgroup, pkey.p, POINT_CONVERSION_COMPRESSED, pub_buf, sizeof(pub_buf), nullptr);
	invariant(si != 0, "EC_POINT_point2oct failed");
	pub_key.assign(pub_buf, pub_buf + si);
	auto pub_key2 = bitcoin_Gn(priv_key);
	invariant(pub_key == pub_key2, "");
	if (debug_print) {
		std::cout << "   pub_key=" << common::to_hex(pub_key) << std::endl;
	}
}

Bip32Key Bip32Key::create_master_key(const std::string &bip39_mnemonic, const std::string &passphrase) {
	Bip32Key result;
	unsigned char bip39_seed[64]{};
	std::string hmac_salt    = "mnemonic" + passphrase;
	std::string bitcoin_seed = "Bitcoin seed";
	pkcs5_pbkdf2_hmac_sha512_checked(reinterpret_cast<const uint8_t *>(bip39_mnemonic.data()), bip39_mnemonic.size(),
	    reinterpret_cast<const uint8_t *>(hmac_salt.data()), hmac_salt.size(), 2048, bip39_seed);
	unsigned char master[64]{};
	hmac_sha512_checked(
	    reinterpret_cast<const uint8_t *>(bitcoin_seed.data()), bitcoin_seed.size(), bip39_seed, 64, master);
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

	unsigned char hash[32];
	sha256_checked(ent_data.data(), ent_data.size(), hash);
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
	if (bip39_mnemonic.empty())
		throw Exception("Mnemonic is empty");
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
	unsigned char hash[32];
	sha256_checked(ent_data.data(), ent_data.size(), hash);
	const size_t crc = size_t(hash[0]) >> (8 - cs_bits);
	if (crc != remaining_value)
		throw Exception("Mnemonic wrong CRC");
	return result;
}

Bip32Key Bip32Key::derive_key(uint32_t child_num) const {
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
	uint8_t master[64]{};
	hmac_sha512_checked(chain_code.data(), chain_code.size(), buf.data(), buf.size(), master);
	result.chain_code.assign(master + 32, master + 64);
	if (debug_print)
		std::cout << "chain code=" << common::to_hex(result.chain_code) << std::endl;
	//	EC_GROUPw group;
	//	BN_CTXw bn_ctx;
	//	BIGNUMw priv_bn(master, 32);
	//	BIGNUMw priv_bn2(priv_key.data(), priv_key.size());
	//	BIGNUMw priv_order;
	//	invariant(BN_add(priv_bn.pbn, priv_bn.pbn, priv_bn2.pbn), "BN_add failed");

	//	invariant(EC_GROUP_get_order(group.pgroup, priv_order.pbn, bn_ctx.ctx), "EC_GROUP_get_order failed");
	//	invariant(BN_mod(priv_bn.pbn, priv_bn.pbn, priv_order.pbn, bn_ctx.ctx), "BN_mod failed");
	result.priv_key = bitcoin_sc_add(priv_key, common::BinaryArray(master, master + 32));
	//	invariant(BN_bn2binpad(priv_bn.pbn, result.priv_key.data(), 32), "BN_bn2binpad failed");
	if (debug_print)
		std::cout << "  priv_key=" << common::to_hex(result.priv_key) << std::endl;
	result.make_pub();

	return result;
}
