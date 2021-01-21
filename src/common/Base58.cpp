// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Base58.hpp"

#include <algorithm>
#include <iostream>
#include <vector>

#include "Invariant.hpp"
#include "StringTools.hpp"
#include "Varint.hpp"
#include "crypto/hash.hpp"
#include "crypto/int-util.h"

namespace common { namespace base58 {

namespace {
const char alphabet[]                = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const size_t alphabet_size           = sizeof(alphabet) - 1;
const size_t full_block_size         = 8;
const size_t full_encoded_block_size = 11;
const size_t encoded_block_sizes[]   = {0, 2, 3, 5, 6, 7, 9, 10, 11};
const int decoded_block_sizes[]      = {0, -1, 1, 2, -1, 3, 4, 5, -1, 6, 7, 8};
const uint64_t java_hi_parts[]       = {0, 0, 0, 0, 0, 0, 8, 514, 29817, 1729386, 100304420};
const uint64_t java_lo_parts[]       = {
    1, 58, 3364, 195112, 11316496, 656356768, 3708954176, 370977408, 41853184, 2427484672, 3355157504};
const int8_t reverse_alphabet_table[] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0, 1, 2, 3, 4, 5, 6, 7, 8, -1, -1, -1, -1, -1, -1, -1, 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1,
    44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57};

const size_t addr_checksum_size = 4;

int reverse_alphabet(char letter) {
	auto idx = static_cast<size_t>(letter);
	return idx < sizeof(reverse_alphabet_table) ? reverse_alphabet_table[idx] : -1;
}

/*struct reverse_alphabet {
    reverse_alphabet() {
//		base     = *std::min_element(alphabet, alphabet + alphabet_size);
        auto top = *std::max_element(alphabet, alphabet + alphabet_size);
        m_data.resize(top + 1, -1);

        for (size_t i = 0; i < alphabet_size; ++i) {
            auto idx    = static_cast<size_t>(alphabet[i]);
            m_data[idx] = static_cast<int8_t>(i);
        }
        for(auto d : m_data)
            std::cout << int(d) << ", ";
        std::cout << std::endl;
    }

    int operator()(char letter) const {
        auto idx = static_cast<size_t>(letter);
        return idx < m_data.size() ? m_data[idx] : -1;
    }

    static reverse_alphabet instance;

private:
    std::vector<int8_t> m_data;
//	char base = 0;
};

reverse_alphabet reverse_alphabet::instance;

struct decoded_block_sizes {
    decoded_block_sizes() {
        m_data.resize(encoded_block_sizes[full_block_size] + 1, -1);
        for (size_t i = 0; i <= full_block_size; ++i) {
            m_data[encoded_block_sizes[i]] = static_cast<int>(i);
        }
    }

    int operator()(size_t encoded_block_size) const {
        invariant(encoded_block_size <= full_encoded_block_size, "");
        return m_data[encoded_block_size];
    }

    static decoded_block_sizes instance;

private:
    std::vector<int> m_data;  // {0, -1, 1, 2, -1, 3, 4, 5, -1, 6, 7, 8};
};

decoded_block_sizes decoded_block_sizes::instance;*/

void encode_block(const uint8_t *block, size_t size, char *res) {
	invariant(size >= 1 && size <= full_block_size, "");

	auto num = uint_be_from_bytes<uint64_t>(block, size);
	for (size_t i = encoded_block_sizes[size]; i-- > 0;) {
		uint64_t remainder = num % alphabet_size;
		num /= alphabet_size;
		res[i] = alphabet[remainder];
	}
}

bool decode_block_legacy(const char *block, size_t size, uint8_t *res) {
	invariant(size <= full_encoded_block_size, "");

	int ires_size = decoded_block_sizes[size];
	if (ires_size <= 0)
		return false;  // Invalid block size
	auto res_size = static_cast<size_t>(ires_size);

	uint64_t res_num = 0;
	uint64_t order   = 1;
	for (size_t i = size; i-- > 0;) {
		int digit = reverse_alphabet(block[i]);
		if (digit < 0)
			return false;  // Invalid symbol

		uint64_t product_hi;
		uint64_t tmp = res_num + mul128(order, static_cast<uint64_t>(digit), &product_hi);
		if (tmp < res_num || 0 != product_hi)
			return false;  // Overflow

		res_num = tmp;
		order *= alphabet_size;  // Never overflows, 58^10 < 2^64
	}

	if (res_size < full_block_size && (uint64_t(1) << (8 * res_size)) <= res_num)
		return false;  // Overflow

	uint_be_to_bytes(res, res_size, res_num);
	return true;
}

bool decode_block_good(const char *block, size_t size, uint8_t *res) {
	invariant(size <= full_encoded_block_size, "");

	int ires_size = decoded_block_sizes[size];
	if (ires_size <= 0)
		return false;  // Invalid block size
	auto res_size = static_cast<size_t>(ires_size);

	uint64_t java_hi_part = 0;
	uint64_t java_lo_part = 0;
	size_t java_pos       = 0;
	for (size_t i = size; i-- > 0; java_pos += 1) {
		int digit = reverse_alphabet(block[i]);
		if (digit < 0)
			return false;  // Invalid symbol
		java_hi_part += java_hi_parts[java_pos] * static_cast<unsigned>(digit);
		java_lo_part += java_lo_parts[java_pos] * static_cast<unsigned>(digit);
	}
	java_hi_part += java_lo_part / 0x100000000;
	java_lo_part %= 0x100000000;  // Not strictly necessary
	if (java_hi_part >= 0x100000000)
		return false;
	if (res_size > 4) {
		if (res_size < full_block_size && java_hi_part >= (uint64_t(1) << (8 * (res_size - 4))))
			return false;  // Overflow
		uint_be_to_bytes(res, res_size - 4, java_hi_part);
		uint_be_to_bytes(res + res_size - 4, 4, java_lo_part);
	} else {
		if (java_hi_part != 0 || java_lo_part >= (uint64_t(1) << (8 * res_size)))
			return false;  // Overflow
		uint_be_to_bytes(res, res_size, java_lo_part);
	}
	return true;
}

bool decode_block(const char *block, size_t size, uint8_t *res) {
	invariant(size <= full_encoded_block_size, "");
	int ires_size = decoded_block_sizes[size];
	if (ires_size <= 0)
		return false;  // Invalid block size
	auto res_size = static_cast<size_t>(ires_size);

	uint8_t result_legacy[full_block_size]{};
	bool res1 = decode_block_good(block, size, res);
	bool res2 = decode_block_legacy(block, size, result_legacy);
	invariant(res1 == res2 && memcmp(res, result_legacy, res_size) == 0, "");
	return res1;
}

}  // namespace

std::string encode(const BinaryArray &data) {
	size_t full_block_count = data.size() / full_block_size;
	size_t last_block_size  = data.size() % full_block_size;
	size_t res_size         = full_block_count * full_encoded_block_size + encoded_block_sizes[last_block_size];

	std::string res(res_size, '*');  // All asterisks must be replaced after encoding
	for (size_t i = 0; i < full_block_count; ++i) {
		encode_block(data.data() + i * full_block_size, full_block_size, &res[i * full_encoded_block_size]);
	}
	if (last_block_size > 0) {
		encode_block(data.data() + full_block_count * full_block_size, last_block_size,
		    &res[full_block_count * full_encoded_block_size]);
	}
	return res;
}

bool decode(const std::string &enc, BinaryArray *data) {
	size_t full_block_count     = enc.size() / full_encoded_block_size;
	size_t last_block_size      = enc.size() % full_encoded_block_size;
	int last_block_decoded_size = decoded_block_sizes[last_block_size];
	if (last_block_decoded_size < 0)
		return false;  // Invalid enc length
	size_t data_size = full_block_count * full_block_size + last_block_decoded_size;

	data->resize(data_size, 0);
	for (size_t i = 0; i < full_block_count; ++i) {
		if (!decode_block(
		        enc.data() + i * full_encoded_block_size, full_encoded_block_size, &(*data)[i * full_block_size]))
			return false;
	}

	if (last_block_size > 0) {
		if (!decode_block(enc.data() + full_block_count * full_encoded_block_size, last_block_size,
		        &(*data)[full_block_count * full_block_size]))
			return false;
	}
	return true;
}

std::string encode_addr(uint64_t tag, const BinaryArray &data) {
	BinaryArray buf = get_varint_data(tag);
	append(buf, data.begin(), data.end());
	crypto::Hash hash = crypto::cn_fast_hash(buf.data(), buf.size());
	append(buf, hash.data, hash.data + addr_checksum_size);
	return encode(buf);
}

bool decode_addr(std::string addr, uint64_t *tag, BinaryArray *data) {
	BinaryArray addr_data;
	bool r = decode(addr, &addr_data);
	if (!r)
		return false;
	if (addr_data.size() <= addr_checksum_size)
		return false;

	std::vector<uint8_t> checksum(addr_data.end() - addr_checksum_size, addr_data.end());

	addr_data.resize(addr_data.size() - addr_checksum_size);

	//	std::cout << common::to_hex(addr_data) << std::endl;
	crypto::Hash hash = crypto::cn_fast_hash(addr_data.data(), addr_data.size());
	//	std::cout << common::to_hex(hash.data, sizeof(hash.data)) << std::endl;

	std::vector<uint8_t> expected_checksum(hash.data, hash.data + addr_checksum_size);
	if (expected_checksum != checksum)
		return false;

	int read = common::read_varint(addr_data.begin(), addr_data.end(), tag);
	if (read <= 0)
		return false;
	data->assign(addr_data.begin() + read, addr_data.end());
	//	tag->assign(addr_data.begin(), addr_data.end() - body_size);
	//	data->assign(addr_data.end() - body_size, addr_data.end());
	return true;
}

void interactive_test() {
	std::cout << "interactive_test" << std::endl;
	BinaryArray addr_data;
	common::from_hex("cef5f4bdd171", &addr_data);
	BinaryArray zeroes(16);
	uint64_t tag = 0;
	common::read_varint(addr_data.begin(), addr_data.end(), &tag);
	std::cout << "tag=" << tag << std::endl;
	while (true) {
		std::cout << common::to_hex(addr_data) << std::endl;
		for (size_t i = 0; i != 256; ++i) {
			BinaryArray ba = addr_data;
			ba.push_back(i);
			append(ba, zeroes.begin(), zeroes.end());
			std::string str = encode(ba);
			std::cout << str << " " << i << std::endl;
		}
		int c = 0;
		std::cin >> c;
		if (c == -1) {
			if (!addr_data.empty())
				addr_data.pop_back();
			continue;
		}
		addr_data.push_back(c);
	}
}

}}  // namespace common::base58
