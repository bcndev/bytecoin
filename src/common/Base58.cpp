// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Base58.hpp"

#include <assert.h>
#include <vector>

#include "Varint.hpp"
#include "crypto/hash.hpp"
#include "crypto/int-util.h"

namespace common {
namespace base58 {

namespace {
const char alphabet[]                = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const size_t alphabet_size           = sizeof(alphabet) - 1;
const size_t encoded_block_sizes[]   = {0, 2, 3, 5, 6, 7, 9, 10, 11};
const size_t full_block_size         = sizeof(encoded_block_sizes) / sizeof(encoded_block_sizes[0]) - 1;
const size_t full_encoded_block_size = encoded_block_sizes[full_block_size];
const size_t addr_checksum_size      = 4;

struct reverse_alphabet {
	reverse_alphabet() {
		m_data.resize(alphabet[alphabet_size - 1] - alphabet[0] + 1, -1);

		for (size_t i = 0; i < alphabet_size; ++i) {
			size_t idx  = static_cast<size_t>(alphabet[i] - alphabet[0]);
			m_data[idx] = static_cast<int8_t>(i);
		}
	}

	int operator()(char letter) const {
		size_t idx = static_cast<size_t>(letter - alphabet[0]);
		return idx < m_data.size() ? m_data[idx] : -1;
	}

	static reverse_alphabet instance;

private:
	std::vector<int8_t> m_data;
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
		assert(encoded_block_size <= full_encoded_block_size);
		return m_data[encoded_block_size];
	}

	static decoded_block_sizes instance;

private:
	std::vector<int> m_data;
};

decoded_block_sizes decoded_block_sizes::instance;

uint64_t uint_8be_to_64(const uint8_t *data, size_t size) {
	assert(1 <= size && size <= sizeof(uint64_t));

	uint64_t res = 0;
	switch (9 - size) {
	case 1:
		res |= *data++;
	case 2:
		res <<= 8;
		res |= *data++;
	case 3:
		res <<= 8;
		res |= *data++;
	case 4:
		res <<= 8;
		res |= *data++;
	case 5:
		res <<= 8;
		res |= *data++;
	case 6:
		res <<= 8;
		res |= *data++;
	case 7:
		res <<= 8;
		res |= *data++;
	case 8:
		res <<= 8;
		res |= *data;
		break;
	default:
		assert(false);
	}

	return res;
}

void uint_64_to_8be(uint64_t num, size_t size, uint8_t *data) {
	assert(1 <= size && size <= sizeof(uint64_t));

	uint64_t num_be = SWAP64BE(num);
	memcpy(data, reinterpret_cast<uint8_t *>(&num_be) + sizeof(uint64_t) - size, size);
}

void encode_block(const uint8_t *block, size_t size, char *res) {
	assert(1 <= size && size <= full_block_size);

	uint64_t num = uint_8be_to_64(block, size);
	int i        = static_cast<int>(encoded_block_sizes[size]) - 1;  // TODO - size_t i?
	while (0 < num) {
		uint64_t remainder = num % alphabet_size;
		num /= alphabet_size;
		res[i] = alphabet[remainder];
		--i;
	}
}

bool decode_block(const char *block, size_t size, uint8_t *res) {
	assert(1 <= size && size <= full_encoded_block_size);

	int res_size = decoded_block_sizes::instance(size);
	if (res_size <= 0)
		return false;  // Invalid block size

	uint64_t res_num = 0;
	uint64_t order   = 1;
	for (size_t i = size - 1; i < size; --i) {
		int digit = reverse_alphabet::instance(block[i]);
		if (digit < 0)
			return false;  // Invalid symbol

		uint64_t product_hi;
		uint64_t tmp = res_num + mul128(order, digit, &product_hi);
		if (tmp < res_num || 0 != product_hi)
			return false;  // Overflow

		res_num = tmp;
		order *= alphabet_size;  // Never overflows, 58^10 < 2^64
	}

	if (static_cast<size_t>(res_size) < full_block_size && (UINT64_C(1) << (8 * res_size)) <= res_num)
		return false;  // Overflow

	uint_64_to_8be(res_num, res_size, res);

	return true;
}
}  // namespace

std::string encode(const BinaryArray &data) {
	if (data.empty())
		return std::string();

	size_t full_block_count = data.size() / full_block_size;
	size_t last_block_size  = data.size() % full_block_size;
	size_t res_size         = full_block_count * full_encoded_block_size + encoded_block_sizes[last_block_size];

	std::string res(res_size, alphabet[0]);
	for (size_t i = 0; i < full_block_count; ++i) {
		encode_block(data.data() + i * full_block_size, full_block_size, &res[i * full_encoded_block_size]);
	}

	if (0 < last_block_size) {
		encode_block(data.data() + full_block_count * full_block_size, last_block_size,
		    &res[full_block_count * full_encoded_block_size]);
	}

	return res;
}

bool decode(const std::string &enc, BinaryArray *data) {
	if (enc.empty()) {
		data->clear();
		return true;
	}

	size_t full_block_count     = enc.size() / full_encoded_block_size;
	size_t last_block_size      = enc.size() % full_encoded_block_size;
	int last_block_decoded_size = decoded_block_sizes::instance(last_block_size);
	if (last_block_decoded_size < 0)
		return false;  // Invalid enc length
	size_t data_size = full_block_count * full_block_size + last_block_decoded_size;

	data->resize(data_size, 0);
	for (size_t i = 0; i < full_block_count; ++i) {
		if (!decode_block(
		        enc.data() + i * full_encoded_block_size, full_encoded_block_size, &(*data)[i * full_block_size]))
			return false;
	}

	if (0 < last_block_size) {
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
	crypto::Hash hash = crypto::cn_fast_hash(addr_data.data(), addr_data.size());

	std::vector<uint8_t> expected_checksum(hash.data, hash.data + addr_checksum_size);
	if (expected_checksum != checksum)
		return false;

	int read = common::read_varint(addr_data.begin(), addr_data.end(), *tag);
	if (read <= 0)
		return false;

	data->assign(addr_data.begin() + read, addr_data.end());  // addr_data.substr(read);
	return true;
}
}
}
