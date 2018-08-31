// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Base58.hpp"

#include <assert.h>
#include <algorithm>
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
		base     = *std::min_element(alphabet, alphabet + alphabet_size);
		auto top = *std::max_element(alphabet, alphabet + alphabet_size);
		m_data.resize(top - base + 1, -1);

		for (size_t i = 0; i < alphabet_size; ++i) {
			size_t idx  = static_cast<size_t>(alphabet[i] - base);
			m_data[idx] = static_cast<int8_t>(i);
		}
	}

	int operator()(char letter) const {
		size_t idx = static_cast<size_t>(letter - base);
		return idx < m_data.size() ? m_data[idx] : -1;
	}

	static reverse_alphabet instance;

private:
	std::vector<int8_t> m_data;
	char base = 0;
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
	std::vector<int> m_data;  // {0, -1, 1, 2, -1, 3, 4, 5, -1, 6, 7, 8};
};

decoded_block_sizes decoded_block_sizes::instance;

void encode_block(const uint8_t *block, size_t size, char *res) {
	assert(1 <= size && size <= full_block_size);

	//	uint64_t num = uint_be_from_bytes<uint64_t>(block, size);
	//	size_t i     = encoded_block_sizes[size] - 1;
	//	while (num > 0) {
	//		uint64_t remainder = num % alphabet_size;
	//		num /= alphabet_size;
	//		res[i] = alphabet[remainder];
	//		--i;
	//	}
	uint64_t num = uint_be_from_bytes<uint64_t>(block, size);
	for (size_t i = encoded_block_sizes[size]; i-- > 0;) {
		uint64_t remainder = num % alphabet_size;
		num /= alphabet_size;
		res[i] = alphabet[remainder];
	}
}

bool decode_block(const char *block, size_t size, uint8_t *res) {
	assert(1 <= size && size <= full_encoded_block_size);

	int res_size = decoded_block_sizes::instance(size);
	if (res_size <= 0)
		return false;  // Invalid block size

	uint64_t res_num = 0;
	uint64_t order   = 1;
	for (size_t i = size; i-- > 0;) {
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

	if (static_cast<size_t>(res_size) < full_block_size && (uint64_t(1) << (8 * res_size)) <= res_num)
		return false;  // Overflow

	uint_be_to_bytes(res, res_size, res_num);
	return true;
}
}  // namespace

std::string encode(const BinaryArray &data) {
	size_t full_block_count = data.size() / full_block_size;
	size_t last_block_size  = data.size() % full_block_size;
	size_t res_size         = full_block_count * full_encoded_block_size + encoded_block_sizes[last_block_size];

	std::string res(res_size, '*');
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

static const uint32_t table[] = {0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535,
    0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 0x136C9856,
    0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E,
    0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6,
    0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
    0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87,
    0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F,
    0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97,
    0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65, 0x4DB26158,
    0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC,
    0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA, 0xBE0B1010,
    0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F, 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
    0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739,
    0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D,
    0x0A00AE27, 0x7D079EB1, 0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671,
    0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B, 0xD80D2BDA,
    0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A,
    0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92,
    0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
    0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B,
    0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B,
    0x6FB077E1, 0x18B74777, 0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3,
    0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9, 0xBDBDF21C,
    0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8,
    0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D};

uint32_t crc32(const uint8_t *data, size_t size, uint32_t crc) {
	crc = crc ^ 0xFFFFFFFFU;
	for (size_t i = 0; i != size; ++i) {
		size_t y = (crc ^ data[i]) & 0xFFU;
		crc      = (crc >> 8) ^ table[y];
	}
	return crc ^ 0xFFFFFFFFU;
}

// Optimized for checking by simple javascript
void encode_crc_block(uint32_t num, size_t encoded_size, char *res) {
	for (size_t i = encoded_size; i-- > 0;) {
		uint64_t remainder = num % base58::alphabet_size;
		num /= base58::alphabet_size;
		res[i] = base58::alphabet[remainder];
	}
}
const size_t future_addr_checksum_size = 4;
static_assert(future_addr_checksum_size <= 4, "we user crc32 so cannot be > 4");
std::string encode_addr_future(std::string prefix, const BinaryArray &addr_data) {
	std::string encoded_data = prefix + base58::encode(addr_data);
	uint32_t crc             = crc32(reinterpret_cast<const uint8_t *>(encoded_data.data()), encoded_data.size());
	size_t res_size          = base58::encoded_block_sizes[future_addr_checksum_size];
	std::string crc_str(res_size, '*');
	encode_crc_block(crc, res_size, &crc_str[0]);
	return encoded_data + crc_str;
}

bool decode_addr_future(std::string addr, std::string prefix, BinaryArray *addr_data) {
	size_t res_size = base58::encoded_block_sizes[future_addr_checksum_size];
	if (addr.size() < res_size + prefix.size())
		return false;
	std::string encoded_data = addr.substr(0, addr.size() - res_size);
	uint32_t crc             = crc32(reinterpret_cast<const uint8_t *>(encoded_data.data()), encoded_data.size());
	std::string crc_str(res_size, '*');
	encode_crc_block(crc, res_size, &crc_str[0]);

	std::string actual_crc_str = addr.substr(addr.size() - res_size);

	if (crc_str != actual_crc_str)
		return false;
	if (encoded_data.substr(0, prefix.size()) != prefix)
		return false;
	return base58::decode(encoded_data.substr(prefix.size()), addr_data);
}

void test_addr_future() {
	//	auto a1 = crypto::random_keypair();
	//	auto a2 = crypto::random_keypair();
	//	AccountPublicAddress ap{a1.public_key, a2.public_key};
	//	std::cout << currency.account_address_as_string(ap) << std::endl;
	//
	//	BinaryArray addr_data = seria::to_binary(ap);
	//	std::string addr = common::encode_addr_future("bcn", addr_data);
	//	std::cout << addr << std::endl;
	//	BinaryArray addr_data2;
	//	bool addr_good = common::decode_addr_future(addr, "bcn", &addr_data2);
	//	std::cout << addr_good << std::endl;
}
}

// Example random addresses

// bcn7rcNCaFR3gSFDgAcgRMn12Fm7BcHot3DBPEXmX3t6x8PdbxwwprTJtrbPN2ismWzYzNpKwmAXT6BqfEbMX5VtW8W5TTRQz
// bcncpS2YQUzZZN52XwyspjWsP6Mcz4Rb36RHEfEduvb1wTdFH9foAsr3xDJJHGzuvX94Qb2oaxsZDAVB5HdMpwtTuS45jxGNu
// bcnVsnFc5eSpMUPCVwtk8vGcf591HcLxjxkTVkPNWSDBvwSGg5p6CCXV6DCrK4Z6mYjrd3DtLFsirNdJEUBCDYPqDAm2U1aqx

// crc	509845007
// crc_str	"1n46AA"
// bcnTvZ8DRwgnRZLC2Db3FHC375LBE9NfrYpREbXDByVwbpB5htuNXSJ1roUDjtbJ5nxVUPWbKCpiaq3eXPcN5x9iMxJ1n46AA

// Javascript impl of future address checking

// function crc32 ( str ) {
//    // http://kevin.vanzonneveld.net
//    // +   original by: Webtoolkit.info (http://www.webtoolkit.info/)
//    // +   improved by: T0bsn
//    // -    depends on: utf8_encode
//    // *     example 1: crc32('Kevin van Zonneveld');
//    // *     returns 1: 1249991249
//
//    var table = "00000000 77073096 EE0E612C 990951BA 076DC419 706AF48F E963A535 9E6495A3 0EDB8832 79DCB8A4 E0D5E91E
//    97D2D988 09B64C2B 7EB17CBD E7B82D07 90BF1D91 1DB71064 6AB020F2 F3B97148 84BE41DE 1ADAD47D 6DDDE4EB F4D4B551
//    83D385C7 136C9856 646BA8C0 FD62F97A 8A65C9EC 14015C4F 63066CD9 FA0F3D63 8D080DF5 3B6E20C8 4C69105E D56041E4
//    A2677172 3C03E4D1 4B04D447 D20D85FD A50AB56B 35B5A8FA 42B2986C DBBBC9D6 ACBCF940 32D86CE3 45DF5C75 DCD60DCF
//    ABD13D59 26D930AC 51DE003A C8D75180 BFD06116 21B4F4B5 56B3C423 CFBA9599 B8BDA50F 2802B89E 5F058808 C60CD9B2
//    B10BE924 2F6F7C87 58684C11 C1611DAB B6662D3D 76DC4190 01DB7106 98D220BC EFD5102A 71B18589 06B6B51F 9FBFE4A5
//    E8B8D433 7807C9A2 0F00F934 9609A88E E10E9818 7F6A0DBB 086D3D2D 91646C97 E6635C01 6B6B51F4 1C6C6162 856530D8
//    F262004E 6C0695ED 1B01A57B 8208F4C1 F50FC457 65B0D9C6 12B7E950 8BBEB8EA FCB9887C 62DD1DDF 15DA2D49 8CD37CF3
//    FBD44C65 4DB26158 3AB551CE A3BC0074 D4BB30E2 4ADFA541 3DD895D7 A4D1C46D D3D6F4FB 4369E96A 346ED9FC AD678846
//    DA60B8D0 44042D73 33031DE5 AA0A4C5F DD0D7CC9 5005713C 270241AA BE0B1010 C90C2086 5768B525 206F85B3 B966D409
//    CE61E49F 5EDEF90E 29D9C998 B0D09822 C7D7A8B4 59B33D17 2EB40D81 B7BD5C3B C0BA6CAD EDB88320 9ABFB3B6 03B6E20C
//    74B1D29A EAD54739 9DD277AF 04DB2615 73DC1683 E3630B12 94643B84 0D6D6A3E 7A6A5AA8 E40ECF0B 9309FF9D 0A00AE27
//    7D079EB1 F00F9344 8708A3D2 1E01F268 6906C2FE F762575D 806567CB 196C3671 6E6B06E7 FED41B76 89D32BE0 10DA7A5A
//    67DD4ACC F9B9DF6F 8EBEEFF9 17B7BE43 60B08ED5 D6D6A3E8 A1D1937E 38D8C2C4 4FDFF252 D1BB67F1 A6BC5767 3FB506DD
//    48B2364B D80D2BDA AF0A1B4C 36034AF6 41047A60 DF60EFC3 A867DF55 316E8EEF 4669BE79 CB61B38C BC66831A 256FD2A0
//    5268E236 CC0C7795 BB0B4703 220216B9 5505262F C5BA3BBE B2BD0B28 2BB45A92 5CB36A04 C2D7FFA7 B5D0CF31 2CD99E8B
//    5BDEAE1D 9B64C2B0 EC63F226 756AA39C 026D930A 9C0906A9 EB0E363F 72076785 05005713 95BF4A82 E2B87A14 7BB12BAE
//    0CB61B38 92D28E9B E5D5BE0D 7CDCEFB7 0BDBDF21 86D3D2D4 F1D4E242 68DDB3F8 1FDA836E 81BE16CD F6B9265B 6FB077E1
//    18B74777 88085AE6 FF0F6A70 66063BCA 11010B5C 8F659EFF F862AE69 616BFFD3 166CCF45 A00AE278 D70DD2EE 4E048354
//    3903B3C2 A7672661 D06016F7 4969474D 3E6E77DB AED16A4A D9D65ADC 40DF0B66 37D83BF0 A9BCAE53 DEBB9EC5 47B2CF7F
//    30B5FFE9 BDBDF21C CABAC28A 53B39330 24B4A3A6 BAD03605 CDD70693 54DE5729 23D967BF B3667A2E C4614AB8 5D681B02
//    2A6F2B94 B40BBE37 C30C8EA1 5A05DF1B 2D02EF8D";
//
//    var crc = 0;
//    var x = 0;
//    var y = 0;
//
//    crc = crc ^ (-1);
//    for( var i = 0, iTop = str.length; i < iTop; i++ ) {
//        y = ( crc ^ str.charCodeAt( i ) ) & 0xFF;
//        x = "0x" + table.substr( y * 9, 8 );
//        crc = ( crc >>> 8 ) ^ x;
//    }
//
//    return (crc ^ (-1)) >>> 0;
//}
// var alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
//
// function encode_crc_block(num, encoded_size) {
//	var result = ""
//	for(var i = encoded_size; i-- > 0 ;) {
//		remainder = num % alphabet.length;
//		num = Math.floor(num/alphabet.length);
//		result = alphabet[remainder] + result;
//	}
//	return result
//}
//
// function check_address(addr, prefix) {
//	var res_size = 6;
//	if( addr.length < res_size + prefix.length )
//		return false;
//	var actual_crc_str = addr.substr(addr.length - res_size);
//	var encoded_addr = addr.substr(0, addr.length - res_size);
//	var crc = crc32(encoded_addr)
//	crc_str = encode_crc_block(crc, res_size);
//	if(crc_str != actual_crc_str)
//		return false;
//	if(encoded_addr.substr(0, prefix.length) != prefix)
//		return false;
//	return true;
//}
