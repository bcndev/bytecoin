// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Varint.hpp"
#include <stdexcept>

namespace common {

template<class T>
T uint_be_from_bytes(const unsigned char *buf, size_t si) {
	T result = 0;
	for (size_t i = 0; i != si; ++i) {
		result <<= 8;
		result |= buf[i];
	}
	return result;
}

template<class T>
void uint_be_to_bytes(unsigned char *buf, size_t si, T val) {
	for (size_t i = si; i-- > 0;) {
		buf[i] = static_cast<unsigned char>(val);
		val >>= 8;
	}
}

size_t get_varint_sqlite4_size(uint64_t val) {
	if (val <= 240)
		return 1;
	if (val <= 2287)
		return 2;
	if (val <= 67823)
		return 3;
	if (val <= 16777215)
		return 4;
	if (val <= 4294967295)
		return 5;
	if (val <= 1099511627775)
		return 6;
	if (val <= 281474976710655)
		return 7;
	if (val <= 72057594037927935)
		return 8;
	return 9;
}

uint64_t read_varint_sqlite4(const std::string &str) {
	const char *be = str.data();
	const char *en = str.data() + str.size();
	uint64_t val   = read_varint_sqlite4(be, en);
	if (be != en)
		throw std::runtime_error("read_varint_sqlite4 excess symbols in string");
	return val;
}

void read(const unsigned char *&begin, const unsigned char *end, unsigned char *to, size_t len) {
	if (end < begin + len)
		throw std::runtime_error("end of read");
	memcpy(to, begin, len);
	begin += len;
}

uint64_t read_varint_sqlite4(const unsigned char *&begin, const unsigned char *end) {
	unsigned char a0;
	read(begin, end, &a0, 1);
	if (a0 <= 240) {
		return a0;
	}
	if (a0 <= 248) {
		unsigned char a1;
		read(begin, end, &a1, 1);
		return 240 + 256 * (a0 - 241) + a1;
	}
	if (a0 == 249) {
		unsigned char buf[2];
		read(begin, end, buf, 2);
		return 2288 + 256 * buf[0] + buf[1];
	}
	unsigned char buf[8];
	int bytes = 3 + a0 - 250;
	read(begin, end, buf, bytes);
	return uint_be_from_bytes<uint64_t>(buf, bytes);
}

std::string str(const unsigned char *buf, size_t len) { return std::string((const char *)buf, len); }

std::string write_varint_sqlite4(uint64_t val) {
	unsigned char buf[9];
	if (val <= 240) {
		buf[0] = static_cast<unsigned char>(val);
		return str(buf, 1);
	}
	if (val <= 2287) {
		buf[0] = static_cast<unsigned char>((val - 240) / 256 + 241);
		buf[1] = static_cast<unsigned char>(val - 240);
		return str(buf, 2);
	}
	if (val <= 67823) {
		buf[0] = 249;
		buf[1] = static_cast<unsigned char>((val - 2288) / 256);
		buf[2] = static_cast<unsigned char>(val - 2288);
		return str(buf, 3);
	}
	if (val <= 16777215) {
		buf[0] = 250;
		uint_be_to_bytes<uint64_t>(buf + 1, 3, val);
		return str(buf, 4);
	}
	if (val <= 4294967295) {
		buf[0] = 251;
		uint_be_to_bytes<uint64_t>(buf + 1, 4, val);
		return str(buf, 5);
	}
	if (val <= 1099511627775) {
		buf[0] = 252;
		uint_be_to_bytes<uint64_t>(buf + 1, 5, val);
		return str(buf, 6);
	}
	if (val <= 281474976710655) {
		buf[0] = 253;
		uint_be_to_bytes<uint64_t>(buf + 1, 6, val);
		return str(buf, 7);
	}
	if (val <= 72057594037927935) {
		buf[0] = 254;
		uint_be_to_bytes<uint64_t>(buf + 1, 7, val);
		return str(buf, 8);
	}
	buf[0] = 255;
	uint_be_to_bytes<uint64_t>(buf + 1, 8, val);
	return str(buf, 9);
}
}
