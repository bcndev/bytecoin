// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Streams.hpp"
#include <algorithm>
#include <stdexcept>
#include "BinaryArray.hpp"
#include "Varint.hpp"

using namespace common;

void IInputStream::read(void *data, size_t count) {
	while (count != 0) {
		size_t rc = read_some(data, count);
		if (rc == 0)
			throw StreamError("IInputStream reading from empty stream");
		data = reinterpret_cast<char *>(data) + rc;
		count -= rc;
	}
}

void IOutputStream::write(const void *data, size_t size) {
	while (size != 0) {
		size_t wc = write_some(data, size);
		if (wc == 0)
			throw StreamError("IOutputStream error writing to full stream");
		data = reinterpret_cast<const char *>(data) + wc;
		size -= wc;
	}
}

static const size_t CHUNK = 1024 * 1024;
// We read sized entities in chunks to prevent over-sized allocation attacks

void IInputStream::read(BinaryArray &data, size_t size) {
	data.resize(std::min(CHUNK, size));
	read(data.data(), data.size());
	while (data.size() != size) {
		size_t add = std::min(CHUNK, size - data.size());
		data.resize(data.size() + add);
		read(data.data() + data.size() - add, add);
	}
}

void IInputStream::read(std::string &data, size_t size) {
	data.resize(std::min(CHUNK, size));
	read(&data[0], data.size());
	while (data.size() != size) {
		size_t add = std::min(CHUNK, size - data.size());
		data.resize(data.size() + add);
		read(&data[0] + data.size() - add, add);
	}
}

template<typename T>
void read_varint_helper(IInputStream &in, T &value) {
	T temp = 0;
	for (uint8_t shift = 0;; shift += 7) {
		uint8_t piece = in.read_byte();
		if (shift >= sizeof(temp) * 8 - 7 && piece >= 1 << (sizeof(temp) * 8 - shift))
			throw std::runtime_error("read_varint, value overflow");
		temp |= static_cast<T>(piece & 0x7f) << shift;
		if ((piece & 0x80) == 0) {
			if (piece == 0 && shift != 0)
				throw std::runtime_error("read_varint, invalid value representation");
			break;
		}
	}
	value = temp;
}
uint8_t IInputStream::read_byte() {
	uint8_t result = 0;
	read(&result, 1);
	return result;
}

uint64_t IInputStream::read_varint64() {
	uint64_t result = 0;
	read_varint_helper(*this, result);
	return result;
}

void IOutputStream::write(const BinaryArray &data) { write(data.data(), data.size()); }

void IOutputStream::write(const std::string &data) { write(data.data(), data.size()); }

void IOutputStream::write_varint(uint64_t value) {
	uint8_t buf[10];  // enough to store uint64_t
	uint8_t *end = buf;
	common::write_varint(end, value);
	write(buf, end - buf);
}
