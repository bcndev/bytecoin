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
		data = (char *)data + rc;
		count -= rc;
	}
}

void IOutputStream::write(const void *data, size_t size) {
	while (size != 0) {
		size_t wc = write_some(data, size);
		if (wc == 0)
			throw StreamError("IOutputStream error writing to full stream");
		data = (const char *)data + wc;
		size -= wc;
	}
}

void common::read(IInputStream &in, int8_t &value) { in.read(&value, sizeof(value)); }

// TODO: Convert funs below from little endian on big endian platforms

void common::read(IInputStream &in, int16_t &value) { in.read(&value, sizeof(value)); }

void common::read(IInputStream &in, int32_t &value) { in.read(&value, sizeof(value)); }

void common::read(IInputStream &in, int64_t &value) { in.read(&value, sizeof(value)); }

void common::read(IInputStream &in, uint8_t &value) { in.read(&value, sizeof(value)); }

void common::read(IInputStream &in, uint16_t &value) { in.read(&value, sizeof(value)); }

void common::read(IInputStream &in, uint32_t &value) { in.read(&value, sizeof(value)); }

void common::read(IInputStream &in, uint64_t &value) { in.read(&value, sizeof(value)); }

static const size_t CHUNK = 1024 * 1024;
// We read sized entities in chunks to prevent over-sized allocation attacks

void common::read(IInputStream &in, BinaryArray &data, size_t size) {
	data.resize(std::min(CHUNK, size));
	in.read(data.data(), data.size());
	while (data.size() != size) {
		size_t add = std::min(CHUNK, size - data.size());
		data.resize(data.size() + add);
		in.read(data.data() + data.size() - add, add);
	}
}

void common::read(IInputStream &in, std::string &data, size_t size) {
	data.resize(std::min(CHUNK, size));
	in.read(&data[0], data.size());
	while (data.size() != size) {
		size_t add = std::min(CHUNK, size - data.size());
		data.resize(data.size() + add);
		in.read(&data[0] + data.size() - add, add);
	}
}

template<typename T>
void read_varint_helper(IInputStream &in, T &value) {
	T temp = 0;
	for (uint8_t shift = 0;; shift += 7) {
		uint8_t piece;
		read(in, piece);
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

void common::read_varint(IInputStream &in, uint8_t &value) { read_varint_helper(in, value); }

void common::read_varint(IInputStream &in, uint16_t &value) { read_varint_helper(in, value); }

void common::read_varint(IInputStream &in, uint32_t &value) { read_varint_helper(in, value); }

void common::read_varint(IInputStream &in, uint64_t &value) { read_varint_helper(in, value); }

void common::write(IOutputStream &out, int8_t value) { out.write(&value, sizeof(value)); }

void common::write(IOutputStream &out, int16_t value) { out.write(&value, sizeof(value)); }

void common::write(IOutputStream &out, int32_t value) { out.write(&value, sizeof(value)); }

void common::write(IOutputStream &out, int64_t value) { out.write(&value, sizeof(value)); }

void common::write(IOutputStream &out, uint8_t value) { out.write(&value, sizeof(value)); }

void common::write(IOutputStream &out, uint16_t value) { out.write(&value, sizeof(value)); }

void common::write(IOutputStream &out, uint32_t value) { out.write(&value, sizeof(value)); }

void common::write(IOutputStream &out, uint64_t value) { out.write(&value, sizeof(value)); }

void common::write(IOutputStream &out, const BinaryArray &data) { out.write(data.data(), data.size()); }

void common::write(IOutputStream &out, const std::string &data) { out.write(data.data(), data.size()); }

void common::write_varint(IOutputStream &out, uint64_t value) {
	uint8_t buf[10];  // enough to store uint64_t
	uint8_t *end = buf;
	common::write_varint(end, value);
	out.write(buf, end - buf);
}
