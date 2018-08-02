// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "BinaryOutputStream.hpp"

#include <cassert>
#include <stdexcept>
#include "common/Invariant.hpp"
#include "common/Streams.hpp"

using namespace common;

using namespace seria;

void BinaryOutputStream::begin_map(size_t &size) { write_varint(stream, size); }

void BinaryOutputStream::next_map_key(std::string &name) { (*this)(name); }

void BinaryOutputStream::begin_array(size_t &size, bool fixed_size) {
	if (!fixed_size)
		write_varint(stream, size);
}

void BinaryOutputStream::seria_v(uint8_t &value) { write_varint(stream, value); }

void BinaryOutputStream::seria_v(uint16_t &value) { write_varint(stream, value); }

void BinaryOutputStream::seria_v(int16_t &value) { write_varint(stream, static_cast<uint16_t>(value)); }

void BinaryOutputStream::seria_v(uint32_t &value) { write_varint(stream, value); }

void BinaryOutputStream::seria_v(int32_t &value) { write_varint(stream, static_cast<uint32_t>(value)); }

void BinaryOutputStream::seria_v(int64_t &value) { write_varint(stream, static_cast<uint64_t>(value)); }

void BinaryOutputStream::seria_v(uint64_t &value) { write_varint(stream, value); }

void BinaryOutputStream::seria_v(bool &value) {
	char bool_val = value;
	stream.write(&bool_val, 1);
}

void BinaryOutputStream::seria_v(std::string &value) {
	write_varint(stream, value.size());
	stream.write(value.data(), value.size());
}
void BinaryOutputStream::seria_v(BinaryArray &value) {
	write_varint(stream, value.size());
	stream.write(value.data(), value.size());
}

void BinaryOutputStream::binary(void *value, size_t size) { stream.write(static_cast<const char *>(value), size); }

void BinaryOutputStream::seria_v(double &value) {
	assert(false);  // the method is not supported for this type of serialization
	invariant(false, "double serialization is not supported in BinaryOutputStreamSeria");
}
