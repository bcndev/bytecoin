// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "BinaryOutputStream.hpp"

#include <cassert>
#include <stdexcept>
#include "common/Invariant.hpp"
#include "common/Streams.hpp"

using namespace common;

using namespace seria;

// We write signed values in a way that is sizeof-independent
// If you write any signed type, reading it into any other signed type will be ok
// and the value will be the same if the result type can fit actual written value.
// Otherwise exception will be thrown from integer_cast

void BinaryOutputStream::begin_map(size_t &size) { stream.write_varint(size); }

void BinaryOutputStream::next_map_key(std::string &name) { ser(name, *this); }

void BinaryOutputStream::begin_array(size_t &size, bool fixed_size) {
	if (!fixed_size)
		stream.write_varint(size);
}

void BinaryOutputStream::seria_v(uint8_t &value) { stream.write_varint(value); }

void BinaryOutputStream::seria_v(uint16_t &value) { stream.write_varint(value); }

void BinaryOutputStream::seria_v(int16_t &value) {
	stream.write_varint(static_cast<uint64_t>(static_cast<int64_t>(value)));
}

void BinaryOutputStream::seria_v(uint32_t &value) { stream.write_varint(value); }

void BinaryOutputStream::seria_v(int32_t &value) {
	stream.write_varint(static_cast<uint64_t>(static_cast<int64_t>(value)));
}

void BinaryOutputStream::seria_v(int64_t &value) { stream.write_varint(static_cast<uint64_t>(value)); }

void BinaryOutputStream::seria_v(uint64_t &value) { stream.write_varint(value); }

void BinaryOutputStream::seria_v(bool &value) {
	char bool_val = value;
	stream.write(&bool_val, 1);
}

bool BinaryOutputStream::seria_v(std::string &value) {
	stream.write_varint(value.size());
	stream.write(value.data(), value.size());
	return true;
}
bool BinaryOutputStream::seria_v(BinaryArray &value) {
	stream.write_varint(value.size());
	stream.write(value.data(), value.size());
	return true;
}

bool BinaryOutputStream::binary(void *value, size_t size) {
	stream.write(value, size);
	return true;
}

// void BinaryOutputStream::seria_v(double &value) {
//	assert(false);  // the method is not supported for this type of serialization
//	throw std::logic_error("double serialization is not supported in BinaryOutputStreamSeria");
//}
