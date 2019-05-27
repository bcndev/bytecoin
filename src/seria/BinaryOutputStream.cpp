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

bool BinaryOutputStream::begin_map(size_t &size) {
	stream.write_varint(size);
	return true;
}

void BinaryOutputStream::next_map_key(std::string &name) { ser(name, *this); }

bool BinaryOutputStream::begin_array(size_t &size, bool fixed_size) {
	if (!fixed_size)
		stream.write_varint(size);
	return true;
}

bool BinaryOutputStream::seria_v(int64_t &value) {
	stream.write_varint(static_cast<uint64_t>(value));
	return true;
}

bool BinaryOutputStream::seria_v(uint64_t &value) {
	stream.write_varint(value);
	return true;
}

bool BinaryOutputStream::seria_v(bool &value) {
	char bool_val = value;
	stream.write(&bool_val, 1);
	return true;
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
