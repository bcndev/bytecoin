// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "BinaryInputStream.hpp"

#include <algorithm>
#include <boost/lexical_cast.hpp>
#include <cassert>
#include <stdexcept>
#include "common/Invariant.hpp"
#include "common/Streams.hpp"

using namespace common;

using namespace seria;

namespace {

template<typename StorageType, typename T>
void read_varint_as(IInputStream &s, T &i) {
	i = static_cast<T>(read_varint<StorageType>(s));
}
}

void BinaryInputStream::begin_array(size_t &size, bool fixed_size) {
	if (!fixed_size)
		read_varint_as<uint64_t>(stream, size);
}

void BinaryInputStream::begin_map(size_t &size) { read_varint_as<uint64_t>(stream, size); }

void BinaryInputStream::next_map_key(std::string &name) { (*this)(name); }

void BinaryInputStream::seria_v(uint8_t &value) { read_varint(stream, value); }

void BinaryInputStream::seria_v(uint16_t &value) { read_varint(stream, value); }

void BinaryInputStream::seria_v(int16_t &value) { read_varint_as<uint16_t>(stream, value); }

void BinaryInputStream::seria_v(uint32_t &value) { read_varint(stream, value); }

void BinaryInputStream::seria_v(int32_t &value) { read_varint_as<uint32_t>(stream, value); }

void BinaryInputStream::seria_v(int64_t &value) { read_varint_as<uint64_t>(stream, value); }

void BinaryInputStream::seria_v(uint64_t &value) { read_varint(stream, value); }

void BinaryInputStream::seria_v(bool &value) { value = read<uint8_t>(stream) != 0; }

void BinaryInputStream::seria_v(BinaryArray &value) {
	uint64_t size;
	read_varint(stream, size);
	common::read(stream, value, boost::lexical_cast<size_t>(size));
}

void BinaryInputStream::seria_v(std::string &value) {
	uint64_t size;
	read_varint(stream, size);

	common::read(stream, value, boost::lexical_cast<size_t>(size));
}

void BinaryInputStream::binary(void *value, size_t size) { stream.read(value, size); }

void BinaryInputStream::seria_v(double &value) {
	assert(false);  // the method is not supported for this type of serialization
	invariant(false, "double serialization is not supported in BinaryInputStreamSeria");
}
