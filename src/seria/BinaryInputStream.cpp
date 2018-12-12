// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "BinaryInputStream.hpp"

#include <algorithm>
#include <cassert>
#include <stdexcept>
#include "common/Invariant.hpp"
#include "common/Math.hpp"
#include "common/Streams.hpp"

using namespace common;

using namespace seria;

// namespace {

// template<typename StorageType, typename T>
// void read_varint_as(IInputStream &s, T &i) {
//	i = static_cast<T>(read_varint<StorageType>(s));
//}
//}

void BinaryInputStream::begin_array(size_t &size, bool fixed_size) {
	if (!fixed_size)
		size = stream.read_varint<size_t>();
	//		read_varint_as<uint64_t>(stream, size);
}

void BinaryInputStream::begin_map(size_t &size) { size = stream.read_varint<size_t>(); }

void BinaryInputStream::next_map_key(std::string &name) { ser(name, *this); }

void BinaryInputStream::seria_v(uint8_t &value) { value = stream.read_varint<uint8_t>(); }

void BinaryInputStream::seria_v(uint16_t &value) { value = stream.read_varint<uint16_t>(); }

void BinaryInputStream::seria_v(int16_t &value) {
	value = integer_cast<int16_t>(static_cast<int64_t>(stream.read_varint<uint64_t>()));
}

void BinaryInputStream::seria_v(uint32_t &value) { value = stream.read_varint<uint32_t>(); }

void BinaryInputStream::seria_v(int32_t &value) {
	value = integer_cast<int32_t>(static_cast<int64_t>(stream.read_varint<uint64_t>()));
}

void BinaryInputStream::seria_v(int64_t &value) { value = static_cast<int64_t>(stream.read_varint<uint64_t>()); }

void BinaryInputStream::seria_v(uint64_t &value) { value = stream.read_varint<uint64_t>(); }

void BinaryInputStream::seria_v(bool &value) { value = (stream.read_byte() != 0); }

bool BinaryInputStream::seria_v(BinaryArray &value) {
	auto size = stream.read_varint<size_t>();
	stream.read(value, size);
	return true;
}

bool BinaryInputStream::seria_v(std::string &value) {
	auto size = stream.read_varint<size_t>();
	stream.read(value, size);
	return true;
}

bool BinaryInputStream::binary(void *value, size_t size) {
	stream.read(value, size);
	return true;
}

// void BinaryInputStream::seria_v(double &value) {
//	assert(false);  // the method is not supported for this type of serialization
//	throw std::logic_error("double serialization is not supported in BinaryInputStreamSeria");
//}
