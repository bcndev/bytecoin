// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#include "BinaryInputStream.hpp"

#include <algorithm>
#include <cassert>
#include <stdexcept>
#include "common/Streams.hpp"

using namespace common;

using namespace seria;

namespace {

template<typename StorageType, typename T>
void readVarintAs(IInputStream &s, T &i) {
	i = static_cast<T>(readVarint<StorageType>(s));
}

}


void BinaryInputStream::beginArray(size_t &size, bool fixed_size) {
	if (!fixed_size)
		readVarintAs<uint64_t>(stream, size);
}

void BinaryInputStream::beginMap(size_t &size) {
	readVarintAs<uint64_t>(stream, size);
}

void BinaryInputStream::nextMapKey(std::string &name) {
	(*this)(name);
}

void BinaryInputStream::seria_v(uint8_t &value) {
	readVarint(stream, value);
}

void BinaryInputStream::seria_v(uint16_t &value) {
	readVarint(stream, value);
}

void BinaryInputStream::seria_v(int16_t &value) {
	readVarintAs<uint16_t>(stream, value);
}

void BinaryInputStream::seria_v(uint32_t &value) {
	readVarint(stream, value);
}

void BinaryInputStream::seria_v(int32_t &value) {
	readVarintAs<uint32_t>(stream, value);
}

void BinaryInputStream::seria_v(int64_t &value) {
	readVarintAs<uint64_t>(stream, value);
}

void BinaryInputStream::seria_v(uint64_t &value) {
	readVarint(stream, value);
}

void BinaryInputStream::seria_v(bool &value) {
	value = read<uint8_t>(stream) != 0;
}

void BinaryInputStream::seria_v(BinaryArray &value) {
	uint64_t size;
	readVarint(stream, size);
	common::read(stream, value, size);
}

void BinaryInputStream::seria_v(std::string &value) {
	uint64_t size;
	readVarint(stream, size);

	common::read(stream, value, size);
}

void BinaryInputStream::binary(void *value, size_t size) {
	stream.read(value, size);
}

void BinaryInputStream::seria_v(double &value) {
	assert(false); //the method is not supported for this type of serialization
	throw std::logic_error("double serialization is not supported in BinaryInputStreamSeria");
}


