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

#include "BinaryOutputStream.hpp"

#include <cassert>
#include <stdexcept>
#include "common/Streams.hpp"

using namespace common;

using namespace seria;


void BinaryOutputStream::beginMap(size_t &size) {
	writeVarint(stream, size);
}

void BinaryOutputStream::nextMapKey(std::string &name) {
	(*this)(name);
}

void BinaryOutputStream::beginArray(size_t &size, bool fixed_size) {
	if (!fixed_size)
		writeVarint(stream, size);
}

void BinaryOutputStream::seria_v(uint8_t &value) {
	writeVarint(stream, value);
}

void BinaryOutputStream::seria_v(uint16_t &value) {
	writeVarint(stream, value);
}

void BinaryOutputStream::seria_v(int16_t &value) {
	writeVarint(stream, static_cast<uint16_t>(value));
}

void BinaryOutputStream::seria_v(uint32_t &value) {
	writeVarint(stream, value);
}

void BinaryOutputStream::seria_v(int32_t &value) {
	writeVarint(stream, static_cast<uint32_t>(value));
}

void BinaryOutputStream::seria_v(int64_t &value) {
	writeVarint(stream, static_cast<uint64_t>(value));
}

void BinaryOutputStream::seria_v(uint64_t &value) {
	writeVarint(stream, value);
}

void BinaryOutputStream::seria_v(bool &value) {
	char boolVal = value;
	stream.write(&boolVal, 1);
}

void BinaryOutputStream::seria_v(std::string &value) {
	writeVarint(stream, value.size());
	stream.write(value.data(), value.size());
}
void BinaryOutputStream::seria_v(BinaryArray &value) {
	writeVarint(stream, value.size());
	stream.write(value.data(), value.size());
}

void BinaryOutputStream::binary(void *value, size_t size) {
	stream.write(static_cast<const char *>(value), size);
}

void BinaryOutputStream::seria_v(double &value) {
	assert(false); //the method is not supported for this type of serialization
	throw std::logic_error("double serialization is not supported in BinaryOutputStreamSeria");
}

