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

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include "BinaryArray.hpp"

namespace common {
// read_some and write_some are allowed to read/write as many bytes as convenient, returning bytes read/written
// read and write are obliged to read/write all data and throw if it is not possible

class IInputStream {
public:
	virtual ~IInputStream() {}
	virtual size_t read_some(void *data, size_t size) = 0;
	void read(void *data, size_t size);
};

class IOutputStream {
public:
	virtual ~IOutputStream() {}
	virtual size_t write_some(const void *data, size_t size) = 0;
	void write(const void *data, size_t size);
};

void read(IInputStream &in, int8_t &value);
void read(IInputStream &in, int16_t &value);
void read(IInputStream &in, int32_t &value);
void read(IInputStream &in, int64_t &value);
void read(IInputStream &in, uint8_t &value);
void read(IInputStream &in, uint16_t &value);
void read(IInputStream &in, uint32_t &value);
void read(IInputStream &in, uint64_t &value);
void read(IInputStream &in, BinaryArray &data, size_t size);
void read(IInputStream &in, std::string &data, size_t size);
void readVarint(IInputStream &in, uint8_t &value);
void readVarint(IInputStream &in, uint16_t &value);
void readVarint(IInputStream &in, uint32_t &value);
void readVarint(IInputStream &in, uint64_t &value);

void write(IOutputStream &out, int8_t value);
void write(IOutputStream &out, int16_t value);
void write(IOutputStream &out, int32_t value);
void write(IOutputStream &out, int64_t value);
void write(IOutputStream &out, uint8_t value);
void write(IOutputStream &out, uint16_t value);
void write(IOutputStream &out, uint32_t value);
void write(IOutputStream &out, uint64_t value);
void write(IOutputStream &out, const BinaryArray &data);
void write(IOutputStream &out, const std::string &data);
void writeVarint(IOutputStream &out, uint64_t value);

template<typename T> T read(IInputStream &in) {
	T value;
	read(in, value);
	return value;
}

template<typename T> T readVarint(IInputStream &in) {
	T value;
	readVarint(in, value);
	return value;
}

}
