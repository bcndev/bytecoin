// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
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

class StreamError : public std::runtime_error {
public:
	explicit StreamError(const std::string &str) : std::runtime_error(str) {}
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
void read_varint(IInputStream &in, uint8_t &value);
void read_varint(IInputStream &in, uint16_t &value);
void read_varint(IInputStream &in, uint32_t &value);
void read_varint(IInputStream &in, uint64_t &value);

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
void write_varint(IOutputStream &out, uint64_t value);

template<typename T>
T read(IInputStream &in) {
	T value;
	read(in, value);
	return value;
}

template<typename T>
T read_varint(IInputStream &in) {
	T value;
	read_varint(in, value);
	return value;
}
}
