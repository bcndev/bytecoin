// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include "BinaryArray.hpp"
#include "Math.hpp"

namespace common {
// read_some and write_some are allowed to read/write as many bytes as convenient, returning bytes read/written
// read and write are obliged to read/write all data and throw if it is not possible

class IInputStream {
public:
	virtual ~IInputStream()                           = default;
	virtual size_t read_some(void *data, size_t size) = 0;
	void read(void *data, size_t size);
	void read(BinaryArray &data, size_t size);
	void read(std::string &data, size_t size);
	uint8_t read_byte();
	uint64_t read_varint64();
	template<class T>
	T read_varint() {
		static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value,
		    "reading signed values in varint format has to be done carefully (no canonical way)");
		return integer_cast<T>(read_varint64());
	}
};

class IOutputStream {
public:
	virtual ~IOutputStream()                                 = default;
	virtual size_t write_some(const void *data, size_t size) = 0;
	void write(const void *data, size_t size);
	void write(const BinaryArray &data);
	void write(const std::string &data);
	void write_byte(uint8_t b) { write(&b, 1); }
	void write_varint(uint64_t value);
};

class StreamError : public std::runtime_error {
public:
	using std::runtime_error::runtime_error;
};
class StreamErrorFileExists : public StreamError {
public:
	using StreamError::StreamError;
};
}  // namespace common
