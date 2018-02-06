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

#include "MemoryStreams.hpp"
#include <cassert>
#include <cstring>
#include <algorithm>
#include <stdexcept>

using namespace common;

MemoryInputStream::MemoryInputStream(const void *buffer, size_t bufferSize)
		: buffer(static_cast<const char *>(buffer)), bufferSize(bufferSize), inPosition(0) {
}

size_t MemoryInputStream::read_some(void *data, size_t size) {
	if(inPosition > bufferSize)
		throw std::logic_error("MemoryInputStream::read_some jump over the end of buffer");
	size = std::min(size, bufferSize - inPosition);

	if (size > 0)
		memcpy(data, buffer + inPosition, size);
	inPosition += size;
	return size;
}

size_t StringInputStream::read_some(void *data, size_t size) {
	if(inPosition > in->size())
		throw std::logic_error("StringInputStream::read_some jump over the end of buffer");
	size = std::min(size, in->size() - inPosition);

	memcpy(data, in->data() + inPosition, size);
	inPosition += size;
	return size;
}

size_t StringInputStream::copyTo(IOutputStream &out, size_t max_count) {
	size_t total_count = 0;
	while (true) {
		size_t rc = std::min(in->size() - inPosition, max_count);
		if (rc == 0)
			break;
		size_t count = out.write_some(in->data() + inPosition, rc);
		inPosition += count;
		max_count -= count;
		total_count += count;
		if (count == 0)
			break;
	}
	return total_count;
}

size_t VectorInputStream::read_some(void *data, size_t size) {
	if(inPosition > in->size())
		throw std::logic_error("VectorInputStream::read_some jump over the end of buffer");
	size = std::min(size, in->size() - inPosition);

	memcpy(data, in->data() + inPosition, size);
	inPosition += size;
	return size;
}

size_t VectorInputStream::copyTo(IOutputStream &out, size_t max_count) {
	size_t total_count = 0;
	while (true) {
		size_t rc = std::min(in->size() - inPosition, max_count);
		if (rc == 0)
			break;
		size_t count = out.write_some(in->data() + inPosition, rc);
		inPosition += count;
		max_count -= count;
		total_count += count;
		if (count == 0)
			break;
	}
	return total_count;
}

size_t StringOutputStream::write_some(const void *data, size_t size) {
	out->append(static_cast<const char *>(data), size);
	return size;
}

size_t VectorOutputStream::write_some(const void *data, size_t size) {
	append(*out, static_cast<const uint8_t *>(data), static_cast<const uint8_t *>(data) + size);
	return size;
}

size_t CircularBuffer::read_some(void *data, size_t size) {
	size_t rc = std::min(size, read_count());
	memcpy(data, read_ptr(), rc);
	did_read(rc);
	return rc;
}

size_t CircularBuffer::write_some(const void *data, size_t size) {
	size_t rc = std::min(size, write_count());
	memcpy(write_ptr(), data, rc);
	did_write(rc);
	return rc;
}

void CircularBuffer::did_write(size_t count) {
	write_pos += count;
	if (write_pos > read_pos + impl.size())
		throw std::logic_error("Writing past end of Buffer");
}

void CircularBuffer::did_read(size_t count) {
	read_pos += count;
	if (read_pos > write_pos)
		throw std::logic_error("Reading past end of Buffer");
	if (read_pos >= impl.size()) {
		read_pos -= impl.size();
		write_pos -= impl.size();
	}
}

void CircularBuffer::copyFrom(IInputStream &in) {
	while (true) {
		size_t wc = write_count();
		if (wc == 0)
			break;
		size_t count = in.read_some(write_ptr(), wc);
		did_write(count);
		if (count == 0)
			break;
	}
}

size_t CircularBuffer::copyTo(IOutputStream &out, size_t max_count) {
	size_t total_count = 0;
	while (true) {
		size_t rc = std::min(read_count(), max_count);
		if (rc == 0)
			break;
		size_t count = out.write_some(read_ptr(), rc);
		did_read(count);
		max_count -= count;
		total_count += count;
		if (count == 0)
			break;
	}
	return total_count;
}
