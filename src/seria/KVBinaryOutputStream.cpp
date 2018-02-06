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

#include "KVBinaryOutputStream.hpp"
#include "KVBinaryCommon.hpp"

#include <cassert>
#include <stdexcept>
#include "common/Streams.hpp"
#include <iostream>

using namespace common;
using namespace bytecoin;
using namespace seria;

static bool verbose_debug = false;
static bool verbose_tokens = false;

namespace {

template<typename T>
void writePod(IOutputStream &s, const T &value) {
	s.write(&value, sizeof(T));
}

template<class T>
size_t packVarint(IOutputStream &s, uint8_t type_or, size_t pv) {
	T v = static_cast<T>(pv << 2);
	v |= type_or;
	s.write(&v, sizeof(T));
	return sizeof(T);
}

void writeElementName(IOutputStream &s, common::StringView name) {
	if (name.getSize() > std::numeric_limits<uint8_t>::max()) {
		throw std::runtime_error("Element name is too long");
	}

	uint8_t len = static_cast<uint8_t>(name.getSize());
	s.write(&len, sizeof(len));
	s.write(name.getData(), len);
	if (verbose_debug)
		std::cout << "writeElementName name=" << (std::string) name << std::endl;
	if (verbose_tokens)
		std::cout << "\"" << (std::string) name << "\"" << std::endl;
}

size_t writeArraySize(IOutputStream &s, size_t val) {
	if (val <= 63) {
		return packVarint<uint8_t>(s, PORTABLE_RAW_SIZE_MARK_BYTE, val);
	} else if (val <= 16383) {
		return packVarint<uint16_t>(s, PORTABLE_RAW_SIZE_MARK_WORD, val);
	} else if (val <= 1073741823) {
		return packVarint<uint32_t>(s, PORTABLE_RAW_SIZE_MARK_DWORD, val);
	} else {
		if (val > 4611686018427387903) {
			throw std::runtime_error("failed to pack varint - too big amount");
		}
		return packVarint<uint64_t>(s, PORTABLE_RAW_SIZE_MARK_INT64, val);
	}
}

}

KVBinaryOutputStream::KVBinaryOutputStream(common::IOutputStream &target) : target(target) {
	KVBinaryStorageBlockHeader hdr;
	hdr.m_signature_a = PORTABLE_STORAGE_SIGNATUREA;
	hdr.m_signature_b = PORTABLE_STORAGE_SIGNATUREB;
	hdr.m_ver = PORTABLE_STORAGE_FORMAT_VER;

	target.write(&hdr, sizeof(hdr));
}

void KVBinaryOutputStream::objectKey(common::StringView name) {
	nextKey = name;
}
void KVBinaryOutputStream::nextMapKey(std::string &name) {
	nextKey = name;
}

void KVBinaryOutputStream::beginObject() {
	if (m_stack.empty()) {
		if (!expectingRoot)
			throw std::logic_error("KVBinaryOutputStream::writeElementPrefix expecting only object");
		expectingRoot = false;
	} else
		writeElementPrefix(BIN_KV_SERIALIZE_TYPE_OBJECT);

	m_stack.push_back(Level(common::StringView("")));
	m_objectsStack.emplace_back();
	if (verbose_debug)
		std::cout << "beginObject m_objectsStack.push_back, m_stack.push_back name=" << std::endl;
}

void KVBinaryOutputStream::endObject() {
	assert(m_objectsStack.size());

	auto level = std::move(m_stack.back());
	m_stack.pop_back();

	auto objStream = std::move(m_objectsStack.back());
	m_objectsStack.pop_back();

	IOutputStream &out = m_objectsStack.empty() ? target : stream();

	if (verbose_debug)
		std::cout << "endObject TYPE_OBJECT level.count=" << level.count << " level.name="
				  << (std::string) level.name << std::endl;

	writeArraySize(out, level.count);
	out.write(objStream.buffer().data(), objStream.buffer().size());
	if (verbose_tokens)
		std::cout << "OBJ c=" << level.count << std::endl;
}

void KVBinaryOutputStream::beginArray(size_t &size, bool fixed_size) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_ARRAY);

	m_stack.push_back(Level(common::StringView(""), size));
	if (verbose_debug)
		std::cout << "beginArray size=" << size << std::endl;
	if (size == 0) {
		auto &s = stream();
		unsigned char c = BIN_KV_SERIALIZE_FLAG_ARRAY |
						  BIN_KV_SERIALIZE_TYPE_STRING; // we do not care which type is empty array
		s.write(&c, 1);
		writeArraySize(s, size);
		m_stack.back().state = State::Array;
		if (verbose_tokens)
			std::cout << "ARR t=" << int(BIN_KV_SERIALIZE_TYPE_OBJECT) << " c=" << size << std::endl;
	}
}

void KVBinaryOutputStream::endArray() {
	bool validArray = m_stack.back().state == State::Array;
	m_stack.pop_back();

	if (verbose_debug)
		std::cout << "endArray validArray=" << int(validArray) << " m_stack.back().state="
				  << int(m_stack.back().state) << std::endl;
}

void KVBinaryOutputStream::writeElementPrefix(uint8_t type) {
	if (m_stack.empty()) {
		throw std::logic_error("KVBinaryOutputStream::beginObject unexpected root");
	}

	Level &level = m_stack.back();
	auto &s = stream();

	if (verbose_debug)
		std::cout << "writeElementPrefix level.state=" << int(level.state) << std::endl;
	if (level.state == State::Object) {
		if (!nextKey.isEmpty()) {
			writeElementName(s, nextKey);
			if (type != BIN_KV_SERIALIZE_TYPE_ARRAY)
				s.write(&type, 1);
			nextKey = common::StringView("");
		}
		++level.count;
	}
	if (level.state == State::ArrayPrefix) {
		unsigned char c = BIN_KV_SERIALIZE_FLAG_ARRAY | type;
		s.write(&c, 1);
		writeArraySize(s, level.count);
		if (verbose_tokens)
			std::cout << "ARR t=" << int(type) << " c=" << level.count << std::endl;
		level.state = State::Array;
		if (verbose_debug)
			std::cout << "written BIN_KV_SERIALIZE_FLAG_ARRAY | type level.count=" << int(level.count) << std::endl;
	}
}

common::VectorStream &KVBinaryOutputStream::stream() {
	assert(m_objectsStack.size());
	return m_objectsStack.back();
}

void KVBinaryOutputStream::seria_v(uint8_t &value) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_UINT8);
	writePod(stream(), value);
}

void KVBinaryOutputStream::seria_v(uint16_t &value) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_UINT16);
	writePod(stream(), value);
}

void KVBinaryOutputStream::seria_v(int16_t &value) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_INT16);
	writePod(stream(), value);
}

void KVBinaryOutputStream::seria_v(uint32_t &value) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_UINT32);
	writePod(stream(), value);
}

void KVBinaryOutputStream::seria_v(int32_t &value) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_INT32);
	writePod(stream(), value);
	if (verbose_tokens)
		std::cout << value << std::endl;
}

void KVBinaryOutputStream::seria_v(int64_t &value) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_INT64);
	writePod(stream(), value);
}

void KVBinaryOutputStream::seria_v(uint64_t &value) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_UINT64);
	writePod(stream(), value);
}

void KVBinaryOutputStream::seria_v(bool &value) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_BOOL);
	writePod(stream(), value);
}

void KVBinaryOutputStream::seria_v(double &value) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_DOUBLE);
	writePod(stream(), value);
}

void KVBinaryOutputStream::seria_v(std::string &value) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_STRING);

	auto &out = stream();
	writeArraySize(out, value.size());
	out.write(value.data(), value.size());
	if (verbose_tokens)
		std::cout << "\"" << value << "\"" << std::endl;
}
void KVBinaryOutputStream::seria_v(common::BinaryArray &value) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_STRING);

	auto &out = stream();
	writeArraySize(out, value.size());
	out.write(value.data(), value.size());
}

void KVBinaryOutputStream::binary(void *value, size_t size) {
	writeElementPrefix(BIN_KV_SERIALIZE_TYPE_STRING);
	auto &out = stream();
	writeArraySize(out, size);
	out.write(value, size);
}

