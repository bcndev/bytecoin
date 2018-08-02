// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "KVBinaryOutputStream.hpp"
#include "KVBinaryCommon.hpp"

#include <cassert>
#include <iostream>
#include <stdexcept>
#include "common/Invariant.hpp"
#include "common/Streams.hpp"

using namespace common;
using namespace bytecoin;
using namespace seria;

static bool verbose_debug  = false;
static bool verbose_tokens = false;

namespace {

template<typename T>
void write_pod(IOutputStream &s, const T &value) {
	s.write(&value, sizeof(T));
}

template<class T>
size_t pack_varint(IOutputStream &s, uint8_t type_or, size_t pv) {
	T v = static_cast<T>(pv << 2);
	v |= type_or;
	s.write(&v, sizeof(T));
	return sizeof(T);
}

void write_element_name(IOutputStream &s, common::StringView name) {
	if (name.size() > std::numeric_limits<uint8_t>::max()) {
		throw std::runtime_error("Element name is too long");
	}

	uint8_t len = static_cast<uint8_t>(name.size());
	s.write(&len, sizeof(len));
	s.write(name.data(), len);
	if (verbose_debug)
		std::cout << "write_element_name name=" << (std::string)name << std::endl;
	if (verbose_tokens)
		std::cout << "\"" << (std::string)name << "\"" << std::endl;
}

size_t write_array_size(IOutputStream &s, size_t val) {
	if (val <= 63) {
		return pack_varint<uint8_t>(s, PORTABLE_RAW_SIZE_MARK_BYTE, val);
	} else if (val <= 16383) {
		return pack_varint<uint16_t>(s, PORTABLE_RAW_SIZE_MARK_WORD, val);
	} else if (val <= 1073741823) {
		return pack_varint<uint32_t>(s, PORTABLE_RAW_SIZE_MARK_DWORD, val);
	} else {
		if (val > 4611686018427387903) {
			throw std::runtime_error("failed to pack varint - too big amount");
		}
		return pack_varint<uint64_t>(s, PORTABLE_RAW_SIZE_MARK_INT64, val);
	}
}
}

KVBinaryOutputStream::KVBinaryOutputStream(common::IOutputStream &target) : m_target(target) {
	KVBinaryStorageBlockHeader hdr;
	hdr.m_signature_a = PORTABLE_STORAGE_SIGNATUREA;
	hdr.m_signature_b = PORTABLE_STORAGE_SIGNATUREB;
	hdr.m_ver         = PORTABLE_STORAGE_FORMAT_VER;

	m_target.write(&hdr, sizeof(hdr));
}

void KVBinaryOutputStream::object_key(common::StringView name, bool optional) { m_next_key = name; }
void KVBinaryOutputStream::next_map_key(std::string &name) { m_next_key = name; }

void KVBinaryOutputStream::begin_object() {
	if (m_stack.empty()) {
		invariant(m_expecting_root, "expecting only object");
		m_expecting_root = false;
	} else
		write_element_prefix(BIN_KV_SERIALIZE_TYPE_OBJECT);

	m_stack.push_back(Level(common::StringView("")));
	m_objects_stack.emplace_back();
	if (verbose_debug)
		std::cout << "begin_object m_objects_stack.push_back, m_stack.push_back name=" << std::endl;
}

void KVBinaryOutputStream::end_object() {
	assert(m_objects_stack.size());

	auto level = std::move(m_stack.back());
	m_stack.pop_back();

	auto obj_stream = std::move(m_objects_stack.back());
	m_objects_stack.pop_back();

	IOutputStream &out = m_objects_stack.empty() ? m_target : stream();

	if (verbose_debug)
		std::cout << "end_object TYPE_OBJECT level.count=" << level.count << " level.name=" << (std::string)level.name
		          << std::endl;

	write_array_size(out, level.count);
	out.write(obj_stream.buffer().data(), obj_stream.buffer().size());
	if (verbose_tokens)
		std::cout << "OBJ c=" << level.count << std::endl;
}

void KVBinaryOutputStream::begin_array(size_t &size, bool fixed_size) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_ARRAY);

	m_stack.push_back(Level(common::StringView(""), size));
	if (verbose_debug)
		std::cout << "begin_array size=" << size << std::endl;
	if (size == 0) {
		auto &s = stream();
		unsigned char c =
		    BIN_KV_SERIALIZE_FLAG_ARRAY | BIN_KV_SERIALIZE_TYPE_STRING;  // we do not care which type is empty array
		s.write(&c, 1);
		write_array_size(s, size);
		m_stack.back().state = State::Array;
		if (verbose_tokens)
			std::cout << "ARR t=" << int(BIN_KV_SERIALIZE_TYPE_OBJECT) << " c=" << size << std::endl;
	}
}

void KVBinaryOutputStream::end_array() {
	bool valid_array = m_stack.back().state == State::Array;
	m_stack.pop_back();

	if (verbose_debug)
		std::cout << "end_array valid_array=" << int(valid_array)
		          << " m_stack.back().state=" << int(m_stack.back().state) << std::endl;
}

void KVBinaryOutputStream::write_element_prefix(uint8_t type) {
	invariant(!m_stack.empty(), "unexpected root");

	Level &level = m_stack.back();
	auto &s      = stream();

	if (verbose_debug)
		std::cout << "write_element_prefix level.state=" << int(level.state) << std::endl;
	if (level.state == State::Object) {
		if (!m_next_key.empty()) {
			write_element_name(s, m_next_key);
			if (type != BIN_KV_SERIALIZE_TYPE_ARRAY)
				s.write(&type, 1);
			m_next_key = common::StringView("");
		}
		++level.count;
	}
	if (level.state == State::ArrayPrefix) {
		unsigned char c = BIN_KV_SERIALIZE_FLAG_ARRAY | type;
		s.write(&c, 1);
		write_array_size(s, level.count);
		if (verbose_tokens)
			std::cout << "ARR t=" << int(type) << " c=" << level.count << std::endl;
		level.state = State::Array;
		if (verbose_debug)
			std::cout << "written BIN_KV_SERIALIZE_FLAG_ARRAY | type level.count=" << int(level.count) << std::endl;
	}
}

common::VectorStream &KVBinaryOutputStream::stream() {
	assert(m_objects_stack.size());
	return m_objects_stack.back();
}

void KVBinaryOutputStream::seria_v(uint8_t &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_UINT8);
	write_pod(stream(), value);
}

void KVBinaryOutputStream::seria_v(uint16_t &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_UINT16);
	write_pod(stream(), value);
}

void KVBinaryOutputStream::seria_v(int16_t &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_INT16);
	write_pod(stream(), value);
}

void KVBinaryOutputStream::seria_v(uint32_t &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_UINT32);
	write_pod(stream(), value);
}

void KVBinaryOutputStream::seria_v(int32_t &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_INT32);
	write_pod(stream(), value);
	if (verbose_tokens)
		std::cout << value << std::endl;
}

void KVBinaryOutputStream::seria_v(int64_t &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_INT64);
	write_pod(stream(), value);
}

void KVBinaryOutputStream::seria_v(uint64_t &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_UINT64);
	write_pod(stream(), value);
}

void KVBinaryOutputStream::seria_v(bool &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_BOOL);
	write_pod(stream(), value);
}

void KVBinaryOutputStream::seria_v(double &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_DOUBLE);
	write_pod(stream(), value);
}

void KVBinaryOutputStream::seria_v(std::string &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_STRING);

	auto &out = stream();
	write_array_size(out, value.size());
	out.write(value.data(), value.size());
	if (verbose_tokens)
		std::cout << "\"" << value << "\"" << std::endl;
}
void KVBinaryOutputStream::seria_v(common::BinaryArray &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_STRING);

	auto &out = stream();
	write_array_size(out, value.size());
	out.write(value.data(), value.size());
}

void KVBinaryOutputStream::binary(void *value, size_t size) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_STRING);
	auto &out = stream();
	write_array_size(out, size);
	out.write(value, size);
}
