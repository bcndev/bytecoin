// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "KVBinaryOutputStream.hpp"
#include "KVBinaryCommon.hpp"

#include <cassert>
#include <iostream>
#include <stdexcept>
#include "common/Invariant.hpp"
#include "common/Streams.hpp"
#include "common/Varint.hpp"

using namespace common;
using namespace cn;
using namespace seria;

static const bool verbose_debug  = false;
static const bool verbose_tokens = false;

namespace {

template<typename T>
void write_pod(IOutputStream &s, const T &value) {
	unsigned char buf[sizeof(T)];
	common::uint_le_to_bytes(buf, sizeof(T), static_cast<typename std::make_unsigned<T>::type>(value));
	s.write(buf, sizeof(T));
}

template<class T>
size_t pack_varint(IOutputStream &s, uint8_t type_or, size_t pv) {
	auto v = static_cast<T>(pv << 2U);
	v |= type_or;
	write_pod(s, v);
	return sizeof(T);
}

void write_element_name(IOutputStream &s, common::StringView name) {
	if (name.size() > 255)
		throw std::runtime_error("Element name is too long");
	// When this happens first time (probably inside begin_map/end_map)
	// We will have to add new BIN_KV_SERIALIZE_TYPE_OBJECT2 format with
	// key length written like write_array_size. Unfortunately we have
	// no way to make this long keys compatible with old format
	auto len = static_cast<uint8_t>(name.size());
	s.write(&len, sizeof(len));
	s.write(name.data(), len);
	if (verbose_debug)
		std::cout << "write_element_name name=" << (std::string)name << std::endl;
	if (verbose_tokens)
		std::cout << "\"" << (std::string)name << "\"" << std::endl;
}

size_t write_array_size(IOutputStream &s, size_t val) {
	if (val <= 63)
		return pack_varint<uint8_t>(s, PORTABLE_RAW_SIZE_MARK_BYTE, val);
	if (val <= 16383)
		return pack_varint<uint16_t>(s, PORTABLE_RAW_SIZE_MARK_WORD, val);
	if (val <= 1073741823)
		return pack_varint<uint32_t>(s, PORTABLE_RAW_SIZE_MARK_DWORD, val);
	if (static_cast<uint64_t>(val) > 4611686018427387903)  // Upcast to prevent warning here on 32-bit platforms
		throw std::runtime_error("failed to pack varint - too big amount");
	return pack_varint<uint64_t>(s, PORTABLE_RAW_SIZE_MARK_INT64, val);
}

}  // namespace

KVBinaryOutputStream::KVBinaryOutputStream(common::IOutputStream &target) : ISeria(false), m_target(target) {
	KVBinaryStorageBlockHeader hdr{
	    PORTABLE_STORAGE_SIGNATUREA, PORTABLE_STORAGE_SIGNATUREB, PORTABLE_STORAGE_FORMAT_VER};
	write_pod(m_target, hdr.m_signature_a);
	write_pod(m_target, hdr.m_signature_b);
	m_target.write(&hdr.m_ver, 1);
}

void KVBinaryOutputStream::object_key(common::StringView name, bool optional) {
	invariant(!m_next_key.data(), "");
	m_next_key = name;
}
void KVBinaryOutputStream::next_map_key(std::string &name) { m_next_key = name; }

bool KVBinaryOutputStream::begin_object() {
	if (m_stack.empty()) {
		invariant(m_expecting_root, "expecting only object");
		m_expecting_root = false;
	} else
		write_element_prefix(BIN_KV_SERIALIZE_TYPE_OBJECT);

	m_stack.push_back(Level(common::StringView("")));
	m_objects_stack.emplace_back();
	if (verbose_debug)
		std::cout << "begin_object m_objects_stack.push_back, m_stack.push_back name=" << std::endl;
	return true;
}

void KVBinaryOutputStream::end_object() {
	invariant(!m_objects_stack.empty(), "");

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

bool KVBinaryOutputStream::begin_array(size_t &size, bool fixed_size) {
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
		// array_type is zero, so adding any element will lead to "Array elements types are non-uniform" logic error
		if (verbose_tokens)
			std::cout << "ARR t=" << int(BIN_KV_SERIALIZE_TYPE_STRING) << " c=" << size << std::endl;
	}
	return true;
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
		invariant(m_next_key.data(), "");
		write_element_name(s, m_next_key);
		if (type != BIN_KV_SERIALIZE_TYPE_ARRAY)
			s.write(&type, 1);
		m_next_key = common::StringView();
		++level.count;
	}
	if (level.state == State::ArrayPrefix) {
		//		if(type == BIN_KV_SERIALIZE_TYPE_INT64 || type == BIN_KV_SERIALIZE_TYPE_UINT64)
		//			std::cout << "Breakpoint" << std::endl;
		unsigned char c = BIN_KV_SERIALIZE_FLAG_ARRAY | type;
		s.write(&c, 1);
		write_array_size(s, level.count);
		if (verbose_tokens)
			std::cout << "ARR t=" << int(type) << " c=" << level.count << std::endl;
		level.state      = State::Array;
		level.array_type = type;
		if (verbose_debug)
			std::cout << "written BIN_KV_SERIALIZE_FLAG_ARRAY | type level.count=" << int(level.count) << std::endl;
	}
	if (level.state == State::Array && level.array_type != type)
		throw std::logic_error("Array elements types are non-uniform");
}

common::VectorStream &KVBinaryOutputStream::stream() {
	invariant(!m_objects_stack.empty(), "");
	return m_objects_stack.back();
}

// TODO - select array/value type on min/max written values

/*void KVBinaryOutputStream::seria_v(uint8_t &value) {
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
}*/

bool KVBinaryOutputStream::seria_v(int64_t &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_INT64);
	write_pod(stream(), value);
	return true;
}

bool KVBinaryOutputStream::seria_v(uint64_t &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_UINT64);
	write_pod(stream(), value);
	return true;
}

bool KVBinaryOutputStream::seria_v(bool &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_BOOL);
	write_pod(stream(), uint8_t(value));
	return true;
}

// void KVBinaryOutputStream::seria_v(double &value) {
//	throw std::logic_error("double serialization is not supported in KVBinaryOutputStream");
//	write_element_prefix(BIN_KV_SERIALIZE_TYPE_DOUBLE);
//	stream().write(&value, sizeof(double)); // TODO - double in binary is bug
//}

bool KVBinaryOutputStream::seria_v(std::string &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_STRING);

	auto &out = stream();
	write_array_size(out, value.size());
	out.write(value.data(), value.size());
	if (verbose_tokens)
		std::cout << "\"" << value << "\"" << std::endl;
	return true;
}

bool KVBinaryOutputStream::seria_v(common::BinaryArray &value) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_STRING);

	auto &out = stream();
	write_array_size(out, value.size());
	out.write(value.data(), value.size());
	return true;
}

bool KVBinaryOutputStream::binary(void *value, size_t size) {
	write_element_prefix(BIN_KV_SERIALIZE_TYPE_STRING);
	auto &out = stream();
	write_array_size(out, size);
	out.write(value, size);
	return true;
}
