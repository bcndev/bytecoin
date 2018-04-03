// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "KVBinaryInputStream.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdexcept>
#include "KVBinaryCommon.hpp"
#include "common/Streams.hpp"

using namespace common;
using namespace bytecoin;
using namespace seria;

namespace {

template<typename T>
T read_pod(common::IInputStream &s) {
	T v;
	s.read(&v, sizeof(T));
	return v;
}

template<typename T, typename JsonT = T>
JsonValue read_pod_json(common::IInputStream &s) {
	JsonValue jv;
	jv = static_cast<JsonT>(read_pod<T>(s));
	return jv;
}

template<typename T>
JsonValue read_integer_json(common::IInputStream &s) {
	return read_pod_json<T, int64_t>(s);
}

size_t read_varint(common::IInputStream &s) {
	uint8_t b         = read<uint8_t>(s);
	uint8_t size_mask = b & PORTABLE_RAW_SIZE_MARK_MASK;
	size_t bytes_left = 0;

	switch (size_mask) {
	case PORTABLE_RAW_SIZE_MARK_BYTE:
		bytes_left = 0;
		break;
	case PORTABLE_RAW_SIZE_MARK_WORD:
		bytes_left = 1;
		break;
	case PORTABLE_RAW_SIZE_MARK_DWORD:
		bytes_left = 3;
		break;
	case PORTABLE_RAW_SIZE_MARK_INT64:
		bytes_left = 7;
		break;
	}

	size_t value = b;

	for (size_t i = 1; i <= bytes_left; ++i) {
		size_t n = read<uint8_t>(s);
		value |= n << (i * 8);
	}

	value >>= 2;
	return value;
}

std::string read_string(common::IInputStream &s) {
	auto size = read_varint(s);
	std::string str;
	common::read(s, str, size);
	return str;
}

JsonValue read_string_json(common::IInputStream &s) { return JsonValue(read_string(s)); }

void read_name(common::IInputStream &s, std::string &name) {
	uint8_t len = read_pod<uint8_t>(s);
	common::read(s, name, len);
}

JsonValue load_value(common::IInputStream &stream, uint8_t type);
JsonValue load_object(common::IInputStream &stream);
JsonValue load_entry(common::IInputStream &stream);
JsonValue load_array(common::IInputStream &stream, uint8_t item_type);

JsonValue load_object(common::IInputStream &stream) {
	JsonValue sec(JsonValue::OBJECT);
	size_t count = read_varint(stream);
	std::string name;

	while (count--) {
		read_name(stream, name);
		sec.insert(name, load_entry(stream));
	}

	return sec;
}

JsonValue load_value(common::IInputStream &stream, uint8_t type) {
	switch (type) {
	case BIN_KV_SERIALIZE_TYPE_INT64:
		return read_integer_json<int64_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_INT32:
		return read_integer_json<int32_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_INT16:
		return read_integer_json<int16_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_INT8:
		return read_integer_json<int8_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_UINT64:
		return read_integer_json<uint64_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_UINT32:
		return read_integer_json<uint32_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_UINT16:
		return read_integer_json<uint16_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_UINT8:
		return read_integer_json<uint8_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_DOUBLE:
		return read_pod_json<double>(stream);  // TODO - double as binary is a BUG
	case BIN_KV_SERIALIZE_TYPE_BOOL:
		return JsonValue(read<uint8_t>(stream) != 0);
	case BIN_KV_SERIALIZE_TYPE_STRING:
		return read_string_json(stream);
	case BIN_KV_SERIALIZE_TYPE_OBJECT:
		return load_object(stream);
	case BIN_KV_SERIALIZE_TYPE_ARRAY:
		return load_array(stream, type);
	default:
		throw std::runtime_error("Unknown data type");
		break;
	}
}

JsonValue load_entry(common::IInputStream &stream) {
	uint8_t type = read_pod<uint8_t>(stream);

	if (type & BIN_KV_SERIALIZE_FLAG_ARRAY) {
		type &= ~BIN_KV_SERIALIZE_FLAG_ARRAY;
		return load_array(stream, type);
	}

	return load_value(stream, type);
}

JsonValue load_array(common::IInputStream &stream, uint8_t item_type) {
	JsonValue arr(JsonValue::ARRAY);
	size_t count = read_varint(stream);

	while (count--) {
		if (item_type == BIN_KV_SERIALIZE_TYPE_ARRAY) {
			uint8_t type = read_pod<uint8_t>(stream);
			if ((type & BIN_KV_SERIALIZE_FLAG_ARRAY) == 0)
				throw std::runtime_error("Incorrect array of array encoding");
			type &= ~BIN_KV_SERIALIZE_FLAG_ARRAY;

			arr.push_back(load_array(stream, type));
		} else
			arr.push_back(load_value(stream, item_type));
	}

	return arr;
}

JsonValue parse_binary(common::IInputStream &stream) {
	auto hdr = read_pod<KVBinaryStorageBlockHeader>(stream);

	if (hdr.m_signature_a != PORTABLE_STORAGE_SIGNATUREA || hdr.m_signature_b != PORTABLE_STORAGE_SIGNATUREB) {
		throw std::runtime_error("Invalid binary storage signature");
	}

	if (hdr.m_ver != PORTABLE_STORAGE_FORMAT_VER) {
		throw std::runtime_error("Unknown binary storage format version");
	}

	return load_object(stream);
}
}

KVBinaryInputStream::KVBinaryInputStream(common::IInputStream &strm) : JsonInputValue(parse_binary(strm)) {}

void KVBinaryInputStream::seria_v(common::BinaryArray &value) {
	std::string str;
	seria_v(str);
	value.assign(str.data(), str.data() + str.size());
}

void KVBinaryInputStream::binary(void *value, size_t size) {
	if (size == 0)
		return;
	std::string str;

	(*this)(str);

	if (str.size() != size) {
		throw std::runtime_error("Binary block size mismatch");
	}

	memcpy(value, str.data(), size);
}
