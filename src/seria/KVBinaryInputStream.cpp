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
T readPod(common::IInputStream &s) {
	T v;
	s.read(&v, sizeof(T));
	return v;
}

template<typename T, typename JsonT = T>
JsonValue readPodJson(common::IInputStream &s) {
	JsonValue jv;
	jv = static_cast<JsonT>(readPod<T>(s));
	return jv;
}

template<typename T>
JsonValue readIntegerJson(common::IInputStream &s) {
	return readPodJson<T, int64_t>(s);
}

size_t read_varint(common::IInputStream &s) {
	uint8_t b         = read<uint8_t>(s);
	uint8_t size_mask = b & PORTABLE_RAW_SIZE_MARK_MASK;
	size_t bytesLeft  = 0;

	switch (size_mask) {
	case PORTABLE_RAW_SIZE_MARK_BYTE:
		bytesLeft = 0;
		break;
	case PORTABLE_RAW_SIZE_MARK_WORD:
		bytesLeft = 1;
		break;
	case PORTABLE_RAW_SIZE_MARK_DWORD:
		bytesLeft = 3;
		break;
	case PORTABLE_RAW_SIZE_MARK_INT64:
		bytesLeft = 7;
		break;
	}

	size_t value = b;

	for (size_t i = 1; i <= bytesLeft; ++i) {
		size_t n = read<uint8_t>(s);
		value |= n << (i * 8);
	}

	value >>= 2;
	return value;
}

std::string readString(common::IInputStream &s) {
	auto size = read_varint(s);
	std::string str;
	common::read(s, str, size);
	return str;
}

JsonValue readStringJson(common::IInputStream &s) { return JsonValue(readString(s)); }

void readName(common::IInputStream &s, std::string &name) {
	uint8_t len = readPod<uint8_t>(s);
	common::read(s, name, len);
}

JsonValue loadValue(common::IInputStream &stream, uint8_t type);
JsonValue loadObject(common::IInputStream &stream);
JsonValue loadEntry(common::IInputStream &stream);
JsonValue loadArray(common::IInputStream &stream, uint8_t itemType);

JsonValue loadObject(common::IInputStream &stream) {
	JsonValue sec(JsonValue::OBJECT);
	size_t count = read_varint(stream);
	std::string name;

	while (count--) {
		readName(stream, name);
		sec.insert(name, loadEntry(stream));
	}

	return sec;
}

JsonValue loadValue(common::IInputStream &stream, uint8_t type) {
	switch (type) {
	case BIN_KV_SERIALIZE_TYPE_INT64:
		return readIntegerJson<int64_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_INT32:
		return readIntegerJson<int32_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_INT16:
		return readIntegerJson<int16_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_INT8:
		return readIntegerJson<int8_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_UINT64:
		return readIntegerJson<uint64_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_UINT32:
		return readIntegerJson<uint32_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_UINT16:
		return readIntegerJson<uint16_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_UINT8:
		return readIntegerJson<uint8_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_DOUBLE:
		return readPodJson<double>(stream);
	case BIN_KV_SERIALIZE_TYPE_BOOL:
		return JsonValue(read<uint8_t>(stream) != 0);
	case BIN_KV_SERIALIZE_TYPE_STRING:
		return readStringJson(stream);
	case BIN_KV_SERIALIZE_TYPE_OBJECT:
		return loadObject(stream);
	case BIN_KV_SERIALIZE_TYPE_ARRAY:
		return loadArray(stream, type);
	default:
		throw std::runtime_error("Unknown data type");
		break;
	}
}

JsonValue loadEntry(common::IInputStream &stream) {
	uint8_t type = readPod<uint8_t>(stream);

	if (type & BIN_KV_SERIALIZE_FLAG_ARRAY) {
		type &= ~BIN_KV_SERIALIZE_FLAG_ARRAY;
		return loadArray(stream, type);
	}

	return loadValue(stream, type);
}

JsonValue loadArray(common::IInputStream &stream, uint8_t itemType) {
	JsonValue arr(JsonValue::ARRAY);
	size_t count = read_varint(stream);

	while (count--) {
		if (itemType == BIN_KV_SERIALIZE_TYPE_ARRAY) {
			uint8_t type = readPod<uint8_t>(stream);
			if ((type & BIN_KV_SERIALIZE_FLAG_ARRAY) == 0)
				throw std::runtime_error("Incorrect array of array encoding");
			type &= ~BIN_KV_SERIALIZE_FLAG_ARRAY;

			arr.push_back(loadArray(stream, type));
		} else
			arr.push_back(loadValue(stream, itemType));
	}

	return arr;
}

JsonValue parseBinary(common::IInputStream &stream) {
	auto hdr = readPod<KVBinaryStorageBlockHeader>(stream);

	if (hdr.m_signature_a != PORTABLE_STORAGE_SIGNATUREA || hdr.m_signature_b != PORTABLE_STORAGE_SIGNATUREB) {
		throw std::runtime_error("Invalid binary storage signature");
	}

	if (hdr.m_ver != PORTABLE_STORAGE_FORMAT_VER) {
		throw std::runtime_error("Unknown binary storage format version");
	}

	return loadObject(stream);
}
}

KVBinaryInputStream::KVBinaryInputStream(common::IInputStream &strm) : JsonInputValue(parseBinary(strm)) {}

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
