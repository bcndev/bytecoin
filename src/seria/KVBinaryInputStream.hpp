// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "ISeria.hpp"
#include "JsonInputStream.hpp"
#include "common/MemoryStreams.hpp"
#include "common/exception.hpp"

namespace seria {

class KVBinaryInputStream : public JsonInputStreamValue {
	common::JsonValue value_storage;

public:
	explicit KVBinaryInputStream(common::IInputStream &strm);
	using JsonInputStreamValue::seria_v;
	bool seria_v(common::BinaryArray &value) override;
	bool binary(void *value, size_t size) override;
};

template<typename T>
void from_binary_kv(T &v, common::MemoryInputStream &stream) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	KVBinaryInputStream s(stream);
	try {
		ser(v, s);
	} catch (const std::exception &) {
		std::throw_with_nested(std::runtime_error(
		    "Error while serializing KV binary object of type '" + common::demangle(typeid(T).name()) + "'"));
	}
	if (!stream.empty())
		throw std::runtime_error(
		    "Excess data after serializing KV binary object of type '" + common::demangle(typeid(T).name()) + "'");
}
template<typename T>
void from_binary_kv(T &v, const common::BinaryArray &buf) {
	common::MemoryInputStream stream(buf.data(), buf.size());
	from_binary_kv(v, stream);
}
template<typename T>
void from_binary_kv(T &v, const std::string &buf) {
	common::MemoryInputStream stream(buf.data(), buf.size());
	from_binary_kv(v, stream);
}
}  // namespace seria
