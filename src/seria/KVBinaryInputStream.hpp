// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <typeinfo>
#include "ISeria.hpp"
#include "JsonInputValue.hpp"
#include "common/MemoryStreams.hpp"

namespace seria {

class KVBinaryInputStream : public JsonInputValue {
public:
	KVBinaryInputStream(common::IInputStream &strm);
	using JsonInputValue::seria_v;
	virtual void seria_v(common::BinaryArray &value) override;
	virtual void binary(void *value, size_t size) override;
};

template<typename T>
void from_binary_key_value(T &v, const common::BinaryArray &buf) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	common::MemoryInputStream stream(buf.data(), buf.size());
	KVBinaryInputStream s(stream);
	s(v);
	if (!stream.empty())
		throw std::runtime_error("Excess data in from_binary_key_value " + std::string(typeid(T).name()));
}
template<typename T>
void from_binary_key_value(T &v, const std::string &buf) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	common::MemoryInputStream stream(buf.data(), buf.size());
	KVBinaryInputStream s(stream);
	s(v);
	if (!stream.empty())
		throw std::runtime_error("Excess data in from_binary_key_value " + std::string(typeid(T).name()));
}
}
