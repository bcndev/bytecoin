// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

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
	common::MemoryInputStream stream(buf.data(), buf.size());
	KVBinaryInputStream s(stream);
	s(v);
}
template<typename T>
void from_binary_key_value(T &v, const std::string &buf) {
	common::MemoryInputStream stream(buf.data(), buf.size());
	KVBinaryInputStream s(stream);
	s(v);
}
}
