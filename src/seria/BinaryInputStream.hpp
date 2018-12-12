// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "ISeria.hpp"
#include "common/MemoryStreams.hpp"
#include "common/exception.hpp"

namespace seria {

class BinaryInputStream : public ISeria {
public:
	explicit BinaryInputStream(common::IInputStream &strm) : stream(strm) {}

	bool is_input() const override { return true; }

	void begin_object() override {}
	bool object_key(common::StringView, bool optional) override { return true; }
	void end_object() override {}

	void begin_map(size_t &size) override;
	void next_map_key(std::string &name) override;
	void end_map() override {}

	void begin_array(size_t &size, bool fixed_size) override;
	void end_array() override {}

	void seria_v(uint8_t &value) override;
	void seria_v(int16_t &value) override;
	void seria_v(uint16_t &value) override;
	void seria_v(int32_t &value) override;
	void seria_v(uint32_t &value) override;
	void seria_v(int64_t &value) override;
	void seria_v(uint64_t &value) override;
	//	void seria_v(double &value) override;
	void seria_v(bool &value) override;
	bool seria_v(std::string &value) override;
	bool seria_v(common::BinaryArray &value) override;
	bool binary(void *value, size_t size) override;

private:
	common::IInputStream &stream;
};

template<typename T, typename... Context>
void from_binary(T &obj, common::MemoryInputStream &stream, Context... context) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	BinaryInputStream ba(stream);
	try {
		ser(obj, ba, context...);
	} catch (const std::exception &) {
		std::throw_with_nested(std::runtime_error(
		    "Error while serializing binary object of type '" + common::demangle(typeid(T).name()) + "'"));
	}
	if (!stream.empty())
		throw std::runtime_error(
		    "Excess data after serializing binary object of type '" + common::demangle(typeid(T).name()) + "'");
}
template<typename T, typename... Context>
void from_binary(T &obj, const common::BinaryArray &blob, Context... context) {
	common::MemoryInputStream stream(blob.data(), blob.size());
	from_binary(obj, stream, context...);
}
template<typename T, typename... Context>
void from_binary(T &obj, const std::string &blob, Context... context) {
	common::MemoryInputStream stream(blob.data(), blob.size());
	from_binary(obj, stream, context...);
}
}  // namespace seria
