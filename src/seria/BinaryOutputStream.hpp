// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "ISeria.hpp"
#include "common/MemoryStreams.hpp"

namespace seria {

class BinaryOutputStream : public ISeria {
public:
	explicit BinaryOutputStream(common::IOutputStream &strm) : ISeria(false), stream(strm) {}

	bool begin_object() override { return true; }
	void object_key(common::StringView, bool optional) override {}
	void end_object() override {}

	bool begin_array(size_t &size, bool fixed_size) override;
	void end_array() override {}

	bool begin_map(size_t &size) override;
	void next_map_key(std::string &name) override;
	void end_map() override {}

	bool seria_v(int64_t &value) override;
	bool seria_v(uint64_t &value) override;

	bool seria_v(bool &value) override;
	bool seria_v(std::string &value) override;
	bool seria_v(common::BinaryArray &value) override;
	bool binary(void *value, size_t size) override;

private:
	common::IOutputStream &stream;
};

template<typename T, typename... Context>
common::BinaryArray to_binary(const T &obj, Context... context) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	common::BinaryArray result;
	common::VectorOutputStream stream(result);
	BinaryOutputStream ba(stream);
	ser(const_cast<T &>(obj), ba, context...);
	return result;
}
template<typename T, typename... Context>
std::string to_binary_str(const T &obj, Context... context) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	std::string result;
	common::StringOutputStream stream(result);
	BinaryOutputStream ba(stream);
	ser(const_cast<T &>(obj), ba, context...);
	return result;
}
template<typename T, typename... Context>
size_t binary_size(const T &obj, Context... context) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	common::BinaryArray result;
	common::VectorOutputStream stream(result);
	BinaryOutputStream ba(stream);
	ser(const_cast<T &>(obj), ba, context...);
	return result.size();
}
}  // namespace seria
