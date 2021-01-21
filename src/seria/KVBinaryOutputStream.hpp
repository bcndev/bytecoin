// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <vector>
#include "ISeria.hpp"
#include "common/MemoryStreams.hpp"

namespace seria {

class KVBinaryOutputStream : public ISeria {
public:
	explicit KVBinaryOutputStream(common::IOutputStream &target);

	bool begin_object() override;
	void object_key(common::StringView name, bool optional) override;
	void end_object() override;

	bool begin_array(size_t &size, bool fixed_size) override;
	void end_array() override;

	bool begin_map(size_t &) override { return begin_object(); }
	void next_map_key(std::string &name) override;
	void end_map() override { end_object(); }

	bool seria_v(int64_t &value) override;
	bool seria_v(uint64_t &value) override;

	bool seria_v(bool &value) override;
	bool seria_v(std::string &value) override;
	bool seria_v(common::BinaryArray &value) override;
	bool binary(void *value, size_t size) override;

private:
	void write_element_prefix(uint8_t type);

	common::VectorStream &stream();

	enum class State { Object, ArrayPrefix, Array };

	struct Level {
		std::string name;
		State state;
		size_t count       = 0;
		uint8_t array_type = 0;

		explicit Level(common::StringView nm) : name(nm), state(State::Object), count(0) {}
		Level(common::StringView nm, size_t array_size) : name(nm), state(State::ArrayPrefix), count(array_size) {}
	};

	bool m_expecting_root = true;
	common::StringView m_next_key;
	std::vector<common::VectorStream> m_objects_stack;
	std::vector<Level> m_stack;
	common::IOutputStream &m_target;
};

template<typename T>
common::BinaryArray to_binary_kv(const T &v) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	common::BinaryArray ba;
	common::VectorOutputStream stream(ba);
	KVBinaryOutputStream s(stream);
	ser(const_cast<T &>(v), s);
	return ba;
}
template<typename T>
std::string to_binary_kv_str(const T &v) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	std::string ba;
	common::StringOutputStream stream(ba);
	KVBinaryOutputStream s(stream);
	ser(const_cast<T &>(v), s);
	return ba;
}
}  // namespace seria
