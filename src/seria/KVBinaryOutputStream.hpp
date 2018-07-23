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
	virtual ~KVBinaryOutputStream() {}

	virtual bool is_input() const override { return false; }

	virtual void begin_object() override;
	virtual void object_key(common::StringView name, bool optional = false) override;
	virtual void end_object() override;

	virtual void begin_array(size_t &size, bool fixed_size = false) override;
	virtual void end_array() override;

	virtual void begin_map(size_t &) override { begin_object(); }
	virtual void next_map_key(std::string &name) override;
	virtual void end_map() override { end_object(); }

	virtual void seria_v(uint8_t &value) override;
	virtual void seria_v(int16_t &value) override;
	virtual void seria_v(uint16_t &value) override;
	virtual void seria_v(int32_t &value) override;
	virtual void seria_v(uint32_t &value) override;
	virtual void seria_v(int64_t &value) override;
	virtual void seria_v(uint64_t &value) override;
	virtual void seria_v(double &value) override;
	virtual void seria_v(bool &value) override;
	virtual void seria_v(std::string &value) override;
	virtual void seria_v(common::BinaryArray &value) override;
	virtual void binary(void *value, size_t size) override;

private:
	void write_element_prefix(uint8_t type);

	common::VectorStream &stream();

	enum class State { Root, Object, ArrayPrefix, Array };

	struct Level {
		std::string name;
		State state;
		size_t count;

		Level(common::StringView nm) : name(nm), state(State::Object), count(0) {}
		Level(common::StringView nm, size_t array_size) : name(nm), state(State::ArrayPrefix), count(array_size) {}
		Level(Level &&rv) {
			state = rv.state;
			name  = std::move(rv.name);
			count = rv.count;
		}
	};

	bool m_expecting_root = true;
	common::StringView m_next_key;
	std::vector<common::VectorStream> m_objects_stack;
	std::vector<Level> m_stack;
	common::IOutputStream &m_target;
};

template<typename T>
common::BinaryArray to_binary_key_value(const T &v) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	common::BinaryArray ba;
	common::VectorOutputStream stream(ba);
	KVBinaryOutputStream s(stream);
	s(const_cast<T &>(v));
	return ba;
}
template<typename T>
std::string to_binary_key_value_str(const T &v) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	std::string ba;
	common::StringOutputStream stream(ba);
	KVBinaryOutputStream s(stream);
	s(const_cast<T &>(v));
	return ba;
}
}
