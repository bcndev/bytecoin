// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <iostream>
#include "ISeria.hpp"
#include "common/JsonValue.hpp"

namespace seria {

class JsonOutputStream : public ISeria {};  // Common base for use with dynamic_cast in ser() methods

class JsonOutputStreamValue : public JsonOutputStream {
public:
	JsonOutputStreamValue();

	bool is_input() const override { return false; }

	void begin_object() override;
	bool object_key(common::StringView name, bool optional) override;
	void end_object() override;

	void begin_map(size_t &) override { begin_object(); }
	void next_map_key(std::string &name) override;
	void end_map() override { end_object(); }

	void begin_array(size_t &size, bool fixed_size) override;
	void end_array() override;

	void seria_v(uint8_t &value) override;
	void seria_v(int16_t &value) override;
	void seria_v(uint16_t &value) override;
	void seria_v(int32_t &value) override;
	void seria_v(uint32_t &value) override;
	void seria_v(int64_t &value) override;
	void seria_v(uint64_t &value) override;
	// void seria_v(double &value) override;
	void seria_v(bool &value) override;
	bool seria_v(std::string &value) override;
	bool seria_v(common::BinaryArray &value) override;
	bool binary(void *value, size_t size) override;

	common::JsonValue move_value() { return std::move(root); }

private:
	bool expecting_root = true;
	common::StringView next_key;
	bool next_optional = false;
	common::JsonValue root;
	std::vector<common::JsonValue *> chain;

	common::JsonValue *insert_or_push(const common::JsonValue &value, bool skip_if_optional);
};

class JsonOutputStreamText : public JsonOutputStream {
public:
	explicit JsonOutputStreamText(std::string &text) : text(text) {}

	bool is_input() const override { return false; }

	void begin_object() override;
	bool object_key(common::StringView name, bool optional) override;
	void end_object() override;

	void begin_map(size_t &) override { begin_object(); }
	void next_map_key(std::string &name) override;
	void end_map() override { end_object(); }

	void begin_array(size_t &size, bool fixed_size) override;
	void end_array() override;

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
	bool expecting_root = true;
	common::StringView next_key;
	bool next_optional = false;
	std::string &text;
	std::vector<std::pair<common::JsonValue::Type, int>>
	    chain;  // object, array or null (for empty array) only + count of elements
	bool append_prefix(const std::string &value, bool skip_if_optional);
};

template<typename T, typename... Context>
common::JsonValue to_json_value(const T &v, Context... context) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	JsonOutputStreamValue s;
	ser(const_cast<T &>(v), s, context...);
	return s.move_value();
}
}  // namespace seria
