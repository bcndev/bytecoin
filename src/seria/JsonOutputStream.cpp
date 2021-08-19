// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "JsonOutputStream.hpp"
#include <cassert>
#include <stdexcept>
#include "common/Invariant.hpp"
#include "common/StringTools.hpp"

using common::JsonValue;
using namespace seria;

// We do not use optional values yet, all empty strings arrays objects are saved as is

JsonOutputStreamValue::JsonOutputStreamValue() : root(JsonValue::NIL) {}

void JsonOutputStreamValue::object_key(common::StringView name, bool optional) {
	invariant(!m_next_key.data(), "");
	m_next_key    = name;
	next_optional = optional;
}

void JsonOutputStreamValue::next_map_key(std::string &name) {
	invariant(!m_next_key.data(), "");
	m_next_key = name;
}

bool JsonOutputStreamValue::begin_object() {
	chain.push_back(insert_or_push(JsonValue(JsonValue::OBJECT), false));
	return true;
}

void JsonOutputStreamValue::end_object() {
	invariant(!chain.empty(), "");
	chain.pop_back();
}

bool JsonOutputStreamValue::begin_array(size_t &size, bool fixed_size) {
	chain.push_back(insert_or_push(JsonValue(JsonValue::ARRAY), size == 0));
	return true;
}

void JsonOutputStreamValue::end_array() {
	invariant(!chain.empty(), "");
	chain.pop_back();
}

bool JsonOutputStreamValue::seria_v(uint64_t &value) {
	insert_or_push(numbers_as_strings ? JsonValue(common::to_string(value)) : JsonValue(value), value == 0);
	return true;
}

bool JsonOutputStreamValue::seria_v(int64_t &value) {
	insert_or_push(numbers_as_strings ? JsonValue(common::to_string(value)) : JsonValue(value), value == 0);
	return true;
}

bool JsonOutputStreamValue::seria_v(std::string &value) {
	insert_or_push(JsonValue(value), value.empty());
	return true;
}

bool JsonOutputStreamValue::seria_v(common::BinaryArray &value) {
	std::string hex = common::to_hex(value);
	seria_v(hex);
	return true;
}

bool JsonOutputStreamValue::seria_v(bool &value) {
	insert_or_push(JsonValue(value), !value);
	return true;
}

bool JsonOutputStreamValue::binary(void *value, size_t size) {
	std::string hex = common::to_hex(value, size);
	bool all_zeroes = hex.find_first_not_of('0') == std::string::npos;
	insert_or_push(all_zeroes ? std::string{} : hex, all_zeroes);
	return true;
}

common::JsonValue *JsonOutputStreamValue::insert_or_push(const common::JsonValue &value, bool skip_if_optional) {
	if (chain.empty()) {
		invariant(expecting_root, "unexpected root");
		root           = common::JsonValue(value);
		expecting_root = false;
		return &root;
	}
	auto js = chain.back();
	if (js->is_array()) {
		return &js->push_back(value);
	}
	if (js->is_object()) {
		invariant(m_next_key.data(), "");
		common::StringView key = m_next_key;
		m_next_key             = common::StringView();
		if (skip_if_optional && next_optional)
			return nullptr;
		return &js->insert(static_cast<std::string>(key), value);
	}
	throw std::logic_error("can only insert into object array or root");
}

bool JsonOutputStreamText::append_prefix(const std::string &value, bool skip_if_optional) {
	if (chain.empty()) {
		invariant(expecting_root, "unexpected root");
		expecting_root = false;
		text += value;
		return true;
	}
	if (chain.back().first == JsonValue::ARRAY) {
		if (chain.back().second != 0)
			text += ",";
		chain.back().second += 1;
		text += value;
		return true;
	}
	invariant(m_next_key.data(), "");
	common::StringView key = m_next_key;
	m_next_key             = common::StringView();
	if (skip_if_optional && next_optional)
		return false;
	if (chain.back().second != 0)
		text += ",";
	chain.back().second += 1;
	text += "\"";
	text += JsonValue::escape_string(std::string(key.begin(), key.end()));
	text += "\":";
	text += value;
	return true;
}

void JsonOutputStreamText::object_key(common::StringView name, bool optional) {
	invariant(!m_next_key.data(), "");
	m_next_key    = name;
	next_optional = optional;
}

void JsonOutputStreamText::next_map_key(std::string &name) {
	invariant(!m_next_key.data(), "");
	m_next_key = name;
}

bool JsonOutputStreamText::begin_object() {
	if (!append_prefix("{", false))
		return true;
	chain.push_back(std::make_pair(JsonValue::OBJECT, 0));
	return true;
}

void JsonOutputStreamText::end_object() {
	invariant(!chain.empty() && chain.back().first == JsonValue::OBJECT, "");
	text += "}";
	chain.pop_back();
}

bool JsonOutputStreamText::begin_array(size_t &size, bool fixed_size) {
	if (!append_prefix(std::string{}, size == 0)) {
		chain.push_back(std::make_pair(JsonValue::NIL, 0));  // NIL to mark empty optional array
		return true;
	}
	text += "[";
	chain.push_back(std::make_pair(JsonValue::ARRAY, 0));
	return true;
}

void JsonOutputStreamText::end_array() {
	invariant(!chain.empty() && (chain.back().first == JsonValue::ARRAY || chain.back().first == JsonValue::NIL), "");
	if (chain.back().first == JsonValue::ARRAY)
		text += "]";
	chain.pop_back();
}

bool JsonOutputStreamText::seria_v(uint64_t &value) {
	if (numbers_as_strings)
		append_prefix("\"" + common::to_string(value) + "\"", value == 0);
	else
		append_prefix(common::to_string(value), value == 0);
	return true;
}

bool JsonOutputStreamText::seria_v(int64_t &value) {
	if (numbers_as_strings)
		append_prefix("\"" + common::to_string(value) + "\"", value == 0);
	else
		append_prefix(common::to_string(value), value == 0);
	return true;
}

bool JsonOutputStreamText::seria_v(std::string &value) {
	if (!append_prefix("\"", value.empty()))
		return true;
	text += JsonValue::escape_string(value);
	text += "\"";
	return true;
}

bool JsonOutputStreamText::seria_v(common::BinaryArray &value) {
	std::string hex = common::to_hex(value);
	return seria_v(hex);
}

bool JsonOutputStreamText::seria_v(bool &value) {
	append_prefix(value ? "true" : "false", !value);
	return true;
}

bool JsonOutputStreamText::binary(void *value, size_t size) {
	std::string hex = common::to_hex(value, size);
	bool all_zeroes = hex.find_first_not_of('0') == std::string::npos;
	if (!append_prefix("\"", all_zeroes))
		return true;
	text += all_zeroes ? std::string{} : hex;
	text += "\"";
	return true;
}
