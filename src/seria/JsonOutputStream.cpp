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

JsonOutputStream::JsonOutputStream() : root(JsonValue::NIL) {}

void JsonOutputStream::object_key(common::StringView name, bool optional) {
	// TODO - check if m_next_key already exists
	next_key      = name;
	next_optional = optional;
}

void JsonOutputStream::next_map_key(std::string &name) {
	// TODO - check if m_next_key already exists
	next_key = name;
}

void JsonOutputStream::begin_object() { chain.push_back(insert_or_push(JsonValue(JsonValue::OBJECT), false)); }

void JsonOutputStream::end_object() {
	assert(!chain.empty());
	chain.pop_back();
}

void JsonOutputStream::begin_array(size_t &size, bool fixed_size) {
	chain.push_back(insert_or_push(JsonValue(JsonValue::ARRAY), size == 0));
}

void JsonOutputStream::end_array() {
	assert(!chain.empty());
	chain.pop_back();
}

void JsonOutputStream::seria_v(uint64_t &value) { insert_or_push(JsonValue(value), value == 0); }

void JsonOutputStream::seria_v(uint16_t &value) { insert_or_push(JsonValue(JsonValue::Unsigned(value)), value == 0); }

void JsonOutputStream::seria_v(int16_t &value) { insert_or_push(JsonValue(JsonValue::Integer(value)), value == 0); }

void JsonOutputStream::seria_v(uint32_t &value) { insert_or_push(JsonValue(JsonValue::Unsigned(value)), value == 0); }

void JsonOutputStream::seria_v(int32_t &value) { insert_or_push(JsonValue(JsonValue::Integer(value)), value == 0); }

void JsonOutputStream::seria_v(int64_t &value) { insert_or_push(JsonValue(value), value == 0); }

void JsonOutputStream::seria_v(double &value) { insert_or_push(JsonValue(value), value == 0); }

void JsonOutputStream::seria_v(std::string &value) { insert_or_push(JsonValue(value), value.empty()); }

void JsonOutputStream::seria_v(common::BinaryArray &value) {
	std::string hex = common::to_hex(value);
	seria_v(hex);
}

void JsonOutputStream::seria_v(uint8_t &value) { insert_or_push(JsonValue(JsonValue::Integer(value)), value == 0); }

void JsonOutputStream::seria_v(bool &value) { insert_or_push(JsonValue(value), !value); }

void JsonOutputStream::binary(void *value, size_t size) {
	std::string hex = common::to_hex(value, size);
	bool all_zeroes = hex.find_first_not_of('0') == std::string::npos;
	insert_or_push(all_zeroes ? std::string() : hex, all_zeroes);
}

common::JsonValue *JsonOutputStream::insert_or_push(const common::JsonValue &value, bool skip_if_optional) {
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
		common::StringView key = next_key;
		next_key               = common::StringView("");
		if (skip_if_optional && next_optional)
			return nullptr;
		return &js->insert((std::string)key, value);
	}
	invariant(false, "can only insert into object array or root");
	return nullptr;  // invariant Will always throw, but compiler does not know it
}
