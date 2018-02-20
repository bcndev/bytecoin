// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include "JsonOutputStream.hpp"
#include <cassert>
#include <stdexcept>
#include "common/StringTools.hpp"

using common::JsonValue;
using namespace seria;

// We do not use optional values yet, all empty strings arrays objects are saved as is

JsonOutputStream::JsonOutputStream() : root(JsonValue::NIL) {}

void JsonOutputStream::object_key(common::StringView name) {
	// TODO - check if m_next_key already exists
	next_key = name;
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
	chain.push_back(insert_or_push(JsonValue(JsonValue::ARRAY), false));  // size == 0
}

void JsonOutputStream::end_array() {
	assert(!chain.empty());
	chain.pop_back();
}

void JsonOutputStream::seria_v(uint64_t &value) { insert_or_push(JsonValue(value), false); }

void JsonOutputStream::seria_v(uint16_t &value) { insert_or_push(JsonValue(JsonValue::Unsigned(value)), false); }

void JsonOutputStream::seria_v(int16_t &value) { insert_or_push(JsonValue(JsonValue::Integer(value)), false); }

void JsonOutputStream::seria_v(uint32_t &value) { insert_or_push(JsonValue(JsonValue::Unsigned(value)), false); }

void JsonOutputStream::seria_v(int32_t &value) { insert_or_push(JsonValue(JsonValue::Integer(value)), false); }

void JsonOutputStream::seria_v(int64_t &value) { insert_or_push(JsonValue(value), false); }

void JsonOutputStream::seria_v(double &value) { insert_or_push(JsonValue(value), false); }

void JsonOutputStream::seria_v(std::string &value) { insert_or_push(JsonValue(value), false); }

void JsonOutputStream::seria_v(common::BinaryArray &value) {
	std::string hex = common::to_hex(value);
	seria_v(hex);
}

void JsonOutputStream::seria_v(uint8_t &value) { insert_or_push(JsonValue(JsonValue::Integer(value)), false); }

void JsonOutputStream::seria_v(bool &value) { insert_or_push(JsonValue(value), false); }

void JsonOutputStream::binary(void *value, size_t size) {
	std::string hex = common::to_hex(value, size);
	bool all_zeroes = hex.find_first_not_of('0') == std::string::npos;
	insert_or_push(all_zeroes ? std::string() : hex, false);
}
