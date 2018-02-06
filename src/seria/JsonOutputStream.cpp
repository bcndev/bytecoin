// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#include "JsonOutputStream.hpp"
#include <cassert>
#include <stdexcept>
#include "common/StringTools.hpp"

using common::JsonValue;
using namespace seria;

// We do not use optional values yet, all empty strings arrays objects are saved as is

JsonOutputStream::JsonOutputStream() : root(JsonValue::NIL) {
}

void JsonOutputStream::objectKey(common::StringView name) {
	// TODO - check if nextKey already exists
	nextKey = name;
}

void JsonOutputStream::nextMapKey(std::string &name) {
	// TODO - check if nextKey already exists
	nextKey = name;
}

void JsonOutputStream::beginObject() {
	chain.push_back(insertOrPush(JsonValue(JsonValue::OBJECT), false));
}

void JsonOutputStream::endObject() {
	assert(!chain.empty());
	chain.pop_back();
}

void JsonOutputStream::beginArray(size_t &size, bool fixed_size) {
	chain.push_back(insertOrPush(JsonValue(JsonValue::ARRAY), false)); // size == 0
}

void JsonOutputStream::endArray() {
	assert(!chain.empty());
	chain.pop_back();
}

void JsonOutputStream::seria_v(uint64_t &value) {
	insertOrPush(JsonValue(value), false);
}

void JsonOutputStream::seria_v(uint16_t &value) {
	insertOrPush(JsonValue(JsonValue::Unsigned(value)), false);
}

void JsonOutputStream::seria_v(int16_t &value) {
	insertOrPush(JsonValue(JsonValue::Integer(value)), false);
}

void JsonOutputStream::seria_v(uint32_t &value) {
	insertOrPush(JsonValue(JsonValue::Unsigned(value)), false);
}

void JsonOutputStream::seria_v(int32_t &value) {
	insertOrPush(JsonValue(JsonValue::Integer(value)), false);
}

void JsonOutputStream::seria_v(int64_t &value) {
	insertOrPush(JsonValue(value), false);
}

void JsonOutputStream::seria_v(double &value) {
	insertOrPush(JsonValue(value), false);
}

void JsonOutputStream::seria_v(std::string &value) {
	insertOrPush(JsonValue(value), false);
}

void JsonOutputStream::seria_v(common::BinaryArray &value) {
	std::string hex = common::to_hex(value);
	seria_v(hex);
}

void JsonOutputStream::seria_v(uint8_t &value) {
	insertOrPush(JsonValue(JsonValue::Integer(value)), false);
}

void JsonOutputStream::seria_v(bool &value) {
	insertOrPush(JsonValue(value), false);
}

void JsonOutputStream::binary(void *value, size_t size) {
	std::string hex = common::to_hex(value, size);
	bool all_zeroes = hex.find_first_not_of('0') == std::string::npos;
	insertOrPush(all_zeroes ? std::string() : hex, false);
}

