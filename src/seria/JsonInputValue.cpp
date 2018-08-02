// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "JsonInputValue.hpp"

#include <cassert>
#include <cstring>
#include <stdexcept>

#include "common/Invariant.hpp"
#include "common/StringTools.hpp"

using common::JsonValue;
using namespace seria;

JsonInputValue::JsonInputValue(const common::JsonValue &value) : value(value) {}

JsonInputValue::JsonInputValue(common::JsonValue &&value) : value(std::move(value)) {}

void JsonInputValue::object_key(common::StringView name, bool optional) {
	const JsonValue *parent = chain.back();
	if (!parent) {
		object_key_value = nullptr;  // All fields are optional
		return;
	}
	if (!parent->is_object())
		throw std::runtime_error("JsonInputValue::object_key this is not an object");
	std::string str_name(name);
	if (!parent->contains(str_name)) {
		object_key_value = nullptr;  // All fields are optional
		// throw std::runtime_error("JsonInputValue::object_key not in object key=" + str_name);
		return;
	}
	object_key_value = &((*parent)(str_name));
}

void JsonInputValue::begin_map(size_t &size) {
	begin_object();
	size = chain.back() ? chain.back()->get_object().size() : 0;
}

void JsonInputValue::next_map_key(std::string &name) {
	const JsonValue *parent = chain.back();
	if (!parent->is_object())
		throw std::runtime_error("JsonInputValue::object_key this is not an object");
	if (itrs.back() == parent->get_object().end())
		throw std::runtime_error("JsonInputValue::object_key too many object keys requested");
	name             = itrs.back()->first;
	object_key_value = &(itrs.back()->second);
	++itrs.back();
}

void JsonInputValue::begin_object() {
	const JsonValue *val = get_value();
	if (val && !val->is_object())
		throw std::runtime_error("Serializer doesn't support this type of serialization: Object expected.");
	chain.push_back(val);
	itrs.push_back(val ? val->get_object().begin() : value.get_object().end());
}

void JsonInputValue::end_object() {
	invariant(!chain.empty() && !itrs.empty(), "unexpected end_object.");
	chain.pop_back();
	itrs.pop_back();
}

void JsonInputValue::begin_array(size_t &size, bool fixed_size) {
	const JsonValue *val = get_value();
	if (val && !val->is_array())
		throw std::runtime_error("Serializer doesn't support this type of serialization: Array expected.");
	size = val ? val->size() : 0;
	chain.push_back(val);
	idxs.push_back(0);
}

void JsonInputValue::end_array() {
	invariant(!chain.empty() && !idxs.empty(), "unexpected end_array.");
	chain.pop_back();
	idxs.pop_back();
}

void JsonInputValue::seria_v(uint16_t &value) { get_unsigned(value); }

void JsonInputValue::seria_v(int16_t &value) { get_integer(value); }

void JsonInputValue::seria_v(uint32_t &value) { get_unsigned(value); }

void JsonInputValue::seria_v(int32_t &value) { get_integer(value); }

void JsonInputValue::seria_v(int64_t &value) { get_integer(value); }

void JsonInputValue::seria_v(uint64_t &value) { get_unsigned(value); }

void JsonInputValue::seria_v(double &value) {
	const common::JsonValue *val = get_value();
	if (val)
		value = val->get_double();
}

void JsonInputValue::seria_v(uint8_t &value) { get_unsigned(value); }

void JsonInputValue::seria_v(std::string &value) {
	const JsonValue *val = get_value();
	if (val)
		value = val->get_string();
}

void JsonInputValue::seria_v(bool &value) {
	const JsonValue *val = get_value();
	if (val)
		value = val->get_bool();
}

void JsonInputValue::binary(void *value, size_t size) {
	const JsonValue *val = get_value();
	if (val) {
		const std::string &str = val->get_string();
		if (str.size() == size * 2)
			common::from_hex(str, value, size);
		else if (str.empty())
			memset(value, 0, size);
		else
			throw std::runtime_error("Binary object size mismatch");
	}
}

void JsonInputValue::seria_v(common::BinaryArray &value) {
	const JsonValue *val = get_value();
	if (!val)
		return;
	value = common::from_hex(val->get_string());
}

const JsonValue *JsonInputValue::get_value() {
	if (chain.empty())
		return &value;
	if (!chain.back())  // Optional object
		return nullptr;
	const JsonValue &val = *chain.back();
	if (val.is_array())
		return &val[idxs.back()++];
	auto ret         = object_key_value;
	object_key_value = nullptr;
	return ret;
}
