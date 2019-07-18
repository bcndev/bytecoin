// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "JsonInputStream.hpp"

#include <cassert>
#include <cstring>
#include <stdexcept>

#include "common/Invariant.hpp"
//#include "common/Math.hpp"
#include "common/StringTools.hpp"

using common::JsonValue;
using namespace seria;

JsonInputStreamValue::JsonInputStreamValue(const common::JsonValue &root_value, bool allow_unused_object_keys)
    : ISeria(true, true), root_value(root_value), allow_unused_object_keys(allow_unused_object_keys) {}

void JsonInputStreamValue::object_key(common::StringView name, bool optional) {
	const JsonValue *parent = chain.back();
	if (!parent) {
		if (!optional)
			throw std::runtime_error("JsonInputStreamValue::object_key '" + std::string(name) + "' is not optional");
		object_key_value = nullptr;  // All fields inside will also be optional
		return;
	}
	if (!parent->is_object())
		throw std::runtime_error("JsonInputStreamValue::object_key '" + std::string(name) + "' is not an object");
	std::string str_name(name);
	remaining_object_keys.back().erase(str_name);
	if (!parent->contains(str_name)) {
		if (!optional)
			throw std::runtime_error("JsonInputStreamValue::object_key '" + std::string(name) + "' is not optional");
		object_key_value = nullptr;  // All fields inside will also be optional
		return;
	}
	object_key_value = &((*parent)(str_name));
}

bool JsonInputStreamValue::begin_map(size_t &size) {
	bool result = begin_object();
	size        = chain.back() ? chain.back()->get_object().size() : 0;
	if (chain.back())  // TODO - better map logic handling
		remaining_object_keys.back().clear();
	return result;
}

void JsonInputStreamValue::next_map_key(std::string &name) {
	const JsonValue *parent = chain.back();
	if (!parent)
		throw std::runtime_error("JsonInputStreamValue::object_key object key of optional empty map is requested");
	if (!parent->is_object())
		throw std::runtime_error("JsonInputStreamValue::object_key this is not an map");
	if (itrs.back() == parent->get_object().end())
		throw std::runtime_error("JsonInputStreamValue::object_key too many map keys requested");
	name             = itrs.back()->first;
	object_key_value = &(itrs.back()->second);
	++itrs.back();
}

bool JsonInputStreamValue::begin_object() {
	const JsonValue *val = get_value();
	if (val && !val->is_object())
		throw std::runtime_error("JsonInputStreamValue doesn't support this type of serialization: Object expected.");
	if (val) {
		itrs.push_back(val->get_object().begin());
		std::set<std::string> all_keys;
		if (!allow_unused_object_keys)
			for (const auto &kv : val->get_object())
				all_keys.insert(kv.first);
		remaining_object_keys.push_back(std::move(all_keys));
	}
	chain.push_back(val);
	return val;
}

void JsonInputStreamValue::end_object() {
	invariant(!chain.empty() && !itrs.empty(), "JsonInputStreamValue unexpected end_object.");
	if (chain.back()) {
		if (!remaining_object_keys.back().empty()) {
			std::string all_keys;
			for (const auto &k : remaining_object_keys.back())
				all_keys += (all_keys.empty() ? "'" : ", '") + k + "'";
			throw std::runtime_error("key(s) " + all_keys + " have no meaning. Typo?");
		}
		remaining_object_keys.pop_back();
		itrs.pop_back();
	}
	chain.pop_back();
}

bool JsonInputStreamValue::begin_array(size_t &size, bool fixed_size) {
	const JsonValue *val = get_value();
	if (val && !val->is_array())
		throw std::runtime_error("JsonInputStreamValue: Array expected.");
	if (val && fixed_size && val->size() != size)
		throw std::runtime_error("JsonInputStreamValue: Array with size=" + common::to_string(size) + " expected.");
	if (!fixed_size)
		size = val ? val->size() : 0;
	chain.push_back(val);
	idxs.push_back(0);
	return val;
}

void JsonInputStreamValue::end_array() {
	invariant(!chain.empty() && !idxs.empty(), "JsonInputStreamValue unexpected end_array.");
	chain.pop_back();
	idxs.pop_back();
}

bool JsonInputStreamValue::seria_v(int64_t &value) {
	const JsonValue *val = get_value();
	if (!val)
		return false;
	if (val->is_string()) {  // We allow languages like JavaScript to send 64-bit values as string
		value = common::integer_cast<int64_t>(val->get_string());
		return true;
	}
	value = val->get_integer();
	return true;
}

bool JsonInputStreamValue::seria_v(uint64_t &value) {
	const JsonValue *val = get_value();
	if (!val)
		return false;
	if (val->is_string()) {  // We allow languages like JavaScript to send 64-bit values as string
		value = common::integer_cast<uint64_t>(val->get_string());
		return true;
	}
	value = val->get_unsigned();
	return true;
}

bool JsonInputStreamValue::seria_v(std::string &value) {
	const JsonValue *val = get_value();
	if (!val)
		return false;
	value = val->get_string();
	return true;
}

bool JsonInputStreamValue::seria_v(bool &value) {
	const JsonValue *val = get_value();
	if (!val)
		return false;
	value = val->get_bool();
	return true;
}

bool JsonInputStreamValue::binary(void *value, size_t size) {
	const JsonValue *val = get_value();
	if (!val)
		return false;
	const std::string &str = val->get_string();
	if (str.empty())
		memset(value, 0, size);
	else
		common::from_hex_or_throw(str, value, size);
	return true;
}

bool JsonInputStreamValue::seria_v(common::BinaryArray &value) {
	const JsonValue *val = get_value();
	if (!val)
		return false;
	value = common::from_hex(val->get_string());
	return true;
}

const JsonValue *JsonInputStreamValue::get_value() {
	if (chain.empty())
		return &root_value;
	if (!chain.back())  // Optional object
		return nullptr;
	const JsonValue &val = *chain.back();
	if (val.is_array())
		return &val[idxs.back()++];  // [] is checked
	auto ret         = object_key_value;
	object_key_value = nullptr;
	return ret;
}
