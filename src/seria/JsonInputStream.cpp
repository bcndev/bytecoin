// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "JsonInputStream.hpp"

#include <cassert>
#include <cstring>
#include <stdexcept>

#include "common/Invariant.hpp"
#include "common/Math.hpp"
#include "common/StringTools.hpp"

using common::JsonValue;
using namespace seria;

namespace {
template<typename T>
void get_integer(const common::JsonValue *val, T &v, const char *t_name) {
	if (val) {
		try {
			v = common::integer_cast<T>(val->get_integer());
		} catch (const std::exception &) {
			throw std::out_of_range(
			    "value " + common::to_string(val->get_integer()) + " does not fit into " + std::string(t_name));
		}
	}
}

template<typename T>
void get_unsigned(const common::JsonValue *val, T &v, const char *t_name) {
	if (val) {
		try {
			v = common::integer_cast<T>(val->get_unsigned());
		} catch (const std::exception &) {
			throw std::out_of_range(
			    "value " + common::to_string(val->get_unsigned()) + " does not fit into " + std::string(t_name));
		}
	}
}
}

JsonInputStreamValue::JsonInputStreamValue(const common::JsonValue &value) : value(value) {}

bool JsonInputStreamValue::object_key(common::StringView name, bool optional) {
	const JsonValue *parent = chain.back();
	if (!parent) {
		object_key_value = nullptr;  // All fields are optional
		return false;
	}
	if (!parent->is_object())
		throw std::runtime_error("JsonInputStreamValue::object_key this is not an object");
	std::string str_name(name);
	remaining_object_keys.back().erase(str_name);
	if (!parent->contains(str_name)) {
		object_key_value = nullptr;  // All fields are optional
		// throw std::runtime_error("JsonInputStreamValue::object_key not in object key=" + str_name);
		return false;
	}
	object_key_value = &((*parent)(str_name));
	return true;
}

void JsonInputStreamValue::begin_map(size_t &size) {
	begin_object();
	size = chain.back() ? chain.back()->get_object().size() : 0;
	if (chain.back()) // TODO - better map logic handling
		remaining_object_keys.back().clear();
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

void JsonInputStreamValue::begin_object() {
	const JsonValue *val = get_value();
	if (val && !val->is_object())
		throw std::runtime_error("JsonInputStreamValue doesn't support this type of serialization: Object expected.");
	if (val) {
		itrs.push_back(val->get_object().begin());
		std::set<std::string> all_keys;
		for (const auto &kv : val->get_object())
			all_keys.insert(kv.first);
		remaining_object_keys.push_back(std::move(all_keys));
	}
	chain.push_back(val);
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

void JsonInputStreamValue::begin_array(size_t &size, bool fixed_size) {
	const JsonValue *val = get_value();
	if (val && !val->is_array())
		throw std::runtime_error("JsonInputStreamValue doesn't support this type of serialization: Array expected.");
	size = val ? val->size() : 0;
	chain.push_back(val);
	idxs.push_back(0);
}

void JsonInputStreamValue::end_array() {
	invariant(!chain.empty() && !idxs.empty(), "JsonInputStreamValue unexpected end_array.");
	chain.pop_back();
	idxs.pop_back();
}

void JsonInputStreamValue::seria_v(uint16_t &value) { get_unsigned(get_value(), value, "uint16_t"); }

void JsonInputStreamValue::seria_v(int16_t &value) { get_integer(get_value(), value, "int16_t"); }

void JsonInputStreamValue::seria_v(uint32_t &value) { get_unsigned(get_value(), value, "uint32_t"); }

void JsonInputStreamValue::seria_v(int32_t &value) { get_integer(get_value(), value, "int32_t"); }

void JsonInputStreamValue::seria_v(int64_t &value) { get_integer(get_value(), value, "int64_t"); }

void JsonInputStreamValue::seria_v(uint64_t &value) { get_unsigned(get_value(), value, "uint64_t"); }

void JsonInputStreamValue::seria_v(double &value) {
	const common::JsonValue *val = get_value();
	if (val)
		value = val->get_double();
}

void JsonInputStreamValue::seria_v(uint8_t &value) { get_unsigned(get_value(), value, "uint8_t"); }

void JsonInputStreamValue::seria_v(std::string &value) {
	const JsonValue *val = get_value();
	if (val)
		value = val->get_string();
}

void JsonInputStreamValue::seria_v(bool &value) {
	const JsonValue *val = get_value();
	if (val)
		value = val->get_bool();
}

void JsonInputStreamValue::binary(void *value, size_t size) {
	const JsonValue *val = get_value();
	if (val) {
		const std::string &str = val->get_string();
		if (str.empty())
			memset(value, 0, size);
		else
			common::from_hex_or_throw(str, value, size);
	}
}

void JsonInputStreamValue::seria_v(common::BinaryArray &value) {
	const JsonValue *val = get_value();
	if (!val)
		return;
	value = common::from_hex(val->get_string());
}

const JsonValue *JsonInputStreamValue::get_value() {
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
