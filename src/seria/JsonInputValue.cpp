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

#include "JsonInputValue.hpp"

#include <cassert>
#include <stdexcept>
#include <cstring>

#include "common/StringTools.hpp"

using common::JsonValue;
using namespace seria;

JsonInputValue::JsonInputValue(const common::JsonValue &value) : value(value) {
}

JsonInputValue::JsonInputValue(common::JsonValue &&value) : value(std::move(value)) {
}

void JsonInputValue::objectKey(common::StringView name) {
	const JsonValue *parent = chain.back();
	if (!parent) {
		objectKeyValue = nullptr; // All fields are optional
		return;
	}
	if (!parent->is_object())
		throw std::runtime_error("JsonInputValue::objectKey this is not an object");
	std::string strName(name);
	if (!parent->contains(strName)) {
		objectKeyValue = nullptr; // All fields are optional
		// throw std::runtime_error("JsonInputValue::objectKey not in object key=" + strName);
		return;
	}
	objectKeyValue = &((*parent)(strName));
}

void JsonInputValue::beginMap(size_t &size) {
	beginObject();
	size = chain.back() ? chain.back()->get_object().size() : 0;
}

void JsonInputValue::nextMapKey(std::string &name) {
	const JsonValue *parent = chain.back();
	if (!parent->is_object())
		throw std::runtime_error("JsonInputValue::objectKey this is not an object");
	if (itrs.back() == parent->get_object().end())
		throw std::runtime_error("JsonInputValue::objectKey too many object keys requested");
	name = itrs.back()->first;
	objectKeyValue = &(itrs.back()->second);
	++itrs.back();
}

void JsonInputValue::beginObject() {
	const JsonValue *val = getValue();
	if (val && !val->is_object())
		throw std::runtime_error("Serializer doesn't support this type of serialization: Object expected.");
	chain.push_back(val);
	itrs.push_back(val ? val->get_object().begin() : value.get_object().end());
}

void JsonInputValue::endObject() {
	if(chain.empty() || itrs.empty())
		throw std::logic_error("JsonInputValue unexpected endObject.");
	chain.pop_back();
	itrs.pop_back();
}

void JsonInputValue::beginArray(size_t &size, bool fixed_size) {
	const JsonValue *val = getValue();
	if (val && !val->is_array())
		throw std::runtime_error("Serializer doesn't support this type of serialization: Array expected.");
	size = val ? val->size() : 0;
	chain.push_back(val);
	idxs.push_back(0);
}

void JsonInputValue::endArray() {
	if(chain.empty() || idxs.empty())
		throw std::logic_error("JsonInputValue unexpected endArray.");
	chain.pop_back();
	idxs.pop_back();
}

void JsonInputValue::seria_v(uint16_t &value) {
	getUnsigned(value);
}

void JsonInputValue::seria_v(int16_t &value) {
	getInteger(value);
}

void JsonInputValue::seria_v(uint32_t &value) {
	getUnsigned(value);
}

void JsonInputValue::seria_v(int32_t &value) {
	getInteger(value);
}

void JsonInputValue::seria_v(int64_t &value) {
	getInteger(value);
}

void JsonInputValue::seria_v(uint64_t &value) {
	getUnsigned(value);
}

void JsonInputValue::seria_v(double &value) {
	const common::JsonValue *val = getValue();
	if( val )
		value = val->get_double();
}

void JsonInputValue::seria_v(uint8_t &value) {
	getUnsigned(value);
}

void JsonInputValue::seria_v(std::string &value) {
	const JsonValue *val = getValue();
	if( val )
		value = val->get_string();
}

void JsonInputValue::seria_v(bool &value) {
	const JsonValue *val = getValue();
	if( val )
		value = val->get_bool();
}

void JsonInputValue::binary(void *value, size_t size) {
	const JsonValue *val = getValue();
	if (val) {
		const std::string & str = val->get_string();
		if( str.size() == size*2)
			common::from_hex(str, value, size);
		else if( str.empty())
			memset(value, 0, size);
		else
			throw std::runtime_error("Binary object size mismatch");
	}
}

void JsonInputValue::seria_v(common::BinaryArray &value) {
	const JsonValue *val = getValue();
	if( !val )
		return;
	std::string valueHex = val->get_string();
	value = common::from_hex(valueHex);
}

const JsonValue *JsonInputValue::getValue() {
	if (chain.empty())
		return &value;
	if (!chain.back()) // Optional object
		return nullptr;
	const JsonValue &val = *chain.back();
	if (val.is_array())
		return &val[idxs.back()++];
	auto ret = objectKeyValue;
	objectKeyValue = nullptr;
	return ret;
}
