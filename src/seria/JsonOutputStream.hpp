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

#pragma once

#include <iostream>
#include "common/JsonValue.hpp"
#include "ISeria.hpp"

namespace seria {

class JsonOutputStream : public ISeria {
public:
	JsonOutputStream();

	virtual bool isInput() const override { return false; }

	virtual void beginObject() override;
	virtual void objectKey(common::StringView name) override;
	virtual void endObject() override;

	virtual void beginMap(size_t &) override { beginObject(); }
	virtual void nextMapKey(std::string &name) override;
	virtual void endMap() override { endObject(); }

	virtual void beginArray(size_t &size, bool fixed_size = false) override;
	virtual void endArray() override;

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
	const common::JsonValue &getValue() const {
		return root;
	}

private:
	bool expectingRoot = true;
	common::StringView nextKey;
	common::JsonValue root;
	std::vector<common::JsonValue *> chain;

	common::JsonValue *insertOrPush(const common::JsonValue &value, bool optional) {
		if (chain.empty()) {
			if (!expectingRoot)
				throw std::logic_error("JsonOutputStream::beginObject unexpected root");
			root = common::JsonValue(value);
			expectingRoot = false;
			return &root;
		}
		auto js = chain.back();
		if (js->is_array()) {
			return &js->push_back(value);
		}
		if (js->is_object()) {
			common::StringView key = nextKey;
			nextKey = common::StringView("");
			if (optional)
				return nullptr;
			return &js->insert((std::string) key, value);
		}
		throw std::logic_error("JsonOutputStream::insertOrPush can only insert into object array or root");
	}
};

template<typename T>
common::JsonValue toJsonValue(const T &v) {
	JsonOutputStream s;
	s(const_cast<T &>(v));
	return s.getValue();
}

}
