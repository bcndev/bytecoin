// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include <iostream>
#include "ISeria.hpp"
#include "common/JsonValue.hpp"

namespace seria {

class JsonOutputStream : public ISeria {
public:
	JsonOutputStream();

	virtual bool is_input() const override { return false; }

	virtual void begin_object() override;
	virtual void object_key(common::StringView name) override;
	virtual void end_object() override;

	virtual void begin_map(size_t &) override { begin_object(); }
	virtual void next_map_key(std::string &name) override;
	virtual void end_map() override { end_object(); }

	virtual void begin_array(size_t &size, bool fixed_size = false) override;
	virtual void end_array() override;

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
	const common::JsonValue &get_value() const { return root; }

private:
	bool expecting_root = true;
	common::StringView next_key;
	common::JsonValue root;
	std::vector<common::JsonValue *> chain;

	common::JsonValue *insert_or_push(const common::JsonValue &value, bool optional) {
		if (chain.empty()) {
			if (!expecting_root)
				throw std::logic_error("JsonOutputStream::begin_object unexpected root");
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
			if (optional)
				return nullptr;
			return &js->insert((std::string)key, value);
		}
		throw std::logic_error("JsonOutputStream::insert_or_push can only insert into object array or root");
	}
};

template<typename T>
common::JsonValue to_json_value(const T &v) {
	JsonOutputStream s;
	s(const_cast<T &>(v));
	return s.get_value();
}
}
