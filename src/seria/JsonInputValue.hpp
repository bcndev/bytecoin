// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "ISeria.hpp"
#include "common/JsonValue.hpp"

namespace seria {

class JsonInputValue : public ISeria {
public:
	JsonInputValue(const common::JsonValue &value);
	JsonInputValue(common::JsonValue &&value);

	virtual bool is_input() const override { return true; }

	virtual void begin_object() override;
	virtual void object_key(common::StringView name, bool optional = false) override;
	virtual void end_object() override;

	virtual void begin_map(size_t &size) override;
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

private:
	common::JsonValue value;
	const common::JsonValue *object_key_value = nullptr;
	std::vector<const common::JsonValue *> chain;
	std::vector<size_t> idxs;
	std::vector<common::JsonValue::Object::const_iterator> itrs;

	const common::JsonValue *get_value();

	template<typename T>
	void get_integer(T &v) {
		const common::JsonValue *val = get_value();
		if (val)
			v = static_cast<T>(val->get_integer());
	}
	template<typename T>
	void get_unsigned(T &v) {
		const common::JsonValue *val = get_value();
		if (val)
			v = static_cast<T>(val->get_unsigned());
	}
};

template<typename T>
void from_json_value(T &v, const common::JsonValue &js) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	JsonInputValue s(js);
	s(v);
}
}
