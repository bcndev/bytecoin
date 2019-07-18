// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "ISeria.hpp"
#include "common/JsonValue.hpp"
#include "common/Nocopy.hpp"
#include "common/exception.hpp"

namespace seria {

class JsonInputStreamValue : public ISeria, private common::Nocopy {
public:
	explicit JsonInputStreamValue(const common::JsonValue &root_value, bool allow_unused_object_keys);

	bool begin_object() override;
	void object_key(common::StringView name, bool optional) override;
	void end_object() override;

	bool begin_map(size_t &size) override;
	void next_map_key(std::string &name) override;
	void end_map() override { end_object(); }

	bool begin_array(size_t &size, bool fixed_size) override;
	void end_array() override;

	bool seria_v(int64_t &value) override;
	bool seria_v(uint64_t &value) override;

	bool seria_v(bool &value) override;
	bool seria_v(std::string &value) override;
	bool seria_v(common::BinaryArray &value) override;
	bool binary(void *value, size_t size) override;

private:
	const common::JsonValue &root_value;
	const bool allow_unused_object_keys;
	const common::JsonValue *object_key_value = nullptr;
	std::vector<const common::JsonValue *> chain;
	std::vector<size_t> idxs;
	std::vector<common::JsonValue::Object::const_iterator> itrs;
	std::vector<std::set<std::string>> remaining_object_keys;

	const common::JsonValue *get_value();
};

template<typename T, typename... Context>
void from_json_value(T &v, const common::JsonValue &js, Context... context) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	JsonInputStreamValue s(js, true);
	try {
		ser(v, s, context...);
	} catch (const std::exception &) {
		std::throw_with_nested(std::runtime_error(
		    "Error while deserializing json value of type '" + common::demangle(typeid(T).name()) + "'"));
	}
}

// Disallow unknown object keys - prevents typos
template<typename T, typename... Context>
void from_json_value_strict(T &v, const common::JsonValue &js, Context... context) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	JsonInputStreamValue s(js, false);
	try {
		ser(v, s, context...);
	} catch (const std::exception &) {
		std::throw_with_nested(std::runtime_error(
		    "Error while deserializing json value of type '" + common::demangle(typeid(T).name()) + "'"));
	}
}

}  // namespace seria
