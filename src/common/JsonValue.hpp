// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

namespace common {

class JsonValue {
public:
	typedef std::string Key;

	typedef std::vector<JsonValue> Array;
	typedef bool Bool;
	typedef int64_t Integer;
	typedef uint64_t Unsigned;
	//	typedef std::nullptr_t Nil; - unfortunately conflicts on some compilers
	typedef std::map<Key, JsonValue> Object;
	typedef double Double;
	typedef std::string String;

	enum Type {
		ARRAY,
		BOOL,
		SIGNED_INTEGER,
		UNSIGNED_INTEGER,
		NIL,
		OBJECT,
		DOUBLE,
		STRING
	};  // We preserve semantic of very large 64-bit values by splitting into signed/unsigned

	JsonValue();
	JsonValue(const JsonValue &other);
	JsonValue(JsonValue &&other) noexcept;
	JsonValue(Type value_type);
	JsonValue(const Array &value);
	JsonValue(Array &&value);
	explicit JsonValue(Bool value);
	JsonValue(Integer value);
	JsonValue(Unsigned value);
	JsonValue(std::nullptr_t value);
	JsonValue(const Object &value);
	JsonValue(Object &&value);
	JsonValue(Double value);
	JsonValue(const String &value);
	JsonValue(String &&value);
	template<size_t size>
	JsonValue(const char (&value)[size]) {
		new (&value_string) String(value, size - 1);
		type = STRING;
	}

	~JsonValue();

	JsonValue &operator=(const JsonValue &other);
	JsonValue &operator=(JsonValue &&other) noexcept;
	JsonValue &operator=(const Array &value);
	JsonValue &operator=(Array &&value);
	JsonValue &operator=(Bool value);
	JsonValue &operator=(Integer value);
	JsonValue &operator=(Unsigned value);
	JsonValue &operator=(std::nullptr_t value);
	JsonValue &operator=(const Object &value);
	JsonValue &operator=(Object &&value);
	JsonValue &operator=(Double value);
	JsonValue &operator=(const String &value);
	JsonValue &operator=(String &&value);
	template<size_t size>
	JsonValue &operator=(const char (&value)[size]) {
		if (type != STRING) {
			destruct_value();
			new (&value_string) String(value, size - 1);
			type = STRING;
		} else {
			reinterpret_cast<String *>(&value_string)->assign(value, size - 1);
		}
		return *this;
	}

	bool is_array() const { return type == ARRAY; }
	bool is_bool() const { return type == BOOL; }
	bool is_integer() const { return type == SIGNED_INTEGER || type == UNSIGNED_INTEGER; }
	bool is_nil() const { return type == NIL; }
	bool is_object() const { return type == OBJECT; }
	bool is_double() const { return type == DOUBLE; }
	bool is_string() const { return type == STRING; }

	//	Type get_type() const { return type; }
	Array &get_array();
	const Array &get_array() const;
	Bool get_bool() const;
	Integer get_integer() const;
	Unsigned get_unsigned() const;
	Object &get_object();
	const Object &get_object() const;
	Double get_double() const;
	String &get_string();
	const String &get_string() const;

	size_t size() const;

	JsonValue &operator[](size_t index);
	const JsonValue &operator[](size_t index) const;
	JsonValue &push_back(const JsonValue &value);
	JsonValue &push_back(JsonValue &&value);

	JsonValue &operator()(const Key &key);
	const JsonValue &operator()(const Key &key) const;
	bool contains(const Key &key) const;
	JsonValue &insert(const Key &key, const JsonValue &value);
	JsonValue &insert(const Key &key, JsonValue &&value);

	// sets or creates value, returns reference to self
	JsonValue &set(const Key &key, const JsonValue &value);
	JsonValue &set(const Key &key, JsonValue &&value);

	size_t erase(const Key &key);

	static JsonValue from_string(const std::string &source);
	std::string to_string() const;

	friend std::ostream &operator<<(std::ostream &out, const JsonValue &json_value);

	static std::string escape_string(const std::string &str);

private:
	Type type;
	union {
		typename std::aligned_storage<sizeof(Array), alignof(Array)>::type value_array;
		Bool value_bool;
		Integer value_integer;
		Unsigned value_unsigned;
		typename std::aligned_storage<sizeof(Object), alignof(Object)>::type value_object;
		Double value_real;
		typename std::aligned_storage<sizeof(std::string), alignof(std::string)>::type value_string;
	};

	void destruct_value();

	struct StreamContext {
		std::istreambuf_iterator<char> it;
		const std::istreambuf_iterator<char> end;
		std::string mini_buf;  // relatively efficient char history buffer
		size_t mini_pos       = 0;
		bool prev_white_space = true;  // collapse whitespaces in mini_buf
	public:
		explicit StreamContext(std::istream &in);
		char peek_char();
		char read_char();
		char read_non_ws_char();
		char peek_non_ws_char();
		std::string read_string_token();
		void eat_all_whitespace();
		void throw_error(const std::string &text);
		void expect(char c, char should_be_c);
	};
	void read_json(size_t level, StreamContext &ctx);

	void read_array(size_t level, StreamContext &ctx);
	void read_true(StreamContext &ctx);
	void read_false(StreamContext &ctx);
	void read_null(StreamContext &ctx);
	void read_number(StreamContext &ctx, char c);
	void read_object(size_t level, StreamContext &ctx);
	void read_string(StreamContext &ctx);
};
}  // namespace common
