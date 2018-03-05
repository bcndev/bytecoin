// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
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
	JsonValue(JsonValue &&other);
	JsonValue(Type valueType);
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
		new (valueString) String(value, size - 1);
		type = STRING;
	}

	~JsonValue();

	JsonValue &operator=(const JsonValue &other);
	JsonValue &operator=(JsonValue &&other);
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
			destructValue();
			new (valueString) String(value, size - 1);
			type = STRING;
		} else {
			reinterpret_cast<String *>(valueString)->assign(value, size - 1);
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

	//	Type getType() const { return type; }
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

	// those operators should no be used because they do not check for correct end of object (example - extra comma
	// after json object)
	friend std::ostream &operator<<(std::ostream &out, const JsonValue &jsonValue);
	friend std::istream &operator>>(std::istream &in, JsonValue &jsonValue);

private:
	Type type;
	union {
		alignas(Array) uint8_t valueArray[sizeof(Array)];
		Bool valueBool;
		Integer valueInteger;
		Unsigned valueUnsigned;
		alignas(Object) uint8_t valueObject[sizeof(Object)];
		Double valueReal;
		alignas(std::string) uint8_t valueString[sizeof(std::string)];
	};

	void destructValue();

	void readArray(std::istream &in);
	void readTrue(std::istream &in);
	void readFalse(std::istream &in);
	void readNull(std::istream &in);
	void readNumber(std::istream &in, char c);
	void readObject(std::istream &in);
	void readString(std::istream &in);
};
}
