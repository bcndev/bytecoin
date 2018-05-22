// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "JsonValue.hpp"
#include <iomanip>
#include <sstream>
#include "StringTools.hpp"

namespace common {

JsonValue::JsonValue() : type(NIL) {}

JsonValue::JsonValue(const JsonValue &other) {
	switch (other.type) {
	case ARRAY:
		new (&value_array) Array(*reinterpret_cast<const Array *>(&other.value_array));
		break;
	case BOOL:
		value_bool = other.value_bool;
		break;
	case SIGNED_INTEGER:
		value_integer = other.value_integer;
		break;
	case UNSIGNED_INTEGER:
		value_unsigned = other.value_unsigned;
		break;
	case NIL:
		break;
	case OBJECT:
		new (&value_object) Object(*reinterpret_cast<const Object *>(&other.value_object));
		break;
	case DOUBLE:
		value_real = other.value_real;
		break;
	case STRING:
		new (&value_string) String(*reinterpret_cast<const String *>(&other.value_string));
		break;
	}

	type = other.type;
}

JsonValue::JsonValue(JsonValue &&other) {
	switch (other.type) {
	case ARRAY:
		new (&value_array) Array(std::move(*reinterpret_cast<Array *>(&other.value_array)));
		reinterpret_cast<Array *>(&other.value_array)->~Array();
		break;
	case BOOL:
		value_bool = other.value_bool;
		break;
	case SIGNED_INTEGER:
		value_integer = other.value_integer;
		break;
	case UNSIGNED_INTEGER:
		value_unsigned = other.value_unsigned;
		break;
	case NIL:
		break;
	case OBJECT:
		new (&value_object) Object(std::move(*reinterpret_cast<Object *>(&other.value_object)));
		reinterpret_cast<Object *>(&other.value_object)->~Object();
		break;
	case DOUBLE:
		value_real = other.value_real;
		break;
	case STRING:
		new (&value_string) String(std::move(*reinterpret_cast<String *>(&other.value_string)));
		reinterpret_cast<String *>(&other.value_string)->~String();
		break;
	}

	type       = other.type;
	other.type = NIL;
}

JsonValue::JsonValue(Type value_type) {
	switch (value_type) {
	case ARRAY:
		new (&value_array) Array;
		break;
	case NIL:
		break;
	case OBJECT:
		new (&value_object) Object;
		break;
	case STRING:
		new (&value_string) String;
		break;
	default:
		throw std::runtime_error("Invalid JsonValue type for constructor");
	}

	type = value_type;
}

JsonValue::JsonValue(const Array &value) {
	new (&value_array) Array(value);
	type = ARRAY;
}

JsonValue::JsonValue(Array &&value) {
	new (&value_array) Array(std::move(value));
	type = ARRAY;
}

JsonValue::JsonValue(Bool value) : type(BOOL), value_bool(value) {}

JsonValue::JsonValue(Integer value) : type(SIGNED_INTEGER), value_integer(value) {}

JsonValue::JsonValue(Unsigned value) : type(UNSIGNED_INTEGER), value_unsigned(value) {}

JsonValue::JsonValue(std::nullptr_t) : type(NIL) {}

JsonValue::JsonValue(const Object &value) {
	new (&value_object) Object(value);
	type = OBJECT;
}

JsonValue::JsonValue(Object &&value) {
	new (&value_object) Object(std::move(value));
	type = OBJECT;
}

JsonValue::JsonValue(Double value) : type(DOUBLE), value_real(value) {}

JsonValue::JsonValue(const String &value) {
	new (&value_string) String(value);
	type = STRING;
}

JsonValue::JsonValue(String &&value) {
	new (&value_string) String(std::move(value));
	type = STRING;
}

JsonValue::~JsonValue() { destruct_value(); }

JsonValue &JsonValue::operator=(const JsonValue &other) {
	if (this == &other)
		return *this;
	if (type != other.type) {
		destruct_value();
		switch (other.type) {
		case ARRAY:
			type = NIL;
			new (&value_array) Array(*reinterpret_cast<const Array *>(&other.value_array));
			break;
		case BOOL:
			value_bool = other.value_bool;
			break;
		case SIGNED_INTEGER:
			value_integer = other.value_integer;
			break;
		case UNSIGNED_INTEGER:
			value_unsigned = other.value_unsigned;
			break;
		case NIL:
			break;
		case OBJECT:
			type = NIL;
			new (&value_object) Object(*reinterpret_cast<const Object *>(&other.value_object));
			break;
		case DOUBLE:
			value_real = other.value_real;
			break;
		case STRING:
			type = NIL;
			new (&value_string) String(*reinterpret_cast<const String *>(&other.value_string));
			break;
		}

		type = other.type;
	} else {
		switch (type) {
		case ARRAY:
			*reinterpret_cast<Array *>(&value_array) = *reinterpret_cast<const Array *>(&other.value_array);
			break;
		case BOOL:
			value_bool = other.value_bool;
			break;
		case SIGNED_INTEGER:
			value_integer = other.value_integer;
			break;
		case UNSIGNED_INTEGER:
			value_unsigned = other.value_unsigned;
			break;
		case NIL:
			break;
		case OBJECT:
			*reinterpret_cast<Object *>(&value_object) = *reinterpret_cast<const Object *>(&other.value_object);
			break;
		case DOUBLE:
			value_real = other.value_real;
			break;
		case STRING:
			*reinterpret_cast<String *>(&value_string) = *reinterpret_cast<const String *>(&other.value_string);
			break;
		}
	}

	return *this;
}

// Analysers might warn about absense of this != &other
JsonValue &JsonValue::operator=(JsonValue &&other) {
	if (type != other.type) {
		destruct_value();
		switch (other.type) {
		case ARRAY:
			type = NIL;
			new (&value_array) Array(std::move(*reinterpret_cast<const Array *>(&other.value_array)));
			reinterpret_cast<Array *>(&other.value_array)->~Array();
			break;
		case BOOL:
			value_bool = other.value_bool;
			break;
		case SIGNED_INTEGER:
			value_integer = other.value_integer;
			break;
		case UNSIGNED_INTEGER:
			value_unsigned = other.value_unsigned;
			break;
		case NIL:
			break;
		case OBJECT:
			type = NIL;
			new (&value_object) Object(std::move(*reinterpret_cast<const Object *>(&other.value_object)));
			reinterpret_cast<Object *>(&other.value_object)->~Object();
			break;
		case DOUBLE:
			value_real = other.value_real;
			break;
		case STRING:
			type = NIL;
			new (&value_string) String(std::move(*reinterpret_cast<const String *>(&other.value_string)));
			reinterpret_cast<String *>(&other.value_string)->~String();
			break;
		}

		type = other.type;
	} else {
		switch (type) {
		case ARRAY:
			*reinterpret_cast<Array *>(&value_array) = std::move(*reinterpret_cast<const Array *>(&other.value_array));
			reinterpret_cast<Array *>(&other.value_array)->~Array();
			break;
		case BOOL:
			value_bool = other.value_bool;
			break;
		case SIGNED_INTEGER:
			value_integer = other.value_integer;
			break;
		case UNSIGNED_INTEGER:
			value_unsigned = other.value_unsigned;
			break;
		case NIL:
			break;
		case OBJECT:
			*reinterpret_cast<Object *>(&value_object) =
			    std::move(*reinterpret_cast<const Object *>(&other.value_object));
			reinterpret_cast<Object *>(&other.value_object)->~Object();
			break;
		case DOUBLE:
			value_real = other.value_real;
			break;
		case STRING:
			*reinterpret_cast<String *>(&value_string) =
			    std::move(*reinterpret_cast<const String *>(&other.value_string));
			reinterpret_cast<String *>(&other.value_string)->~String();
			break;
		}
	}
	other.type = NIL;
	return *this;
}

JsonValue &JsonValue::operator=(const Array &value) {
	if (type != ARRAY) {
		destruct_value();
		new (&value_array) Array(value);
		type = ARRAY;
	} else {
		*reinterpret_cast<Array *>(&value_array) = value;
	}
	return *this;
}

JsonValue &JsonValue::operator=(Array &&value) {
	if (type != ARRAY) {
		destruct_value();
		new (&value_array) Array(std::move(value));
		type = ARRAY;
	} else {
		*reinterpret_cast<Array *>(&value_array) = std::move(value);
	}
	return *this;
}

JsonValue &JsonValue::operator=(Bool value) {
	destruct_value();
	type       = BOOL;
	value_bool = value;
	return *this;
}

JsonValue &JsonValue::operator=(Integer value) {
	destruct_value();
	type          = SIGNED_INTEGER;
	value_integer = value;
	return *this;
}

JsonValue &JsonValue::operator=(Unsigned value) {
	destruct_value();
	type           = UNSIGNED_INTEGER;
	value_unsigned = value;
	return *this;
}

JsonValue &JsonValue::operator=(std::nullptr_t) {
	destruct_value();
	return *this;
}

JsonValue &JsonValue::operator=(const Object &value) {
	if (type != OBJECT) {
		destruct_value();
		new (&value_object) Object(value);
		type = OBJECT;
	} else {
		*reinterpret_cast<Object *>(&value_object) = value;
	}
	return *this;
}

JsonValue &JsonValue::operator=(Object &&value) {
	if (type != OBJECT) {
		destruct_value();
		new (&value_object) Object(std::move(value));
		type = OBJECT;
	} else {
		*reinterpret_cast<Object *>(&value_object) = std::move(value);
	}
	return *this;
}

JsonValue &JsonValue::operator=(Double value) {
	destruct_value();
	type       = DOUBLE;
	value_real = value;
	return *this;
}

JsonValue &JsonValue::operator=(const String &value) {
	if (type != STRING) {
		destruct_value();
		new (&value_string) String(value);
		type = STRING;
	} else {
		*reinterpret_cast<String *>(&value_string) = value;
	}
	return *this;
}

JsonValue &JsonValue::operator=(String &&value) {
	if (type != STRING) {
		destruct_value();
		new (&value_string) String(std::move(value));
		type = STRING;
	} else {
		*reinterpret_cast<String *>(&value_string) = std::move(value);
	}
	return *this;
}

JsonValue::Array &JsonValue::get_array() {
	if (type != ARRAY) {
		throw std::runtime_error("JsonValue type is not ARRAY");
	}
	return *reinterpret_cast<Array *>(&value_array);
}

const JsonValue::Array &JsonValue::get_array() const {
	if (type != ARRAY) {
		throw std::runtime_error("JsonValue type is not ARRAY");
	}
	return *reinterpret_cast<const Array *>(&value_array);
}

JsonValue::Bool JsonValue::get_bool() const {
	if (type != BOOL) {
		throw std::runtime_error("JsonValue type is not BOOL");
	}
	return value_bool;
}

JsonValue::Integer JsonValue::get_integer() const {
	if (type == SIGNED_INTEGER)
		return value_integer;
	if (type == UNSIGNED_INTEGER)
		return value_unsigned;
	throw std::runtime_error("JsonValue type is not INTEGER");
}

JsonValue::Unsigned JsonValue::get_unsigned() const {
	if (type == SIGNED_INTEGER)
		return value_integer;
	if (type == UNSIGNED_INTEGER)
		return value_unsigned;
	throw std::runtime_error("JsonValue type is not INTEGER");
}

JsonValue::Object &JsonValue::get_object() {
	if (type != OBJECT) {
		throw std::runtime_error("JsonValue type is not OBJECT");
	}
	return *reinterpret_cast<Object *>(&value_object);
}

const JsonValue::Object &JsonValue::get_object() const {
	if (type != OBJECT) {
		throw std::runtime_error("JsonValue type is not OBJECT");
	}
	return *reinterpret_cast<const Object *>(&value_object);
}

JsonValue::Double JsonValue::get_double() const {
	if (type != DOUBLE) {
		throw std::runtime_error("JsonValue type is not REAL");
	}
	return value_real;
}

JsonValue::String &JsonValue::get_string() {
	if (type != STRING) {
		throw std::runtime_error("JsonValue type is not STRING");
	}
	return *reinterpret_cast<String *>(&value_string);
}

const JsonValue::String &JsonValue::get_string() const {
	if (type != STRING) {
		throw std::runtime_error("JsonValue type is not STRING");
	}
	return *reinterpret_cast<const String *>(&value_string);
}

size_t JsonValue::size() const {
	switch (type) {
	case ARRAY:
		return reinterpret_cast<const Array *>(&value_array)->size();
	case OBJECT:
		return reinterpret_cast<const Object *>(&value_object)->size();
	default:
		throw std::runtime_error("JsonValue type is not ARRAY or OBJECT");
	}
}

JsonValue &JsonValue::operator[](size_t index) { return get_array().at(index); }

const JsonValue &JsonValue::operator[](size_t index) const { return get_array().at(index); }

JsonValue &JsonValue::push_back(const JsonValue &value) {
	auto &arr = get_array();
	arr.emplace_back(value);
	return arr.back();
}

JsonValue &JsonValue::push_back(JsonValue &&value) {
	auto &arr = get_array();
	arr.emplace_back(std::move(value));
	return arr.back();
}

JsonValue &JsonValue::operator()(const Key &key) { return get_object().at(key); }

const JsonValue &JsonValue::operator()(const Key &key) const { return get_object().at(key); }

bool JsonValue::contains(const Key &key) const { return get_object().count(key) > 0; }

JsonValue &JsonValue::insert(const Key &key, const JsonValue &value) {
	return get_object().emplace(key, value).first->second;
}

JsonValue &JsonValue::insert(const Key &key, JsonValue &&value) {
	return get_object().emplace(key, std::move(value)).first->second;
}

JsonValue &JsonValue::set(const Key &key, const JsonValue &value) {
	get_object()[key] = value;
	return *this;
}

JsonValue &JsonValue::set(const Key &key, JsonValue &&value) {
	get_object()[key] = std::move(value);
	return *this;
}

size_t JsonValue::erase(const Key &key) { return get_object().erase(key); }

JsonValue JsonValue::from_string(const std::string &source) {
	JsonValue json_value;
	std::istringstream stream(source);
	stream >> json_value;
	if (stream.fail()) {
		throw std::runtime_error("Unable to parse JsonValue");
	}
	char c = 0;
	while (stream >> c) {
		if (!isspace(c))
			throw std::runtime_error("Extra characters at end of stream");
	}
	//	if( !json_value.is_object() && !json_value.is_array())
	//		throw std::runtime_error("Json should be object or array at top level");
	return json_value;
}

std::string JsonValue::to_string() const {
	std::ostringstream stream;
	stream << *this;
	return stream.str();
}

static std::string escape_string(const std::string &str) {
	std::string result;
	static const std::string escape_table[32] = {"\\u0000", "\\u0001", "\\u0002", "\\u0003", "\\u0004", "\\u0005",
	    "\\u0006", "\\u0007", "\\b", "\\t", "\\n", "\\u000B", "\\f", "\\r", "\\u000E", "\\u000F", "\\u0010", "\\u0011",
	    "\\u0012", "\\u0013", "\\u0014", "\\u0015", "\\u0016", "\\u0017", "\\u0018", "\\u0019", "\\u001A", "\\u001B",
	    "\\u001C", "\\u001D", "\\u001E", "\\u001F"};
	for (auto &&c : str)
		if (c == '\\' || c == '"') {
			result += '\\';
			result += c;
		} else if (static_cast<unsigned char>(c) < ' ') {
			result += escape_table[static_cast<unsigned char>(c)];
		} else {
			result += c;
		}
	return result;
}

std::ostream &operator<<(std::ostream &out, const JsonValue &json_value) {
	switch (json_value.type) {
	case JsonValue::ARRAY: {
		const JsonValue::Array &array = *reinterpret_cast<const JsonValue::Array *>(&json_value.value_array);
		out << '[';
		if (array.size() > 0) {
			out << array[0];
			for (size_t i = 1; i < array.size(); ++i) {
				out << ',' << array[i];
			}
		}

		out << ']';
		break;
	}
	case JsonValue::BOOL:
		out << (json_value.value_bool ? "true" : "false");
		break;
	case JsonValue::SIGNED_INTEGER:
		out << json_value.value_integer;
		break;
	case JsonValue::UNSIGNED_INTEGER:
		out << json_value.value_unsigned;
		break;
	case JsonValue::NIL:
		out << "null";
		break;
	case JsonValue::OBJECT: {
		const JsonValue::Object &object = *reinterpret_cast<const JsonValue::Object *>(&json_value.value_object);
		out << '{';
		auto iter = object.begin();
		if (iter != object.end()) {
			out << '"' << escape_string(iter->first) << "\":" << iter->second;
			++iter;
			for (; iter != object.end(); ++iter) {
				out << ",\"" << escape_string(iter->first) << "\":" << iter->second;
			}
		}

		out << '}';
		break;
	}
	case JsonValue::DOUBLE: {
		std::ostringstream stream;
		stream << std::fixed << std::setprecision(11) << json_value.value_real;
		std::string value = stream.str();
		while (value.size() > 1 && value[value.size() - 2] != '.' && value[value.size() - 1] == '0') {
			value.resize(value.size() - 1);
		}

		out << value;
		break;
	}
	case JsonValue::STRING:
		out << '"' << escape_string(*reinterpret_cast<const JsonValue::String *>(&json_value.value_string)) << '"';
		break;
	}

	return out;
}

namespace {

char read_char(std::istream &in) {
	char c = 0;

	if (!(in >> c)) {
		throw std::runtime_error("Unable to parse: unexpected end of stream");
	}
	return c;
}

char read_non_ws_char(std::istream &in) {
	char c = 0;

	do {
		c = read_char(in);
	} while (isspace(c));

	return c;
}

char read_char2(std::istreambuf_iterator<char> &it, const std::istreambuf_iterator<char> &end) {
	if (it == end)
		throw std::runtime_error("Unable to parse: unexpected end of stream");
	char c = *it++;
	return c;
}

std::string read_string_token(std::istream &in) {
	std::string value;

	std::istreambuf_iterator<char> it(in), end;

	while (it != end) {
		char c = read_char2(it, end);
		if (iscntrl(c))
			throw std::runtime_error("Unable to parse: control character inside string");
		if (c == '"') {
			return value;
		}
		if (c == '\\') {
			c = read_char2(it, end);
			switch (c) {
			case '\\':
				value += '\\';
				continue;
			case '/':
				value += '/';
				continue;
			case '"':
				value += '"';
				continue;
			case 'n':
				value += '\n';
				continue;
			case 'r':
				value += '\r';
				continue;
			case 't':
				value += '\t';
				continue;
			case 'b':
				value += '\b';
				continue;
			case 'f':
				value += '\f';
				continue;
			case 'u': {
				// WTF those retards invented...
				char c0           = read_char2(it, end);
				char c1           = read_char2(it, end);
				char c2           = read_char2(it, end);
				char c3           = read_char2(it, end);
				unsigned char c0v = 0, c1v = 0, c2v = 0, c3v = 0;
				if (!common::from_hex(c0, c0v) || !common::from_hex(c1, c1v) || !common::from_hex(c2, c2v) ||
				    !common::from_hex(c3, c3v))
					throw std::runtime_error(
					    "Unable to parse: \\u wrong control code " + std::string({c0, c1, c2, c3}));
				unsigned cp = unsigned(c0v) * 4096 + unsigned(c1v) * 256 + unsigned(c2v) * 16 + unsigned(c3v);
				if ((cp >= 0xD800 && cp <= 0xDFFF) || cp >= 0xFFFE)
					throw std::runtime_error(
					    "Unable to parse: \\u does not support surrogate pairs " + std::string({c0, c1, c2, c3}));
				if (cp < 0x80) {
					value += static_cast<char>(cp);
					continue;
				}
				if (cp < 0x800) {
					value += static_cast<char>(0x80 | (cp & 0x3F));
					cp >>= 6;
					value += static_cast<char>(0xC0 | cp);
					continue;
				}
				value += static_cast<char>(0x80 | (cp & 0x3F));
				cp >>= 6;
				value += static_cast<char>(0x80 | (cp & 0x3F));
				cp >>= 6;
				value += static_cast<char>(0xE0 | cp);
				continue;
			}
			default:
				throw std::runtime_error("Unable to parse: unknown escape character " + std::string({c}));
			}
		}
		value += c;
	}
	throw std::runtime_error("Unable to parse: end of stream inside string");
}
}

std::istream &operator>>(std::istream &in, JsonValue &json_value) {
	char c = read_non_ws_char(in);

	if (c == '[') {
		json_value.read_array(in);
	} else if (c == 't') {
		json_value.read_true(in);
	} else if (c == 'f') {
		json_value.read_false(in);
	} else if ((c == '-') || (c >= '0' && c <= '9')) {
		json_value.read_number(in, c);
	} else if (c == 'n') {
		json_value.read_null(in);
	} else if (c == '{') {
		json_value.read_object(in);
	} else if (c == '"') {
		json_value.read_string(in);
	} else {
		throw std::runtime_error("Unable to parse");
	}

	return in;
}

void JsonValue::destruct_value() {
	switch (type) {
	case ARRAY:
		reinterpret_cast<Array *>(&value_array)->~Array();
		break;
	case OBJECT:
		reinterpret_cast<Object *>(&value_object)->~Object();
		break;
	case STRING:
		reinterpret_cast<String *>(&value_string)->~String();
		break;
	default:
		break;
	}
	type = NIL;
}

void JsonValue::read_array(std::istream &in) {
	JsonValue::Array value;
	char c = read_non_ws_char(in);

	if (c != ']') {
		in.putback(c);
		for (;;) {
			value.resize(value.size() + 1);
			in >> value.back();
			c = read_non_ws_char(in);

			if (c == ']') {
				break;
			}

			if (c != ',') {
				throw std::runtime_error("Unable to parse");
			}
		}
	}

	*this = std::move(value);
}

void JsonValue::read_true(std::istream &in) {
	char data[3];
	in.read(data, 3);
	if (data[0] != 'r' || data[1] != 'u' || data[2] != 'e') {
		throw std::runtime_error("Unable to parse");
	}

	destruct_value();
	type       = JsonValue::BOOL;
	value_bool = true;
}

void JsonValue::read_false(std::istream &in) {
	char data[4];
	in.read(data, 4);
	if (data[0] != 'a' || data[1] != 'l' || data[2] != 's' || data[3] != 'e') {
		throw std::runtime_error("Unable to parse");
	}

	destruct_value();
	type       = JsonValue::BOOL;
	value_bool = false;
}

void JsonValue::read_null(std::istream &in) {
	char data[3];
	in.read(data, 3);
	if (data[0] != 'u' || data[1] != 'l' || data[2] != 'l') {
		throw std::runtime_error("Unable to parse");
	}

	destruct_value();
}

void JsonValue::read_number(std::istream &in, char c) {
	std::string text;
	text += c;
	size_t dots = 0;
	for (;;) {
		int i = in.peek();
		if (i >= '0' && i <= '9') {
			in.read(&c, 1);
			text += c;
		} else if (i == '.') {
			in.read(&c, 1);
			text += '.';
			++dots;
		} else {
			break;
		}
	}

	char pee = in.peek();
	if (dots > 0 || pee == 'e' || pee == 'E') {
		if (dots > 1) {
			throw std::runtime_error("Unable to parse");
		}
		if (pee == 'e' || pee == 'E') {
			in.read(&c, 1);
			text += c;
			int i = in.peek();
			if (i == '+') {
				in.read(&c, 1);
				text += c;
				i = in.peek();
			} else if (i == '-') {
				in.read(&c, 1);
				text += c;
				i = in.peek();
			}

			if (i < '0' || i > '9') {
				throw std::runtime_error("Unable to parse");
			}

			do {
				in.read(&c, 1);
				text += c;
				i = in.peek();
			} while (i >= '0' && i <= '9');
		}

		destruct_value();
		std::istringstream(text) >> value_real;
		type = DOUBLE;
	} else {
		if (text.size() > 1 && ((text[0] == '0') || (text[0] == '-' && text[1] == '0'))) {
			throw std::runtime_error("Unable to parse");
		}
		destruct_value();
		if (text.size() > 1 && text[0] == '-') {
			std::istringstream(text) >> value_integer;
			type = SIGNED_INTEGER;
		} else {
			std::istringstream(text) >> value_unsigned;
			type = UNSIGNED_INTEGER;
		}
	}
}

void JsonValue::read_object(std::istream &in) {
	char c = read_non_ws_char(in);
	JsonValue::Object value;

	if (c != '}') {
		std::string name;

		for (;;) {
			if (c != '"') {
				throw std::runtime_error("Unable to parse");
			}

			name = read_string_token(in);
			c    = read_non_ws_char(in);

			if (c != ':') {
				throw std::runtime_error("Unable to parse");
			}

			in >> value[name];
			c = read_non_ws_char(in);

			if (c == '}') {
				break;
			}

			if (c != ',') {
				throw std::runtime_error("Unable to parse");
			}

			c = read_non_ws_char(in);
		}
	}
	*this = std::move(value);
}

void JsonValue::read_string(std::istream &in) {
	String value = read_string_token(in);
	*this        = std::move(value);
}
}
