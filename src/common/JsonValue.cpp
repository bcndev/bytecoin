// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include "JsonValue.hpp"
#include <iomanip>
#include <sstream>
#include "StringTools.hpp"

namespace common {

JsonValue::JsonValue() : type(NIL) {}

JsonValue::JsonValue(const JsonValue &other) {
	switch (other.type) {
	case ARRAY:
		new (valueArray) Array(*reinterpret_cast<const Array *>(other.valueArray));
		break;
	case BOOL:
		valueBool = other.valueBool;
		break;
	case SIGNED_INTEGER:
		valueInteger = other.valueInteger;
		break;
	case UNSIGNED_INTEGER:
		valueUnsigned = other.valueUnsigned;
		break;
	case NIL:
		break;
	case OBJECT:
		new (valueObject) Object(*reinterpret_cast<const Object *>(other.valueObject));
		break;
	case DOUBLE:
		valueReal = other.valueReal;
		break;
	case STRING:
		new (valueString) String(*reinterpret_cast<const String *>(other.valueString));
		break;
	}

	type = other.type;
}

JsonValue::JsonValue(JsonValue &&other) {
	switch (other.type) {
	case ARRAY:
		new (valueArray) Array(std::move(*reinterpret_cast<Array *>(other.valueArray)));
		reinterpret_cast<Array *>(other.valueArray)->~Array();
		break;
	case BOOL:
		valueBool = other.valueBool;
		break;
	case SIGNED_INTEGER:
		valueInteger = other.valueInteger;
		break;
	case UNSIGNED_INTEGER:
		valueUnsigned = other.valueUnsigned;
		break;
	case NIL:
		break;
	case OBJECT:
		new (valueObject) Object(std::move(*reinterpret_cast<Object *>(other.valueObject)));
		reinterpret_cast<Object *>(other.valueObject)->~Object();
		break;
	case DOUBLE:
		valueReal = other.valueReal;
		break;
	case STRING:
		new (valueString) String(std::move(*reinterpret_cast<String *>(other.valueString)));
		reinterpret_cast<String *>(other.valueString)->~String();
		break;
	}

	type       = other.type;
	other.type = NIL;
}

JsonValue::JsonValue(Type valueType) {
	switch (valueType) {
	case ARRAY:
		new (valueArray) Array;
		break;
	case NIL:
		break;
	case OBJECT:
		new (valueObject) Object;
		break;
	case STRING:
		new (valueString) String;
		break;
	default:
		throw std::runtime_error("Invalid JsonValue type for constructor");
	}

	type = valueType;
}

JsonValue::JsonValue(const Array &value) {
	new (valueArray) Array(value);
	type = ARRAY;
}

JsonValue::JsonValue(Array &&value) {
	new (valueArray) Array(std::move(value));
	type = ARRAY;
}

JsonValue::JsonValue(Bool value) : type(BOOL), valueBool(value) {}

JsonValue::JsonValue(Integer value) : type(SIGNED_INTEGER), valueInteger(value) {}

JsonValue::JsonValue(Unsigned value) : type(UNSIGNED_INTEGER), valueUnsigned(value) {}

JsonValue::JsonValue(std::nullptr_t) : type(NIL) {}

JsonValue::JsonValue(const Object &value) {
	new (valueObject) Object(value);
	type = OBJECT;
}

JsonValue::JsonValue(Object &&value) {
	new (valueObject) Object(std::move(value));
	type = OBJECT;
}

JsonValue::JsonValue(Double value) : type(DOUBLE), valueReal(value) {}

JsonValue::JsonValue(const String &value) {
	new (valueString) String(value);
	type = STRING;
}

JsonValue::JsonValue(String &&value) {
	new (valueString) String(std::move(value));
	type = STRING;
}

JsonValue::~JsonValue() { destructValue(); }

JsonValue &JsonValue::operator=(const JsonValue &other) {
	if (this == &other)
		return *this;
	if (type != other.type) {
		destructValue();
		switch (other.type) {
		case ARRAY:
			type = NIL;
			new (valueArray) Array(*reinterpret_cast<const Array *>(other.valueArray));
			break;
		case BOOL:
			valueBool = other.valueBool;
			break;
		case SIGNED_INTEGER:
			valueInteger = other.valueInteger;
			break;
		case UNSIGNED_INTEGER:
			valueUnsigned = other.valueUnsigned;
			break;
		case NIL:
			break;
		case OBJECT:
			type = NIL;
			new (valueObject) Object(*reinterpret_cast<const Object *>(other.valueObject));
			break;
		case DOUBLE:
			valueReal = other.valueReal;
			break;
		case STRING:
			type = NIL;
			new (valueString) String(*reinterpret_cast<const String *>(other.valueString));
			break;
		}

		type = other.type;
	} else {
		switch (type) {
		case ARRAY:
			*reinterpret_cast<Array *>(valueArray) = *reinterpret_cast<const Array *>(other.valueArray);
			break;
		case BOOL:
			valueBool = other.valueBool;
			break;
		case SIGNED_INTEGER:
			valueInteger = other.valueInteger;
			break;
		case UNSIGNED_INTEGER:
			valueUnsigned = other.valueUnsigned;
			break;
		case NIL:
			break;
		case OBJECT:
			*reinterpret_cast<Object *>(valueObject) = *reinterpret_cast<const Object *>(other.valueObject);
			break;
		case DOUBLE:
			valueReal = other.valueReal;
			break;
		case STRING:
			*reinterpret_cast<String *>(valueString) = *reinterpret_cast<const String *>(other.valueString);
			break;
		}
	}

	return *this;
}

JsonValue &JsonValue::operator=(JsonValue &&other) {
	if (type != other.type) {
		destructValue();
		switch (other.type) {
		case ARRAY:
			type = NIL;
			new (valueArray) Array(std::move(*reinterpret_cast<const Array *>(other.valueArray)));
			reinterpret_cast<Array *>(other.valueArray)->~Array();
			break;
		case BOOL:
			valueBool = other.valueBool;
			break;
		case SIGNED_INTEGER:
			valueInteger = other.valueInteger;
			break;
		case UNSIGNED_INTEGER:
			valueUnsigned = other.valueUnsigned;
			break;
		case NIL:
			break;
		case OBJECT:
			type = NIL;
			new (valueObject) Object(std::move(*reinterpret_cast<const Object *>(other.valueObject)));
			reinterpret_cast<Object *>(other.valueObject)->~Object();
			break;
		case DOUBLE:
			valueReal = other.valueReal;
			break;
		case STRING:
			type = NIL;
			new (valueString) String(std::move(*reinterpret_cast<const String *>(other.valueString)));
			reinterpret_cast<String *>(other.valueString)->~String();
			break;
		}

		type = other.type;
	} else {
		switch (type) {
		case ARRAY:
			*reinterpret_cast<Array *>(valueArray) = std::move(*reinterpret_cast<const Array *>(other.valueArray));
			reinterpret_cast<Array *>(other.valueArray)->~Array();
			break;
		case BOOL:
			valueBool = other.valueBool;
			break;
		case SIGNED_INTEGER:
			valueInteger = other.valueInteger;
			break;
		case UNSIGNED_INTEGER:
			valueUnsigned = other.valueUnsigned;
			break;
		case NIL:
			break;
		case OBJECT:
			*reinterpret_cast<Object *>(valueObject) = std::move(*reinterpret_cast<const Object *>(other.valueObject));
			reinterpret_cast<Object *>(other.valueObject)->~Object();
			break;
		case DOUBLE:
			valueReal = other.valueReal;
			break;
		case STRING:
			*reinterpret_cast<String *>(valueString) = std::move(*reinterpret_cast<const String *>(other.valueString));
			reinterpret_cast<String *>(other.valueString)->~String();
			break;
		}
	}
	other.type = NIL;
	return *this;
}

JsonValue &JsonValue::operator=(const Array &value) {
	if (type != ARRAY) {
		destructValue();
		new (valueArray) Array(value);
		type = ARRAY;
	} else {
		*reinterpret_cast<Array *>(valueArray) = value;
	}
	return *this;
}

JsonValue &JsonValue::operator=(Array &&value) {
	if (type != ARRAY) {
		destructValue();
		new (valueArray) Array(std::move(value));
		type = ARRAY;
	} else {
		*reinterpret_cast<Array *>(valueArray) = std::move(value);
	}
	return *this;
}

JsonValue &JsonValue::operator=(Bool value) {
	destructValue();
	type      = BOOL;
	valueBool = value;
	return *this;
}

JsonValue &JsonValue::operator=(Integer value) {
	destructValue();
	type         = SIGNED_INTEGER;
	valueInteger = value;
	return *this;
}

JsonValue &JsonValue::operator=(Unsigned value) {
	destructValue();
	type          = UNSIGNED_INTEGER;
	valueUnsigned = value;
	return *this;
}

JsonValue &JsonValue::operator=(std::nullptr_t) {
	destructValue();
	return *this;
}

JsonValue &JsonValue::operator=(const Object &value) {
	if (type != OBJECT) {
		destructValue();
		new (valueObject) Object(value);
		type = OBJECT;
	} else {
		*reinterpret_cast<Object *>(valueObject) = value;
	}
	return *this;
}

JsonValue &JsonValue::operator=(Object &&value) {
	if (type != OBJECT) {
		destructValue();
		new (valueObject) Object(std::move(value));
		type = OBJECT;
	} else {
		*reinterpret_cast<Object *>(valueObject) = std::move(value);
	}
	return *this;
}

JsonValue &JsonValue::operator=(Double value) {
	destructValue();
	type      = DOUBLE;
	valueReal = value;
	return *this;
}

JsonValue &JsonValue::operator=(const String &value) {
	if (type != STRING) {
		destructValue();
		new (valueString) String(value);
		type = STRING;
	} else {
		*reinterpret_cast<String *>(valueString) = value;
	}
	return *this;
}

JsonValue &JsonValue::operator=(String &&value) {
	if (type != STRING) {
		destructValue();
		new (valueString) String(std::move(value));
		type = STRING;
	} else {
		*reinterpret_cast<String *>(valueString) = std::move(value);
	}
	return *this;
}

JsonValue::Array &JsonValue::get_array() {
	if (type != ARRAY) {
		throw std::runtime_error("JsonValue type is not ARRAY");
	}
	return *reinterpret_cast<Array *>(valueArray);
}

const JsonValue::Array &JsonValue::get_array() const {
	if (type != ARRAY) {
		throw std::runtime_error("JsonValue type is not ARRAY");
	}
	return *reinterpret_cast<const Array *>(valueArray);
}

JsonValue::Bool JsonValue::get_bool() const {
	if (type != BOOL) {
		throw std::runtime_error("JsonValue type is not BOOL");
	}
	return valueBool;
}

JsonValue::Integer JsonValue::get_integer() const {
	if (type == SIGNED_INTEGER)
		return valueInteger;
	if (type == UNSIGNED_INTEGER)
		return valueUnsigned;
	throw std::runtime_error("JsonValue type is not INTEGER");
}

JsonValue::Unsigned JsonValue::get_unsigned() const {
	if (type == SIGNED_INTEGER)
		return valueInteger;
	if (type == UNSIGNED_INTEGER)
		return valueUnsigned;
	throw std::runtime_error("JsonValue type is not INTEGER");
}

JsonValue::Object &JsonValue::get_object() {
	if (type != OBJECT) {
		throw std::runtime_error("JsonValue type is not OBJECT");
	}
	return *reinterpret_cast<Object *>(valueObject);
}

const JsonValue::Object &JsonValue::get_object() const {
	if (type != OBJECT) {
		throw std::runtime_error("JsonValue type is not OBJECT");
	}
	return *reinterpret_cast<const Object *>(valueObject);
}

JsonValue::Double JsonValue::get_double() const {
	if (type != DOUBLE) {
		throw std::runtime_error("JsonValue type is not REAL");
	}
	return valueReal;
}

JsonValue::String &JsonValue::get_string() {
	if (type != STRING) {
		throw std::runtime_error("JsonValue type is not STRING");
	}
	return *reinterpret_cast<String *>(valueString);
}

const JsonValue::String &JsonValue::get_string() const {
	if (type != STRING) {
		throw std::runtime_error("JsonValue type is not STRING");
	}
	return *reinterpret_cast<const String *>(valueString);
}

size_t JsonValue::size() const {
	switch (type) {
	case ARRAY:
		return reinterpret_cast<const Array *>(valueArray)->size();
	case OBJECT:
		return reinterpret_cast<const Object *>(valueObject)->size();
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
	JsonValue jsonValue;
	std::istringstream stream(source);
	stream >> jsonValue;
	if (stream.fail()) {
		throw std::runtime_error("Unable to parse JsonValue");
	}
	char c = 0;
	while (stream >> c) {
		if (!isspace(c))
			throw std::runtime_error("Extra characters at end of stream");
	}
	//	if( !jsonValue.is_object() && !jsonValue.is_array())
	//		throw std::runtime_error("Json should be object or array at top level");
	return jsonValue;
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

std::ostream &operator<<(std::ostream &out, const JsonValue &jsonValue) {
	switch (jsonValue.type) {
	case JsonValue::ARRAY: {
		const JsonValue::Array &array = *reinterpret_cast<const JsonValue::Array *>(jsonValue.valueArray);
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
		out << (jsonValue.valueBool ? "true" : "false");
		break;
	case JsonValue::SIGNED_INTEGER:
		out << jsonValue.valueInteger;
		break;
	case JsonValue::UNSIGNED_INTEGER:
		out << jsonValue.valueUnsigned;
		break;
	case JsonValue::NIL:
		out << "null";
		break;
	case JsonValue::OBJECT: {
		const JsonValue::Object &object = *reinterpret_cast<const JsonValue::Object *>(jsonValue.valueObject);
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
		stream << std::fixed << std::setprecision(11) << jsonValue.valueReal;
		std::string value = stream.str();
		while (value.size() > 1 && value[value.size() - 2] != '.' && value[value.size() - 1] == '0') {
			value.resize(value.size() - 1);
		}

		out << value;
		break;
	}
	case JsonValue::STRING:
		out << '"' << escape_string(*reinterpret_cast<const JsonValue::String *>(jsonValue.valueString)) << '"';
		break;
	}

	return out;
}

namespace {

char readChar(std::istream &in) {
	char c = 0;

	if (!(in >> c)) {
		throw std::runtime_error("Unable to parse: unexpected end of stream");
	}
	return c;
}

char readNonWsChar(std::istream &in) {
	char c = 0;

	do {
		c = readChar(in);
	} while (isspace(c));

	return c;
}

char readChar2(std::istreambuf_iterator<char> &it, const std::istreambuf_iterator<char> &end) {
	if (it == end)
		throw std::runtime_error("Unable to parse: unexpected end of stream");
	char c = *it++;
	return c;
}

std::string readStringToken(std::istream &in) {
	std::string value;

	std::istreambuf_iterator<char> it(in), end;

	while (it != end) {
		char c = readChar2(it, end);
		if (iscntrl(c))
			throw std::runtime_error("Unable to parse: control character inside string");
		if (c == '"') {
			return value;
		}
		if (c == '\\') {
			c = readChar2(it, end);
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
				char c0           = readChar2(it, end);
				char c1           = readChar2(it, end);
				char c2           = readChar2(it, end);
				char c3           = readChar2(it, end);
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

std::istream &operator>>(std::istream &in, JsonValue &jsonValue) {
	char c = readNonWsChar(in);

	if (c == '[') {
		jsonValue.readArray(in);
	} else if (c == 't') {
		jsonValue.readTrue(in);
	} else if (c == 'f') {
		jsonValue.readFalse(in);
	} else if ((c == '-') || (c >= '0' && c <= '9')) {
		jsonValue.readNumber(in, c);
	} else if (c == 'n') {
		jsonValue.readNull(in);
	} else if (c == '{') {
		jsonValue.readObject(in);
	} else if (c == '"') {
		jsonValue.readString(in);
	} else {
		throw std::runtime_error("Unable to parse");
	}

	return in;
}

void JsonValue::destructValue() {
	switch (type) {
	case ARRAY:
		reinterpret_cast<Array *>(valueArray)->~Array();
		break;
	case OBJECT:
		reinterpret_cast<Object *>(valueObject)->~Object();
		break;
	case STRING:
		reinterpret_cast<String *>(valueString)->~String();
		break;
	default:
		break;
	}
	type = NIL;
}

void JsonValue::readArray(std::istream &in) {
	JsonValue::Array value;
	char c = readNonWsChar(in);

	if (c != ']') {
		in.putback(c);
		for (;;) {
			value.resize(value.size() + 1);
			in >> value.back();
			c = readNonWsChar(in);

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

void JsonValue::readTrue(std::istream &in) {
	char data[3];
	in.read(data, 3);
	if (data[0] != 'r' || data[1] != 'u' || data[2] != 'e') {
		throw std::runtime_error("Unable to parse");
	}

	destructValue();
	type      = JsonValue::BOOL;
	valueBool = true;
}

void JsonValue::readFalse(std::istream &in) {
	char data[4];
	in.read(data, 4);
	if (data[0] != 'a' || data[1] != 'l' || data[2] != 's' || data[3] != 'e') {
		throw std::runtime_error("Unable to parse");
	}

	destructValue();
	type      = JsonValue::BOOL;
	valueBool = false;
}

void JsonValue::readNull(std::istream &in) {
	char data[3];
	in.read(data, 3);
	if (data[0] != 'u' || data[1] != 'l' || data[2] != 'l') {
		throw std::runtime_error("Unable to parse");
	}

	destructValue();
}

void JsonValue::readNumber(std::istream &in, char c) {
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

		destructValue();
		std::istringstream(text) >> valueReal;
		type = DOUBLE;
	} else {
		if (text.size() > 1 && ((text[0] == '0') || (text[0] == '-' && text[1] == '0'))) {
			throw std::runtime_error("Unable to parse");
		}
		destructValue();
		if (text.size() > 1 && text[0] == '-') {
			std::istringstream(text) >> valueInteger;
			type = SIGNED_INTEGER;
		} else {
			std::istringstream(text) >> valueUnsigned;
			type = UNSIGNED_INTEGER;
		}
	}
}

void JsonValue::readObject(std::istream &in) {
	char c = readNonWsChar(in);
	JsonValue::Object value;

	if (c != '}') {
		std::string name;

		for (;;) {
			if (c != '"') {
				throw std::runtime_error("Unable to parse");
			}

			name = readStringToken(in);
			c    = readNonWsChar(in);

			if (c != ':') {
				throw std::runtime_error("Unable to parse");
			}

			in >> value[name];
			c = readNonWsChar(in);

			if (c == '}') {
				break;
			}

			if (c != ',') {
				throw std::runtime_error("Unable to parse");
			}

			c = readNonWsChar(in);
		}
	}
	*this = std::move(value);
}

void JsonValue::readString(std::istream &in) {
	String value = readStringToken(in);
	*this        = std::move(value);
}
}
