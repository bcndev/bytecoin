// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "JsonValue.hpp"
#include <iomanip>
#include <iterator>
#include <limits>
#include <sstream>
#include "StringTools.hpp"
#include "string.hpp"

namespace common {

JsonValue::JsonValue() : type(NIL) {}

JsonValue::JsonValue(const JsonValue &other) {
	switch (other.type) {
	case ARRAY:
		new (&value_array) Array(reinterpret_cast<const Array &>(other.value_array));
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
		new (&value_object) Object(reinterpret_cast<const Object &>(other.value_object));
		break;
	case DOUBLE:
		value_real = other.value_real;
		break;
	case STRING:
		new (&value_string) String(reinterpret_cast<const String &>(other.value_string));
		break;
	}
	type = other.type;
}

JsonValue::JsonValue(JsonValue &&other) noexcept {
	switch (other.type) {
	case ARRAY:
		new (&value_array) Array(std::move(reinterpret_cast<Array &>(other.value_array)));
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
		new (&value_object) Object(std::move(reinterpret_cast<Object &>(other.value_object)));
		break;
	case DOUBLE:
		value_real = other.value_real;
		break;
	case STRING:
		new (&value_string) String(std::move(reinterpret_cast<String &>(other.value_string)));
		break;
	}
	type = other.type;
	other.destruct_value();
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
			new (&value_array) Array(reinterpret_cast<const Array &>(other.value_array));
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
			new (&value_object) Object(reinterpret_cast<const Object &>(other.value_object));
			break;
		case DOUBLE:
			value_real = other.value_real;
			break;
		case STRING:
			new (&value_string) String(reinterpret_cast<const String &>(other.value_string));
			break;
		}
		type = other.type;
	} else {
		switch (type) {
		case ARRAY:
			reinterpret_cast<Array &>(value_array) = reinterpret_cast<const Array &>(other.value_array);
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
			reinterpret_cast<Object &>(value_object) = reinterpret_cast<const Object &>(other.value_object);
			break;
		case DOUBLE:
			value_real = other.value_real;
			break;
		case STRING:
			reinterpret_cast<String &>(value_string) = reinterpret_cast<const String &>(other.value_string);
			break;
		}
	}
	return *this;
}

// Analysers might warn about absense of this != &other
JsonValue &JsonValue::operator=(JsonValue &&other) noexcept {
	if (type != other.type) {
		destruct_value();
		switch (other.type) {
		case ARRAY:
			new (&value_array) Array(std::move(reinterpret_cast<Array &>(other.value_array)));
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
			new (&value_object) Object(std::move(reinterpret_cast<Object &>(other.value_object)));
			break;
		case DOUBLE:
			value_real = other.value_real;
			break;
		case STRING:
			new (&value_string) String(std::move(reinterpret_cast<String &>(other.value_string)));
			break;
		}
		type = other.type;
	} else {
		switch (type) {
		case ARRAY:
			reinterpret_cast<Array &>(value_array) = std::move(reinterpret_cast<Array &>(other.value_array));
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
			reinterpret_cast<Object &>(value_object) = std::move(reinterpret_cast<Object &>(other.value_object));
			break;
		case DOUBLE:
			value_real = other.value_real;
			break;
		case STRING:
			reinterpret_cast<String &>(value_string) = std::move(reinterpret_cast<String &>(other.value_string));
			break;
		}
	}
	other.destruct_value();
	return *this;
}

JsonValue &JsonValue::operator=(const Array &value) {
	if (type != ARRAY) {
		destruct_value();
		new (&value_array) Array(value);
		type = ARRAY;
	} else {
		reinterpret_cast<Array &>(value_array) = value;
	}
	return *this;
}

JsonValue &JsonValue::operator=(Array &&value) {
	if (type != ARRAY) {
		destruct_value();
		new (&value_array) Array(std::move(value));
		type = ARRAY;
	} else {
		reinterpret_cast<Array &>(value_array) = std::move(value);
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
		reinterpret_cast<Object &>(value_object) = value;
	}
	return *this;
}

JsonValue &JsonValue::operator=(Object &&value) {
	if (type != OBJECT) {
		destruct_value();
		new (&value_object) Object(std::move(value));
		type = OBJECT;
	} else {
		reinterpret_cast<Object &>(value_object) = std::move(value);
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
		reinterpret_cast<String &>(value_string) = value;
	}
	return *this;
}

JsonValue &JsonValue::operator=(String &&value) {
	if (type != STRING) {
		destruct_value();
		new (&value_string) String(std::move(value));
		type = STRING;
	} else {
		reinterpret_cast<String &>(value_string) = std::move(value);
	}
	return *this;
}

JsonValue::Array &JsonValue::get_array() {
	if (type != ARRAY)
		throw std::runtime_error("JsonValue type is not ARRAY");
	return reinterpret_cast<Array &>(value_array);
}

const JsonValue::Array &JsonValue::get_array() const {
	if (type != ARRAY)
		throw std::runtime_error("JsonValue type is not ARRAY");
	return reinterpret_cast<const Array &>(value_array);
}

JsonValue::Bool JsonValue::get_bool() const {
	if (type != BOOL)
		throw std::runtime_error("JsonValue type is not BOOL");
	return value_bool;
}

JsonValue::Integer JsonValue::get_integer() const {
	if (type == SIGNED_INTEGER)
		return value_integer;
	if (type == UNSIGNED_INTEGER) {
		if (value_unsigned > static_cast<Unsigned>(std::numeric_limits<Integer>::max()))
			throw std::runtime_error(
			    "Too big unsigned number does not fit into integer (" + common::to_string(value_unsigned) + ")");
		return value_unsigned;
	}
	throw std::runtime_error("JsonValue type is not INTEGER");
}

JsonValue::Unsigned JsonValue::get_unsigned() const {
	if (type == SIGNED_INTEGER) {
		if (value_integer < 0)
			throw std::runtime_error(
			    "JsonValue value < 0 cannot be returned as unsigned (" + common::to_string(value_integer) + ")");
		return value_integer;
	}
	if (type == UNSIGNED_INTEGER)
		return value_unsigned;
	throw std::runtime_error("JsonValue type is not INTEGER");
}

JsonValue::Object &JsonValue::get_object() {
	if (type != OBJECT)
		throw std::runtime_error("JsonValue type is not OBJECT");
	return reinterpret_cast<Object &>(value_object);
}

const JsonValue::Object &JsonValue::get_object() const {
	if (type != OBJECT)
		throw std::runtime_error("JsonValue type is not OBJECT");
	return reinterpret_cast<const Object &>(value_object);
}

JsonValue::Double JsonValue::get_double() const {
	if (type != DOUBLE)
		throw std::runtime_error("JsonValue type is not REAL");
	return value_real;
}

JsonValue::String &JsonValue::get_string() {
	if (type != STRING)
		throw std::runtime_error("JsonValue type is not STRING");
	return reinterpret_cast<String &>(value_string);
}

const JsonValue::String &JsonValue::get_string() const {
	if (type != STRING)
		throw std::runtime_error("JsonValue type is not STRING");
	return reinterpret_cast<const String &>(value_string);
}

size_t JsonValue::size() const {
	switch (type) {
	case ARRAY:
		return reinterpret_cast<const Array &>(value_array).size();
	case OBJECT:
		return reinterpret_cast<const Object &>(value_object).size();
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
	StreamContext ctx(stream);
	json_value.read_json(ctx);
	if (stream.fail())
		ctx.throw_error("Stream error");
	ctx.eat_all_whitespace();
	//	if( !json_value.is_object() && !json_value.is_array())
	//		throw std::runtime_error("Json should be object or array at top level");
	return json_value;
}

std::string JsonValue::to_string() const {
	std::ostringstream stream;
	stream << *this;
	return stream.str();
}

std::string JsonValue::escape_string(const std::string &str) {
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
		if (!array.empty()) {
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
			out << '"' << JsonValue::escape_string(iter->first) << "\":" << iter->second;
			++iter;
			for (; iter != object.end(); ++iter) {
				out << ",\"" << JsonValue::escape_string(iter->first) << "\":" << iter->second;
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
		out << '"' << JsonValue::escape_string(*reinterpret_cast<const JsonValue::String *>(&json_value.value_string))
		    << '"';
		break;
	}

	return out;
}

JsonValue::StreamContext::StreamContext(std::istream &in) : it(in) {}

char JsonValue::StreamContext::read_char() {
	if (it == end)
		throw_error("unexpected end of stream");
	char c           = *it++;
	bool white_space = isspace(c);
	if (!white_space || !prev_white_space) {
		if (mini_pos == mini_buf.size()) {
			if (mini_buf.size() < 32)     // We track up to 32 characters
				mini_buf.push_back(' ');  // will be overwritten immediately
			else
				mini_pos = 0;
		}
		mini_buf[mini_pos++] = c;
		prev_white_space     = white_space;
	}
	return c;
}

char JsonValue::StreamContext::peek_char() {
	if (it == end)
		throw_error("unexpected end of stream");
	return *it;
}

char JsonValue::StreamContext::read_non_ws_char() {
	char c = 0;

	do {
		c = read_char();
	} while (isspace(c));

	return c;
}

char JsonValue::StreamContext::peek_non_ws_char() {
	char c = peek_char();

	while (isspace(c)) {
		read_char();
		c = peek_char();
	}
	return c;
}

void JsonValue::StreamContext::throw_error(const std::string &text) {
	std::string before = mini_buf.substr(mini_pos) + mini_buf.substr(0, mini_pos);
	throw std::runtime_error("Failed to parse json, " + text + ", ..." + before + " <-- here");
}
void JsonValue::StreamContext::expect(char c, char should_be_c) {
	if (c == should_be_c)
		return;
	throw_error("expecting '" + std::string({should_be_c}) + "' but got '" + std::string({c}) + "' (character code " +
	            common::to_string(static_cast<unsigned char>(c)) + ") instead");
}

void JsonValue::StreamContext::eat_all_whitespace() {
	while (it != end)
		if (!isspace(read_char()))
			throw_error("expecting only whitespace at the end of json");
}

std::string JsonValue::StreamContext::read_string_token() {
	std::string value;

	while (it != end) {
		char c = read_char();
		if (iscntrl(c))
			throw_error("control character inside string '" + std::string({c}) + "' (character code " +
			            common::to_string(static_cast<unsigned char>(c)) + ")");
		if (c == '"')
			return value;
		if (c == '\\') {
			c = read_char();
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
				char c0           = read_char();
				char c1           = read_char();
				char c2           = read_char();
				char c3           = read_char();
				unsigned char c0v = 0, c1v = 0, c2v = 0, c3v = 0;
				if (!common::from_hex(c0, c0v) || !common::from_hex(c1, c1v) || !common::from_hex(c2, c2v) ||
				    !common::from_hex(c3, c3v))
					throw_error(
					    "Unable to parse json: \\u wrong hex characters '" + std::string({c0, c1, c2, c3}) + "'");
				unsigned cp = unsigned(c0v) * 4096 + unsigned(c1v) * 256 + unsigned(c2v) * 16 + unsigned(c3v);
				if ((cp >= 0xD800 && cp <= 0xDFFF) || cp >= 0xFFFE)
					throw_error(
					    "Unable to parse json: \\u does not support surrogate pairs " + std::string({c0, c1, c2, c3}));
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
				throw_error("unknown escape character '" + std::string({c}) + "' (character code " +
				            common::to_string(static_cast<unsigned char>(c)) + ")");
			}
		}
		value += c;
	}
	throw_error("end of stream inside string");
	return std::string();
}

void JsonValue::read_json(StreamContext &ctx) {
	char c = ctx.read_non_ws_char();

	if (c == '[') {
		read_array(ctx);
	} else if (c == 't') {
		read_true(ctx);
	} else if (c == 'f') {
		read_false(ctx);
	} else if ((c == '-') || (c >= '0' && c <= '9')) {
		read_number(ctx, c);
	} else if (c == 'n') {
		read_null(ctx);
	} else if (c == '{') {
		read_object(ctx);
	} else if (c == '"') {
		read_string(ctx);
	} else {
		ctx.throw_error("Unexpected character");
	}
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

void JsonValue::read_array(StreamContext &ctx) {
	JsonValue::Array value;
	char c = ctx.peek_non_ws_char();

	if (c == ']')
		ctx.read_non_ws_char();
	else {
		for (;;) {
			value.resize(value.size() + 1);
			value.back().read_json(ctx);
			c = ctx.read_non_ws_char();

			if (c == ']')
				break;
			ctx.expect(c, ',');
		}
	}

	*this = std::move(value);
}

void JsonValue::read_true(StreamContext &ctx) {
	char data[3]{ctx.read_char(), ctx.read_char(), ctx.read_char()};
	if (data[0] != 'r' || data[1] != 'u' || data[2] != 'e')
		ctx.throw_error("'true' is expected");
	destruct_value();
	type       = JsonValue::BOOL;
	value_bool = true;
}

void JsonValue::read_false(StreamContext &ctx) {
	char data[4]{ctx.read_char(), ctx.read_char(), ctx.read_char(), ctx.read_char()};
	if (data[0] != 'a' || data[1] != 'l' || data[2] != 's' || data[3] != 'e')
		ctx.throw_error("'false' is expected");

	destruct_value();
	type       = JsonValue::BOOL;
	value_bool = false;
}

void JsonValue::read_null(StreamContext &ctx) {
	char data[3]{ctx.read_char(), ctx.read_char(), ctx.read_char()};
	if (data[0] != 'u' || data[1] != 'l' || data[2] != 'l')
		ctx.throw_error("'null' is expected");

	destruct_value();
}

void JsonValue::read_number(StreamContext &ctx, char c) {
	std::string text;
	text += c;
	size_t dots = 0;
	for (;;) {
		int i = ctx.peek_char();
		if (i >= '0' && i <= '9') {
			c = ctx.read_char();
			text += c;
		} else if (i == '.') {
			c = ctx.read_char();
			text += '.';
			++dots;
		} else {
			break;
		}
	}

	char pee = ctx.peek_char();
	if (dots > 0 || pee == 'e' || pee == 'E') {
		if (dots > 1) {
			ctx.throw_error("More than one '.' in a number");
		}
		if (pee == 'e' || pee == 'E') {
			c = ctx.read_char();
			text += c;
			int i = ctx.peek_char();
			if (i == '+') {
				c = ctx.read_char();
				text += c;
				i = ctx.peek_char();
			} else if (i == '-') {
				c = ctx.read_char();
				text += c;
				i = ctx.peek_char();
			}

			if (i < '0' || i > '9')
				ctx.throw_error("Digit expected");

			do {
				c = ctx.read_char();
				text += c;
				i = ctx.peek_char();
			} while (i >= '0' && i <= '9');
		}
		destruct_value();
		std::istringstream(text) >> value_real;
		type = DOUBLE;
	} else {
		if (text.size() > 1 && ((text[0] == '0') || (text[0] == '-' && text[1] == '0')))
			ctx.throw_error("Number expected");
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

void JsonValue::read_object(StreamContext &ctx) {
	char c = ctx.read_non_ws_char();
	JsonValue::Object value;

	if (c != '}') {
		std::string name;
		for (;;) {
			ctx.expect(c, '"');
			name = ctx.read_string_token();
			c    = ctx.read_non_ws_char();

			ctx.expect(c, ':');

			value[name].read_json(ctx);
			c = ctx.read_non_ws_char();

			if (c == '}')
				break;
			ctx.expect(c, ',');
			c = ctx.read_non_ws_char();
		}
	}
	*this = std::move(value);
}

void JsonValue::read_string(StreamContext &ctx) {
	String value = ctx.read_string_token();
	*this        = std::move(value);
}
}  // namespace common
