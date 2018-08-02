// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "StringTools.hpp"
#include <stdexcept>

namespace common {

namespace {

const uint8_t character_values[256] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
}

std::string as_string(const void *data, size_t size) { return std::string(static_cast<const char *>(data), size); }

BinaryArray as_binary_array(const std::string &data) {
	auto data_ptr = reinterpret_cast<const uint8_t *>(data.data());
	return BinaryArray(data_ptr, data_ptr + data.size());
}

uint8_t from_hex(char character) {
	uint8_t value = character_values[static_cast<unsigned char>(character)];
	if (value > 0x0f) {
		throw std::runtime_error("from_hex: invalid character");
	}

	return value;
}

bool from_hex(char character, uint8_t &value) {
	if (character_values[static_cast<unsigned char>(character)] > 0x0f) {
		return false;
	}

	value = character_values[static_cast<unsigned char>(character)];
	return true;
}

size_t from_hex(const std::string &text, void *data, size_t buffer_size) {
	if ((text.size() & 1) != 0) {
		throw std::runtime_error("from_hex: invalid string size");
	}

	if (text.size() >> 1 > buffer_size) {
		throw std::runtime_error("from_hex: invalid buffer size");
	}

	for (size_t i = 0; i<text.size()>> 1; ++i) {
		static_cast<uint8_t *>(data)[i] = from_hex(text[i << 1]) << 4 | from_hex(text[(i << 1) + 1]);
	}

	return text.size() >> 1;
}

bool from_hex(const std::string &text, void *data, size_t buffer_size, size_t &size) {
	if ((text.size() & 1) != 0) {
		return false;
	}

	if (text.size() >> 1 > buffer_size) {
		return false;
	}

	for (size_t i = 0; i<text.size()>> 1; ++i) {
		uint8_t value1;
		if (!from_hex(text[i << 1], value1)) {
			return false;
		}

		uint8_t value2;
		if (!from_hex(text[(i << 1) + 1], value2)) {
			return false;
		}

		static_cast<uint8_t *>(data)[i] = value1 << 4 | value2;
	}

	size = text.size() >> 1;
	return true;
}

BinaryArray from_hex(const std::string &text) {
	if ((text.size() & 1) != 0) {
		throw std::runtime_error("from_hex: invalid string size");
	}

	BinaryArray data(text.size() >> 1);
	for (size_t i = 0; i < data.size(); ++i) {
		data[i] = from_hex(text[i << 1]) << 4 | from_hex(text[(i << 1) + 1]);
	}

	return data;
}

bool from_hex(const std::string &text, BinaryArray &data) {
	if ((text.size() & 1) != 0) {
		return false;
	}

	for (size_t i = 0; i<text.size()>> 1; ++i) {
		uint8_t value1;
		if (!from_hex(text[i << 1], value1)) {
			return false;
		}

		uint8_t value2;
		if (!from_hex(text[(i << 1) + 1], value2)) {
			return false;
		}

		data.push_back(value1 << 4 | value2);
	}

	return true;
}

std::string to_hex(const void *data, size_t size) {
	std::string text;
	for (size_t i = 0; i < size; ++i) {
		text += "0123456789abcdef"[static_cast<const uint8_t *>(data)[i] >> 4];
		text += "0123456789abcdef"[static_cast<const uint8_t *>(data)[i] & 15];
	}

	return text;
}

void append_hex(const void *data, size_t size, std::string &text) {
	for (size_t i = 0; i < size; ++i) {
		text += "0123456789abcdef"[static_cast<const uint8_t *>(data)[i] >> 4];
		text += "0123456789abcdef"[static_cast<const uint8_t *>(data)[i] & 15];
	}
}

std::string to_hex(const BinaryArray &data) {
	std::string text;
	for (size_t i = 0; i < data.size(); ++i) {
		text += "0123456789abcdef"[data[i] >> 4];
		text += "0123456789abcdef"[data[i] & 15];
	}

	return text;
}

void append_hex(const BinaryArray &data, std::string &text) {
	for (size_t i = 0; i < data.size(); ++i) {
		text += "0123456789abcdef"[data[i] >> 4];
		text += "0123456789abcdef"[data[i] & 15];
	}
}

std::string extract(std::string &text, char delimiter) {
	size_t delimiter_pos = text.find(delimiter);
	std::string sub_text;
	if (delimiter_pos != std::string::npos) {
		sub_text = text.substr(0, delimiter_pos);
		text     = text.substr(delimiter_pos + 1);
	} else {
		sub_text.swap(text);
	}

	return sub_text;
}

std::string extract(const std::string &text, char delimiter, size_t &offset) {
	size_t delimiter_pos = text.find(delimiter, offset);
	if (delimiter_pos != std::string::npos) {
		offset = delimiter_pos + 1;
		return text.substr(offset, delimiter_pos);
	} else {
		offset = text.size();
		return text.substr(offset);
	}
}
}
