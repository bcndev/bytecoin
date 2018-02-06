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

#include "StringTools.hpp"
#include "platform/Files.hpp"
#include <boost/lexical_cast.hpp>

namespace common {

namespace {

const uint8_t characterValues[256] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

}

std::string as_string(const void *data, size_t size) {
	return std::string(static_cast<const char *>(data), size);
}

BinaryArray as_binary_array(const std::string &data) {
	auto dataPtr = reinterpret_cast<const uint8_t *>(data.data());
	return BinaryArray(dataPtr, dataPtr + data.size());
}

uint8_t from_hex(char character) {
	uint8_t value = characterValues[static_cast<unsigned char>(character)];
	if (value > 0x0f) {
		throw std::runtime_error("fromHex: invalid character");
	}

	return value;
}

bool from_hex(char character, uint8_t &value) {
	if (characterValues[static_cast<unsigned char>(character)] > 0x0f) {
		return false;
	}

	value = characterValues[static_cast<unsigned char>(character)];
	return true;
}

size_t from_hex(const std::string &text, void *data, size_t bufferSize) {
	if ((text.size() & 1) != 0) {
		throw std::runtime_error("fromHex: invalid string size");
	}

	if (text.size() >> 1 > bufferSize) {
		throw std::runtime_error("fromHex: invalid buffer size");
	}

	for (size_t i = 0; i < text.size() >> 1; ++i) {
		static_cast<uint8_t *>(data)[i] = from_hex(text[i << 1]) << 4 | from_hex(text[(i << 1) + 1]);
	}

	return text.size() >> 1;
}

bool from_hex(const std::string &text, void *data, size_t bufferSize, size_t &size) {
	if ((text.size() & 1) != 0) {
		return false;
	}

	if (text.size() >> 1 > bufferSize) {
		return false;
	}

	for (size_t i = 0; i < text.size() >> 1; ++i) {
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
		throw std::runtime_error("fromHex: invalid string size");
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

	for (size_t i = 0; i < text.size() >> 1; ++i) {
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
	size_t delimiterPosition = text.find(delimiter);
	std::string subText;
	if (delimiterPosition != std::string::npos) {
		subText = text.substr(0, delimiterPosition);
		text = text.substr(delimiterPosition + 1);
	} else {
		subText.swap(text);
	}

	return subText;
}

std::string extract(const std::string &text, char delimiter, size_t &offset) {
	size_t delimiterPosition = text.find(delimiter, offset);
	if (delimiterPosition != std::string::npos) {
		offset = delimiterPosition + 1;
		return text.substr(offset, delimiterPosition);
	} else {
		offset = text.size();
		return text.substr(offset);
	}
}

bool load_file(const std::string &filepath, std::string &buf) {
	try {
		platform::FileStream fs(filepath, platform::FileStream::READ_EXISTING);
		size_t fileSize = boost::lexical_cast<size_t>(fs.seek(0, SEEK_END));
		fs.seek(0, SEEK_SET);
		buf.resize(fileSize);
		fs.read(&buf[0], buf.size());
	} catch (const std::exception &) {
		return false;
	}
	return true;
}

bool load_file(const std::string &filepath, BinaryArray &buf) {
	try {
		platform::FileStream fs(filepath, platform::FileStream::READ_EXISTING);
		size_t fileSize = boost::lexical_cast<size_t>(fs.seek(0, SEEK_END));
		fs.seek(0, SEEK_SET);
		buf.resize(fileSize);
		fs.read(buf.data(), buf.size());
	} catch (const std::exception &) {
		return false;
	}
	return true;
}

bool save_file(const std::string &filepath, const void *buf, size_t size) {
	try {
		platform::FileStream fs(filepath, platform::FileStream::TRUNCATE_READ_WRITE);
		fs.write(buf, size);
	} catch (const std::exception &) {
		return false;
	}
	return true;
}

}
