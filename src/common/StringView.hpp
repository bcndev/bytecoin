// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cassert>
#include <limits>
#include <string>

namespace common {

// 'StringView' is a pair of pointer to constant char and size.
// It is recommended to pass 'StringView' to procedures by value.
class StringView {
public:
	typedef char Char;
	typedef size_t Size;

	constexpr static Size INVALID = std::numeric_limits<Size>::max();

	StringView() : m_data(nullptr), m_size(0) {}

	StringView(const Char *data, Size size) : m_data(data), m_size(size) { assert(m_data != nullptr || m_size == 0); }

	template<Size size>
	StringView(const Char (&data)[size]) : m_data(data), m_size(size - 1) {
		assert(m_data != nullptr || m_size == 0);
	}

	StringView(const std::string &string) : m_data(string.data()), m_size(string.size()) {}

	explicit operator std::string() const { return std::string(m_data, m_size); }

	const Char *data() const { return m_data; }
	Size size() const { return m_size; }
	bool empty() const { return m_size == 0; }

	Char operator[](Size index) const {
		assert(index < m_size);
		return *(m_data + index);
	}
	Char at(Size index) const;

	const Char *begin() const { return m_data; }
	const Char *end() const { return m_data + m_size; }

	bool operator==(const StringView &other) const;
	bool operator!=(const StringView &other) const { return !(*this == other); }
	bool operator<(const StringView &other) const;
	bool operator<=(const StringView &other) const { return !(other < *this); }
	bool operator>(const StringView &other) const { return other < *this; }
	bool operator>=(const StringView &other) const { return !(*this < other); }

protected:
	const Char *m_data;
	Size m_size;
};
}
