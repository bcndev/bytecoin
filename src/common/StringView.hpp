// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

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

	StringView(const Char *stringData, Size stringSize) : m_data(stringData), m_size(stringSize) {
		assert(m_data != nullptr || m_size == 0);
	}

	template<Size stringSize>
	StringView(const Char (&stringData)[stringSize]) : m_data(stringData), m_size(stringSize - 1) {
		assert(m_data != nullptr || m_size == 0);
	}

	StringView(const std::string &string) : m_data(string.data()), m_size(string.size()) {}

	explicit operator std::string() const { return std::string(m_data, m_size); }

	const Char *data() const { return m_data; }
	Size size() const { return m_size; }
	bool empty() const { return m_size == 0; }

	// Get 'StringView' element by index.
	// The behavior is undefined unless 'StringView' was initialized and 'index' < 'm_size'.
	Char operator[](Size index) const;

	// Get first element.
	// The behavior is undefined unless 'StringView' was initialized and 'm_size' > 0
	Char front() const;

	// Get last element.
	// The behavior is undefined unless 'StringView' was initialized and 'm_size' > 0
	Char back() const;

	const Char *begin() const { return m_data; }
	const Char *end() const { return m_data + m_size; }

	bool operator==(const StringView &other) const;
	bool operator!=(const StringView &other) const { return !(*this == other); }
	bool operator<(const StringView &other) const;
	bool operator<=(const StringView &other) const { return !(other < *this); }
	bool operator>(const StringView &other) const { return other < *this; }
	bool operator>=(const StringView &other) const { return !(*this < other); }
	/*
	    // Return false if 'StringView' does not contain 'object' at the beginning.
	    // The behavior is undefined unless 'StringView' was initialized.
	    bool beginsWith(const Char &object) const;

	    // Return false if 'StringView' does not contain 'other' at the beginning.
	    // The behavior is undefined unless both strings were initialized.
	    bool beginsWith(StringView other) const;

	    // Return false if 'StringView' does not contain 'object'.
	    // The behavior is undefined unless 'StringView' was initialized.
	    bool contains(const Char &object) const;

	    // Return false if 'StringView' does not contain 'other'.
	    // The behavior is undefined unless both strings were initialized.
	    bool contains(StringView other) const;

	    // Return false if 'StringView' does not contain 'object' at the end.
	    // The behavior is undefined unless 'StringView' was initialized.
	    bool endsWith(const Char &object) const;

	    // Return false if 'StringView' does not contain 'other' at the end.
	    // The behavior is undefined unless both strings were initialized.
	    bool endsWith(StringView other) const;

	    // Looks for the first occurence of 'object' in 'StringView',
	    // returns index or INVALID if there are no occurences.
	    // The behavior is undefined unless 'StringView' was initialized.
	    Size find(const Char &object) const;

	    // Looks for the first occurence of 'other' in 'StringView',
	    // returns index or INVALID if there are no occurences.
	    // The behavior is undefined unless both strings were initialized.
	    Size find(StringView other) const;

	    // Looks for the last occurence of 'object' in 'StringView',
	    // returns index or INVALID if there are no occurences.
	    // The behavior is undefined unless 'StringView' was initialized.
	    Size findLast(const Char &object) const;

	    // Looks for the first occurence of 'other' in 'StringView',
	    // returns index or INVALID if there are no occurences.
	    // The behavior is undefined unless both strings were initialized.
	    Size findLast(StringView other) const;

	    // Returns substring of 'headSize' first elements.
	    // The behavior is undefined unless 'StringView' was initialized and 'headSize' <= 'm_size'.
	    StringView head(Size headSize) const;

	    // Returns substring of 'tailSize' last elements.
	    // The behavior is undefined unless 'StringView' was initialized and 'tailSize' <= 'm_size'.
	    StringView tail(Size tailSize) const;

	    // Returns 'StringView' without 'headSize' first elements.
	    // The behavior is undefined unless 'StringView' was initialized and 'headSize' <= 'm_size'.
	    StringView unhead(Size headSize) const;

	    // Returns 'StringView' without 'tailSize' last elements.
	    // The behavior is undefined unless 'StringView' was initialized and 'tailSize' <= 'm_size'.
	    StringView untail(Size tailSize) const;

	    // Returns substring starting at 'startIndex' and contaning 'endIndex' - 'startIndex' elements.
	    // The behavior is undefined unless 'StringView' was initialized and 'startIndex' <= 'endIndex' and 'endIndex'
	   <=
	    // 'm_size'.
	    StringView range(Size startIndex, Size endIndex) const;

	    // Returns substring starting at 'startIndex' and contaning 'sliceSize' elements.
	    // The behavior is undefined unless 'StringView' was initialized and 'startIndex' <= 'm_size' and 'startIndex' +
	    // 'sliceSize' <= 'm_size'.
	    StringView slice(Size startIndex, Size sliceSize) const;
	*/
protected:
	const Char *m_data;
	Size m_size;
};
}
