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

#pragma once

#include <cassert>
#include <string>
#include <limits>

namespace common {

// 'StringView' is a pair of pointer to constant char and size.
// It is recommended to pass 'StringView' to procedures by value.
class StringView {
public:
	typedef char Char;
	typedef size_t Size;

	constexpr static Size INVALID = std::numeric_limits<Size>::max();

	StringView() : data(nullptr), size(0) {}

	StringView(const Char *stringData, Size stringSize) : data(stringData), size(stringSize) {
		assert(data != nullptr || size == 0);
	}

	template<Size stringSize> StringView(const Char(&stringData)[stringSize])
			: data(stringData), size(stringSize - 1) {
		assert(data != nullptr || size == 0);
	}

	StringView(const std::string &string) : data(string.data()), size(string.size()) {}

	explicit operator std::string() const { return std::string(data, size); }

	const Char *getData() const { return data; }
	Size getSize() const { return size; }
	bool isEmpty() const { return size == 0; }

	// Get 'StringView' element by index.
	// The behavior is undefined unless 'StringView' was initialized and 'index' < 'size'.
	const Char &operator[](Size index) const;

	// Get first element.
	// The behavior is undefined unless 'StringView' was initialized and 'size' > 0
	const Char &first() const;

	// Get last element.
	// The behavior is undefined unless 'StringView' was initialized and 'size' > 0
	const Char &last() const;

	const Char *begin() const { return data; }
	const Char *end() const { return data + size; }

	bool operator==(const StringView & other) const;
	bool operator!=(const StringView & other) const { return !(*this == other); }
	bool operator<(const StringView & other) const;
	bool operator<=(const StringView & other) const { return !(other < *this); }
	bool operator>(const StringView & other) const { return other < *this; }
	bool operator>=(const StringView & other) const { return !(*this < other); }

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
	// The behavior is undefined unless 'StringView' was initialized and 'headSize' <= 'size'.
	StringView head(Size headSize) const;

	// Returns substring of 'tailSize' last elements.
	// The behavior is undefined unless 'StringView' was initialized and 'tailSize' <= 'size'.
	StringView tail(Size tailSize) const;

	// Returns 'StringView' without 'headSize' first elements.
	// The behavior is undefined unless 'StringView' was initialized and 'headSize' <= 'size'.
	StringView unhead(Size headSize) const;

	// Returns 'StringView' without 'tailSize' last elements.
	// The behavior is undefined unless 'StringView' was initialized and 'tailSize' <= 'size'.
	StringView untail(Size tailSize) const;

	// Returns substring starting at 'startIndex' and contaning 'endIndex' - 'startIndex' elements.
	// The behavior is undefined unless 'StringView' was initialized and 'startIndex' <= 'endIndex' and 'endIndex' <= 'size'.
	StringView range(Size startIndex, Size endIndex) const;

	// Returns substring starting at 'startIndex' and contaning 'sliceSize' elements.
	// The behavior is undefined unless 'StringView' was initialized and 'startIndex' <= 'size' and 'startIndex' + 'sliceSize' <= 'size'.
	StringView slice(Size startIndex, Size sliceSize) const;

protected:
	const Char *data;
	Size size;
};

}
