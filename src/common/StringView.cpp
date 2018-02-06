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

#include "StringView.hpp"
#include <limits>
#include <cstring>
#include <algorithm>

namespace common {

const StringView::Char &StringView::operator[](Size index) const {
	assert(index < size);
	return *(data + index);
}

const StringView::Char &StringView::first() const {
	assert(size > 0);
	return *data;
}

const StringView::Char &StringView::last() const {
	assert(size > 0);
	return *(data + (size - 1));
}

bool StringView::operator==(const StringView & other) const {
	if (size != other.size)
		return false;
	if (other.size == 0)
		return true;
	return memcmp(data, other.data, size) == 0;
}

bool StringView::operator<(const StringView & other) const {
	size_t common_size = std::min(size, other.size);
	int res = memcmp(data, other.data, common_size);
	if( res != 0)
		return res < 0;
	return size < other.size;
}

bool StringView::beginsWith(const Char &object) const {
	if (size == 0)
		return false;
	return *data == object;
}

bool StringView::beginsWith(StringView other) const {
	if (size >= other.size) {
		for (Size i = 0;; ++i) {
			if (i == other.size) {
				return true;
			}
			if (!(*(data + i) == *(other.data + i))) {
				break;
			}
		}
	}
	return false;
}

bool StringView::contains(const Char &object) const {
	for (Size i = 0; i < size; ++i) {
		if (*(data + i) == object) {
			return true;
		}
	}
	return false;
}

bool StringView::contains(StringView other) const {
	if (size >= other.size) {
		Size i = size - other.size;
		for (Size j = 0; !(i < j); ++j) {
			for (Size k = 0;; ++k) {
				if (k == other.size) {
					return true;
				}
				if (!(*(data + j + k) == *(other.data + k))) {
					break;
				}
			}
		}
	}
	return false;
}

bool StringView::endsWith(const Char &object) const {
	if (size == 0)
		return false;
	return *(data + (size - 1)) == object;
}

bool StringView::endsWith(StringView other) const {
	if (size >= other.size) {
		Size i = size - other.size;
		for (Size j = 0;; ++j) {
			if (j == other.size) {
				return true;
			}
			if (!(*(data + i + j) == *(other.data + j))) {
				break;
			}
		}
	}
	return false;
}

StringView::Size StringView::find(const Char &object) const {
	for (Size i = 0; i < size; ++i) {
		if (*(data + i) == object) {
			return i;
		}
	}
	return INVALID;
}

StringView::Size StringView::find(StringView other) const {
	if (size >= other.size) {
		Size i = size - other.size;
		for (Size j = 0; !(i < j); ++j) {
			for (Size k = 0;; ++k) {
				if (k == other.size) {
					return j;
				}
				if (!(*(data + j + k) == *(other.data + k))) {
					break;
				}
			}
		}
	}
	return INVALID;
}

StringView::Size StringView::findLast(const Char &object) const {
	for (Size i = 0; i < size; ++i) {
		if (*(data + (size - 1 - i)) == object) {
			return size - 1 - i;
		}
	}
	return INVALID;
}

StringView::Size StringView::findLast(StringView other) const {
	if (size >= other.size) {
		Size i = size - other.size;
		for (Size j = 0; !(i < j); ++j) {
			for (Size k = 0;; ++k) {
				if (k == other.size) {
					return i - j;
				}
				if (!(*(data + (i - j + k)) == *(other.data + k))) {
					break;
				}
			}
		}
	}
	return INVALID;
}

StringView StringView::head(Size headSize) const {
	assert(headSize <= size);
	return StringView(data, headSize);
}

StringView StringView::tail(Size tailSize) const {
	assert(tailSize <= size);
	return StringView(data + (size - tailSize), tailSize);
}

StringView StringView::unhead(Size headSize) const {
	assert(headSize <= size);
	return StringView(data + headSize, size - headSize);
}

StringView StringView::untail(Size tailSize) const {
	assert(tailSize <= size);
	return StringView(data, size - tailSize);
}

StringView StringView::range(Size startIndex, Size endIndex) const {
	assert(startIndex <= endIndex && endIndex <= size);
	return StringView(data + startIndex, endIndex - startIndex);
}

StringView StringView::slice(Size startIndex, Size sliceSize) const {
	assert(startIndex <= size && startIndex + sliceSize <= size);
	return StringView(data + startIndex, sliceSize);
}

}
