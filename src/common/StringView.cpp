// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include "StringView.hpp"
#include <algorithm>
#include <cstring>
#include <limits>

namespace common {

StringView::Char StringView::operator[](Size index) const {
	assert(index < m_size);
	return *(m_data + index);
}

StringView::Char StringView::front() const {
	assert(m_size > 0);
	return *m_data;
}

StringView::Char StringView::back() const {
	assert(m_size > 0);
	return *(m_data + (m_size - 1));
}

bool StringView::operator==(const StringView &other) const {
	if (m_size != other.m_size)
		return false;
	if (other.m_size == 0)
		return true;
	return memcmp(m_data, other.m_data, m_size) == 0;
}

bool StringView::operator<(const StringView &other) const {
	size_t common_size = std::min(m_size, other.m_size);
	int res            = memcmp(m_data, other.m_data, common_size);
	if (res != 0)
		return res < 0;
	return m_size < other.m_size;
}
/*
bool StringView::beginsWith(const Char &object) const {
    if (m_size == 0)
        return false;
    return *m_data == object;
}

bool StringView::beginsWith(StringView other) const {
    if (m_size >= other.m_size) {
        for (Size i = 0;; ++i) {
            if (i == other.m_size) {
                return true;
            }
            if (!(*(m_data + i) == *(other.m_data + i))) {
                break;
            }
        }
    }
    return false;
}

bool StringView::contains(const Char &object) const {
    for (Size i = 0; i < m_size; ++i) {
        if (*(m_data + i) == object) {
            return true;
        }
    }
    return false;
}

bool StringView::contains(StringView other) const {
    if (m_size >= other.m_size) {
        Size i = m_size - other.m_size;
        for (Size j = 0; !(i < j); ++j) {
            for (Size k = 0;; ++k) {
                if (k == other.m_size) {
                    return true;
                }
                if (!(*(m_data + j + k) == *(other.m_data + k))) {
                    break;
                }
            }
        }
    }
    return false;
}

bool StringView::endsWith(const Char &object) const {
    if (m_size == 0)
        return false;
    return *(m_data + (m_size - 1)) == object;
}

bool StringView::endsWith(StringView other) const {
    if (m_size >= other.m_size) {
        Size i = m_size - other.m_size;
        for (Size j = 0;; ++j) {
            if (j == other.m_size) {
                return true;
            }
            if (!(*(m_data + i + j) == *(other.m_data + j))) {
                break;
            }
        }
    }
    return false;
}

StringView::Size StringView::find(const Char &object) const {
    for (Size i = 0; i < m_size; ++i) {
        if (*(m_data + i) == object) {
            return i;
        }
    }
    return INVALID;
}

StringView::Size StringView::find(StringView other) const {
    if (m_size >= other.m_size) {
        Size i = m_size - other.m_size;
        for (Size j = 0; !(i < j); ++j) {
            for (Size k = 0;; ++k) {
                if (k == other.m_size) {
                    return j;
                }
                if (!(*(m_data + j + k) == *(other.m_data + k))) {
                    break;
                }
            }
        }
    }
    return INVALID;
}

StringView::Size StringView::findLast(const Char &object) const {
    for (Size i = 0; i < m_size; ++i) {
        if (*(m_data + (m_size - 1 - i)) == object) {
            return m_size - 1 - i;
        }
    }
    return INVALID;
}

StringView::Size StringView::findLast(StringView other) const {
    if (m_size >= other.m_size) {
        Size i = m_size - other.m_size;
        for (Size j = 0; !(i < j); ++j) {
            for (Size k = 0;; ++k) {
                if (k == other.m_size) {
                    return i - j;
                }
                if (!(*(m_data + (i - j + k)) == *(other.m_data + k))) {
                    break;
                }
            }
        }
    }
    return INVALID;
}

StringView StringView::head(Size headSize) const {
    assert(headSize <= m_size);
    return StringView(m_data, headSize);
}

StringView StringView::tail(Size tailSize) const {
    assert(tailSize <= m_size);
    return StringView(m_data + (m_size - tailSize), tailSize);
}

StringView StringView::unhead(Size headSize) const {
    assert(headSize <= m_size);
    return StringView(m_data + headSize, m_size - headSize);
}

StringView StringView::untail(Size tailSize) const {
    assert(tailSize <= m_size);
    return StringView(m_data, m_size - tailSize);
}

StringView StringView::range(Size startIndex, Size endIndex) const {
    assert(startIndex <= endIndex && endIndex <= m_size);
    return StringView(m_data + startIndex, endIndex - startIndex);
}

StringView StringView::slice(Size startIndex, Size sliceSize) const {
    assert(startIndex <= m_size && startIndex + sliceSize <= m_size);
    return StringView(m_data + startIndex, sliceSize);
}
 */
}
