// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "StringView.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace common {

StringView::Char StringView::at(Size index) const {
	if (index >= m_size)
		throw std::out_of_range("StringView::at");
	return (*this)[index];
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
}
