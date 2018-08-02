// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "BinaryArray.hpp"
#include <stdexcept>
#include "Invariant.hpp"

namespace common {

// TODO - check self-inserts and other corner cases

BinaryArrayImpl::iterator BinaryArrayImpl::insert(iterator pos, const value_type *be, const value_type *en) {
	size_t left = pos - m_data;
	invariant(left <= m_size, "insert after the end");
	size_t right = m_size - left;
	size_t add   = en - be;
	if (m_size + add <= m_reserved) {
		good_memmove(m_data + left + add, m_data + left, right);
		good_memmove(m_data + left, be, add);
		m_size += add;
		return m_data + left;
	}
	BinaryArrayImpl other((m_size + add + 32) * 3 / 2);
	good_memmove(other.m_data, m_data, left);
	good_memmove(other.m_data + left + add, m_data + left, right);
	good_memmove(other.m_data + left, be, add);
	other.m_size = m_size + add;
	swap(other);
	return m_data + left;
}
BinaryArrayImpl::iterator BinaryArrayImpl::insert(iterator pos, size_t add, value_type va) {
	size_t left = pos - m_data;
	invariant(left <= m_size, "insert after the end");
	size_t right = m_size - left;
	if (m_size + add <= m_reserved) {
		good_memmove(m_data + left + add, m_data + left, right);
		memset(m_data + left, va, add);
		m_size += add;
		return m_data + left;
	}
	BinaryArrayImpl other((m_size + add + 32) * 3 / 2);
	good_memmove(other.m_data, m_data, left);
	good_memmove(other.m_data + left + add, m_data + left, right);
	memset(other.m_data + left, va, add);
	other.m_size = m_size + add;
	swap(other);
	return m_data + left;
}

void BinaryArrayImpl::reserve_grow(size_t re, bool more) {
	if (re <= m_reserved)
		return;
	BinaryArrayImpl other(more ? (re + 32) * 3 / 2 : re);
	good_memmove(other.m_data, m_data, m_size);
	other.m_size = m_size;
	swap(other);
}

void BinaryArrayImpl::reserve(size_t re) { reserve_grow(re, false); }

void BinaryArrayImpl::push_back(value_type va) {
	reserve_grow(m_size + 1, true);
	m_data[m_size] = va;
	m_size += 1;
}

void BinaryArrayImpl::assign(const value_type *be, const value_type *en) {
	size_t si = en - be;
	if (si <= m_reserved) {
		good_memmove(m_data, be, si);
		m_size = si;
		return;
	}
	BinaryArrayImpl other(be, en);
	swap(other);
}

void BinaryArrayImpl::resize(size_t si) {
	if (si <= m_reserved) {
		m_size = si;
		return;
	}
	BinaryArrayImpl other(si);
	good_memmove(other.m_data, m_data, m_size);
	swap(other);
}
void BinaryArrayImpl::resize(size_t si, value_type va) {
	if (si <= m_size) {
		m_size = si;
		return;
	}
	if (si <= m_reserved) {
		memset(m_data + m_size, va, si - m_size);
		m_size = si;
		return;
	}
	BinaryArrayImpl other(si);
	good_memmove(other.m_data, m_data, m_size);
	memset(other.m_data + m_size, va, si - m_size);
	swap(other);
}

const unsigned char *slow_memmem(const unsigned char *buf, size_t buflen, const unsigned char *pat, size_t patlen) {
	if (patlen == 0)
		return nullptr;
	while (buflen) {
		auto char_ptr = (const unsigned char *)memchr(buf, pat[0], buflen);
		if (char_ptr - buf + patlen > buflen)
			return nullptr;
		if (memcmp(char_ptr, pat, patlen) == 0)
			return char_ptr;
		buflen = buflen - (char_ptr - buf);
		buf    = char_ptr + 1;
	}
	return nullptr;
}
}
