// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <string.h>
#include <cstddef>
#include <initializer_list>
#include <utility>

namespace common {

class BinaryArrayImpl {
public:
	typedef unsigned char value_type;
	typedef value_type *iterator;
	typedef const value_type *const_iterator;
	BinaryArrayImpl() {}
	~BinaryArrayImpl() { delete[] m_data; }
	explicit BinaryArrayImpl(size_t si) { alloc(si); }
	explicit BinaryArrayImpl(size_t si, value_type va) {
		alloc(si);
		memset(m_data, va, si);
	}
	explicit BinaryArrayImpl(std::initializer_list<value_type> li) {
		alloc(li.size());
		memmove(m_data, li.begin(), li.size());
	}
	explicit BinaryArrayImpl(const value_type *be, const value_type *en) {
		alloc(en - be);
		good_memmove(m_data, be, en - be);
	}
	explicit BinaryArrayImpl(const char *be, const char *en) {
		alloc(en - be);
		good_memmove(m_data, be, en - be);
	}
	BinaryArrayImpl(const BinaryArrayImpl &other) {
		alloc(other.size());
		good_memmove(m_data, other.m_data, m_size);
	}
	void swap(BinaryArrayImpl &other) {
		std::swap(m_data, other.m_data);
		std::swap(m_size, other.m_size);
		std::swap(m_reserved, other.m_reserved);
	}
	BinaryArrayImpl(BinaryArrayImpl &&other) { swap(other); }
	BinaryArrayImpl &operator=(const BinaryArrayImpl &other) {
		BinaryArrayImpl copy(other);
		swap(copy);
		return *this;
	}
	BinaryArrayImpl &operator=(BinaryArrayImpl &&other) {
		swap(other);
		return *this;
	}
	size_t size() const { return m_size; }
	size_t empty() const { return size() == 0; }
	const value_type *data() const { return m_data; }
	value_type *data() { return m_data; }
	const_iterator begin() const { return m_data; }
	iterator begin() { return m_data; }
	const_iterator end() const { return m_data + m_size; }
	iterator end() { return m_data + m_size; }
	value_type &operator[](size_t i) { return m_data[i]; }
	const value_type &operator[](size_t i) const { return m_data[i]; }
	void clear() { resize(0); }
	void resize(size_t si);
	void resize(size_t si, value_type va);
	void reserve(size_t re);
	void assign(const value_type *be, const value_type *en);
	void assign(const char *be, const char *en) {
		return assign(reinterpret_cast<const value_type *>(be), reinterpret_cast<const value_type *>(en));
	}
	void push_back(value_type va);
	iterator insert(iterator pos, const value_type *be, const value_type *en);
	iterator insert(iterator pos, size_t add, value_type va);

	bool operator==(const BinaryArrayImpl &other) const {
		return m_size == other.m_size && memcmp(m_data, other.m_data, m_size) == 0;
	}
	bool operator!=(const BinaryArrayImpl &other) const { return !(*this == other); }
	ptrdiff_t compare(const BinaryArrayImpl &other) const {
		int diff = memcmp(m_data, other.m_data, m_size < other.m_size ? m_size : other.m_size);  // We avoid std::min
		return diff != 0 ? static_cast<ptrdiff_t>(diff)
		                 : static_cast<ptrdiff_t>(m_size) - static_cast<ptrdiff_t>(other.m_size);
	}
	bool operator<(const BinaryArrayImpl &other) const { return compare(other) < 0; }
	bool operator<=(const BinaryArrayImpl &other) const { return compare(other) <= 0; }
	bool operator>(const BinaryArrayImpl &other) const { return compare(other) > 0; }
	bool operator>=(const BinaryArrayImpl &other) const { return compare(other) >= 0; }

private:
	value_type *m_data = nullptr;
	size_t m_size      = 0;
	size_t m_reserved  = 0;
	void reserve_grow(size_t re, bool more);
	void alloc(size_t si) {
		m_size = m_reserved = si;
		m_data              = new value_type[m_reserved];
	}
	void good_memmove(void *dst, const void *src, size_t size) {
		if (size != 0)  // We have src == nullptr when size == 0, this combination is prohibited by C++ standard
			memmove(dst, src, size);
	}
};

// typedef std::vector<uint8_t> BinaryArray;
typedef BinaryArrayImpl BinaryArray;

template<class It>
inline BinaryArray::iterator append(BinaryArray &ba, It be, It en) {
	return ba.insert(ba.end(), be, en);
}
inline BinaryArray::iterator append(BinaryArray &ba, size_t add, BinaryArray::value_type va) {
	return ba.insert(ba.end(), add, va);
}

const unsigned char *slow_memmem(const unsigned char *buf, size_t buflen, const unsigned char *pat, size_t patlen);
}
