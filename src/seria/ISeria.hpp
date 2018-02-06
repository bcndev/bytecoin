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

#include <string>
#include <cstdint>
#include <vector>
#include <list>
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>

#include "common/StringView.hpp"
#include "common/BinaryArray.hpp"

namespace seria {
class ISeria;

template<typename T>
void ser(T &value, ISeria &s);

class ISeria {
public:
	virtual ~ISeria() {}

	virtual bool isInput() const = 0;

	virtual void beginObject() = 0;
	virtual void objectKey(common::StringView name) = 0; // throw if key not found
	virtual void endObject() = 0;

	virtual void beginMap(size_t &size) = 0;
	virtual void nextMapKey(std::string &name) = 0; // iterates through map when input serializer
	virtual void endMap() = 0;

	virtual void beginArray(size_t &size, bool fixed_size = false) = 0; // When we know array size from other field, we will skipping saving it
	virtual void endArray() = 0;

	virtual void seria_v(uint8_t &value) = 0;
	virtual void seria_v(int16_t &value) = 0;
	virtual void seria_v(uint16_t &value) = 0;
	virtual void seria_v(int32_t &value) = 0;
	virtual void seria_v(uint32_t &value) = 0;
	virtual void seria_v(int64_t &value) = 0;
	virtual void seria_v(uint64_t &value) = 0;
	virtual void seria_v(double &value) = 0;
	virtual void seria_v(bool &value) = 0;
	virtual void seria_v(std::string &value) = 0;
	virtual void seria_v(common::BinaryArray &value) = 0;

	// read/write binary block
	virtual void binary(void *value, size_t size) = 0; // fixed width, no size written

	template<typename T>
	void operator()(T &value) {
		ser(value, *this);
	}
};

inline void ser(uint8_t &value, ISeria &s) {
	return s.seria_v(value);
}
inline void ser(int16_t &value, ISeria &s) {
	return s.seria_v(value);
}
inline void ser(uint16_t &value, ISeria &s) {
	return s.seria_v(value);
}
// Code below is a trick to solve the following problem
// seria_v is defined for uint32_t uint64_t, but in C++ there is 3 unsigned types - unsigned, unsigned long, unsigned long long
// so on some platforms size_t, uint32_t and uint64_t may be mapped to 3 distinct types. We need to select appropriate seria_v.
// Ultimate fix - rewrite ISeria in terms of basic integral types
template<typename T>
void serIntegral(T & value, ISeria &s, std::true_type){
	s.seria_v(value);
}
template<typename T>
void serIntegral(T & value, ISeria &s, std::false_type){
	static_assert(sizeof(T)==sizeof(uint32_t) || sizeof(T)==sizeof(uint64_t), "This impl only selects between 32- and 64-bit types");
	typename std::conditional<sizeof(T)==sizeof(uint32_t), uint32_t, uint64_t>::type val = value;
	s.seria_v(val);
	if( s.isInput() )
		value = val;
}
inline void ser(int32_t &value, ISeria &s) {
	return s.seria_v(value);
}
inline void ser(int64_t &value, ISeria &s) {
	return s.seria_v(value);
}
inline void ser(unsigned &value, ISeria &s) {
	serIntegral(value, s, std::integral_constant<bool, std::is_same<unsigned, uint32_t>::value || std::is_same<unsigned, uint64_t>::value>{});
}
inline void ser(unsigned long &value, ISeria &s) {
	serIntegral(value, s, std::integral_constant<bool, std::is_same<unsigned long, uint32_t>::value || std::is_same<unsigned long, uint64_t>::value>{});
}
inline void ser(unsigned long long &value, ISeria &s) {
	serIntegral(value, s, std::integral_constant<bool, std::is_same<unsigned long long, uint32_t>::value || std::is_same<unsigned long long, uint64_t>::value>{});
}
inline void ser(double &value, ISeria &s) {
	return s.seria_v(value);
}
inline void ser(bool &value, ISeria &s) {
	return s.seria_v(value);
}
inline void ser(std::string &value, ISeria &s) {
	return s.seria_v(value);
}
inline void ser(common::BinaryArray &value, ISeria &s) {
	return s.seria_v(value);
}

template<typename T>
void seria_kv(common::StringView name, T &value, ISeria &s) {
	s.objectKey(name);
	s(value);
}

template<typename T>
void serMembers(T &value, ISeria &s);//{
//        static_assert(false); // Good idea, but clang complains
//    }

template<typename T>
void ser(T &value, ISeria &s) {
	s.beginObject();
	serMembers(value, s);
	s.endObject();
}
template<typename Cont>
void seriaContainer(Cont &value, ISeria &s) {
	size_t size = value.size();
	s.beginArray(size);
	if (s.isInput())
		value.resize(size);
	for (auto &item : value) {
		s(const_cast<typename Cont::value_type &>(item));
	}
	s.endArray();
}

template<typename T>
void ser(std::vector<T> &value, ISeria &serializer) {
	seriaContainer(value, serializer);
}

template<typename T>
void ser(std::list<T> &value, ISeria &serializer) {
	seriaContainer(value, serializer);
}

template<typename MapT>
void seriaMapString(MapT &value, ISeria &s) {
	size_t size = value.size();
	s.beginMap(size);
	if (s.isInput()) {
		for (size_t i = 0; i != size; ++i) {
			std::string k;
			typename MapT::mapped_type v;
			s.nextMapKey(k);
			s(v);
			value.insert(std::make_pair(std::move(k), std::move(v)));
		}
	} else {
		for (auto &kv : value) {
			s.nextMapKey(const_cast<std::string &>(kv.first));
			s(const_cast<typename MapT::mapped_type &>(kv.second));
		}
	}
	s.endMap();
}

template<typename MapT>
void seriaMapIntegral(MapT &value, ISeria &s, std::true_type) {
	size_t size = value.size();
	s.beginMap(size);
	if (s.isInput()) {
		for (size_t i = 0; i != size; ++i) {
			std::string key;
			s.nextMapKey(key);
			typename MapT::key_type k = static_cast<typename MapT::key_type>(std::stoll(key)); // We use widest possible because no generic function provided in C++
			typename MapT::mapped_type v;
			s(v);
			value.insert(std::make_pair(k, std::move(v)));
		}
	} else {
		for (auto &kv : value) {
			auto str_key = std::to_string(kv.first);
			s.nextMapKey(const_cast<std::string &>(str_key));
			s(const_cast<typename MapT::mapped_type &>(kv.second));
		}
	}
	s.endMap();
}

template<typename SetT>
void seriaSet(SetT &value, ISeria &s) {
	size_t size = value.size();

	s.beginArray(size);
	if (s.isInput()) {
		for (size_t i = 0; i < size; ++i) {
			typename SetT::value_type key;
			s(key);
			value.insert(std::move(key));
		}
	} else {
		for (auto &key : value) {
			s(const_cast<typename SetT::value_type &>(key));
		}
	}
	s.endArray();
}

template<typename K, typename Hash>
void ser(std::unordered_set<K, Hash> &value, ISeria &s) {
	return seriaSet(value, s);
}
template<typename K, typename Cmp>
void ser(std::set<K, Cmp> &value, ISeria &s) {
	return seriaSet(value, s);
}
template<typename V, typename Hash>
void ser(std::unordered_map<std::string, V, Hash> &value, ISeria &s) {
	return seriaMapString(value, s);
}
template<typename K, typename V, typename Hash>
void ser(std::unordered_map<K, V, Hash> &value, ISeria &s) {
	return seriaMapIntegral(value, s, std::is_integral<K>());
}
template<typename V, typename Hash>
void ser(std::map<std::string, V, Hash> &value, ISeria &s) {
	return seriaMapString(value, s);
}
template<typename K, typename V, typename Hash>
void ser(std::map<K, V, Hash> &value, ISeria &s) {
	return seriaMapIntegral(value, s, std::is_integral<K>());
}
//  Impossible to directly map to Json. Consider using map<K, set<V>> or map<K, vector<V>> instead
//     template<typename V, typename Hash>
//    void ser(std::multimap<std::string, V, Hash>& value, ISeria& s);
//    template<typename K, typename V, typename Hash>
//    void ser(std::multimap<K, V, Hash>& value, ISeria& s);
//    template<typename V, typename Hash>
//    void ser(std::unordered_multimap<std::string, V, Hash>& value, ISeria& s);
//    template<typename K, typename V, typename Hash>
//    void ser(std::unordered_multimap<K, V, Hash>& value, ISeria& s)
template<size_t size>
void ser(std::array<uint8_t, size> &value, ISeria &s) {
	return s.binary(value.data(), value.size());
}
template<typename T1, typename T2>
void serMembers(std::pair<T1, T2> &value, ISeria &s) {
	s.objectKey("first");
	s(value.first);
	s.objectKey("second");
	s(value.second);
}
}
