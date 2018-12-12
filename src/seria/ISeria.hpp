// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <boost/optional.hpp>
#include <cstdint>
#include <list>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "common/BinaryArray.hpp"
#include "common/Int128.hpp"
#include "common/StringView.hpp"
#include "common/exception.hpp"
#include "common/string.hpp"

namespace seria {
class ISeria;

// template<typename T>
// void ser(T &value, ISeria &s);

class ISeria {
public:
	virtual ~ISeria() = default;

	virtual bool is_input() const = 0;

	virtual void begin_object()                                     = 0;
	virtual bool object_key(common::StringView name, bool optional) = 0;  // return true if key is there
	bool object_key(common::StringView name) { return object_key(name, false); }
	virtual void end_object() = 0;

	virtual void begin_map(size_t &size)         = 0;
	virtual void next_map_key(std::string &name) = 0;  // iterates through map when input serializer
	virtual void end_map()                       = 0;

	virtual void begin_array(size_t &size, bool fixed_size) = 0;
	void begin_array(size_t &size) { return begin_array(size, false); }
	// When we know array size from other field, we will skipping saving it
	virtual void end_array() = 0;

	virtual void seria_v(uint8_t &value)  = 0;
	virtual void seria_v(int16_t &value)  = 0;
	virtual void seria_v(uint16_t &value) = 0;
	virtual void seria_v(int32_t &value)  = 0;
	virtual void seria_v(uint32_t &value) = 0;
	virtual void seria_v(int64_t &value)  = 0;
	virtual void seria_v(uint64_t &value) = 0;
	//	virtual void seria_v(double &value)              = 0;
	virtual void seria_v(bool &value)                = 0;
	virtual bool seria_v(std::string &value)         = 0;
	virtual bool seria_v(common::BinaryArray &value) = 0;

	// read/write binary block
	virtual bool binary(void *value, size_t size) = 0;  // fixed width, no size written
};

inline void ser(uint8_t &value, ISeria &s) { return s.seria_v(value); }
inline void ser(int16_t &value, ISeria &s) { return s.seria_v(value); }
inline void ser(uint16_t &value, ISeria &s) { return s.seria_v(value); }
// Code below is a trick to solve the following problem
// seria_v is defined for uint32_t uint64_t, but in C++ there is 3 unsigned types - unsigned, unsigned long, unsigned
// long long
// so on some platforms size_t, uint32_t and uint64_t may be mapped to 3 distinct types. We need to select appropriate
// seria_v.
// Ultimate fix - rewrite ISeria in terms of basic integral types
template<typename T>
void ser_integral(T &value, ISeria &s, std::true_type) {
	s.seria_v(value);
}
template<typename T>
void ser_integral(T &value, ISeria &s, std::false_type) {
	static_assert(sizeof(T) == sizeof(uint32_t) || sizeof(T) == sizeof(uint64_t),
	    "This impl only selects between 32- and 64-bit types");
	typename std::conditional<sizeof(T) == sizeof(uint32_t), uint32_t, uint64_t>::type val = value;
	s.seria_v(val);
	if (s.is_input())
		value = val;
}
inline void ser(int32_t &value, ISeria &s) { return s.seria_v(value); }
inline void ser(int64_t &value, ISeria &s) { return s.seria_v(value); }
inline void ser(unsigned &value, ISeria &s) {
	ser_integral(value, s, std::integral_constant < bool,
	    std::is_same<unsigned, uint32_t>::value || std::is_same<unsigned, uint64_t>::value > {});
}
inline void ser(unsigned long &value, ISeria &s) {
	ser_integral(value, s, std::integral_constant < bool,
	    std::is_same<unsigned long, uint32_t>::value || std::is_same<unsigned long, uint64_t>::value > {});
}
inline void ser(unsigned long long &value, ISeria &s) {
	ser_integral(value, s, std::integral_constant < bool,
	    std::is_same<unsigned long long, uint32_t>::value || std::is_same<unsigned long long, uint64_t>::value > {});
}
// inline void ser(double &value, ISeria &s) { return s.seria_v(value); }
inline void ser(bool &value, ISeria &s) { return s.seria_v(value); }
inline void ser(std::string &value, ISeria &s) { s.seria_v(value); }
inline void ser(common::BinaryArray &value, ISeria &s) { s.seria_v(value); }

template<typename T, typename... Context>
void seria_kv(common::StringView name, T &value, ISeria &s, Context... context) {
	try {
		s.object_key(name);
		ser(value, s, context...);
	} catch (const std::exception &) {
		std::throw_with_nested(
		    std::runtime_error("Error while serializing object value for key '" + std::string(name) + "'"));
	}
}
template<typename T>
void seria_kv(common::StringView name, boost::optional<T> &value, ISeria &s) {
	try {
		if (s.is_input()) {
			if (s.object_key(name, true)) {
				value = T{};
				ser(value.get(), s);
			}
		} else {
			s.object_key(name, !value);
			T temp{};
			ser(value ? value.get() : temp, s);
		}
	} catch (const std::exception &) {
		std::throw_with_nested(
		    std::runtime_error("Error while serializing object value for key '" + std::string(name) + "'"));
	}
}
template<typename T>
void seria_kv_optional(common::StringView name, T &value, ISeria &s) {
	try {
		s.object_key(name, true);
		ser(value, s);
	} catch (const std::exception &) {
		std::throw_with_nested(
		    std::runtime_error("Error while serializing object value for key '" + std::string(name) + "'"));
	}
}

template<typename T, typename... Context>
void ser_members(T &value, ISeria &s, Context... context);  //{
//        static_assert(false); // Good idea, but clang complains
//    }

template<typename T, typename... Context>
void ser(T &value, ISeria &s, Context... context) {
	s.begin_object();
	ser_members(value, s, context...);
	s.end_object();
}
template<typename Cont, typename... Context>
void seria_container(Cont &value, ISeria &s, Context... context) {
	size_t size = value.size();
	s.begin_array(size);
	if (s.is_input())
		value.resize(size);
	size_t counter = 0;
	for (auto &item : value) {
		try {
			ser(const_cast<typename Cont::value_type &>(item), s, context...);
		} catch (const std::exception &) {
			std::throw_with_nested(
			    std::runtime_error("Error while serializing array element #" + common::to_string(counter)));
		}
		counter += 1;
	}
	s.end_array();
}

template<typename T, typename... Context>
void ser(std::vector<T> &value, ISeria &serializer, Context... context) {
	seria_container(value, serializer, context...);
}

template<typename T, typename... Context>
void ser(std::list<T> &value, ISeria &serializer, Context... context) {
	seria_container(value, serializer, context...);
}

template<typename MapT, typename... Context>
void seria_map_string(MapT &value, ISeria &s, Context... context) {
	size_t size = value.size();
	s.begin_map(size);
	if (s.is_input()) {
		for (size_t i = 0; i != size; ++i) {
			std::string k;
			try {
				s.next_map_key(k);
			} catch (const std::exception &) {
				std::throw_with_nested(std::runtime_error("Error while serializing map key #" + common::to_string(i)));
			}
			try {
				typename MapT::mapped_type v;
				ser(v, s, context...);
				value.insert(std::make_pair(std::move(k), std::move(v)));
			} catch (const std::exception &) {
				std::throw_with_nested(std::runtime_error("Error while serializing map value for key '" + k + "'"));
			}
		}
	} else {
		size_t counter = 0;
		for (auto &kv : value) {
			try {
				s.next_map_key(const_cast<std::string &>(kv.first));
				ser(const_cast<typename MapT::mapped_type &>(kv.second), s, context...);
			} catch (const std::exception &) {
				std::throw_with_nested(
				    std::runtime_error("Error while serializing map value for key '" + kv.first + "'"));
			}
			counter += 1;
		}
	}
	s.end_map();
}

template<typename MapT, typename... Context>
void seria_map_integral(MapT &value, ISeria &s, std::true_type, Context... context) {
	size_t size = value.size();
	s.begin_map(size);
	if (s.is_input()) {
		for (size_t i = 0; i != size; ++i) {
			std::string key;
			typename MapT::key_type k;
			try {
				s.next_map_key(key);
				k = static_cast<typename MapT::key_type>(common::stoll(key));
			} catch (const std::exception &) {
				std::throw_with_nested(std::runtime_error("Error while serializing map key #" + common::to_string(i)));
			}
			// We use widest possible conversion because no generic function provided in C++
			try {
				typename MapT::mapped_type v;
				ser(v, s, context...);
				value.insert(std::make_pair(k, std::move(v)));
			} catch (const std::exception &) {
				std::throw_with_nested(std::runtime_error("Error while serializing map value for key '" + key + "'"));
			}
		}
	} else {
		size_t counter = 0;
		for (auto &kv : value) {
			auto str_key = common::to_string(kv.first);
			try {
				s.next_map_key(const_cast<std::string &>(str_key));
				ser(const_cast<typename MapT::mapped_type &>(kv.second), s, context...);
			} catch (const std::exception &) {
				std::throw_with_nested(
				    std::runtime_error("Error while serializing map value for key '" + str_key + "'"));
			}
			counter += 1;
		}
	}
	s.end_map();
}

template<typename SetT>
void seria_set(SetT &value, ISeria &s) {
	size_t size = value.size();

	s.begin_array(size);
	if (s.is_input()) {
		for (size_t i = 0; i < size; ++i) {
			typename SetT::value_type key;
			try {
				ser(key, s);
				value.insert(std::move(key));
			} catch (const std::exception &) {
				std::throw_with_nested(
				    std::runtime_error("Error while serializing set element #" + common::to_string(i)));
			}
		}
	} else {
		size_t counter = 0;
		for (auto &key : value) {
			try {
				ser(const_cast<typename SetT::value_type &>(key), s);
			} catch (const std::exception &) {
				std::throw_with_nested(
				    std::runtime_error("Error while serializing set element #" + common::to_string(counter)));
			}
			counter += 1;
		}
	}
	s.end_array();
}

template<typename K, typename Hash>
void ser(std::unordered_set<K, Hash> &value, ISeria &s) {
	return seria_set(value, s);
}
template<typename K, typename Cmp>
void ser(std::set<K, Cmp> &value, ISeria &s) {
	return seria_set(value, s);
}
template<typename V, typename Hash, typename... Context>
void ser(std::unordered_map<std::string, V, Hash> &value, ISeria &s, Context... context) {
	return seria_map_string(value, s, context...);
}
template<typename K, typename V, typename Hash, typename... Context>
void ser(std::unordered_map<K, V, Hash> &value, ISeria &s, Context... context) {
	return seria_map_integral(value, s, std::is_integral<K>(), context...);
}
template<typename V, typename Hash, typename... Context>
void ser(std::map<std::string, V, Hash> &value, ISeria &s, Context... context) {
	return seria_map_string(value, s, context...);
}
template<typename K, typename V, typename Hash, typename... Context>
void ser(std::map<K, V, Hash> &value, ISeria &s, Context... context) {
	return seria_map_integral(value, s, std::is_integral<K>(), context...);
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
	s.binary(value.data(), value.size());
}
template<typename T1, typename T2>
void ser_members(std::pair<T1, T2> &value, ISeria &s) {
	seria_kv("first", value.first, s);
	seria_kv("second", value.second, s);
}
}  // namespace seria
