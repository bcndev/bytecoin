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
#include "common/Math.hpp"
#include "common/StringTools.hpp"
#include "common/StringView.hpp"
#include "common/exception.hpp"
#include "common/string.hpp"

namespace seria {
class ISeria;

class ISeria {
	bool is_input_value;  // optimization
protected:
	explicit ISeria(bool iv) : is_input_value(iv) {}

public:
	virtual ~ISeria() = default;

	bool is_input() const { return is_input_value; }

	virtual bool begin_object()                                     = 0;
	virtual void object_key(common::StringView name, bool optional) = 0;
	void object_key(common::StringView name) { object_key(name, is_input_value); }  // optional when input
	virtual void end_object() = 0;

	virtual bool begin_map(size_t &size)         = 0;
	virtual void next_map_key(std::string &name) = 0;  // iterates through map when input serializer
	virtual void end_map()                       = 0;

	virtual bool begin_array(size_t &size, bool fixed_size) = 0;
	bool begin_array(size_t &size) { return begin_array(size, false); }
	// When we know array size from other field, we will skipping saving it
	virtual void end_array() = 0;

	virtual bool seria_v(uint64_t &value)            = 0;
	virtual bool seria_v(int64_t &value)             = 0;
	virtual bool seria_v(bool &value)                = 0;
	virtual bool seria_v(std::string &value)         = 0;
	virtual bool seria_v(common::BinaryArray &value) = 0;

	// read/write binary block
	virtual bool binary(void *value, size_t size) = 0;  // fixed width, no size written
};

template<typename BT, typename T>
bool ser_integral(T &value, ISeria &s) {
	if (s.is_input()) {
		BT tmp = 0;
		if (!s.seria_v(tmp))
			return false;
		value = common::integer_cast<T>(tmp);
		return true;
	}
	BT tmp = static_cast<BT>(value);
	return s.seria_v(tmp);
}

inline bool ser(uint8_t &value, ISeria &s) { return ser_integral<uint64_t>(value, s); }
inline bool ser(short &value, ISeria &s) { return ser_integral<int64_t>(value, s); }
inline bool ser(unsigned short &value, ISeria &s) { return ser_integral<uint64_t>(value, s); }
inline bool ser(int &value, ISeria &s) { return ser_integral<int64_t>(value, s); }
inline bool ser(unsigned int &value, ISeria &s) { return ser_integral<uint64_t>(value, s); }
inline bool ser(long &value, ISeria &s) { return ser_integral<int64_t>(value, s); }
inline bool ser(unsigned long &value, ISeria &s) { return ser_integral<uint64_t>(value, s); }
inline bool ser(long long &value, ISeria &s) { return ser_integral<int64_t>(value, s); }
inline bool ser(unsigned long long &value, ISeria &s) { return ser_integral<uint64_t>(value, s); }

inline bool ser(bool &value, ISeria &s) { return s.seria_v(value); }
inline bool ser(std::string &value, ISeria &s) { return s.seria_v(value); }
inline bool ser(common::BinaryArray &value, ISeria &s) { return s.seria_v(value); }

template<typename T, typename... Context>
bool seria_kv(common::StringView name, T &value, ISeria &s, Context... context) {
	try {
		s.object_key(name);
		return ser(value, s, context...);
	} catch (const std::exception &) {
		std::throw_with_nested(
		    std::runtime_error("Error while serializing object value for key '" + std::string(name) + "'"));
	}
}
template<typename T, typename... Context>
bool seria_kv(common::StringView name, boost::optional<T> &value, ISeria &s, Context... context) {
	try {
		if (s.is_input()) {
			s.object_key(name, true);
			T temp{};
			if (!ser(temp, s, context...))
				return false;
			value = std::move(temp);
			return true;
		}
		s.object_key(name, !value);
		T temp{};
		return ser(value ? value.get() : temp, s, context...);
	} catch (const std::exception &) {
		std::throw_with_nested(
		    std::runtime_error("Error while serializing object value for key '" + std::string(name) + "'"));
	}
}
template<typename T, typename... Context>
bool seria_kv_optional(common::StringView name, T &value, ISeria &s, Context... context) {
	try {
		s.object_key(name, true);
		return ser(value, s, context...);
	} catch (const std::exception &) {
		std::throw_with_nested(
		    std::runtime_error("Error while serializing object value for key '" + std::string(name) + "'"));
	}
}
template<typename T, typename... Context>
bool seria_kv_strict(common::StringView name, T &value, ISeria &s, Context... context) {
	try {
		s.object_key(name, false);
		return ser(value, s, context...);
	} catch (const std::exception &) {
		std::throw_with_nested(
		    std::runtime_error("Error while serializing object value for key '" + std::string(name) + "'"));
	}
}
inline bool seria_kv_binary(common::StringView name, void *value, size_t size, ISeria &s) {
	s.object_key(name, true);
	return s.binary(value, size);
}

template<typename T, typename... Context>
void ser_members(T &value, ISeria &s, Context... context);  //{
//        static_assert(false); // Good idea, but clang complains
//    }

template<typename T, typename... Context>
bool ser(T &value, ISeria &s, Context... context) {
	bool result = s.begin_object();
	ser_members(value, s, context...);
	s.end_object();
	return result;
}
template<typename Cont, typename... Context>
bool seria_container(Cont &value, ISeria &s, Context... context) {
	size_t size = value.size();
	bool result = s.begin_array(size);
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
	return result;
}

template<typename T, typename... Context>
bool ser(std::vector<T> &value, ISeria &serializer, Context... context) {
	return seria_container(value, serializer, context...);
}

template<typename T, typename... Context>
bool ser(std::list<T> &value, ISeria &serializer, Context... context) {
	return seria_container(value, serializer, context...);
}

template<typename MapT, typename... Context>
bool seria_map_string(MapT &value, ISeria &s, Context... context) {
	size_t size = value.size();
	bool result = s.begin_map(size);
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
	return result;
}

template<typename MapT, typename... Context>
bool seria_map_integral(MapT &value, ISeria &s, std::true_type, Context... context) {
	size_t size = value.size();
	bool result = s.begin_map(size);
	if (s.is_input()) {
		for (size_t i = 0; i != size; ++i) {
			std::string key;
			typename MapT::key_type k;
			try {
				s.next_map_key(key);
				k = static_cast<typename MapT::key_type>(common::stoll(key));
			} catch (const std::exception &) {
				std::throw_with_nested(std::runtime_error(
				    "Error while serializing map key #" + common::to_string(i) + ", cannot convert " + key));
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
	return result;
}

template<typename MapT, typename... Context>
bool seria_map_integral(MapT &value, ISeria &s, std::false_type, Context... context) {
	size_t size = value.size();
	bool result = s.begin_map(size);
	if (s.is_input()) {
		for (size_t i = 0; i != size; ++i) {
			std::string key;
			typename MapT::key_type k;
			try {
				s.next_map_key(key);
				if (!common::pod_from_hex(key, &k))
					throw std::runtime_error(
					    "Error while serializing map key #" + common::to_string(i) + ", cannot convert " + key);
			} catch (const std::exception &) {
				std::throw_with_nested(std::runtime_error(
				    "Error while serializing map key #" + common::to_string(i) + ", cannot convert " + key));
			}
			// We use widest possible conversion because no generic function provided in C++
			try {
				typename MapT::mapped_type v;
				ser(v, s, context...);
				value.insert(std::make_pair(std::move(k), std::move(v)));
			} catch (const std::exception &) {
				std::throw_with_nested(std::runtime_error("Error while serializing map value for key '" + key + "'"));
			}
		}
	} else {
		size_t counter = 0;
		for (auto &kv : value) {
			auto str_key = common::pod_to_hex(kv.first);
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
	return result;
}
template<typename SetT>
bool seria_set(SetT &value, ISeria &s) {
	size_t size = value.size();

	bool result = s.begin_array(size);
	if (s.is_input()) {
		for (size_t i = 0; i != size; ++i) {
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
	return result;
}

template<typename K, typename Hash>
bool ser(std::unordered_set<K, Hash> &value, ISeria &s) {
	return seria_set(value, s);
}
template<typename K, typename Cmp>
bool ser(std::set<K, Cmp> &value, ISeria &s) {
	return seria_set(value, s);
}
template<typename V, typename Hash, typename... Context>
bool ser(std::unordered_map<std::string, V, Hash> &value, ISeria &s, Context... context) {
	return seria_map_string(value, s, context...);
}
template<typename K, typename V, typename Hash, typename... Context>
bool ser(std::unordered_map<K, V, Hash> &value, ISeria &s, Context... context) {
	return seria_map_integral(value, s, std::is_integral<K>(), context...);
}
template<typename V, typename Hash, typename... Context>
bool ser(std::map<std::string, V, Hash> &value, ISeria &s, Context... context) {
	return seria_map_string(value, s, context...);
}
template<typename K, typename V, typename Hash, typename... Context>
bool ser(std::map<K, V, Hash> &value, ISeria &s, Context... context) {
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
bool ser(std::array<uint8_t, size> &value, ISeria &s) {
	return s.binary(value.data(), value.size());
}
template<typename T1, typename T2, typename... Context>
void ser_members(std::pair<T1, T2> &value, ISeria &s, Context... context) {
	seria_kv("first", value.first, s, context...);
	seria_kv("second", value.second, s, context...);
}
}  // namespace seria
