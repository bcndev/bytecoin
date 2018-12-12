// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <algorithm>
#include <typeinfo>
#include <vector>
#include "exception.hpp"
#include "string.hpp"

namespace common {

template<class T>
T median_value(std::vector<T> *v) {
	if (v->empty())
		return T();

	auto n = v->size() / 2;
	std::sort(v->begin(), v->end());

	if (v->size() % 2)  // 1, 3, 5...
		return (*v)[n];
	return ((*v)[n - 1] + (*v)[n]) / 2;  // 2, 4, 6...
}

template<typename Target, typename Source>
void integer_cast_throw(const Source &arg) {
	throw std::out_of_range(
	    "Failed integer cast of " + common::to_string(arg) + " to " + common::demangle(typeid(Target).name()));
}

template<typename Target, typename Source>
inline Target integer_cast_impl(const Source &arg, std::true_type, std::true_type) {
	// both unsigned
	if (arg > std::numeric_limits<Target>::max())
		integer_cast_throw<Target>(arg);
	return static_cast<Target>(arg);
}

template<typename Target, typename Source>
inline Target integer_cast_impl(const Source &arg, std::false_type, std::false_type) {
	// both signed
	if (arg > std::numeric_limits<Target>::max())
		integer_cast_throw<Target>(arg);
	if (arg < std::numeric_limits<Target>::min())
		integer_cast_throw<Target>(arg);
	return static_cast<Target>(arg);
}

template<typename Target, typename Source>
inline Target integer_cast_impl(const Source &arg, std::true_type, std::false_type) {
	// signed to unsigned
	typedef typename std::make_unsigned<Source>::type USource;
	if (arg < 0)
		integer_cast_throw<Target>(arg);
	if (static_cast<USource>(arg) > std::numeric_limits<Target>::max())
		integer_cast_throw<Target>(arg);
	return static_cast<Target>(arg);
}

template<typename Target, typename Source>
inline Target integer_cast_impl(const Source &arg, std::false_type, std::true_type) {
	// unsigned to signed
	typedef typename std::make_unsigned<Target>::type UTarget;
	if (arg > static_cast<UTarget>(std::numeric_limits<Target>::max()))
		integer_cast_throw<Target>(arg);
	return static_cast<Target>(arg);
}

template<typename Target, typename Source>
inline Target integer_cast(const Source &arg) {
	static_assert(std::is_integral<Target>::value && std::is_integral<Source>::value, "Needs 2 integral types");
	return integer_cast_impl<Target, Source>(arg, std::is_unsigned<Target>{}, std::is_unsigned<Source>{});
}

// template<typename Target, typename Source>
// void test_convert(Source arg){
//	try{
//		Target t = common::integer_cast<Target>(arg);
//		std::cout << "Success " << arg << " -> " << common::to_string(t) << std::endl;
//	}catch(const std::exception &){
//		std::cout << "Fail " << arg << " -> " << typeid(Target).name() << std::endl;
//	}
//}

//	test_convert<uint32_t, uint8_t>(1);
//	test_convert<uint32_t, uint8_t>(0xFF);
//	test_convert<uint32_t, int8_t>(1);
//	test_convert<uint32_t, int8_t>(0x7F);
//	test_convert<uint32_t, int8_t>(-2);
//
//	test_convert<uint32_t, int64_t>(2000000000);
//	test_convert<uint32_t, int64_t>(-2000000000);
//	test_convert<uint32_t, int64_t>(-2);
//
//	test_convert<int32_t, uint64_t>(2);
//	test_convert<int32_t, uint64_t>(2000000000);
//	test_convert<int32_t, uint64_t>(4000000000);
//
//	test_convert<uint16_t, uint64_t>(2);
//	test_convert<uint16_t, uint64_t>(20000);
//	test_convert<uint16_t, uint64_t>(2000000000);
//	test_convert<uint16_t, uint64_t>(4000000000);
//
//	test_convert<uint16_t, int64_t>(-2);
//	test_convert<uint16_t, int64_t>(2);
//	test_convert<uint16_t, int64_t>(20000);
//	test_convert<uint16_t, int64_t>(60000);
//	test_convert<uint16_t, int64_t>(2000000000);
//
//	test_convert<int16_t, uint64_t>(2);
//	test_convert<int16_t, uint64_t>(20000);
//	test_convert<int16_t, uint64_t>(60000);
//	test_convert<int16_t, uint64_t>(2000000000);
//	test_convert<int16_t, uint64_t>(4000000000);
//
//	test_convert<int16_t, int64_t>(-2000000000);
//	test_convert<int16_t, int64_t>(-60000);
//	test_convert<int16_t, int64_t>(-20000);
//	test_convert<int16_t, int64_t>(-2);
//	test_convert<int16_t, int64_t>(2);
//	test_convert<int16_t, int64_t>(20000);
//	test_convert<int16_t, int64_t>(60000);
//	test_convert<int16_t, int64_t>(2000000000);
}  // namespace common
