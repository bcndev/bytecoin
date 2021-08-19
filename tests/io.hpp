// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for
// details.

#pragma once

#include <cstddef>
#include <ios>
#include <iostream>
#include <type_traits>
#include <vector>
#include "common/StringTools.hpp"

inline void get(std::istream &input, bool &res) {
	std::string sres;
	input >> sres;
	if (sres == "false") {
		res = false;
	} else if (sres == "true") {
		res = true;
	} else {
		input.setstate(std::ios_base::failbit);
	}
}

template<typename T>
typename std::enable_if<std::is_integral<T>::value, void>::type get(std::istream &input, T &res) {
	input >> res;
}

inline void getvar(std::istream &input, std::size_t length, void *res) {
	std::string sres;
	input >> sres;
	//	if (!sres.length() != 2 * length || !hexdecode(sres.data(), length, res))
	//		input.setstate(std::ios_base::failbit);
	if (!common::from_hex(sres, res, length))
		input.setstate(std::ios_base::failbit);
}

template<typename T>
typename std::enable_if<std::is_standard_layout<T>::value && !std::is_scalar<T>::value, void>::type get(
    std::istream &input, T &res) {
	getvar(input, sizeof(T), &res);
}

inline void get(std::istream &input, std::vector<char> &res) {
	std::string sres;
	input >> sres;
	if (sres == "x") {
		res.clear();
	} else if (sres.length() % 2 != 0) {
		input.setstate(std::ios_base::failbit);
	} else {
		std::size_t length = sres.length() / 2;
		res.resize(length);
		if (!common::from_hex(sres, res.data(), length))
			//		if (!hexdecode(sres.data(), length, res.data()))
			input.setstate(std::ios_base::failbit);
	}
}

#if !defined(_MSC_VER) || _MSC_VER >= 1800

template<typename T, typename... TT>
typename std::enable_if<(sizeof...(TT) > 0), void>::type get(std::istream &input, T &res, TT &... resres) {
	get(input, res);
	get(input, resres...);
}

#else
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/enum_binary_params.hpp>
#include <boost/preprocessor/repetition/enum_params.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>

#define NESTED_GET(z, n, data) get(input, BOOST_PP_CAT(res, n));
#define GET(z, n, data)                                                      \
	template<BOOST_PP_ENUM_PARAMS(n, typename T)>                            \
	void get(std::istream &input, BOOST_PP_ENUM_BINARY_PARAMS(n, T, &res)) { \
		BOOST_PP_REPEAT(n, NESTED_GET, ~)                                    \
	}
BOOST_PP_REPEAT_FROM_TO(2, 5, GET, ~)

#endif
