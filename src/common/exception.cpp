// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "exception.hpp"
#include <boost/algorithm/string/replace.hpp>
#include <boost/core/demangle.hpp>

static std::string what_impl(const std::exception &e, size_t level) {
	std::string nested_what;
	try {
		std::rethrow_if_nested(e);
	} catch (const std::exception &n) {
		nested_what = "\n" + what_impl(n, level + 1);
	} catch (...) {
		nested_what = "\n...";
	}
	return std::string(level * 2, ' ') + e.what() + nested_what;
}

std::string common::demangle(const char *name) {
	std::string str = boost::core::demangle(name);
	boost::replace_all(str, "cn::", "");
	boost::replace_all(str, "api::walletd::", "");
	boost::replace_all(str, "api::cnd::", "");
	boost::replace_all(str, "crypto::", "");
	return str;
}

std::string common::what(const std::exception &e) { return what_impl(e, 0); }
