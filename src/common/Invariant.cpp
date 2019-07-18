// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Invariant.hpp"
#include <sstream>
#include <stdexcept>
#include "string.hpp"

#ifndef __EMSCRIPTEN__
#define BOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED 1
#include <boost/stacktrace.hpp>
#endif
std::string common::invariant_violated(const char *expr, const char *file, int line, const std::string &msg) {
	std::stringstream str;
	str << "Invariant " << std::string(expr) << " violated at " << line << " " << msg << " stacktrace:\n";
#ifndef __EMSCRIPTEN__
	str << boost::stacktrace::stacktrace();
#endif
	return str.str();
}
