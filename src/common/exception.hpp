// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <stdexcept>
#include <string>
#include <typeinfo>  // clients of demangle will probably appreciate this include

namespace common {
std::string demangle(const char *name);
std::string what(const std::exception &e);
}  // namespace common

#define ewrap(expr, ex)                \
	try {                              \
		expr;                          \
	} catch (const std::exception &) { \
		std::throw_with_nested(ex);    \
	}
