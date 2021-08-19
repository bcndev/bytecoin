// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <stdexcept>
#include <string>

namespace common {
std::string invariant_violated(const char *expr, const char *file, int line, const std::string &msg);
}

// We cannot use F/IL/E macro because of anonymity concerns
#define invariant(expr, msg)                                                              \
	do {                                                                                  \
		if (!(expr))                                                                      \
			throw std::logic_error(common::invariant_violated(#expr, "", __LINE__, msg)); \
	} while (0)
