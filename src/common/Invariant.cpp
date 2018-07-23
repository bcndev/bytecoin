// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Invariant.hpp"
#include <stdexcept>
#include "string.hpp"

void common::invariant_violated(const char *expr, const char *file, int line, const std::string &msg) {
	throw std::logic_error("Invariant " + std::string(expr) + " violated at " + common::to_string(line) + " " + msg);
}
