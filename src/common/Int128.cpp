// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Int128.hpp"
#include <iostream>

std::ostream &common::operator<<(std::ostream &out, const Uint128 &v) {
	if (v.hi != 0)
		return out << "(" << v.hi << ", " << v.lo << ")" << std::endl;
	return out << v.lo << std::endl;
}
