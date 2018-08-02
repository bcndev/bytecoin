// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <random>

namespace common {

// Tests require deterministic random with the same sequence on all platforms
// We declare it here
typedef std::mt19937_64 Random;
}
