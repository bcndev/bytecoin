// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include <cstdint>
#include <vector>

#include "CryptoNote.hpp"

namespace byterub {

bool check_hash(const crypto::Hash &hash, Difficulty difficulty);
}
