// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>

namespace platform {

uint32_t now_unix_timestamp(uint32_t *usec = nullptr);
int get_time_multiplier_for_tests();
void set_time_multiplier_for_tests(int multiplier);
}
