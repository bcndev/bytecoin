// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#if BYTERUB_SQLITE
#include "platform/DBsqlite3.hpp"
namespace platform {
typedef DBsqlite DB;
}
#else
#include "platform/DBlmdb.hpp"
namespace platform {
typedef DBlmdb DB;
}
#endif
