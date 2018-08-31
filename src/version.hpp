// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

// defines are for Windows resource compiler
#define bytecoin_VERSION_WINDOWS_COMMA 3, 18, 8, 31
#define bytecoin_VERSION_STRING "3.3.0"

#ifndef RC_INVOKED  // Windows resource compiler

namespace bytecoin {
inline const char *app_version() { return bytecoin_VERSION_STRING; }
}

#endif
