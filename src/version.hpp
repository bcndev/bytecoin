// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

// defines are for Windows resource compiler
#define bytecoin_VERSION_WINDOWS_COMMA 0, 0, 2, 0
#define bytecoin_VERSION_STRING "v0.0.2"

#ifndef RC_INVOKED  // Windows resource compiler

namespace cn {
inline const char *app_version() { return bytecoin_VERSION_STRING; }
}  // namespace cn

#endif
