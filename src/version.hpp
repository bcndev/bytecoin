// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

// defines are for Windows resource compiler
#define BYTERUB_VERSION_WINDOWS_COMMA 3, 18, 2, 19
#define BYTERUB_VERSION_WINDOWS_STRING "3.0.0-20180219-beta"

#ifdef __cplusplus

namespace byterub {
inline const char *app_version() { return BYTERUB_VERSION_WINDOWS_STRING; }
}

#endif
