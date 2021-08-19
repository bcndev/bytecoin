// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#if defined(__GNUC__)
#define INITIALIZER(name) __attribute__((constructor(101))) static void name(void)
#define FINALIZER(name) __attribute__((destructor(101))) static void name(void)
#define REGISTER_FINALIZER(name) ((void)0)

#elif defined(_MSC_VER)
#include <assert.h>
#include <stdlib.h>
// http://stackoverflow.com/questions/1113409/attribute-constructor-equivalent-in-vc
// http://msdn.microsoft.com/en-us/library/bb918180.aspx
#pragma section(".CRT$XCT", read)
#define INITIALIZER(name)                                                        \
	static void __cdecl name(void);                                              \
	__declspec(allocate(".CRT$XCT")) void(__cdecl *const _##name)(void) = &name; \
	static void __cdecl name(void)
#define FINALIZER(name) static void __cdecl name(void)
#define REGISTER_FINALIZER(name) \
	do {                         \
		int _res = atexit(name); \
		assert(_res == 0);       \
	} while (0);

#else
#error Unsupported compiler
#endif
