// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <assert.h>
#include <new>

#include "hash.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace crypto {

enum { MAP_SIZE = SLOW_HASH_CONTEXT_SIZE + ((-SLOW_HASH_CONTEXT_SIZE) & 0xfff) };

#if defined(_WIN32)

CryptoNightContext::CryptoNightContext() {
	data = VirtualAlloc(nullptr, MAP_SIZE, MEM_COMMIT, PAGE_READWRITE);
	if (data == nullptr) {
		throw std::bad_alloc();
	}
}

CryptoNightContext::~CryptoNightContext() {
	if (!VirtualFree(data, 0, MEM_RELEASE))
		assert(false);
}

#else

CryptoNightContext::CryptoNightContext() {
#if !defined(__APPLE__)
	data = mmap(nullptr, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
#else
	data = mmap(nullptr, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
#endif
	if (data == MAP_FAILED) {
		throw std::bad_alloc();
	}
	mlock(data, MAP_SIZE);
}

CryptoNightContext::~CryptoNightContext() {
	if (munmap(data, MAP_SIZE) != 0)
		assert(false);
}

#endif
}
