// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#include <new>
#include <assert.h>

#include "hash.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace crypto {
	
	enum {
		MAP_SIZE = SLOW_HASH_CONTEXT_SIZE + ((-SLOW_HASH_CONTEXT_SIZE) & 0xfff)
	};
	
#if defined(_WIN32)
	
	CryptoNightContext::CryptoNightContext() {
		data = VirtualAlloc(nullptr, MAP_SIZE, MEM_COMMIT, PAGE_READWRITE);
		if (data == nullptr) {
			throw std::bad_alloc();
		}
	}
	
	CryptoNightContext::~CryptoNightContext() {
		if(!VirtualFree(data, 0, MEM_RELEASE))
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
		if(munmap(data, MAP_SIZE) != 0)
			assert(false);
	}
	
#endif
	
}
