// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers.
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

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "hash.h"
#include "initializer.h"
#include "random.h"

static inline void *padd(void *p, size_t i) { return (char *)p + i; }

#if defined(_WIN32)
#include <windows.h>
// clangformat will switch order
#include <wincrypt.h>

static void generate_system_random_bytes(size_t n, void *result) {
	HCRYPTPROV prov = 0;
	if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT) ||
	    !CryptGenRandom(prov, (DWORD)n, result) || !CryptReleaseContext(prov, 0)) {
		wchar_t message[]    = L"Failed to acquire random bytes from PROV_RSA_FULL provider";
		DWORD dwToWrite      = (DWORD)wcslen(message);
		DWORD dwWritten      = 0;
		HANDLE hParentStdErr = GetStdHandle(STD_ERROR_HANDLE);
		WriteConsoleW(hParentStdErr, message, dwToWrite, &dwWritten, NULL);
		abort();
	}
}

#else

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

static void generate_system_random_bytes(size_t n, void *result) {
	int fd;
	if ((fd = open("/dev/urandom", O_RDONLY | O_NOCTTY | O_CLOEXEC)) < 0) {
		err(EXIT_FAILURE, "open /dev/urandom");
	}
	for (;;) {
		ssize_t res = read(fd, result, n);
		if ((size_t)res == n) {
			break;
		}
		if (res < 0) {
			if (errno != EINTR) {
				err(EXIT_FAILURE, "read /dev/urandom");
			}
		} else if (res == 0) {
			err(EXIT_FAILURE, "read /dev/urandom: end of file");
		} else {
			result = padd(result, (size_t)res);
			n -= (size_t)res;
		}
	}
	if (close(fd) < 0) {
		err(EXIT_FAILURE, "close /dev/urandom");
	}
}

#endif

static struct cryptoKeccakState state;
static int initialized = 0;

void crypto_initialize_random(void) {
	generate_system_random_bytes(32, &state);
	initialized = 1;
}

void crypto_unsafe_generate_random_bytes(void *result, size_t n) {
	if (!initialized)
		crypto_initialize_random();
	for (;;) {
		crypto_keccak_permutation(&state);
		if (n <= HASH_DATA_AREA) {
			memcpy(result, &state, n);
			return;
		}
		memcpy(result, &state, HASH_DATA_AREA);
		result = padd(result, HASH_DATA_AREA);
		n -= HASH_DATA_AREA;
	}
}

void crypto_initialize_random_for_tests(void) {
	memset(&state, 42, sizeof(struct cryptoKeccakState));
	initialized = 1;
}

// We keep initialize@start, because generate_system_random_bytes will exit on errror
// If INITIALIZER fails to compile on your platform, just comment out INITIALIZER below
INITIALIZER(init_random) { crypto_initialize_random(); }
