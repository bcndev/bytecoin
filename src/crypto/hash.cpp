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
	if (data == nullptr)
		throw std::bad_alloc();
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
	if (data == MAP_FAILED)
		throw std::bad_alloc();
	mlock(data, MAP_SIZE);
}

CryptoNightContext::~CryptoNightContext() {
	if (munmap(data, MAP_SIZE) != 0)
		assert(false);
}

#endif

static Hash fill_merge_mining_branches(const std::vector<MergeMiningItem *> &pitems, size_t depth) {
	if (pitems.size() == 1)
		return pitems.at(0)->leaf;
	std::vector<MergeMiningItem *> halves[2];
	for (auto pitem : pitems) {
		bool dir = (pitem->path.data[depth >> 3] & (1 << (depth & 7))) != 0;
		halves[dir].push_back(pitem);
		pitem->branch.push_back(Hash{});
	}
	Hash hashes[2] = {halves[0].empty() ? Hash{} : fill_merge_mining_branches(halves[0], depth + 1),
	    halves[1].empty() ? Hash{} : fill_merge_mining_branches(halves[1], depth + 1)};
	for (size_t ha = 0; ha != 2; ++ha)
		for (auto pitem : halves[ha])
			pitem->branch.at(depth) = hashes[1 - ha];
	return cn_fast_hash(hashes, 2 * sizeof(Hash));
}

Hash fill_merge_mining_branches(MergeMiningItem items[], size_t count) {
	assert(count > 0);
	if (count == 0)
		return Hash{};
	std::vector<MergeMiningItem *> pitems(count);
	for (size_t i = 0; i != count; ++i)
		pitems[i] = items + i;
	return fill_merge_mining_branches(pitems, 0);
}
}
