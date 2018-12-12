// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <assert.h>
#include <new>

#include "hash.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <algorithm>

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
	if (count == 0)
		return Hash{};
	std::vector<MergeMiningItem *> pitems(count);
	for (size_t i = 0; i != count; ++i)
		pitems[i] = items + i;
	return fill_merge_mining_branches(pitems, 0);
}

#pragma pack(push, 1)
struct HashingBranch {
	Hash hashes[2];
	unsigned char depth;
};
#pragma pack(pop)

static Hash fill_cm_branches(const std::vector<CMTreeItem *> &pitems, size_t depth) {
	if (depth >= 256)
		throw std::logic_error("fill_cm_branches same currency ids");  // "Same currency ids"
	if (pitems.size() == 1)
		return pitems.at(0)->leaf;
	std::vector<CMTreeItem *> halves[2];
	for (auto pitem : pitems) {
		bool dir = (pitem->path.data[depth >> 3] & (1 << (depth & 7))) != 0;
		halves[dir].push_back(pitem);
	}
	if (halves[0].empty())
		return fill_cm_branches(halves[1], depth + 1);
	if (halves[1].empty())
		return fill_cm_branches(halves[0], depth + 1);
	HashingBranch buffer;
	buffer.hashes[0] = fill_cm_branches(halves[0], depth + 1);
	buffer.hashes[1] = fill_cm_branches(halves[1], depth + 1);
	buffer.depth     = static_cast<uint8_t>(depth);
	for (size_t ha = 0; ha != 2; ++ha)
		for (auto pitem : halves[ha])
			pitem->branch.push_back(CMBranchElement{buffer.depth, buffer.hashes[1 - ha]});
	return cn_fast_hash(&buffer, sizeof(buffer));
}

Hash fill_cm_branches(CMTreeItem items[], size_t count) {
	if (count == 0)
		return Hash{};
	std::vector<CMTreeItem *> pitems(count);
	for (size_t i = 0; i != count; ++i)
		pitems[i] = items + i;
	Hash result = fill_cm_branches(pitems, 0);
	for (size_t i = 0; i != count; ++i)  // We push_back instead of insert(begin, ) for speed
		std::reverse(pitems[i]->branch.begin(), pitems[i]->branch.end());
	return result;
}

bool cm_branch_valid(const std::vector<CMBranchElement> &branch) {
	size_t last_depth = 0x100;
	for (size_t i = branch.size(); i-- > 0;) {
		const auto &br = branch[i];
		if (br.depth >= last_depth)
			return false;
		last_depth = br.depth;
	}
	return true;
}

Hash tree_hash_from_cm_branch(const std::vector<CMBranchElement> &branch, const Hash &leaf, const Hash &path) {
	if (branch.empty())
		return leaf;

	Hash last_hash    = leaf;
	size_t last_depth = 0x100;

	for (size_t i = branch.size(); i-- > 0;) {
		const auto &br = branch[i];
		if (br.depth >= last_depth)
			throw std::logic_error("CM branch invalid");
		size_t leaf_path = (path.data[br.depth >> 3] & (1 << (br.depth & 7))) != 0 ? 1 : 0;
		HashingBranch buffer;
		buffer.hashes[leaf_path]     = last_hash;
		buffer.hashes[1 - leaf_path] = br.hash;
		buffer.depth                 = br.depth;
		last_hash                    = cn_fast_hash(&buffer, sizeof(buffer));
		last_depth                   = br.depth;
	}
	return last_hash;
}

}  // namespace crypto
