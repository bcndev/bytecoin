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

#pragma once

#include <stddef.h>

#include "types.hpp"
#include "hash-ops.h"

namespace crypto {
  // Cryptonight hash functions

	inline Hash cn_fast_hash(const void *data, size_t length) {
		Hash h;
		cn_fast_hash(data, length, h.data);
		return h;
	}
//	inline Hash cn_fast_hash(const std::vector<uint8_t> & data) {
//		return cn_fast_hash(data.data(), data.size());
//	}

  class CryptoNightContext {
  public:
    CryptoNightContext();
	~CryptoNightContext();

    CryptoNightContext(const CryptoNightContext &) = delete;
    void operator=(const CryptoNightContext &) = delete;
	  
  	inline void cn_slow_hash(const void *src_data, size_t length, unsigned char * hash) {
    	crypto::cn_slow_hash(data, src_data, length, hash);
  	}
  	inline Hash cn_slow_hash(const void *src_data, size_t length) {
  		Hash hash;
    	crypto::cn_slow_hash(data, src_data, length, hash.data);
    	return hash;
  	}
  private:
    void *data;
  };

  inline Hash tree_hash(const Hash *hashes, size_t count) {
	Hash root_hash;
    tree_hash(reinterpret_cast<const unsigned char (*)[HASH_SIZE]>(hashes), count, root_hash.data);
    return root_hash;
  }

  inline void tree_branch(const Hash *hashes, size_t count, Hash *branch) {
    tree_branch(reinterpret_cast<const unsigned char (*)[HASH_SIZE]>(hashes), count, reinterpret_cast<unsigned char (*)[HASH_SIZE]>(branch));
  }

  inline Hash tree_hash_from_branch(const Hash *branch, size_t depth, const Hash &leaf, const void *path) {
	Hash root_hash;
    tree_hash_from_branch(reinterpret_cast<const unsigned char (*)[HASH_SIZE]>(branch), depth, leaf.data, path, root_hash.data);
    return root_hash;
  }

}

