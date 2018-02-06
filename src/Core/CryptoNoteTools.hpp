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

#include <limits>
#include "crypto/hash.hpp"
#include "CryptoNote.hpp"
#include "seria/BinaryOutputStream.hpp"

namespace bytecoin {

template<class T>
Hash getObjectHash(const T &object, size_t * size = nullptr) {
	BinaryArray ba = seria::toBinary(object);
	if( size )
		*size = ba.size();
	return crypto::cn_fast_hash(ba.data(), ba.size());
}

Hash getBaseTransactionHash(const BaseTransaction &tx);

void decomposeAmount(Amount amount, Amount dustThreshold, std::vector<Amount> &decomposedAmounts);
size_t getMaximumTxSize(size_t inputCount, size_t outputCount, size_t mixinCount);

bool get_tx_fee(const Transaction &tx, uint64_t &fee);
uint64_t get_tx_fee(const Transaction &tx);

struct ParentBlockSerializer {
	ParentBlockSerializer(ParentBlock &parentBlock, Timestamp &timestamp, uint32_t &nonce, bool hashingSerialization, bool headerOnly)
			:
			m_parentBlock(parentBlock), m_timestamp(timestamp), m_nonce(nonce),
			m_hashingSerialization(hashingSerialization), m_headerOnly(headerOnly) {
	}
	ParentBlock &m_parentBlock;
	Timestamp &m_timestamp;
	uint32_t &m_nonce;
	bool m_hashingSerialization;
	bool m_headerOnly;
};

inline ParentBlockSerializer makeParentBlockSerializer(const BlockTemplate &b, bool hashingSerialization, bool headerOnly) {
	BlockTemplate &blockRef = const_cast<BlockTemplate &>(b);
	return ParentBlockSerializer(blockRef.parent_block, blockRef.timestamp, blockRef.nonce, hashingSerialization, headerOnly);
}

}

namespace seria {
	class ISeria;
	void serMembers(bytecoin::ParentBlockSerializer &v, ISeria &s);
}
