// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <limits>
#include "CryptoNote.hpp"
#include "crypto/hash.hpp"
#include "seria/BinaryOutputStream.hpp"

namespace bytecoin {

template<class T>
Hash get_object_hash(const T &object, size_t *size = nullptr) {
	BinaryArray ba = seria::to_binary(object);
	if (size)
		*size = ba.size();
	return crypto::cn_fast_hash(ba.data(), ba.size());
}

Hash get_base_transaction_hash(const BaseTransaction &tx);

void fix_merge_mining_tag(BlockTemplate &block);  // If solo mining, we must still have valid merge mining tag

void decompose_amount(Amount amount, Amount dust_threshold, std::vector<Amount> *decomposed_amounts);
size_t get_maximum_tx_size(size_t input_count, size_t output_count, size_t mixin_count);

bool get_tx_fee(const TransactionPrefix &tx, uint64_t *fee);
uint64_t get_tx_fee(const TransactionPrefix &tx);

struct ParentBlockSerializer {
	ParentBlockSerializer(
	    ParentBlock &parent_block, Timestamp &timestamp, uint32_t &nonce, bool hashing_serialization, bool header_only)
	    : m_parent_block(parent_block)
	    , m_timestamp(timestamp)
	    , m_nonce(nonce)
	    , m_hashing_serialization(hashing_serialization)
	    , m_header_only(header_only) {}
	ParentBlock &m_parent_block;
	Timestamp &m_timestamp;
	uint32_t &m_nonce;
	bool m_hashing_serialization;
	bool m_header_only;
};

inline ParentBlockSerializer make_parent_block_serializer(
    const BlockTemplate &b, bool hashing_serialization, bool header_only) {
	BlockTemplate &block_ref = const_cast<BlockTemplate &>(b);
	return ParentBlockSerializer(
	    block_ref.parent_block, block_ref.timestamp, block_ref.nonce, hashing_serialization, header_only);
}
}

namespace seria {
class ISeria;
void ser_members(bytecoin::ParentBlockSerializer &v, ISeria &s);
}
