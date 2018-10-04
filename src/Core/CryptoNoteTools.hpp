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

void set_solo_mining_tag(BlockTemplate &block);  // MM headers must still have valid mm_tag if solo mining

void decompose_amount(Amount amount, Amount dust_threshold, std::vector<Amount> *decomposed_amounts);
size_t get_maximum_tx_size(size_t input_count, size_t output_count, size_t anonymity);
size_t get_maximum_tx_input_size(size_t anonymity);

bool get_tx_fee(const TransactionPrefix &tx, uint64_t *fee);
uint64_t get_tx_fee(const TransactionPrefix &tx);

BlockBodyProxy get_body_proxy_from_template(const BlockTemplate &bt);
}
