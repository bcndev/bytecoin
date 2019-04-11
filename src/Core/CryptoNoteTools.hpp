// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <limits>
#include "CryptoNote.hpp"
#include "crypto/hash.hpp"
#include "seria/BinaryOutputStream.hpp"

namespace cn {

template<class T>
Hash get_object_hash(const T &object, size_t *size = nullptr) {
	BinaryArray ba = seria::to_binary(object);
	if (size)
		*size = ba.size();
	return crypto::cn_fast_hash(ba.data(), ba.size());
}

Hash get_root_block_base_transaction_hash(const RootBaseTransaction &tx);

void set_root_extra_to_solo_mining_tag(BlockTemplate &block);  // MM headers must still have valid mm_tag if solo mining

void decompose_amount(Amount amount, Amount dust_threshold, std::vector<Amount> *decomposed_amounts);
size_t get_maximum_tx_size(size_t input_count, size_t output_count, size_t anonymity);
size_t get_maximum_tx_input_size(size_t anonymity);

Amount get_tx_sum_outputs(const TransactionPrefix &tx);
Amount get_tx_sum_inputs(const TransactionPrefix &tx);

size_t get_tx_key_outputs_count(const TransactionPrefix &tx);

inline bool add_amount(Amount &sum, Amount amount) {
	if (std::numeric_limits<Amount>::max() - amount < sum)
		return false;
	sum += amount;
	return true;
}

bool get_tx_fee(const TransactionPrefix &tx, Amount *fee);
Amount get_tx_fee(const TransactionPrefix &tx);

std::vector<size_t> absolute_output_offsets_to_relative(const std::vector<size_t> &off);
bool relative_output_offsets_to_absolute(std::vector<size_t> *result, const std::vector<size_t> &off);

BlockBodyProxy get_body_proxy_from_template(const BlockTemplate &bt);

}  // namespace cn
