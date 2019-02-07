// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "CryptoNoteTools.hpp"
#include "Currency.hpp"
#include "TransactionExtra.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "seria/ISeria.hpp"

using namespace cn;

Hash cn::get_root_block_base_transaction_hash(const BaseTransaction &tx) {
	if (tx.version < 2)
		return get_object_hash(tx);
	// XMR(XMO) as popular MM root, see details in monero/src/cryptonote_basic/cryptonote_format_utils.cpp
	// bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a = hash(1 zero byte (RCTTypeNull))
	BinaryArray data{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbc, 0x36,
	    0x78, 0x9e, 0x7a, 0x1e, 0x28, 0x14, 0x36, 0x46, 0x42, 0x29, 0x82, 0x8f, 0x81, 0x7d, 0x66, 0x12, 0xf7, 0xb4,
	    0x77, 0xd6, 0x65, 0x91, 0xff, 0x96, 0xa9, 0xe0, 0x64, 0xbc, 0xc9, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
	*reinterpret_cast<Hash *>(data.data()) = get_object_hash(static_cast<const TransactionPrefix &>(tx));
	return crypto::cn_fast_hash(data.data(), data.size());
}

void cn::set_root_extra_to_solo_mining_tag(BlockTemplate &block) {
	if (block.is_merge_mined()) {
		TransactionExtraMergeMiningTag mmTag;
		mmTag.depth = 0;
		block.root_block.base_transaction.extra.clear();
		mmTag.merkle_root = get_auxiliary_block_header_hash(block, get_body_proxy_from_template(block));
		extra_add_merge_mining_tag(block.root_block.base_transaction.extra, mmTag);
	}
}

// 62387455827 -> 455827 + 7000000 + 80000000 + 300000000 + 2000000000 +
// 60000000000, where 455827 <= dust_threshold
template<typename chunk_handler_t, typename dust_handler_t>
void decompose_amount_into_digits(
    Amount amount, Amount dust_threshold, const chunk_handler_t &chunk_handler, const dust_handler_t &dust_handler) {
	// TODO - Rewrite this fun
	if (0 == amount) {
		return;
	}

	bool is_dust_handled = false;
	uint64_t dust        = 0;
	uint64_t order       = 1;
	while (0 != amount) {
		uint64_t chunk = (amount % 10) * order;
		amount /= 10;
		order *= 10;

		if (dust + chunk <= dust_threshold) {
			dust += chunk;
		} else {
			if (!is_dust_handled && 0 != dust) {
				dust_handler(dust);
				is_dust_handled = true;
			}
			if (0 != chunk) {
				chunk_handler(chunk);
			}
		}
	}

	if (!is_dust_handled && 0 != dust) {
		dust_handler(dust);
	}
}

void cn::decompose_amount(Amount amount, Amount dust_threshold, std::vector<Amount> *decomposed_amounts) {
	decompose_amount_into_digits(amount, dust_threshold, [&](Amount amount) { decomposed_amounts->push_back(amount); },
	    [&](Amount dust) {
		    // This code will work relatively well for any dust_threshold <= 6
		    Amount du0 = dust % 1000;
		    Amount du1 = dust - du0;
		    if (du1 != 0)
			    decomposed_amounts->push_back(du1);
		    if (du0 != 0)
			    decomposed_amounts->push_back(du0);
	    });
}

const size_t KEY_IMAGE_SIZE                    = sizeof(KeyImage);
const size_t OUTPUT_KEY_SIZE                   = sizeof(PublicKey);
const size_t OUTPUT_SECRET_SIZE                = sizeof(Hash);
const size_t AMOUNT_SIZE                       = sizeof(uint64_t) + 2;  // varint
const size_t IO_COUNT_SIZE                     = 3;                     // varint
const size_t GLOBAL_INDEXES_VECTOR_SIZE_SIZE   = 1;                     // varint
const size_t GLOBAL_INDEXES_INITIAL_VALUE_SIZE = sizeof(size_t);        // varint
const size_t GLOBAL_INDEXES_DIFFERENCE_SIZE    = sizeof(size_t);        // varint
const size_t SIGNATURE_SIZE                    = sizeof(Signature);
const size_t EXTRA_TAG_SIZE                    = 1;
const size_t INPUT_TAG_SIZE                    = 1;
const size_t OUTPUT_TAG_SIZE                   = 1;
const size_t PUBLIC_KEY_SIZE                   = sizeof(PublicKey);
const size_t TRANSACTION_VERSION_SIZE          = 1;
const size_t TRANSACTION_UNLOCK_TIME_SIZE      = sizeof(uint64_t);

const size_t header_size = TRANSACTION_VERSION_SIZE + TRANSACTION_UNLOCK_TIME_SIZE + EXTRA_TAG_SIZE + PUBLIC_KEY_SIZE;

size_t cn::get_maximum_tx_input_size(size_t anonymity) {
	return INPUT_TAG_SIZE + AMOUNT_SIZE + KEY_IMAGE_SIZE + SIGNATURE_SIZE + GLOBAL_INDEXES_VECTOR_SIZE_SIZE +
	       GLOBAL_INDEXES_INITIAL_VALUE_SIZE + anonymity * (GLOBAL_INDEXES_DIFFERENCE_SIZE + SIGNATURE_SIZE);
}

size_t cn::get_maximum_tx_size(size_t input_count, size_t output_count, size_t anonymity) {
	const size_t outputs_size =
	    IO_COUNT_SIZE + output_count * (OUTPUT_TAG_SIZE + OUTPUT_KEY_SIZE + OUTPUT_SECRET_SIZE + AMOUNT_SIZE);
	const size_t inputs_size = IO_COUNT_SIZE + input_count * get_maximum_tx_input_size(anonymity);
	return header_size + outputs_size + inputs_size;
}

Amount cn::get_tx_sum_outputs(const TransactionPrefix &tx) {
	uint64_t amount_out = 0;
	for (const auto &o : tx.outputs) {
		if (o.type() == typeid(OutputKey))
			amount_out += boost::get<OutputKey>(o).amount;
	}
	return amount_out;
}
Amount cn::get_tx_sum_inputs(const TransactionPrefix &tx) {
	uint64_t amount_in = 0;
	for (const auto &in : tx.inputs) {
		if (in.type() == typeid(InputKey))
			amount_in += boost::get<InputKey>(in).amount;
	}
	return amount_in;
}

size_t cn::get_tx_key_outputs_count(const TransactionPrefix &tx) {
	size_t count = 0;
	for (const auto &o : tx.outputs) {
		if (o.type() == typeid(OutputKey))
			count += 1;
	}
	return count;
}

bool cn::get_tx_fee(const TransactionPrefix &tx, uint64_t *fee) {
	uint64_t amount_in  = get_tx_sum_inputs(tx);
	uint64_t amount_out = get_tx_sum_outputs(tx);

	if (amount_in < amount_out)
		return false;
	*fee = amount_in - amount_out;
	return true;
}

uint64_t cn::get_tx_fee(const TransactionPrefix &tx) {
	uint64_t r = 0;
	if (!get_tx_fee(tx, &r))
		return 0;
	return r;
}

std::vector<size_t> cn::absolute_output_offsets_to_relative(const std::vector<size_t> &off) {
	invariant(!off.empty(), "Output indexes cannot be empty");
	std::vector<size_t> relative(off.size());
	relative[0] = off[0];
	for (size_t i = 1; i < off.size(); ++i) {
		invariant(off[i] > off[i - 1], "Output indexes must be unique and sorted");
		relative[i] = off[i] - off[i - 1];
	}
	return relative;
}

bool cn::relative_output_offsets_to_absolute(std::vector<size_t> *result, const std::vector<size_t> &off) {
	if (off.empty())
		return false;
	std::vector<size_t> absolute(off.size());
	absolute[0] = off[0];
	for (size_t i = 1; i < off.size(); ++i) {
		if (off[i] == 0 || std::numeric_limits<size_t>::max() - absolute[i - 1] < off[i])
			return false;
		absolute[i] = absolute[i - 1] + off[i];
	}
	*result = std::move(absolute);
	return true;
}

BlockBodyProxy cn::get_body_proxy_from_template(const BlockTemplate &bt) {
	BlockBodyProxy body_proxy;
	std::vector<Hash> transaction_hashes;
	transaction_hashes.reserve(bt.transaction_hashes.size() + 1);
	transaction_hashes.push_back(get_object_hash(bt.base_transaction));
	transaction_hashes.insert(transaction_hashes.end(), bt.transaction_hashes.begin(), bt.transaction_hashes.end());
	body_proxy.transactions_merkle_root = crypto::tree_hash(transaction_hashes.data(), transaction_hashes.size());
	body_proxy.transaction_count        = transaction_hashes.size();
	return body_proxy;
}
