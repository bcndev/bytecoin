// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "CryptoNoteTools.hpp"
#include "Currency.hpp"
#include "TransactionExtra.hpp"
#include "seria/ISeria.hpp"

using namespace bytecoin;

Hash bytecoin::get_base_transaction_hash(const BaseTransaction &tx) {
	if (tx.version < 2)
		return get_object_hash(tx);
	BinaryArray data{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbc, 0x36,
	    0x78, 0x9e, 0x7a, 0x1e, 0x28, 0x14, 0x36, 0x46, 0x42, 0x29, 0x82, 0x8f, 0x81, 0x7d, 0x66, 0x12, 0xf7, 0xb4,
	    0x77, 0xd6, 0x65, 0x91, 0xff, 0x96, 0xa9, 0xe0, 0x64, 0xbc, 0xc9, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
	*reinterpret_cast<Hash *>(data.data()) = get_object_hash(static_cast<const TransactionPrefix &>(tx));
	return crypto::cn_fast_hash(data.data(), data.size());
}

void bytecoin::fix_merge_mining_tag(BlockTemplate &block) {
	if (block.major_version >= 2) {
		bytecoin::TransactionExtraMergeMiningTag mmTag;
		mmTag.depth = 0;
		block.parent_block.base_transaction.extra.clear();
		mmTag.merkle_root = get_auxiliary_block_header_hash(block);
		if (!bytecoin::append_merge_mining_tag_to_extra(block.parent_block.base_transaction.extra, mmTag))
			throw std::runtime_error("bytecoin::append_merge_mining_tag_to_extra failed");
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

void bytecoin::decompose_amount(Amount amount, Amount dust_threshold, std::vector<Amount> *decomposed_amounts) {
	decompose_amount_into_digits(amount, dust_threshold, [&](Amount amount) { decomposed_amounts->push_back(amount); },
	    [&](Amount dust) {
		    Amount du0 = dust % 1000;
		    Amount du1 = dust - du0;
		    if (du0 != 0)
			    decomposed_amounts->push_back(du0);
		    if (du1 != 0)
			    decomposed_amounts->push_back(du1);
		});
}

size_t bytecoin::get_maximum_tx_size(size_t input_count, size_t output_count, size_t mixin_count) {
	const size_t KEY_IMAGE_SIZE                    = sizeof(crypto::KeyImage);
	const size_t OUTPUT_KEY_SIZE                   = sizeof(crypto::PublicKey);
	const size_t AMOUNT_SIZE                       = sizeof(uint64_t) + 2;  // varint
	const size_t GLOBAL_INDEXES_VECTOR_SIZE_SIZE   = sizeof(uint8_t);       // varint
	const size_t GLOBAL_INDEXES_INITIAL_VALUE_SIZE = sizeof(uint32_t);      // varint
	const size_t GLOBAL_INDEXES_DIFFERENCE_SIZE    = sizeof(uint32_t);      // varint
	const size_t SIGNATURE_SIZE                    = sizeof(crypto::Signature);
	const size_t EXTRA_TAG_SIZE                    = sizeof(uint8_t);
	const size_t INPUT_TAG_SIZE                    = sizeof(uint8_t);
	const size_t OUTPUT_TAG_SIZE                   = sizeof(uint8_t);
	const size_t PUBLIC_KEY_SIZE                   = sizeof(crypto::PublicKey);
	const size_t TRANSACTION_VERSION_SIZE          = sizeof(uint8_t);
	const size_t TRANSACTION_UNLOCK_TIME_SIZE      = sizeof(uint64_t);

	const size_t outputs_size = output_count * (OUTPUT_TAG_SIZE + OUTPUT_KEY_SIZE + AMOUNT_SIZE);
	const size_t header_size =
	    TRANSACTION_VERSION_SIZE + TRANSACTION_UNLOCK_TIME_SIZE + EXTRA_TAG_SIZE + PUBLIC_KEY_SIZE;
	const size_t input_size = INPUT_TAG_SIZE + AMOUNT_SIZE + KEY_IMAGE_SIZE + SIGNATURE_SIZE +
	                          GLOBAL_INDEXES_VECTOR_SIZE_SIZE + GLOBAL_INDEXES_INITIAL_VALUE_SIZE +
	                          mixin_count * (GLOBAL_INDEXES_DIFFERENCE_SIZE + SIGNATURE_SIZE);
	return header_size + outputs_size + input_size * input_count;
}

bool bytecoin::get_tx_fee(const TransactionPrefix &tx, uint64_t *fee) {
	uint64_t amount_in  = 0;
	uint64_t amount_out = 0;

	for (const auto &in : tx.inputs) {
		if (in.type() == typeid(KeyInput)) {
			amount_in += boost::get<KeyInput>(in).amount;
		}
	}

	for (const auto &o : tx.outputs) {
		amount_out += o.amount;
	}

	if (amount_in < amount_out) {
		return false;
	}

	*fee = amount_in - amount_out;
	return true;
}

uint64_t bytecoin::get_tx_fee(const TransactionPrefix &tx) {
	uint64_t r = 0;
	if (!get_tx_fee(tx, &r))
		return 0;
	return r;
}

void seria::ser_members(ParentBlockSerializer &v, ISeria &s) {
	seria_kv("major_version", v.m_parent_block.major_version, s);

	seria_kv("minor_version", v.m_parent_block.minor_version, s);
	seria_kv("timestamp", v.m_timestamp, s);
	seria_kv("previous_block_hash", v.m_parent_block.previous_block_hash, s);
	s.object_key("nonce");
	s.binary(&v.m_nonce, sizeof(v.m_nonce));  // TODO - fix endianess

	if (v.m_hashing_serialization) {
		crypto::Hash miner_tx_hash = get_base_transaction_hash(v.m_parent_block.base_transaction);
		crypto::Hash merkle_root   = crypto::tree_hash_from_branch(v.m_parent_block.base_transaction_branch.data(),
		    v.m_parent_block.base_transaction_branch.size(), miner_tx_hash, 0);

		seria_kv("merkle_root", merkle_root, s);
	}

	uint64_t tx_num = static_cast<uint64_t>(v.m_parent_block.transaction_count);
	seria_kv("transaction_count", tx_num, s);
	v.m_parent_block.transaction_count = static_cast<uint16_t>(tx_num);
	if (v.m_parent_block.transaction_count < 1)
		throw std::runtime_error("Wrong transactions number");

	if (v.m_header_only) {
		return;
	}

	size_t branch_size = crypto::tree_depth(v.m_parent_block.transaction_count);
	if (!s.is_input()) {
		if (v.m_parent_block.base_transaction_branch.size() != branch_size)
			throw std::runtime_error("Wrong miner transaction branch size");
	} else {
		v.m_parent_block.base_transaction_branch.resize(branch_size);
	}

	s.object_key("base_transaction_branch");
	size_t btb_size = v.m_parent_block.base_transaction_branch.size();
	s.begin_array(btb_size, true);
	for (crypto::Hash &hash : v.m_parent_block.base_transaction_branch) {
		s(hash);
	}
	s.end_array();

	seria_kv("miner_tx", v.m_parent_block.base_transaction, s);

	TransactionExtraMergeMiningTag mm_tag;
	if (!get_merge_mining_tag_from_extra(v.m_parent_block.base_transaction.extra, mm_tag))
		throw std::runtime_error("Can't get extra merge mining tag");
	if (mm_tag.depth > 8 * sizeof(crypto::Hash))
		throw std::runtime_error("Wrong merge mining tag depth");

	if (!s.is_input()) {
		if (mm_tag.depth != v.m_parent_block.blockchain_branch.size())
			throw std::runtime_error("Blockchain branch size must be equal to merge mining tag depth");
	} else {
		v.m_parent_block.blockchain_branch.resize(mm_tag.depth);
	}

	s.object_key("blockchain_branch");
	btb_size = v.m_parent_block.blockchain_branch.size();
	s.begin_array(btb_size, true);
	for (crypto::Hash &hash : v.m_parent_block.blockchain_branch) {
		s(hash);
	}
	s.end_array();
}
