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

#include "CryptoNoteTools.hpp"
#include "seria/ISeria.hpp"
#include "TransactionExtra.hpp"

using namespace bytecoin;

Hash bytecoin::getBaseTransactionHash(const BaseTransaction &tx) {
	if (tx.version < 2)
		return getObjectHash(tx);
	BinaryArray data{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbc, 0x36, 0x78, 0x9e, 0x7a, 0x1e, 0x28, 0x14, 0x36, 0x46, 0x42, 0x29, 0x82, 0x8f, 0x81, 0x7d, 0x66, 0x12, 0xf7, 0xb4, 0x77, 0xd6, 0x65, 0x91, 0xff, 0x96, 0xa9, 0xe0, 0x64, 0xbc, 0xc9, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
	*reinterpret_cast<Hash *>(data.data()) = getObjectHash(static_cast<const TransactionPrefix &>(tx));
	return crypto::cn_fast_hash(data.data(), data.size());
}

// 62387455827 -> 455827 + 7000000 + 80000000 + 300000000 + 2000000000 + 60000000000, where 455827 <= dust_threshold
template<typename chunk_handler_t, typename dust_handler_t>
void decompose_amount_into_digits(Amount amount, Amount dust_threshold, const chunk_handler_t &chunk_handler, const dust_handler_t &dust_handler) {
	// TODO - Rewrite this fun
	if (0 == amount) {
		return;
	}
	
	bool is_dust_handled = false;
	uint64_t dust = 0;
	uint64_t order = 1;
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

void bytecoin::decomposeAmount(Amount amount, Amount dustThreshold, std::vector<Amount> &decomposedAmounts) {
	decompose_amount_into_digits(amount, dustThreshold,
		 [&](Amount amount) {
			 decomposedAmounts.push_back(amount);
		 },
		 [&](Amount dust) {
			 Amount du0 = dust % 1000;
			 Amount du1 = dust - du0;
			 if (du0 != 0)
				 decomposedAmounts.push_back(du0);
			 if (du1 != 0)
				 decomposedAmounts.push_back(du1);
		 }
	);
}

size_t bytecoin::getMaximumTxSize(size_t inputCount, size_t outputCount, size_t mixinCount) {
	const size_t KEY_IMAGE_SIZE = sizeof(crypto::KeyImage);
	const size_t OUTPUT_KEY_SIZE = sizeof(crypto::PublicKey);
	const size_t AMOUNT_SIZE = sizeof(uint64_t) + 2; //varint
	const size_t GLOBAL_INDEXES_VECTOR_SIZE_SIZE = sizeof(uint8_t);//varint
	const size_t GLOBAL_INDEXES_INITIAL_VALUE_SIZE = sizeof(uint32_t);//varint
	const size_t GLOBAL_INDEXES_DIFFERENCE_SIZE = sizeof(uint32_t);//varint
	const size_t SIGNATURE_SIZE = sizeof(crypto::Signature);
	const size_t EXTRA_TAG_SIZE = sizeof(uint8_t);
	const size_t INPUT_TAG_SIZE = sizeof(uint8_t);
	const size_t OUTPUT_TAG_SIZE = sizeof(uint8_t);
	const size_t PUBLIC_KEY_SIZE = sizeof(crypto::PublicKey);
	const size_t TRANSACTION_VERSION_SIZE = sizeof(uint8_t);
	const size_t TRANSACTION_UNLOCK_TIME_SIZE = sizeof(uint64_t);

	const size_t outputsSize = outputCount * (OUTPUT_TAG_SIZE + OUTPUT_KEY_SIZE + AMOUNT_SIZE);
	const size_t headerSize = TRANSACTION_VERSION_SIZE + TRANSACTION_UNLOCK_TIME_SIZE + EXTRA_TAG_SIZE + PUBLIC_KEY_SIZE;
	const size_t inputSize = INPUT_TAG_SIZE + AMOUNT_SIZE + KEY_IMAGE_SIZE + SIGNATURE_SIZE + GLOBAL_INDEXES_VECTOR_SIZE_SIZE + GLOBAL_INDEXES_INITIAL_VALUE_SIZE +
							 mixinCount * (GLOBAL_INDEXES_DIFFERENCE_SIZE + SIGNATURE_SIZE);
	return headerSize + outputsSize + inputSize * inputCount;
}

bool bytecoin::get_tx_fee(const Transaction &tx, uint64_t &fee) {
	uint64_t amount_in = 0;
	uint64_t amount_out = 0;

	for (const auto &in : tx.inputs) {
		if (in.type() == typeid(KeyInput)) {
			amount_in += boost::get<KeyInput>(in).amount;
		}
	}

	for (const auto &o : tx.outputs) {
		amount_out += o.amount;
	}

	if (!(amount_in >= amount_out)) {
		return false;
	}

	fee = amount_in - amount_out;
	return true;
}

uint64_t bytecoin::get_tx_fee(const Transaction &tx) {
	uint64_t r = 0;
	if (!get_tx_fee(tx, r))
		return 0;
	return r;
}

void seria::serMembers(ParentBlockSerializer &v, ISeria &s) {
	seria_kv("major_version", v.m_parentBlock.major_version, s);

	seria_kv("minor_version", v.m_parentBlock.minor_version, s);
	seria_kv("timestamp", v.m_timestamp, s);
	seria_kv("previous_block_hash", v.m_parentBlock.previous_block_hash, s);
	s.objectKey("nonce");
	s.binary(&v.m_nonce, sizeof(v.m_nonce));  // TODO - fix endianess

	if (v.m_hashingSerialization) {
		crypto::Hash minerTxHash = getBaseTransactionHash(v.m_parentBlock.base_transaction);
		crypto::Hash merkleRoot =
				crypto::tree_hash_from_branch(v.m_parentBlock.base_transaction_branch.data(),
											  v.m_parentBlock.base_transaction_branch.size(), minerTxHash, 0);

		seria_kv("merkle_root", merkleRoot, s);
	}

	uint64_t txNum = static_cast<uint64_t>(v.m_parentBlock.transaction_count);
	seria_kv("transaction_count", txNum, s);
	v.m_parentBlock.transaction_count = static_cast<uint16_t>(txNum);
	if (v.m_parentBlock.transaction_count < 1)
		throw std::runtime_error("Wrong transactions number");

	if (v.m_headerOnly) {
		return;
	}

	size_t branchSize = crypto::tree_depth(v.m_parentBlock.transaction_count);
	if (!s.isInput()) {
		if (v.m_parentBlock.base_transaction_branch.size() != branchSize)
			throw std::runtime_error("Wrong miner transaction branch size");
	} else {
		v.m_parentBlock.base_transaction_branch.resize(branchSize);
	}

	//  serializer(m_parentBlock.baseTransactionBranch, "baseTransactionBranch");
	s.objectKey("base_transaction_branch");
	size_t btb_size = v.m_parentBlock.base_transaction_branch.size();
	s.beginArray(btb_size, true);
	// TODO: Make arrays with computable size! This code won't work with json serialization!
	for (crypto::Hash &hash : v.m_parentBlock.base_transaction_branch) {
		s(hash);
	}
	s.endArray();

	seria_kv("miner_tx", v.m_parentBlock.base_transaction, s);

	TransactionExtraMergeMiningTag mmTag;
	if (!getMergeMiningTagFromExtra(v.m_parentBlock.base_transaction.extra, mmTag))
		throw std::runtime_error("Can't get extra merge mining tag");
	if (mmTag.depth > 8 * sizeof(crypto::Hash))
		throw std::runtime_error("Wrong merge mining tag depth");

	if (!s.isInput()) {
		if (mmTag.depth != v.m_parentBlock.blockchain_branch.size())
			throw std::runtime_error("Blockchain branch size must be equal to merge mining tag depth");
	} else {
		v.m_parentBlock.blockchain_branch.resize(mmTag.depth);
	}

	//  serializer(m_parentBlock.blockchainBranch, "blockchainBranch");
	// TODO: Make arrays with computable size! This code won't work with json serialization!
	s.objectKey("blockchain_branch");
	btb_size = v.m_parentBlock.blockchain_branch.size();
	s.beginArray(btb_size, true);
	for (crypto::Hash &hash : v.m_parentBlock.blockchain_branch) {
		s(hash);
	}
	s.endArray();
}
