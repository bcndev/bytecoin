// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <boost/variant.hpp>
#include <vector>

#include "CryptoNote.hpp"
#include "seria/ISeria.hpp"

namespace cn {

struct TransactionExtraPadding {
	size_t size = 0;
	enum { tag = 0x00 };
	// We removed MAX_COUNT, when padding encountered, remaining bytes are padding
};

struct TransactionExtraPublicKey {
	PublicKey public_key;
	enum { tag = 0x01 };
};

struct TransactionExtraNonce {
	BinaryArray nonce;
	enum { tag = 0x02, MAX_COUNT = 127, PAYMENT_ID = 0x00 };
	// We limit MAX_COUNT so that single byte (former) is equal to varint encoding (now)
};

struct TransactionExtraMergeMiningTag {
	size_t depth = 0;
	Hash merkle_root;
	enum { tag = 0x03 };
};

struct TransactionExtraBlockCapacityVote {
	size_t block_capacity = 0;
	enum { tag = 0x04 };
};

// tx_extra_field format, except TransactionExtraPadding, TransactionExtraPublicKey:
//   varint tag;
//   varint size | byte size
//   varint data[];

PublicKey extra_get_transaction_public_key(const BinaryArray &tx_extra);
void extra_add_transaction_public_key(BinaryArray &tx_extra, const PublicKey &tx_pub_key);

void extra_add_nonce(BinaryArray &tx_extra, const BinaryArray &extra_nonce);

void extra_add_merge_mining_tag(BinaryArray &tx_extra, const TransactionExtraMergeMiningTag &field);
bool extra_get_merge_mining_tag(const BinaryArray &tx_extra, TransactionExtraMergeMiningTag &field);

void extra_add_block_capacity_vote(BinaryArray &tx_extra, size_t block_capacity);
bool extra_get_block_capacity_vote(const BinaryArray &tx_extra, size_t *block_capacity);

void extra_add_payment_id(BinaryArray &tx_extra, const Hash &payment_id);
bool extra_get_payment_id(const BinaryArray &tx_extra, Hash &payment_id);
}  // namespace cn

namespace seria {
class ISeria;
void ser_members(cn::TransactionExtraMergeMiningTag &v, ISeria &s);
void ser_members(cn::TransactionExtraBlockCapacityVote &v, ISeria &s);
}  // namespace seria
