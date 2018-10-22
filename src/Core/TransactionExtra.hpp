// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <boost/variant.hpp>
#include <vector>

#include "CryptoNote.hpp"
#include "seria/ISeria.hpp"

namespace bytecoin {

struct TransactionExtraPadding {
	size_t size = 0;
	enum { tag = 0x00, MAX_COUNT = 255 };
};

struct TransactionExtraPublicKey {
	PublicKey public_key;
	enum { tag = 0x01 };
};

struct TransactionExtraNonce {
	BinaryArray nonce;
	enum { tag = 0x02, MAX_COUNT = 255, PAYMENT_ID = 0x00 };
};

struct TransactionExtraMergeMiningTag {
	size_t depth = 0;
	Hash merkle_root;
	enum { tag = 0x03 };
};

// tx_extra_field format, except tx_extra_padding and tx_extra_pub_key:
//   varint tag;
//   varint size;
//   varint data[];
// typedef boost::variant<TransactionExtraPadding, TransactionExtraPublicKey, TransactionExtraNonce,
//    TransactionExtraMergeMiningTag>
//    TransactionExtraField;

// bool parse_transaction_extra(const BinaryArray &tx_extra, std::vector<TransactionExtraField> &tx_extra_fields);
// bool write_transaction_extra(BinaryArray &tx_extra, const std::vector<TransactionExtraField> &tx_extra_fields);

PublicKey extra_get_transaction_public_key(const BinaryArray &tx_extra);
void extra_add_transaction_public_key(BinaryArray &tx_extra, const PublicKey &tx_pub_key);

void extra_add_nonce(BinaryArray &tx_extra, const BinaryArray &extra_nonce);

void extra_add_merge_mining_tag(BinaryArray &tx_extra, const TransactionExtraMergeMiningTag &mm_tag);
bool extra_get_merge_mining_tag(const BinaryArray &tx_extra, TransactionExtraMergeMiningTag &mm_tag);

void extra_add_payment_id(BinaryArray &tx_extra, const Hash &payment_id);
bool extra_get_payment_id(const BinaryArray &tx_extra, Hash &payment_id);
}

namespace seria {
class ISeria;
void ser(bytecoin::TransactionExtraMergeMiningTag &v, ISeria &s);
}
