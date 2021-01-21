// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "CryptoNote.hpp"

namespace cn { namespace extra {

struct Padding {
	size_t size = 0;
	enum { tag = 0x00 };
	// We removed MAX_COUNT, when padding encountered, remaining bytes are padding
};

struct TransactionPublicKey {
	PublicKey public_key;
	enum { tag = 0x01 };
};

struct Nonce {
	BinaryArray nonce;
	enum { tag = 0x02, MAX_COUNT = 127, PAYMENT_ID = 0x00 };
	// We limit MAX_COUNT so that single byte (former) is equal to varint encoding (now)
};

struct MergeMiningTag {
	size_t depth = 0;
	Hash merkle_root;
	enum { tag = 0x03 };
};

struct BlockCapacityVote {
	size_t block_capacity = 0;
	enum { tag = 0x04 };
};

struct EncryptedMessage {
	OutputKey output;             // Always amethyst type, amount is not serialized
	common::BinaryArray message;  // No CRC needed because we run normal coin detection algorithm
	enum { tag = 0x05 };
};
// tx_extra_field format, except Padding, TransactionPublicKey:
//   varint tag;
//   varint size | byte size
//   varint data[];

bool is_valid(const BinaryArray &tx_extra);

void add_transaction_public_key(BinaryArray &tx_extra, const PublicKey &tx_pub_key);
bool get_transaction_public_key(const BinaryArray &tx_extra, PublicKey *tx_pub_key);

void add_nonce(BinaryArray &tx_extra, const BinaryArray &extra_nonce);
void add_merge_mining_tag(BinaryArray &tx_extra, const MergeMiningTag &field);
bool get_merge_mining_tag(const BinaryArray &tx_extra, MergeMiningTag *field);

void add_block_capacity_vote(BinaryArray &tx_extra, size_t block_capacity);
bool get_block_capacity_vote(const BinaryArray &tx_extra, size_t *block_capacity);

void add_payment_id(BinaryArray &tx_extra, const Hash &payment_id);
bool get_payment_id(const BinaryArray &tx_extra, Hash *payment_id);

void add_encrypted_message(BinaryArray &tx_extra, const EncryptedMessage &message);
size_t get_encrypted_message_size(size_t size);
std::vector<EncryptedMessage> get_encrypted_messages(const BinaryArray &tx_extra);

}}  // namespace cn::extra

namespace seria {
class ISeria;
void ser_members(cn::extra::MergeMiningTag &v, ISeria &s);
void ser_members(cn::extra::BlockCapacityVote &v, ISeria &s);
void ser_members(cn::extra::EncryptedMessage &v, ISeria &s);
}  // namespace seria
