// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "TransactionExtra.hpp"
#include "CryptoNoteConfig.hpp"
#include "CryptoNoteTools.hpp"
#include "common/MemoryStreams.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/ISeria.hpp"

using namespace cn;

template<typename T, typename U>
bool set_field_good(const T &, U &, std::false_type) {
	return false;
}
template<typename T>
bool set_field_good(const T &a, T &b, std::true_type) {
	b = a;  // If more than one specified, we take the first field
	return true;
}
template<typename T>
bool set_field_good(const BinaryArray &field_data, T &b, std::true_type) {
	seria::from_binary(b, field_data);
	return true;
}
bool set_field_good(const BinaryArray &field_data, std::vector<extra::EncryptedMessage> &b, std::true_type) {
	extra::EncryptedMessage a;
	seria::from_binary(a, field_data);
	b.push_back(a);
	return false;  // We do not stop parsing on first message
}

template<typename T>
bool find_field_in_extra(const BinaryArray &extra, T &field) {
	try {
		common::MemoryInputStream iss(extra.data(), extra.size());

		while (!iss.empty()) {
			uint8_t c = iss.read_byte();
			if (c == extra::Padding::tag) {
				extra::Padding value{1 + iss.size()};
				// tag is itself '0', counts towards padding size
				// bytes usually set to zero, but we do not care
				return set_field_good(value, field, std::is_same<T, extra::Padding>{});  // last field
			}
			if (c == extra::TransactionPublicKey::tag) {
				extra::TransactionPublicKey value;
				iss.read(value.public_key.data, sizeof(value.public_key.data));
				if (set_field_good(value, field, std::is_same<T, extra::TransactionPublicKey>{}))
					return true;
				continue;
			}
			// other tags have uniform format
			BinaryArray field_data;
			auto size = iss.read_varint<size_t>();
			iss.read(field_data, size);
			switch (c) {
			case extra::Nonce::tag:
				// We have some base transactions (like in blocks 558479, 558984)
				// which have wrong extra nonce size, so they will throw here
				if (set_field_good(extra::Nonce{field_data}, field, std::is_same<T, extra::Nonce>{}))
					return true;
				break;
			case extra::MergeMiningTag::tag:
				if (set_field_good(field_data, field, std::is_same<T, extra::MergeMiningTag>{}))
					return true;
				break;
			case extra::BlockCapacityVote::tag:
				if (set_field_good(field_data, field, std::is_same<T, extra::BlockCapacityVote>{}))
					return true;
				break;
			case extra::EncryptedMessage::tag:
				if (set_field_good(field_data, field, std::is_same<T, std::vector<extra::EncryptedMessage>>{}))
					return true;
				break;
			}
		}
	} catch (std::exception &) {
	}
	return false;  // Not found
}

bool cn::extra::is_valid(const BinaryArray &extra) {
	try {
		common::MemoryInputStream iss(extra.data(), extra.size());

		while (!iss.empty()) {
			int c = iss.read_byte();
			if (c == extra::Padding::tag)
				return true;  // last field
			if (c == extra::TransactionPublicKey::tag) {
				extra::TransactionPublicKey value;
				iss.read(value.public_key.data, sizeof(value.public_key.data));
				continue;
			}
			// other tags have uniform format
			BinaryArray field_data;
			auto size = iss.read_varint<size_t>();
			iss.read(field_data, size);
		}
		return true;
	} catch (std::exception &) {
	}
	return false;
}

void cn::extra::add_transaction_public_key(BinaryArray &tx_extra, const PublicKey &tx_pub_key) {
	tx_extra.push_back(TransactionPublicKey::tag);
	common::append(tx_extra, std::begin(tx_pub_key.data), std::end(tx_pub_key.data));
}

bool cn::extra::get_transaction_public_key(const BinaryArray &tx_extra, PublicKey *tx_pub_key) {
	TransactionPublicKey pub_key_field;
	if (!find_field_in_extra(tx_extra, pub_key_field))
		return false;
	*tx_pub_key = pub_key_field.public_key;
	return true;
}

void cn::extra::add_nonce(BinaryArray &tx_extra, const BinaryArray &extra_nonce) {
	if (extra_nonce.size() > Nonce::MAX_COUNT)
		throw std::runtime_error("Extra nonce cannot be > " + common::to_string(Nonce::MAX_COUNT));
	tx_extra.push_back(Nonce::tag);
	tx_extra.push_back(static_cast<uint8_t>(extra_nonce.size()));
	common::append(tx_extra, extra_nonce);
}

void cn::extra::add_merge_mining_tag(BinaryArray &tx_extra, const extra::MergeMiningTag &field) {
	BinaryArray blob = seria::to_binary(field);
	tx_extra.push_back(MergeMiningTag::tag);
	common::append(tx_extra, common::get_varint_data(blob.size()));
	common::append(tx_extra, blob);
}

bool cn::extra::get_merge_mining_tag(const BinaryArray &tx_extra, extra::MergeMiningTag *field) {
	return find_field_in_extra(tx_extra, *field);
}

void cn::extra::add_block_capacity_vote(BinaryArray &tx_extra, size_t block_capacity) {
	BinaryArray blob = seria::to_binary(block_capacity);
	tx_extra.push_back(BlockCapacityVote::tag);
	common::append(tx_extra, common::get_varint_data(blob.size()));
	common::append(tx_extra, blob);
}

bool cn::extra::get_block_capacity_vote(const BinaryArray &tx_extra, size_t *block_capacity) {
	BlockCapacityVote field;
	if (!find_field_in_extra(tx_extra, field))
		return false;
	*block_capacity = field.block_capacity;
	return true;
}

void cn::extra::add_payment_id(BinaryArray &tx_extra, const Hash &payment_id) {
	BinaryArray extra_nonce;
	extra_nonce.push_back(Nonce::PAYMENT_ID);
	common::append(extra_nonce, std::begin(payment_id.data), std::end(payment_id.data));
	add_nonce(tx_extra, extra_nonce);
}

bool cn::extra::get_payment_id(const BinaryArray &tx_extra, Hash *payment_id) {
	Nonce extra_nonce;
	if (!find_field_in_extra(tx_extra, extra_nonce))
		return false;
	if (extra_nonce.nonce.size() != sizeof(Hash) + 1)
		return false;
	if (extra_nonce.nonce.at(0) != Nonce::PAYMENT_ID)
		return false;
	std::copy(extra_nonce.nonce.begin() + 1, extra_nonce.nonce.end(), payment_id->data);
	return true;
}

void cn::extra::add_encrypted_message(BinaryArray &tx_extra, const EncryptedMessage &message) {
	BinaryArray blob = seria::to_binary(message);
	tx_extra.push_back(EncryptedMessage::tag);
	common::append(tx_extra, common::get_varint_data(blob.size()));
	common::append(tx_extra, blob);
}

size_t cn::extra::get_encrypted_message_size(size_t size) {
	size_t body_size = 2 * sizeof(PublicKey) + 1 + common::get_varint_data_size(size) + size;
	return 1 + common::get_varint_data_size(body_size) + body_size;
}

std::vector<extra::EncryptedMessage> cn::extra::get_encrypted_messages(const BinaryArray &tx_extra) {
	std::vector<extra::EncryptedMessage> field;
	find_field_in_extra(tx_extra, field);
	return field;
}

void seria::ser_members(extra::MergeMiningTag &v, ISeria &s) {
	seria_kv("depth", v.depth, s);
	seria_kv("merkle_root", v.merkle_root, s);
}

void seria::ser_members(extra::BlockCapacityVote &v, ISeria &s) { seria_kv("block_capacity", v.block_capacity, s); }

void seria::ser_members(extra::EncryptedMessage &v, ISeria &s) {
	s.object_key("output");
	s.begin_object();
	seria_kv("public_key", v.output.public_key, s);
	seria_kv("encrypted_secret", v.output.encrypted_secret, s);
	seria_kv_binary("encrypted_address_type", &v.output.encrypted_address_type, 1, s);
	s.end_object();
	seria_kv("message", v.message, s);
}
