// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "TransactionExtra.hpp"

#include "CryptoNoteTools.hpp"
#include "common/MemoryStreams.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/ISeria.hpp"

using namespace cn;

template<typename T, typename U>
bool set_field_good(const T &, U &) {
	return false;
}
template<typename T>
bool set_field_good(const T &a, T &b) {
	b = a;  // If more than one specified, we take the first field
	return true;
}
bool set_field_good(const extra::EncryptedMessage &a, std::vector<extra::EncryptedMessage> &b) {
	b.push_back(a);  // We take all messages
	return false;
}

template<typename T>
bool find_field_in_extra(const BinaryArray &extra, T &field, bool *valid = nullptr) {
	try {
		if (valid)
			*valid = true;  // Presumption
		common::MemoryInputStream iss(extra.data(), extra.size());
		seria::BinaryInputStream ar(iss);

		while (!iss.empty()) {
			int c = iss.read_byte();
			switch (c) {
			case extra::Padding::tag: {
				extra::Padding value{1 + iss.size()};
				// tag is itself '0', counts towards padding size
				// bytes usually set to zero, but we do not care
				return set_field_good(value, field);  // last field
			}
			case extra::TransactionPublicKey::tag: {
				extra::TransactionPublicKey value;
				iss.read(value.public_key.data, sizeof(value.public_key.data));
				if (set_field_good(value, field))
					return true;
				break;
			}
			case extra::Nonce::tag: {
				extra::Nonce value;
				uint8_t size = iss.read_byte();  // TODO - turn into varint after Amethyst fork
				value.nonce.resize(size);
				iss.read(value.nonce.data(), value.nonce.size());
				// We have some base transactions (like in blocks 558479, 558984)
				// which have wrong extra nonce size, so they will not parse and
				// throw here from iss.read
				if (set_field_good(value, field))
					return true;
				break;
			}
			case extra::MergeMiningTag::tag: {
				extra::MergeMiningTag value;
				std::string field_data;
				ser(field_data, ar);
				common::MemoryInputStream stream(field_data.data(), field_data.size());
				seria::BinaryInputStream input(stream);
				ser(value, input);
				if (set_field_good(value, field))
					return true;
				break;
			}
			case extra::BlockCapacityVote::tag: {
				extra::BlockCapacityVote value;
				std::string field_data;
				ser(field_data, ar);
				common::MemoryInputStream stream(field_data.data(), field_data.size());
				seria::BinaryInputStream input(stream);
				ser(value, input);
				if (set_field_good(value, field))
					return true;
				break;
			}
			case extra::EncryptedMessage::tag: {
				extra::EncryptedMessage value;
				ser(value.message, ar);
				if (set_field_good(value, field))
					return true;
				break;
			}
			default: {  // We hope to skip unknown tags
				std::string field_data;
				ser(field_data, ar);
			}
			}
		}
	} catch (std::exception &) {
		if (valid)
			*valid = false;
	}
	return false;  // Not found
}

PublicKey cn::extra::get_transaction_public_key(const BinaryArray &tx_extra) {
	TransactionPublicKey pub_key_field;
	if (!find_field_in_extra(tx_extra, pub_key_field))
		return PublicKey{};
	return pub_key_field.public_key;
}

void cn::extra::add_transaction_public_key(BinaryArray &tx_extra, const PublicKey &tx_pub_key) {
	tx_extra.push_back(TransactionPublicKey::tag);
	common::append(tx_extra, std::begin(tx_pub_key.data), std::end(tx_pub_key.data));
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

bool cn::extra::get_merge_mining_tag(const BinaryArray &tx_extra, extra::MergeMiningTag &field) {
	return find_field_in_extra(tx_extra, field);
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

bool cn::extra::get_payment_id(const BinaryArray &tx_extra, Hash &payment_id) {
	Nonce extra_nonce;
	if (!find_field_in_extra(tx_extra, extra_nonce))
		return false;
	if (extra_nonce.nonce.size() != sizeof(Hash) + 1)
		return false;
	if (extra_nonce.nonce.at(0) != Nonce::PAYMENT_ID)
		return false;
	std::copy(extra_nonce.nonce.begin() + 1, extra_nonce.nonce.end(), payment_id.data);
	return true;
}

std::vector<extra::EncryptedMessage> cn::extra::get_encrypted_messages(const BinaryArray &tx_extra) {
	std::vector<extra::EncryptedMessage> field;
	find_field_in_extra(tx_extra, field);
	return field;
}

void cn::extra::add_encrypted_message(BinaryArray &tx_extra, const BinaryArray &message) {
	tx_extra.push_back(EncryptedMessage::tag);
	common::append(tx_extra, common::get_varint_data(message.size()));
	common::append(tx_extra, message);
}

void seria::ser_members(extra::MergeMiningTag &v, ISeria &s) {
	seria_kv("depth", v.depth, s);
	seria_kv("merkle_root", v.merkle_root, s);
}

void seria::ser_members(extra::BlockCapacityVote &v, ISeria &s) { seria_kv("block_capacity", v.block_capacity, s); }
