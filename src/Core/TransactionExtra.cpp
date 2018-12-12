// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "TransactionExtra.hpp"

#include "CryptoNoteTools.hpp"
#include "common/MemoryStreams.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace cn;

template<typename T, typename U>
bool set_field_good(const T &, U &) {
	return false;
}
template<typename T>
bool set_field_good(const T &a, T &b) {
	b = a;
	return true;
}

template<typename T>
bool find_field_in_extra(const BinaryArray &extra, T &field) {
	try {
		common::MemoryInputStream iss(extra.data(), extra.size());
		seria::BinaryInputStream ar(iss);

		while (!iss.empty()) {
			int c = iss.read_byte();
			switch (c) {
			case TransactionExtraPadding::tag: {
				size_t size = 1;  // tag is itself '0', counts towards max count
				for (; !iss.empty() && size <= TransactionExtraPadding::MAX_COUNT; ++size) {
					if (iss.read_byte() != 0)
						return false;  // all bytes should be zero
				}
				if (size > TransactionExtraPadding::MAX_COUNT)
					return false;
				TransactionExtraPadding padding;
				padding.size = size;
				return set_field_good(padding, field);  // last field
			}
			case TransactionExtraPublicKey::tag: {
				TransactionExtraPublicKey extra_pk;
				iss.read(extra_pk.public_key.data, sizeof(extra_pk.public_key.data));
				if (set_field_good(extra_pk, field))
					return true;
				break;
			}
			case TransactionExtraNonce::tag: {
				TransactionExtraNonce extra_nonce;
				uint8_t size = iss.read_byte();  // TODO - turn into varint <= 127?
				extra_nonce.nonce.resize(size);
				iss.read(extra_nonce.nonce.data(), extra_nonce.nonce.size());
				// We have some base transactions (like in blocks 558479, 558984)
				// which have wrong extra nonce size, so they will not parse and
				// throw here from iss.read
				if (set_field_good(extra_nonce, field))
					return true;
				break;
			}
			case TransactionExtraMergeMiningTag::tag: {
				TransactionExtraMergeMiningTag mm_tag;
				std::string field_data;
				ser(field_data, ar);
				common::MemoryInputStream stream(field_data.data(), field_data.size());
				seria::BinaryInputStream input(stream);
				ser(mm_tag, input);
				if (set_field_good(mm_tag, field))
					return true;
				break;
			}
			case TransactionExtraBlockCapacityVote::tag: {
				TransactionExtraBlockCapacityVote bsv;
				std::string field_data;
				ser(field_data, ar);
				common::MemoryInputStream stream(field_data.data(), field_data.size());
				seria::BinaryInputStream input(stream);
				ser(bsv, input);
				if (set_field_good(bsv, field))
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
	}
	return false;  // Not found
}

PublicKey cn::extra_get_transaction_public_key(const BinaryArray &tx_extra) {
	TransactionExtraPublicKey pub_key_field;
	if (!find_field_in_extra(tx_extra, pub_key_field))
		return PublicKey{};
	return pub_key_field.public_key;
}

void cn::extra_add_transaction_public_key(BinaryArray &tx_extra, const PublicKey &tx_pub_key) {
	tx_extra.push_back(TransactionExtraPublicKey::tag);
	common::append(tx_extra, std::begin(tx_pub_key.data), std::end(tx_pub_key.data));
}

void cn::extra_add_nonce(BinaryArray &tx_extra, const BinaryArray &extra_nonce) {
	if (extra_nonce.size() > TransactionExtraNonce::MAX_COUNT)
		throw std::runtime_error("Extra nonce cannot be > " + common::to_string(TransactionExtraNonce::MAX_COUNT));
	tx_extra.push_back(TransactionExtraNonce::tag);
	tx_extra.push_back(static_cast<uint8_t>(extra_nonce.size()));
	common::append(tx_extra, extra_nonce);
}

void cn::extra_add_merge_mining_tag(BinaryArray &tx_extra, const TransactionExtraMergeMiningTag &field) {
	BinaryArray blob = seria::to_binary(field);
	tx_extra.push_back(TransactionExtraMergeMiningTag::tag);
	common::append(tx_extra, common::get_varint_data(blob.size()));
	common::append(tx_extra, blob);
}

bool cn::extra_get_merge_mining_tag(const BinaryArray &tx_extra, TransactionExtraMergeMiningTag &field) {
	return find_field_in_extra(tx_extra, field);
}

void cn::extra_add_block_capacity_vote(BinaryArray &tx_extra, size_t block_capacity) {
	BinaryArray blob = seria::to_binary(block_capacity);
	tx_extra.push_back(TransactionExtraBlockCapacityVote::tag);
	common::append(tx_extra, common::get_varint_data(blob.size()));
	common::append(tx_extra, blob);
}

bool cn::extra_get_block_capacity_vote(const BinaryArray &tx_extra, size_t *block_capacity) {
	TransactionExtraBlockCapacityVote field;
	if (!find_field_in_extra(tx_extra, field))
		return false;
	*block_capacity = field.block_capacity;
	return true;
}

void cn::extra_add_payment_id(BinaryArray &tx_extra, const Hash &payment_id) {
	BinaryArray extra_nonce;
	extra_nonce.push_back(TransactionExtraNonce::PAYMENT_ID);
	common::append(extra_nonce, std::begin(payment_id.data), std::end(payment_id.data));
	extra_add_nonce(tx_extra, extra_nonce);
}

bool cn::extra_get_payment_id(const BinaryArray &tx_extra, Hash &payment_id) {
	TransactionExtraNonce extra_nonce;
	if (!find_field_in_extra(tx_extra, extra_nonce))
		return false;
	if (extra_nonce.nonce.size() != sizeof(Hash) + 1)
		return false;
	if (extra_nonce.nonce.at(0) != TransactionExtraNonce::PAYMENT_ID)
		return false;
	std::copy(extra_nonce.nonce.begin() + 1, extra_nonce.nonce.end(), payment_id.data);
	return true;
}

void seria::ser_members(TransactionExtraMergeMiningTag &v, ISeria &s) {
	seria_kv("depth", v.depth, s);
	seria_kv("merkle_root", v.merkle_root, s);
}

void seria::ser_members(TransactionExtraBlockCapacityVote &v, ISeria &s) {
	seria_kv("block_capacity", v.block_capacity, s);
}
