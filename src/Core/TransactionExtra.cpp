// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "TransactionExtra.hpp"

#include "CryptoNoteTools.hpp"
#include "common/MemoryStreams.hpp"
#include "common/StringTools.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace bytecoin;

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
			int c = common::read<uint8_t>(iss);
			switch (c) {
			case TransactionExtraPadding::tag: {
				size_t size = 1;  // tag is itself '0', counts towards max count
				for (; !iss.empty() && size <= TransactionExtraPadding::MAX_COUNT; ++size) {
					if (common::read<uint8_t>(iss) != 0)
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
				uint8_t size = common::read<uint8_t>(iss);
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
				ser(mm_tag, ar);
				if (set_field_good(mm_tag, field))
					return true;
				break;
			}
			}
		}
	} catch (std::exception &) {
	}
	return false;  // Not found
}

PublicKey bytecoin::extra_get_transaction_public_key(const BinaryArray &tx_extra) {
	TransactionExtraPublicKey pub_key_field;
	if (!find_field_in_extra(tx_extra, pub_key_field))
		return PublicKey{};
	return pub_key_field.public_key;
}

void bytecoin::extra_add_transaction_public_key(BinaryArray &tx_extra, const PublicKey &tx_pub_key) {
	tx_extra.push_back(TransactionExtraPublicKey::tag);
	common::append(tx_extra, std::begin(tx_pub_key.data), std::end(tx_pub_key.data));
}

void bytecoin::extra_add_nonce(BinaryArray &tx_extra, const BinaryArray &extra_nonce) {
	if (extra_nonce.size() > TransactionExtraNonce::MAX_COUNT)
		throw std::runtime_error("Extra nonce cannot be > " + common::to_string(TransactionExtraNonce::MAX_COUNT));
	tx_extra.push_back(TransactionExtraNonce::tag);
	tx_extra.push_back(static_cast<uint8_t>(extra_nonce.size()));
	common::append(tx_extra, extra_nonce.begin(), extra_nonce.end());
}

void bytecoin::extra_add_merge_mining_tag(BinaryArray &tx_extra, const TransactionExtraMergeMiningTag &mm_tag) {
	BinaryArray blob = seria::to_binary(mm_tag);
	tx_extra.push_back(TransactionExtraMergeMiningTag::tag);
	common::append(tx_extra, blob.begin(), blob.end());
}

bool bytecoin::extra_get_merge_mining_tag(const BinaryArray &tx_extra, TransactionExtraMergeMiningTag &mm_tag) {
	return find_field_in_extra(tx_extra, mm_tag);
}

void bytecoin::extra_add_payment_id(BinaryArray &tx_extra, const Hash &payment_id) {
	BinaryArray extra_nonce;
	extra_nonce.push_back(TransactionExtraNonce::PAYMENT_ID);
	common::append(extra_nonce, std::begin(payment_id.data), std::end(payment_id.data));
	extra_add_nonce(tx_extra, extra_nonce);
}

bool bytecoin::extra_get_payment_id(const BinaryArray &tx_extra, Hash &payment_id) {
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

static void do_serialize(TransactionExtraMergeMiningTag &tag, seria::ISeria &s) {
	s.begin_object();
	uint64_t depth = static_cast<uint64_t>(tag.depth);
	seria_kv("depth", depth, s);
	tag.depth = static_cast<size_t>(depth);
	seria_kv("merkle_root", tag.merkle_root, s);
	s.end_object();
}

void seria::ser(TransactionExtraMergeMiningTag &v, ISeria &s) {
	if (s.is_input()) {
		std::string field;
		ser(field, s);
		common::MemoryInputStream stream(field.data(), field.size());
		seria::BinaryInputStream input(stream);
		do_serialize(v, input);
	} else {
		std::string field;
		common::StringOutputStream os(field);
		seria::BinaryOutputStream output(os);
		do_serialize(v, output);
		ser(field, s);
	}
}
