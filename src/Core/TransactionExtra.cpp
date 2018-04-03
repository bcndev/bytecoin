// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "TransactionExtra.hpp"

#include "CryptoNoteTools.hpp"
#include "common/MemoryStreams.hpp"
#include "common/StringTools.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

namespace bytecoin {

template<typename T>
bool find_transaction_extra_field_by_type(const std::vector<TransactionExtraField> &tx_extra_fields, T &field) {
	auto it = std::find_if(tx_extra_fields.begin(), tx_extra_fields.end(),
	    [](const TransactionExtraField &f) { return typeid(T) == f.type(); });

	if (tx_extra_fields.end() == it)
		return false;

	field = boost::get<T>(*it);
	return true;
}

bool parse_transaction_extra(const BinaryArray &extra, std::vector<TransactionExtraField> &extra_fields) {
	extra_fields.clear();

	if (extra.empty())
		return true;

	try {
		common::MemoryInputStream iss(extra.data(), extra.size());
		seria::BinaryInputStream ar(iss);

		int c = 0;

		while (!iss.empty()) {
			c = common::read<uint8_t>(iss);
			switch (c) {
			case TransactionExtraPadding::tag: {
				size_t size = 1;
				for (; !iss.empty() && size <= TX_EXTRA_PADDING_MAX_COUNT; ++size) {
					if (common::read<uint8_t>(iss) != 0) {
						return false;  // all bytes should be zero
					}
				}

				if (size > TX_EXTRA_PADDING_MAX_COUNT) {
					return false;
				}
				TransactionExtraPadding padding;
				padding.size = size;
				extra_fields.push_back(padding);  // TODO - return {} initializer when Google updates NDK copmiler
				break;
			}

			case TransactionExtraPublicKey::tag: {
				TransactionExtraPublicKey extra_pk;
				iss.read(extra_pk.public_key.data, sizeof(extra_pk.public_key.data));
				extra_fields.push_back(extra_pk);
				break;
			}

			case TransactionExtraNonce::tag: {
				TransactionExtraNonce extra_nonce;
				uint8_t size = common::read<uint8_t>(iss);
				if (size > 0) {
					extra_nonce.nonce.resize(size);
					iss.read(extra_nonce.nonce.data(), extra_nonce.nonce.size());
					// We have some base transactions (like in blocks 558479, 558984)
					// which have wrong
					// extra nonce size, so they will not parse and throw here from
					// iss.read
				}

				extra_fields.push_back(extra_nonce);
				break;
			}

			case TransactionExtraMergeMiningTag::tag: {
				TransactionExtraMergeMiningTag mm_tag;
				ar(mm_tag);
				extra_fields.push_back(mm_tag);
				break;
			}
			}
		}
	} catch (std::exception &) {
		return false;
	}

	return true;
}

struct ExtraSerializerVisitor : public boost::static_visitor<bool> {
	BinaryArray &extra;

	ExtraSerializerVisitor(BinaryArray &tx_extra) : extra(tx_extra) {}

	bool operator()(const TransactionExtraPadding &t) {
		if (t.size > TX_EXTRA_PADDING_MAX_COUNT) {
			return false;
		}
		common::append(extra, t.size, 0);
		return true;
	}

	bool operator()(const TransactionExtraPublicKey &t) {
		return add_transaction_public_key_to_extra(extra, t.public_key);
	}

	bool operator()(const TransactionExtraNonce &t) { return add_extra_nonce_to_transaction_extra(extra, t.nonce); }

	bool operator()(const TransactionExtraMergeMiningTag &t) { return append_merge_mining_tag_to_extra(extra, t); }
};

bool write_transaction_extra(BinaryArray &tx_extra, const std::vector<TransactionExtraField> &tx_extra_fields) {
	ExtraSerializerVisitor visitor(tx_extra);

	for (const auto &tag : tx_extra_fields) {
		if (!boost::apply_visitor(visitor, tag)) {
			return false;
		}
	}

	return true;
}

PublicKey get_transaction_public_key_from_extra(const BinaryArray &tx_extra) {
	std::vector<TransactionExtraField> tx_extra_fields;
	parse_transaction_extra(tx_extra, tx_extra_fields);

	TransactionExtraPublicKey pub_key_field;
	if (!find_transaction_extra_field_by_type(tx_extra_fields, pub_key_field))
		return PublicKey{};

	return pub_key_field.public_key;
}

bool add_transaction_public_key_to_extra(BinaryArray &tx_extra, const PublicKey &tx_pub_key) {
	tx_extra.push_back(TransactionExtraPublicKey::tag);
	common::append(tx_extra, std::begin(tx_pub_key.data), std::end(tx_pub_key.data));
	return true;
}

bool add_extra_nonce_to_transaction_extra(BinaryArray &tx_extra, const BinaryArray &extra_nonce) {
	if (extra_nonce.size() > TX_EXTRA_NONCE_MAX_COUNT) {
		return false;
	}

	size_t start_pos = tx_extra.size();
	tx_extra.resize(tx_extra.size() + 2 + extra_nonce.size());
	// write tag
	tx_extra[start_pos] = TransactionExtraNonce::tag;
	// write len
	++start_pos;
	tx_extra[start_pos] = static_cast<uint8_t>(extra_nonce.size());
	// write data
	++start_pos;
	memcpy(&tx_extra[start_pos], extra_nonce.data(), extra_nonce.size());
	return true;
}

bool append_merge_mining_tag_to_extra(BinaryArray &tx_extra, const TransactionExtraMergeMiningTag &mm_tag) {
	BinaryArray blob = seria::to_binary(mm_tag);
	tx_extra.push_back(TransactionExtraMergeMiningTag::tag);
	common::append(tx_extra, blob.begin(), blob.end());
	return true;
}

bool get_merge_mining_tag_from_extra(const BinaryArray &tx_extra, TransactionExtraMergeMiningTag &mm_tag) {
	std::vector<TransactionExtraField> tx_extra_fields;
	parse_transaction_extra(tx_extra, tx_extra_fields);

	return find_transaction_extra_field_by_type(tx_extra_fields, mm_tag);
}

void set_payment_id_to_transaction_extra_nonce(BinaryArray &extra_nonce, const Hash &payment_id) {
	extra_nonce.clear();
	extra_nonce.push_back(TX_EXTRA_NONCE_PAYMENT_ID);
	common::append(extra_nonce, std::begin(payment_id.data), std::end(payment_id.data));
}

bool get_payment_id_from_transaction_extra_nonce(const BinaryArray &extra_nonce, Hash &payment_id) {
	if (sizeof(Hash) + 1 != extra_nonce.size())
		return false;
	if (TX_EXTRA_NONCE_PAYMENT_ID != extra_nonce[0])
		return false;
	payment_id = *reinterpret_cast<const Hash *>(extra_nonce.data() + 1);
	return true;
}

bool get_payment_id_from_tx_extra(const BinaryArray &extra, Hash &payment_id) {
	std::vector<TransactionExtraField> tx_extra_fields;
	parse_transaction_extra(extra, tx_extra_fields);
	TransactionExtraNonce extra_nonce;
	if (!find_transaction_extra_field_by_type(tx_extra_fields, extra_nonce))
		return false;
	if (!get_payment_id_from_transaction_extra_nonce(extra_nonce.nonce, payment_id))
		return false;
	return true;
}
}

static void do_serialize(bytecoin::TransactionExtraMergeMiningTag &tag, seria::ISeria &s) {
	s.begin_object();
	uint64_t depth = static_cast<uint64_t>(tag.depth);
	seria_kv("depth", depth, s);
	tag.depth = static_cast<size_t>(depth);
	seria_kv("merkle_root", tag.merkle_root, s);
	s.end_object();
}

void seria::ser(bytecoin::TransactionExtraMergeMiningTag &v, ISeria &s) {
	if (s.is_input()) {
		std::string field;
		s(field);
		common::MemoryInputStream stream(field.data(), field.size());
		seria::BinaryInputStream input(stream);
		do_serialize(v, input);
	} else {
		std::string field;
		common::StringOutputStream os(field);
		seria::BinaryOutputStream output(os);
		do_serialize(v, output);
		s(field);
	}
}
