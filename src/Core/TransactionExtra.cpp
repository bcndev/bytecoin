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
bool set_field_good(const T &, U &){
	return false;
}
template<typename T>
bool set_field_good(const T & a, T & b){
	b = a;
	return true;
}

template<typename T>
bool find_field_in_extra(const BinaryArray &extra, T & field) {
	try {
		common::MemoryInputStream iss(extra.data(), extra.size());
		seria::BinaryInputStream ar(iss);

		while (!iss.empty()) {
			int c = common::read<uint8_t>(iss);
			switch (c) {
			case TransactionExtraPadding::tag: {
				size_t size = 1; // tag is itself '0', counts towards max count
				for (; !iss.empty() && size <= TransactionExtraPadding::MAX_COUNT; ++size) {
					if (common::read<uint8_t>(iss) != 0)
						return false;  // all bytes should be zero
				}
				if (size > TransactionExtraPadding::MAX_COUNT)
					return false;
				TransactionExtraPadding padding;
				padding.size = size;
				return set_field_good(padding, field); // last field
			}
			case TransactionExtraPublicKey::tag: {
				TransactionExtraPublicKey extra_pk;
				iss.read(extra_pk.public_key.data, sizeof(extra_pk.public_key.data));
				if(set_field_good(extra_pk, field))
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
				if(set_field_good(extra_nonce, field))
					return true;
				break;
			}
			case TransactionExtraMergeMiningTag::tag: {
				TransactionExtraMergeMiningTag mm_tag;
				ser(mm_tag, ar);
				if(set_field_good(mm_tag, field))
					return true;
				break;
			}
			}
		}
	} catch (std::exception &) {
	}
	return false; // Not found
}

/*template<typename T>
bool find_transaction_extra_field_by_type(const std::vector<TransactionExtraField> &tx_extra_fields, T &field) {
	auto it = std::find_if(tx_extra_fields.begin(), tx_extra_fields.end(),
	    [](const TransactionExtraField &f) { return typeid(T) == f.type(); });

	if (tx_extra_fields.end() == it)
		return false;

	field = boost::get<T>(*it);
	return true;
}

bool bytecoin::parse_transaction_extra(const BinaryArray &extra, std::vector<TransactionExtraField> &extra_fields) {
	extra_fields.clear();

//	if (extra.empty())
//		return true;

	try {
		common::MemoryInputStream iss(extra.data(), extra.size());
		seria::BinaryInputStream ar(iss);

		while (!iss.empty()) {
			int c = common::read<uint8_t>(iss);
			switch (c) {
			case TransactionExtraPadding::tag: {
				size_t size = 1; // tag is itself '0', counts towards max count
				for (; !iss.empty() && size <= TX_EXTRA_PADDING_MAX_COUNT; ++size) {
					if (common::read<uint8_t>(iss) != 0)
						return false;  // all bytes should be zero
				}
				if (size > TX_EXTRA_PADDING_MAX_COUNT)
					return false;
				TransactionExtraPadding padding;
				padding.size = size;
				extra_fields.push_back(padding);  // TODO - return {} initializer when Google updates NDK compiler
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
//				if (size > 0) {
					extra_nonce.nonce.resize(size);
					iss.read(extra_nonce.nonce.data(), extra_nonce.nonce.size());
					// We have some base transactions (like in blocks 558479, 558984)
					// which have wrong
					// extra nonce size, so they will not parse and throw here from
					// iss.read
//				}
				extra_fields.push_back(extra_nonce);
				if (size > 127)
					throw std::runtime_error(""); // TODO - remove before release
				break;
			}
			case TransactionExtraMergeMiningTag::tag: {
				TransactionExtraMergeMiningTag mm_tag;
				ser(mm_tag, ar);
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
		add_transaction_public_key_to_extra(extra, t.public_key); return true;
	}

	bool operator()(const TransactionExtraNonce &t) { add_extra_nonce_to_transaction_extra(extra, t.nonce); return true; }

	bool operator()(const TransactionExtraMergeMiningTag &t) { append_merge_mining_tag_to_extra(extra, t); return true; }
};

bool bytecoin::write_transaction_extra(
    BinaryArray &tx_extra, const std::vector<TransactionExtraField> &tx_extra_fields) {
	ExtraSerializerVisitor visitor(tx_extra);

	for (const auto &tag : tx_extra_fields) {
		if (!boost::apply_visitor(visitor, tag)) {
			return false;
		}
	}

	return true;
}*/

PublicKey bytecoin::extra_get_transaction_public_key(const BinaryArray &tx_extra) {
	TransactionExtraPublicKey pub_key_field;
	if( !find_field_in_extra(tx_extra, pub_key_field) )
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
//	size_t start_pos = tx_extra.size();
//	tx_extra.resize(tx_extra.size() + 2 + extra_nonce.size());
	// write tag
//	tx_extra[start_pos] = TransactionExtraNonce::tag;
	// write len
//	++start_pos;
//	tx_extra[start_pos] = static_cast<uint8_t>(extra_nonce.size());
	// write data
//	++start_pos;
//	memcpy(&tx_extra[start_pos], extra_nonce.data(), extra_nonce.size());
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
//	memcpy(payment_id.data, extra_nonce.nonce.data() + 1, sizeof(Hash));
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
