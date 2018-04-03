// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <boost/variant.hpp>
#include <vector>

#include "CryptoNote.hpp"
#include "seria/ISeria.hpp"

namespace bytecoin {

enum { TX_EXTRA_PADDING_MAX_COUNT = 255, TX_EXTRA_NONCE_MAX_COUNT = 255, TX_EXTRA_NONCE_PAYMENT_ID = 0x00 };

struct TransactionExtraPadding {
	size_t size = 0;
	enum { tag = 0x00 };
};

struct TransactionExtraPublicKey {
	crypto::PublicKey public_key;
	enum { tag = 0x01 };
};

struct TransactionExtraNonce {
	BinaryArray nonce;
	enum { tag = 0x02 };
};

struct TransactionExtraMergeMiningTag {
	size_t depth = 0;
	crypto::Hash merkle_root;
	enum { tag = 0x03 };
};

// tx_extra_field format, except tx_extra_padding and tx_extra_pub_key:
//   varint tag;
//   varint size;
//   varint data[];
typedef boost::variant<TransactionExtraPadding, TransactionExtraPublicKey, TransactionExtraNonce,
    TransactionExtraMergeMiningTag>
    TransactionExtraField;

bool parse_transaction_extra(const BinaryArray &tx_extra, std::vector<TransactionExtraField> &tx_extra_fields);
bool write_transaction_extra(BinaryArray &tx_extra, const std::vector<TransactionExtraField> &tx_extra_fields);

crypto::PublicKey get_transaction_public_key_from_extra(const BinaryArray &tx_extra);
bool add_transaction_public_key_to_extra(BinaryArray &tx_extra, const crypto::PublicKey &tx_pub_key);
bool add_extra_nonce_to_transaction_extra(BinaryArray &tx_extra, const BinaryArray &extra_nonce);
void set_payment_id_to_transaction_extra_nonce(BinaryArray &extra_nonce, const crypto::Hash &payment_id);
bool get_payment_id_from_transaction_extra_nonce(const BinaryArray &extra_nonce, crypto::Hash &payment_id);
bool append_merge_mining_tag_to_extra(BinaryArray &tx_extra, const TransactionExtraMergeMiningTag &mm_tag);
bool get_merge_mining_tag_from_extra(const BinaryArray &tx_extra, TransactionExtraMergeMiningTag &mm_tag);

bool get_payment_id_from_tx_extra(const BinaryArray &extra, crypto::Hash &payment_id);

class TransactionExtra {
public:
	TransactionExtra() {}
	TransactionExtra(const BinaryArray &extra) { parse(extra); }
	bool parse(const BinaryArray &extra) {
		m_fields.clear();
		return bytecoin::parse_transaction_extra(extra, m_fields);
	}
	template<typename T>
	bool get(T &value) const {
		auto it = find(typeid(T));
		if (it == m_fields.end()) {
			return false;
		}
		value = boost::get<T>(*it);
		return true;
	}
	template<typename T>
	void set(const T &value) {
		auto it = find(typeid(T));
		if (it != m_fields.end()) {
			*it = value;
		} else {
			m_fields.push_back(value);
		}
	}

	template<typename T>
	void append(const T &value) {
		m_fields.push_back(value);
	}

	bool get_public_key(crypto::PublicKey &pk) const {
		bytecoin::TransactionExtraPublicKey extra_pk;
		if (!get(extra_pk)) {
			return false;
		}
		pk = extra_pk.public_key;
		return true;
	}

	BinaryArray serialize() const {
		BinaryArray extra;
		write_transaction_extra(extra, m_fields);
		return extra;
	}

private:
	std::vector<bytecoin::TransactionExtraField>::const_iterator find(const std::type_info &t) const {
		return std::find_if(
		    m_fields.begin(), m_fields.end(), [&t](const bytecoin::TransactionExtraField &f) { return t == f.type(); });
	}
	std::vector<bytecoin::TransactionExtraField>::iterator find(const std::type_info &t) {
		return std::find_if(
		    m_fields.begin(), m_fields.end(), [&t](const bytecoin::TransactionExtraField &f) { return t == f.type(); });
	}

	std::vector<bytecoin::TransactionExtraField> m_fields;
};
}

namespace seria {
class ISeria;
void ser(bytecoin::TransactionExtraMergeMiningTag &v, ISeria &s);
}
