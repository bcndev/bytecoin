// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <vector>
#include <boost/variant.hpp>

#include "CryptoNote.hpp"
#include "seria/ISeria.hpp"

namespace bytecoin {

	enum { TX_EXTRA_PADDING_MAX_COUNT = 255,
		TX_EXTRA_NONCE_MAX_COUNT      = 255,
		TX_EXTRA_NONCE_PAYMENT_ID     = 0x00 };

struct TransactionExtraPadding {
	size_t size = 0;
	enum { tag = 0x00 };
};

struct TransactionExtraPublicKey {
	crypto::PublicKey publicKey;
	enum { tag = 0x01 };
};

struct TransactionExtraNonce {
	BinaryArray nonce;
	enum { tag = 0x02 };
};

struct TransactionExtraMergeMiningTag {
	size_t depth = 0;
	crypto::Hash merkleRoot;
	enum { tag = 0x03 };
};

// tx_extra_field format, except tx_extra_padding and tx_extra_pub_key:
//   varint tag;
//   varint size;
//   varint data[];
typedef boost::variant<TransactionExtraPadding, TransactionExtraPublicKey, TransactionExtraNonce, TransactionExtraMergeMiningTag> TransactionExtraField;


template<typename T>
bool findTransactionExtraFieldByType(const std::vector<TransactionExtraField> &tx_extra_fields, T &field) {
	auto it = std::find_if(tx_extra_fields.begin(), tx_extra_fields.end(),
						   [](const TransactionExtraField &f) { return typeid(T) == f.type(); });

	if (tx_extra_fields.end() == it)
		return false;

	field = boost::get<T>(*it);
	return true;
}

bool parseTransactionExtra(const BinaryArray &tx_extra, std::vector<TransactionExtraField> &tx_extra_fields);
bool writeTransactionExtra(BinaryArray &tx_extra, const std::vector<TransactionExtraField> &tx_extra_fields);

crypto::PublicKey getTransactionPublicKeyFromExtra(const BinaryArray &tx_extra);
bool addTransactionPublicKeyToExtra(BinaryArray &tx_extra, const crypto::PublicKey &tx_pub_key);
bool addExtraNonceToTransactionExtra(BinaryArray &tx_extra, const BinaryArray &extra_nonce);
void setPaymentIdToTransactionExtraNonce(BinaryArray &extra_nonce, const crypto::Hash &payment_id);
bool getPaymentIdFromTransactionExtraNonce(const BinaryArray &extra_nonce, crypto::Hash &payment_id);
bool appendMergeMiningTagToExtra(BinaryArray &tx_extra, const TransactionExtraMergeMiningTag &mm_tag);
bool getMergeMiningTagFromExtra(const BinaryArray &tx_extra, TransactionExtraMergeMiningTag &mm_tag);

bool createTxExtraWithPaymentId(const std::string &paymentIdString, BinaryArray &extra);
//returns false if payment id is not found or parse error
bool getPaymentIdFromTxExtra(const BinaryArray &extra, crypto::Hash &paymentId);
bool parsePaymentId(const std::string &paymentIdString, crypto::Hash &paymentId);

class TransactionExtra {
public:
	TransactionExtra() {}
	TransactionExtra(const BinaryArray &extra) {
		parse(extra);
	}
	bool parse(const BinaryArray &extra) {
		m_fields.clear();
		return bytecoin::parseTransactionExtra(extra, m_fields);
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

	bool getPublicKey(crypto::PublicKey &pk) const {
		bytecoin::TransactionExtraPublicKey extraPk;
		if (!get(extraPk)) {
			return false;
		}
		pk = extraPk.publicKey;
		return true;
	}

	BinaryArray serialize() const {
		BinaryArray extra;
		writeTransactionExtra(extra, m_fields);
		return extra;
	}
private:
	std::vector<bytecoin::TransactionExtraField>::const_iterator find(const std::type_info &t) const {
		return std::find_if(m_fields.begin(), m_fields.end(), [&t](const bytecoin::TransactionExtraField &f) { return t == f.type(); });
	}
	std::vector<bytecoin::TransactionExtraField>::iterator find(const std::type_info &t) {
		return std::find_if(m_fields.begin(), m_fields.end(), [&t](const bytecoin::TransactionExtraField &f) { return t == f.type(); });
	}

	std::vector<bytecoin::TransactionExtraField> m_fields;
};

}

namespace seria {
class ISeria;
void ser(bytecoin::TransactionExtraMergeMiningTag &v, ISeria &s);
}
