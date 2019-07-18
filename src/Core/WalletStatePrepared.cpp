// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletStatePrepared.hpp"
#include "TransactionExtra.hpp"
#include "crypto/crypto.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace cn;

PreparedWalletTransaction::PreparedWalletTransaction(const Hash &tid, size_t size, TransactionPrefix &&ttx,
    const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key)
    : tid(tid), size(size), tx(std::move(ttx)) {
	prepare(o_handler, view_secret_key);
}

PreparedWalletTransaction::PreparedWalletTransaction(const Hash &tid, size_t size, Transaction &&tx,
    const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key)
    : PreparedWalletTransaction(
          tid, size, std::move(static_cast<TransactionPrefix &&>(tx)), o_handler, view_secret_key) {}

void PreparedWalletTransaction::prepare(const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key) {
	// We ignore results of most crypto calls here and absence of tx_public_key
	// All errors will lead to spend_key not found in our wallet for legacy crypto
	PublicKey tx_public_key;
	if (extra::get_transaction_public_key(tx.extra, &tx_public_key))
		derivation = generate_key_derivation(tx_public_key, view_secret_key);
	auto encrypted_messages = extra::get_encrypted_messages(tx.extra);

	prefix_hash = get_transaction_prefix_hash(tx);
	inputs_hash = get_transaction_inputs_hash(tx);

	KeyPair tx_keys;
	address_public_keys.reserve(tx.outputs.size() + encrypted_messages.size());
	output_shared_secrets.reserve(tx.outputs.size() + encrypted_messages.size());
	for (size_t out_index = 0; out_index != tx.outputs.size(); ++out_index) {
		const auto &output = tx.outputs.at(out_index);
		if (output.type() != typeid(OutputKey))
			continue;
		const auto &out = boost::get<OutputKey>(output);
		PublicKey pk, ss;
		o_handler(tx.version, derivation, inputs_hash, out_index, out, &pk, &ss);
		address_public_keys.push_back(pk);
		output_shared_secrets.push_back(ss);
	}
	for (size_t m_index = 0; m_index != encrypted_messages.size(); ++m_index) {
		PublicKey pk, ss;
		o_handler(tx.version, derivation, inputs_hash, tx.outputs.size() + m_index,
		    encrypted_messages.at(m_index).output, &pk, &ss);
		address_public_keys.push_back(pk);
		output_shared_secrets.push_back(ss);
	}
}

void PreparedWalletBlock::prepare(const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key) {
	transactions.reserve(raw_block.raw_transactions.size());
	const Hash base_transaction_hash   = get_transaction_hash(this->raw_block.base_transaction);
	const size_t base_transaction_size = seria::binary_size(this->raw_block.base_transaction);
	// We pass copies because we wish to keep raw_block as is
	transactions.emplace_back(base_transaction_hash, base_transaction_size, Transaction(raw_block.base_transaction),
	    o_handler, view_secret_key);
	for (size_t tx_index = 0; tx_index != raw_block.raw_transactions.size(); ++tx_index) {
		const Hash transaction_hash = raw_block.transaction_hashes.at(tx_index);
		const size_t size           = raw_block.transaction_sizes.at(tx_index);
		transactions.emplace_back(transaction_hash, size, TransactionPrefix(raw_block.raw_transactions.at(tx_index)),
		    o_handler, view_secret_key);
	}
}
