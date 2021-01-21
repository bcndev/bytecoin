// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "CryptoNote.hpp"
#include "Wallet.hpp"
#include "rpc_api.hpp"

namespace cn {

class Config;

struct PreparedWalletTransaction {
	Hash tid;
	size_t size = 0;
	TransactionPrefix tx;
	Hash prefix_hash;
	Hash inputs_hash;
	KeyDerivation derivation;  // Will be KeyDerivation{} if invalid or no tx_public_key
	std::vector<PublicKey> address_public_keys;
	std::vector<PublicKey> output_shared_secrets;

	PreparedWalletTransaction() = default;
	PreparedWalletTransaction(const Hash &tid, size_t size, TransactionPrefix &&tx,
	    const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key);
	PreparedWalletTransaction(const Hash &tid, size_t size, Transaction &&tx, const Wallet::OutputHandler &o_handler,
	    const SecretKey &view_secret_key);

	// TODO - remove constructors and always use prepare()?
	void prepare(const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key);
};

struct PreparedWalletBlock {
	api::cnd::SyncBlocks::RawBlockCompact raw_block;
	std::vector<PreparedWalletTransaction> transactions;
	// coinbase_transaction will be inserted before other transactions

	void prepare(const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key);
};

}  // namespace cn
