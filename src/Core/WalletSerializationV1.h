// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include "Core/Wallet.hpp"  // for WalletRecord
#include "common/Streams.hpp"
#include "crypto/chacha8.h"
#include "seria/ISeria.hpp"

namespace byterub {

class WalletSerializerV1 {
public:
	WalletSerializerV1(
	    //    ITransfersObserver& transfersObserver,
	    crypto::PublicKey &view_public_key,
	    crypto::SecretKey &view_secret_key,
	    //	    uint64_t &actual_balance,
	    //	    uint64_t &pending_palance,
	    std::vector<WalletRecord> &wallets_container
	    //    TransfersSyncronizer& synchronizer,
	    //    UnlockTransactionJobs& unlockTransactions,
	    //    WalletTransactions& transactions,
	    //    WalletTransfers& transfers,
	    //    UncommitedTransactions& uncommitedTransactions,
	    //    uint32_t transactionSoftLockTime
	    );

	void load(const crypto::chacha8_key &key, common::IInputStream &source);

	struct CryptoContext {
		crypto::chacha8_key key;
		crypto::chacha8_iv iv;

		void incIv();
	};

private:
	static const uint32_t SERIALIZATION_VERSION;

	void load_wallet(common::IInputStream &source, const crypto::chacha8_key &key, uint32_t version);
	void load_wallet_v1(common::IInputStream &source, const crypto::chacha8_key &key);

	uint32_t load_version(common::IInputStream &source);
	void load_iv(common::IInputStream &source, crypto::chacha8_iv &iv);
	void load_keys(common::IInputStream &source, CryptoContext &);
	void load_public_key(common::IInputStream &source, CryptoContext &);
	void load_secret_key(common::IInputStream &source, CryptoContext &);
	void check_keys();
	void load_flags(bool &details, bool &cache, common::IInputStream &source, CryptoContext &);
	void load_wallets(common::IInputStream &source, CryptoContext &);
	//  void subscribeWallets();
	//	void load_balances(common::IInputStream &source, CryptoContext &);
	//  void loadTransfersSynchronizer(common::IInputStream& source, CryptoContext& cryptoContext);
	//  void loadObsoleteSpentOutputs(common::IInputStream& source, CryptoContext& cryptoContext);
	//  void loadUnlockTransactionsJobs(common::IInputStream& source, CryptoContext& cryptoContext);
	//  void loadObsoleteChange(common::IInputStream& source, CryptoContext& cryptoContext);
	//  void loadUncommitedTransactions(common::IInputStream& source, CryptoContext& cryptoContext);
	//  void loadTransactions(common::IInputStream& source, CryptoContext& cryptoContext);
	//  void loadTransfers(common::IInputStream& source, CryptoContext& cryptoContext, uint32_t version);

	void load_wallet_v1_keys(seria::ISeria &s);
	// void loadWalletV1Details(BinaryInputStreamSerializer& serializer);
	//	void add_wallet_v1_details(const std::vector<WalletLegacyTransaction> &txs,
	//	                           const std::vector<WalletLegacyTransfer> &trs);
	//  void resetCachedBalance();
	//  void updateTransactionsBaseStatus();
	//  void updateTransfersSign();

	//  ITransfersObserver& m_transfersObserver;
	crypto::PublicKey &m_view_public_key;
	crypto::SecretKey &m_view_secret_key;
	//	uint64_t &m_actual_balance;
	//	uint64_t &m_pending_balance;
	std::vector<WalletRecord> &m_wallets_container;
	//  TransfersSyncronizer& m_synchronizer;
	//  UnlockTransactionJobs& m_unlockTransactions;
	//  WalletTransactions& m_transactions;
	//  WalletTransfers& m_transfers;
	//  UncommitedTransactions& m_uncommitedTransactions;
	//  uint32_t m_transactionSoftLockTime;
};

}  // namespace byterub
