// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>
#include "BlockChainState.hpp"
#include "CryptoNote.hpp"
#include "Multicore.hpp"
#include "Wallet.hpp"
#include "WalletStateBasic.hpp"
#include "platform/DB.hpp"

namespace cn {

class Config;

class WalletState : public WalletStateBasic {
	class DeltaState : public IWalletState {
		typedef std::map<PublicKey, std::vector<api::Output>> Unspents;

	public:
		struct DeltaStateTransaction {
			TransactionPrefix tx;
			api::Transaction atx;
			std::set<crypto::EllipticCurvePoint> used_ki_or_pk;
		};
		explicit DeltaState() {}
		void clear();

		const Unspents &get_unspents() const { return m_unspents; }
		const std::map<crypto::EllipticCurvePoint, int> &get_used_kis_or_pks() const { return m_used_kis_or_pks; }

		const std::map<Hash, DeltaStateTransaction> &get_transactions() const { return m_transactions; }

		void undo_transaction(const Hash &tid);  // For mem pool

		Amount add_incoming_output(const api::Output &, const Hash &tid) override;  // added amount may be lower
		Amount add_incoming_keyimage(Height, const KeyImage &) override;
		Amount add_incoming_deterministic_input(
		    Height block_height, Amount am, size_t gi, const PublicKey &pk) override;
		void add_transaction(
		    Height, const Hash &tid, const TransactionPrefix &tx, const api::Transaction &ptx) override;

	private:
		Unspents m_unspents;
		std::map<crypto::EllipticCurvePoint, int>
		    m_used_kis_or_pks;  // counter, because double spends are allowed in pool
		std::map<Hash, DeltaStateTransaction> m_transactions;
		Hash m_last_added_transaction;
	};

public:
	explicit WalletState(Wallet &, logging::ILogger &, const Config &, const Currency &);

	const Wallet &get_wallet() const { return m_wallet; }
	Wallet &get_wallet() { return m_wallet; }

	bool sync_with_blockchain(api::cnd::SyncBlocks::Response &);   // We move from it
	bool sync_with_blockchain(api::cnd::SyncMemPool::Response &);  // We move from it

	virtual std::vector<api::Output> api_get_locked_or_unconfirmed_unspent(
	    const std::string &address, Height confirmed_height) const override;
	virtual api::Balance get_balance(const std::string &address, Height confirmed_height) const override;

	bool add_to_payment_queue(const BinaryArray &binary_transaction, bool save_file);
	void process_payment_queue_send_error(Hash hash, const api::cnd::SendTransaction::Error &error);
	BinaryArray get_next_from_sending_queue(Hash *previous_hash);

	bool api_has_transaction(Hash tid, bool check_pool) const;
	bool api_get_transaction(Hash tid, bool check_pool, TransactionPrefix *tx, api::Transaction *atx) const;

	bool parse_raw_transaction(bool is_base, api::Transaction &ptx, Transaction &&tx, Hash tid) const;

	// Read state
	bool api_create_proof(const TransactionPrefix &tx, Sendproof &sp) const;
	api::Block api_get_pool_as_history(const std::string &address) const;

	size_t get_tx_pool_version() const { return m_tx_pool_version; }
	size_t get_pq_version() const { return m_pq_version; }
	std::vector<Hash> get_tx_pool_hashes() const;

	void wallet_addresses_updated();
	// generating through state prevents undo of blocks within 2*block_future_time_limit from now
	std::vector<WalletRecord> generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct, Timestamp now);
	void create_addresses(size_t count);

protected:
	bool redo_block(const api::BlockHeader &header, const PreparedWalletBlock &block,
	    const BlockChainState::BlockGlobalIndices &global_indices, Height height);

	bool parse_raw_transaction(bool is_base, api::Transaction *ptx, std::vector<api::Transfer> *input_transfers,
	    std::vector<api::Transfer> *output_transfers, Amount *output_amount, const PreparedWalletTransaction &pwtx,
	    Hash tid, const std::vector<size_t> &global_indices, Height block_heights) const;
	bool redo_transaction(const PreparedWalletTransaction &pwtx, const std::vector<size_t> &global_indices,
	    IWalletState *delta_state, bool is_base, Hash tid, Height block_height, Hash bid, Timestamp tx_timestamp);
	const std::map<crypto::EllipticCurvePoint, int> &get_mempool_kis_or_pks() const override;
	void on_first_transaction_found(Timestamp ts) override;

	struct QueueEntry {
		Hash hash;
		BinaryArray binary_transaction;
		Amount fee_per_kb    = 0;
		Height remove_height = 0;
		bool in_blockchain() const { return remove_height != 0; }
	};

private:
	size_t m_tx_pool_version = 1;
	size_t m_pq_version      = 1;
	std::chrono::steady_clock::time_point m_log_redo_block;

	Wallet &m_wallet;
	DeltaState m_memory_state;
	std::set<Hash> m_pool_hashes;

	void add_transaction_to_mempool(Hash tid, Transaction &&tx, bool from_pq);
	void remove_transaction_from_mempool(Hash tid, bool from_pq);

	struct by_hash {};
	struct by_fee_per_kb {};
	struct by_remove_height {};

	typedef boost::multi_index_container<QueueEntry,
	    boost::multi_index::indexed_by<boost::multi_index::ordered_unique<boost::multi_index::tag<by_hash>,
	                                       boost::multi_index::member<QueueEntry, Hash, &QueueEntry::hash>>,
	        boost::multi_index::ordered_non_unique<boost::multi_index::tag<by_fee_per_kb>,
	            boost::multi_index::member<QueueEntry, Amount, &QueueEntry::fee_per_kb>>,
	        boost::multi_index::ordered_non_unique<boost::multi_index::tag<by_remove_height>,
	            boost::multi_index::member<QueueEntry, Height, &QueueEntry::remove_height>>>>
	    PaymentQueue;
	PaymentQueue payment_queue;
	void fix_payment_queue_after_undo_redo();
	const QueueEntry *find_in_payment_queue(const Hash &hash);

	WalletPreparatorMulticore preparator;
};

}  // namespace cn
