// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>
#include <chrono>
#include "WalletStateBasic.hpp"

namespace cn {

class Config;

class WalletState : public WalletStateBasic {
	class DeltaState : public IWalletState {
		typedef std::map<PublicKey, std::vector<api::Output>> Unspents;
		// TODO - change PublicKey to KeyImage in 3.5
	public:
		struct DeltaStateTransaction {
			PreparedWalletTransaction pwtx;
			api::Transaction atx;
			std::set<KeyImage> used_keyimages;
		};
		void clear();

		const Unspents &get_unspents() const { return m_unspents; }
		const std::map<KeyImage, std::vector<Hash>> &get_used_keyimages() const { return m_used_keyimages; }

		const std::map<Hash, DeltaStateTransaction> &get_transactions() const { return m_transactions; }

		void undo_transaction(const Hash &tid);                       // For mem pool
		void apply(IWalletState *parent_state, Height height) const;  // For redoing blocks

		bool add_incoming_output(const api::Output &) override;  // added amount may be lower
		Amount add_incoming_keyimage(Height, const KeyImage &) override;
		void add_transaction(
		    Height, const Hash &tid, const PreparedWalletTransaction &pwtx, const api::Transaction &ptx) override;

		// TODO - refactor later
		void add_keyimage_from_block(const KeyImage &);
		std::set<Hash> transactions_to_reaply;
		// We reapply transaction if keyimage used by it is found during redo_block
	private:
		Unspents m_unspents;
		std::map<KeyImage, std::vector<Hash>> m_used_keyimages;  // double spends are allowed in pool
		std::map<Hash, DeltaStateTransaction> m_transactions;
		Hash m_last_added_transaction;
	};

public:
	explicit WalletState(Wallet &, logging::ILogger &, const Config &, const Currency &, DB &db);

	const Wallet &get_wallet() const { return m_wallet; }
	Wallet &get_wallet() { return m_wallet; }

	bool sync_with_blockchain(const std::vector<Hash> &removed_hashes);
	bool sync_with_blockchain(const PreparedWalletBlock &pb, Height top_known_block_height);
	bool sync_with_blockchain(const PreparedWalletTransaction &pwtx);
	bool sync_with_blockchain_finished();
	void fix_payment_queue_after_undo_redo();

	std::vector<api::Output> api_get_locked_or_unconfirmed_unspent(
	    const std::string &address, Height confirmed_height) const override;
	api::Balance get_balance(const std::string &address, Height confirmed_height) const override;

	bool add_to_payment_queue(const BinaryArray &binary_transaction, bool save_file);
	void process_payment_queue_send_error(Hash hash, const api::cnd::SendTransaction::Error &error);
	BinaryArray get_next_from_sending_queue(Hash *previous_hash);

	bool api_has_transaction(Hash tid, bool check_pool) const;
	bool api_get_transaction(Hash tid, bool check_pool, TransactionPrefix *tx, api::Transaction *atx) const;

	bool parse_raw_transaction(bool is_base, api::Transaction &ptx, Transaction &&tx, Hash tid, size_t tx_size) const;

	// Read state
	std::string api_create_proof(const TransactionPrefix &tx,
	    const std::vector<std::vector<PublicKey>> &mixed_public_keys, const std::string &addr_str, const Hash &tid,
	    const std::string &message, bool reveal_secret_message) const;
	api::Block api_get_pool_as_history(const std::string &address) const;

	size_t get_tx_pool_version() const { return m_tx_pool_version; }
	std::vector<Hash> get_tx_pool_hashes() const;

	void wallet_addresses_updated();
	// generating through state prevents undo of blocks within 2*block_future_time_limit from now
	std::vector<WalletRecord> generate_new_addresses(
	    const std::vector<SecretKey> &sks, Timestamp ct, Timestamp now, std::vector<AccountAddress> *addresses);
	void create_addresses(size_t count);

protected:
	bool redo_block(
	    const PreparedWalletBlock &block, const std::vector<std::vector<size_t>> &global_indices, Height height);

	bool parse_raw_transaction(bool is_base, api::Transaction *ptx, std::vector<api::Transfer> *input_transfers,
	    std::vector<api::Transfer> *output_transfers, Amount *output_amount, const PreparedWalletTransaction &pwtx,
	    Hash tid, const std::vector<size_t> &global_indices, size_t start_global_key_output_index,
	    Height block_heights) const;
	bool redo_transaction(const PreparedWalletTransaction &pwtx, const std::vector<size_t> &global_indices,
	    size_t start_global_key_output_index, IWalletState *delta_state, bool is_base, Hash tid, Height block_height,
	    Hash bid, Timestamp tx_timestamp) const;
	const std::map<KeyImage, std::vector<Hash>> &get_mempool_keyimages() const override;
	void on_first_transaction_found(Timestamp ts) override;
	bool add_incoming_output(const api::Output &) override;

	struct QueueEntry {
		Hash hash;
		BinaryArray binary_transaction;
		PreparedWalletTransaction pwtx;
		Amount fee_per_kb    = 0;
		Height remove_height = 0;
		bool in_blockchain() const { return remove_height != 0; }
	};

private:
	size_t m_tx_pool_version = 0;
	std::chrono::steady_clock::time_point m_log_redo_block;

	Wallet &m_wallet;
	DeltaState m_memory_state;
	std::set<Hash> m_pool_hashes;

	void add_transaction_to_mempool(Hash tid, const PreparedWalletTransaction &pwtx, bool from_pq);
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
	const QueueEntry *find_in_payment_queue(const Hash &hash);
};

}  // namespace cn
