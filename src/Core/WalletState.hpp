// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include <condition_variable>
#include <mutex>
#include <thread>
#include "BlockChainState.hpp"
#include "CryptoNote.hpp"
#include "Wallet.hpp"
#include "crypto/chacha8.h"
#include "platform/DB.hpp"
#include "rpc_api.hpp"

namespace byterub {

class Config;

class IWalletState {
public:
	virtual ~IWalletState() {}

	virtual void redo_transaction(
	    Height, const Hash &tid, const TransactionPrefix &tx, const api::Transaction &ptx) = 0;
	virtual void undo_transaction(Height, const Hash &tid) = 0;

	virtual void redo_keyimage_output(const api::Output &, Height block_height, Timestamp block_unlock_timestamp) = 0;
	virtual void undo_keyimage_output(const api::Output &) = 0;

	virtual void redo_height_keyimage(Height, const KeyImage &) = 0;
	virtual void undo_height_keyimage(Height, const KeyImage &) = 0;
};

// Experimental machinery to offload heavy calcs to other cores
struct PreparedWalletTransaction {
	TransactionPrefix tx;
	KeyDerivation derivation;
	std::vector<PublicKey> spend_keys;

	PreparedWalletTransaction() {}
	PreparedWalletTransaction(TransactionPrefix &&tx, const SecretKey &view_secret_key);
};

struct PreparedWalletBlock {
	BlockTemplate header;
	PreparedWalletTransaction base_transaction;
	Hash base_transaction_hash;
	std::vector<PreparedWalletTransaction> transactions;
	PreparedWalletBlock() {}
	PreparedWalletBlock(BlockTemplate &&bc_header, std::vector<TransactionPrefix> &&bc_transactions,
	    Hash base_transaction_hash, const SecretKey &view_secret_key);
};

class WalletPreparatorMulticore {
	std::vector<std::thread> threads;
	std::mutex mu;
	std::condition_variable have_work;
	std::condition_variable result_ready;
	bool quit = false;

	std::map<Height, PreparedWalletBlock> prepared_blocks;
	api::byterubd::SyncBlocks::Response work;
	int work_counter = 0;
	SecretKey work_secret_key;
	void thread_run();

public:
	WalletPreparatorMulticore();
	~WalletPreparatorMulticore();
	void cancel_work();
	void start_work(const api::byterubd::SyncBlocks::Response &new_work, const SecretKey &view_secret_key);
	PreparedWalletBlock get_ready_work(Height height);
};

class WalletState : private IWalletState {
	class DeltaState : public IWalletState {
		Height m_block_height;
		Timestamp m_unlock_timestamp;
		typedef std::map<PublicKey, std::vector<api::Output>> Unspents;
		Unspents m_unspents;
		std::map<KeyImage, int> m_used_keyimages;  // counter, because double spends are allowed in pool
		std::map<Hash, std::pair<TransactionPrefix, api::Transaction>> m_transactions;

	public:
		explicit DeltaState(Height block_height, Timestamp unlock_timestamp)
		    : m_block_height(block_height), m_unlock_timestamp(unlock_timestamp) {}
		Height get_block_height() const { return m_block_height; }
		Height get_unlock_timestamp() const { return m_unlock_timestamp; }
		void apply(IWalletState *parent_state) const;  // Apply modifications to (non-const) parent
		void clear(Height new_block_height);           // We use it for memory_state
		void set_height(Height new_block_height);
		const Unspents &get_unspents() const { return m_unspents; }
		const std::map<Hash, std::pair<TransactionPrefix, api::Transaction>> &get_transactions() const {
			return m_transactions;
		}
		bool is_spent(const api::Output &) const;

		void undo_transaction(const Hash &tid);  // For mem pool

		virtual void redo_transaction(
		    Height, const Hash &tid, const TransactionPrefix &tx, const api::Transaction &ptx) override;
		virtual void undo_transaction(Height, const Hash &tid) override;

		virtual void redo_keyimage_output(
		    const api::Output &, Height block_height, Timestamp block_unlock_timestamp) override;
		virtual void undo_keyimage_output(const api::Output &) override;

		virtual void redo_height_keyimage(Height, const KeyImage &) override;
		virtual void undo_height_keyimage(Height, const KeyImage &) override;
	};

public:
	typedef platform::DB DB;

	explicit WalletState(Wallet &, logging::ILogger &, const Config &, const Currency &);
	const Currency &get_currency() const { return m_currency; };

	Hash get_tip_bid() const { return m_tip.hash; }
	Height get_tip_height() const { return m_tip_height; }
	const api::BlockHeader &get_tip() const { return m_tip; }

	std::vector<Hash> get_sparse_chain() const;
	bool sync_with_blockchain(api::byterubd::SyncBlocks::Response &);  // We move from it
	bool sync_with_blockchain(const api::byterubd::SyncMemPool::Response &);
	void add_transient_transaction(const Hash &tid, const TransactionPrefix &tx);

	bool parse_raw_transaction(api::Transaction &ptx, const TransactionPrefix &tx, Hash tid) const;
	void test_undo_blocks();
	void test_print_everything(const std::string &str);

	// Read state
	std::vector<api::Block> api_get_transfers(const std::string &address, Height &from_height, Height &to_height,
	    bool forward, uint32_t desired_tx_count = std::numeric_limits<uint32_t>::max()) const;
	bool api_get_transaction(Hash tid, TransactionPrefix &tx, api::Transaction &ptx) const;
	bool api_create_proof(SendProof &sp) const;
	api::Block api_get_pool_as_history(const std::string &address) const;
	std::map<std::pair<Amount, uint32_t>, api::Output> api_get_unlocked_outputs(
	    const std::string &address, Height from_height, Height to_height = std::numeric_limits<Height>::max()) const;
	std::vector<api::Transaction> api_list_history(const std::string &address, Hash start_transaction,
	    size_t max_count = std::numeric_limits<size_t>::max()) const;
	std::vector<api::Output> api_get_unspent(
	    const std::string &address, Height height, Amount max_amount = std::numeric_limits<Amount>::max()) const;
	std::vector<api::Output> api_get_locked_or_unconfirmed_unspent(const std::string &address, Height height) const;
	api::Balance get_balance(const std::string &address, Height height) const;

	uint32_t get_tx_pool_version() const { return m_tx_pool_version; }
	std::vector<Hash> get_tx_pool_hashes() const;

	bool test_check_transaction(const TransactionPrefix &tx);
	const Wallet &get_wallet() const { return m_wallet; }
	Wallet &get_wallet() { return m_wallet; }

	void wallet_addresses_updated();
	// generating through state prevents undo of blocks within 2*block_future_time_limit from now
	std::vector<WalletRecord> generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct);

	void db_commit();

protected:
	bool redo_block(const api::BlockHeader &header, const PreparedWalletBlock &block,
	    const BlockChainState::BlockGlobalIndices &global_indices, Height height);
	void undo_block(Height height);

	bool parse_raw_transaction(api::Transaction &ptx, Amount &output_amount, const PreparedWalletTransaction &pwtx,
	    Hash tid, const std::vector<uint32_t> &global_indices, Height block_height,
	    Timestamp block_unlock_timestamp) const;
	bool redo_transaction(const PreparedWalletTransaction &pwtx, const std::vector<uint32_t> &global_indices,
	    DeltaState *delta_state, bool is_base, Hash tid, Hash bid, Timestamp tx_timestamp);
	void undo_transaction(const TransactionPrefix &tx);
	void read_unlock_index(std::map<std::pair<Amount, uint32_t>, api::Output> &add, const std::string &index_prefix,
	    uint32_t begin, uint32_t end) const;
	void lock_unlock(Height prev_height, Height now_height, Timestamp prev, Timestamp now, bool lock);
	void add_to_unspent_index(const api::Output &);
	void remove_from_unspent_index(const api::Output &);
	bool is_unspent(const api::Output &) const;
	void add_to_lock_index(const api::Output &);
	void remove_from_lock_index(const api::Output &);

	virtual void redo_transaction(
	    Height, const Hash &tid, const TransactionPrefix &tx, const api::Transaction &ptx) override;
	virtual void undo_transaction(Height, const Hash &tid) override;

	virtual void redo_keyimage_output(
	    const api::Output &, Height block_height, Timestamp block_unlock_timestamp) override;
	virtual void undo_keyimage_output(const api::Output &) override;

	virtual void redo_height_keyimage(Height, const KeyImage &) override;
	virtual void undo_height_keyimage(Height, const KeyImage &) override;

	const Hash m_genesis_bid;
	const Config &m_config;
	const Currency &m_currency;
	logging::ILogger &m_log;
	Wallet &m_wallet;

private:
	void modify_balance(const api::Output &output, int locked_op, int spendable_op);
	DB m_db;

	Height m_tip_height  = -1;
	Height m_tail_height = 0;
	api::BlockHeader m_tip;
	uint32_t m_tx_pool_version = 1;

	bool read_tips();
	void push_chain(const api::BlockHeader &);
	bool read_chain(Height, api::BlockHeader &) const;
	void pop_chain();
	api::BlockHeader read_chain(Height) const;

	DeltaState m_memory_state;
	std::set<Hash> m_pool_hashes;

	WalletPreparatorMulticore preparator;
};

}  // namespace byterub
