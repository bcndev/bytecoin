// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <set>
#include <unordered_map>
#include <unordered_set>
#include "BlockChain.hpp"
#include "Multicore.hpp"
#include "crypto/hash.hpp"

namespace bytecoin {

class Config;

class IBlockChainState {
public:
	struct UnlockTimePublickKeyHeightSpent {
		UnlockMoment unlock_time = 0;
		PublicKey public_key;
		Height height = 0;
		bool spent    = false;
	};
	virtual ~IBlockChainState() {}
	virtual void store_keyimage(const KeyImage &, Height) = 0;
	virtual void delete_keyimage(const KeyImage &) = 0;
	virtual bool read_keyimage(const KeyImage &, Height *) const = 0;

	virtual uint32_t push_amount_output(Amount, UnlockMoment, Height, const PublicKey &) = 0;
	virtual void pop_amount_output(Amount, UnlockMoment, const PublicKey &) = 0;
	virtual uint32_t next_global_index_for_amount(Amount) const = 0;
	virtual bool read_amount_output(Amount, uint32_t global_index, UnlockTimePublickKeyHeightSpent *) const = 0;
	virtual void spend_output(Amount, uint32_t global_index) = 0;
};

class BlockChainState : public BlockChain, private IBlockChainState {
public:
	BlockChainState(logging::ILogger &, const Config &, const Currency &, bool read_only);

	const Currency &get_currency() const { return m_currency; }
	uint32_t get_next_effective_median_size() const;

	std::vector<api::Output> get_random_outputs(Amount, size_t outs_count, Height, Timestamp) const;
	typedef std::vector<std::vector<uint32_t>> BlockGlobalIndices;
	bool read_block_output_global_indices(const Hash &bid, BlockGlobalIndices *) const;

	Amount minimum_pool_fee_per_byte(Hash *minimal_tid) const;
	AddTransactionResult add_transaction(const Hash &tid, const Transaction &, const BinaryArray &binary_tx,
	    Timestamp now, Height *conflict_height, const std::string &source_address);
	bool get_largest_referenced_height(const TransactionPrefix &tx, Height *block_height) const;

	uint32_t get_tx_pool_version() const { return m_tx_pool_version; }
	struct PoolTransaction {
		Transaction tx;
		BinaryArray binary_tx;
		Amount fee;
		Timestamp timestamp;

		PoolTransaction(const Transaction &tx, const BinaryArray &binary_tx, Amount fee, Timestamp timestamp);
		Amount fee_per_byte() const { return fee / binary_tx.size(); }
	};
	typedef std::map<Hash, PoolTransaction> PoolTransMap;
	const PoolTransMap &get_memory_state_transactions() const { return m_memory_state_tx; }

	bool create_mining_block_template(
	    BlockTemplate *, const AccountPublicAddress &, const BinaryArray &extra_nonce, Difficulty *, Height *) const;
	bool create_mining_block_template2(
	    BlockTemplate *, const AccountPublicAddress &, const BinaryArray &extra_nonce, Difficulty *, Hash) const;
	BroadcastAction add_mined_block(const BinaryArray &raw_block_template, RawBlock *, api::BlockHeader *);

	static api::BlockHeader fill_genesis(Hash genesis_bid, const BlockTemplate &);

	void test_print_outputs();

protected:
	virtual std::string check_standalone_consensus(const PreparedBlock &pb, api::BlockHeader *info,
	    const api::BlockHeader &prev_info, bool check_pow) const override;
	virtual bool redo_block(const Hash &bhash, const Block &, const api::BlockHeader &) override;
	virtual void undo_block(const Hash &bhash, const Block &, Height) override;

private:
	class DeltaState : public IBlockChainState {
		std::map<KeyImage, Height> m_keyimages;  // sorted to speed up bulk saving to DB
		std::map<Amount, std::vector<std::pair<uint64_t, PublicKey>>> m_global_amounts;
		std::vector<std::pair<Amount, uint32_t>> m_spent_outputs;
		Height m_block_height;  // Every delta state corresponds to some height
		Timestamp m_unlock_timestamp;
		const IBlockChainState *m_parent_state;  // const parent to prevent accidental parent modification
	public:
		explicit DeltaState(Height block_height, Timestamp unlock_timestamp, const IBlockChainState *parent_state)
		    : m_block_height(block_height), m_unlock_timestamp(unlock_timestamp), m_parent_state(parent_state) {}
		Height get_block_height() const { return m_block_height; }
		Height get_unlock_timestamp() const { return m_unlock_timestamp; }
		void apply(IBlockChainState *parent_state) const;  // Apply modifications to (non-const) parent
		void clear(Height new_block_height);               // We use it for memory_state
		const std::map<KeyImage, Height> &get_keyimages() const { return m_keyimages; }

		void store_keyimage(const KeyImage &, Height) override;
		void delete_keyimage(const KeyImage &) override;
		bool read_keyimage(const KeyImage &, Height *) const override;

		uint32_t push_amount_output(Amount, UnlockMoment, Height, const PublicKey &) override;
		void pop_amount_output(Amount, UnlockMoment, const PublicKey &) override;
		uint32_t next_global_index_for_amount(Amount) const override;
		bool read_amount_output(Amount, uint32_t global_index, UnlockTimePublickKeyHeightSpent *) const override;
		void spend_output(Amount, uint32_t global_index) override;
	};

	void store_keyimage(const KeyImage &, Height) override;
	void delete_keyimage(const KeyImage &) override;
	bool read_keyimage(const KeyImage &, Height *) const override;

	uint32_t push_amount_output(Amount, UnlockMoment, Height, const PublicKey &) override;
	void pop_amount_output(Amount, UnlockMoment, const PublicKey &) override;
	uint32_t next_global_index_for_amount(Amount) const override;
	bool read_amount_output(Amount, uint32_t global_index, UnlockTimePublickKeyHeightSpent *) const override;
	void spend_output(Amount, uint32_t global_index) override;
	void spend_output(Amount, uint32_t global_index, bool spent);

	std::string redo_transaction_get_error(bool generating, const Transaction &, DeltaState *, BlockGlobalIndices *,
	    Height *conflict_height, bool check_sigs) const;
	bool redo_block(const Block &, const api::BlockHeader &, DeltaState *, BlockGlobalIndices *) const;

	void undo_transaction(IBlockChainState *delta_state, Height, const Transaction &);

	mutable crypto::CryptoNightContext m_hash_crypto_context;
	mutable std::unordered_map<Amount, uint32_t>
	    m_next_gi_for_amount;  // Read from db on first use, write on modification

	AddTransactionResult add_transaction(const Hash &tid, const Transaction &tx, const BinaryArray &binary_tx,
	    Height unlock_height, Timestamp unlock_timestamp, Height *conflict_height, bool check_sigs,
	    const std::string &source_address);
	void remove_from_pool(Hash tid);

	uint32_t m_tx_pool_version = 2;  // Incremented every time pool changes, reset to 2 on redo block. 2 is selected
	                                 // because wallet resets to 1, so after both reset pool versions do not equal
	PoolTransMap m_memory_state_tx;
	std::map<KeyImage, Hash> m_memory_state_ki_tx;
	std::map<Amount, std::set<Hash>> m_memory_state_fee_tx;
	size_t m_memory_state_total_size = 0;

	mutable std::map<Hash, std::pair<BinaryArray, Height>> m_mining_transactions;
	// We remember them for several blocks
	void clear_mining_transactions() const;

	Timestamp m_next_median_timestamp = 0;
	uint32_t m_next_median_size       = 0;
	virtual void tip_changed() override;  // Updates values above
	virtual void on_reorganization(
	    const std::map<Hash, std::pair<Transaction, BinaryArray>> &undone_transactions, bool undone_blocks) override;
	void calculate_consensus_values(
	    const api::BlockHeader &prev_info, uint32_t *next_median_size, Timestamp *next_median_timestamp) const;

	RingCheckerMulticore ring_checker;
	std::chrono::steady_clock::time_point log_redo_block_timestamp;
};

}  // namespace bytecoin
