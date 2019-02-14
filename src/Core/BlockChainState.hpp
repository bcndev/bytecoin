// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <set>
#include <unordered_map>
#include "BlockChain.hpp"
#include "Multicore.hpp"
#include "crypto/hash.hpp"

namespace cn {

class Config;

class IBlockChainState {
public:
	struct OutputIndexData {
		Amount amount;  // We will serialize encrypted amount if amount == 0
		BlockOrTimestamp unlock_block_or_timestamp = 0;
		PublicKey public_key;
		Height height    = 0;
		uint8_t spent    = 0;  // Aftermath of "keyimage out of subgroup" attack
		bool is_amethyst = false;
		std::vector<size_t> dins;
	};
	virtual ~IBlockChainState()                                  = default;
	virtual void store_keyimage(const KeyImage &, Height)        = 0;
	virtual void delete_keyimage(const KeyImage &)               = 0;
	virtual bool read_keyimage(const KeyImage &, Height *) const = 0;

	virtual size_t push_amount_output(Amount, BlockOrTimestamp, Height, const PublicKey &, bool is_amethyst) = 0;
	virtual void pop_amount_output(Amount, BlockOrTimestamp, const PublicKey &)                              = 0;
	virtual size_t next_stack_index_for_amount(Amount) const                                                 = 0;
	virtual bool read_amount_output(Amount, size_t stack_index, OutputIndexData *) const                     = 0;
};

class BlockChainState : public BlockChain, private IBlockChainState {
public:
	class Exception : public std::runtime_error {
	public:
		using std::runtime_error::runtime_error;
	};
	BlockChainState(logging::ILogger &, const Config &, const Currency &, bool read_only);

	std::vector<api::Output> get_random_outputs(uint8_t block_major_version, Amount, size_t output_count, Height,
	    Timestamp block_timestamp, Timestamp block_median_timestamp) const;
	typedef std::vector<std::vector<size_t>> BlockGlobalIndices;
	bool read_block_output_global_indices(const Hash &bid, BlockGlobalIndices *) const;

	Amount minimum_pool_fee_per_byte(bool zero_if_not_full, Hash *minimal_tid = nullptr) const;
	bool add_transaction(const Hash &tid, const Transaction &, const BinaryArray &binary_tx, bool check_sigs,
	    const std::string &source_address);
	bool get_largest_referenced_height(const TransactionPrefix &tx, Height *block_height) const;

	size_t get_tx_pool_version() const { return m_tx_pool_version; }
	struct PoolTransaction {
		Transaction tx;
		BinaryArray binary_tx;
		Amount amount;
		Amount fee;
		Timestamp timestamp;
		Hash newest_referenced_block;

		PoolTransaction(const Transaction &tx, const BinaryArray &binary_tx, Amount fee, Timestamp timestamp,
		    const Hash &newest_referenced_block);
		Amount fee_per_byte() const { return fee / binary_tx.size(); }
	};
	typedef std::map<Hash, PoolTransaction> PoolTransMap;
	const PoolTransMap &get_memory_state_transactions() const { return m_memory_state_tx; }
	std::vector<TransactionDesc> sync_pool(
	    const std::pair<Amount, Hash> &from, const std::pair<Amount, Hash> &to, size_t max_count) const;

	void create_mining_block_template(const Hash &, const AccountAddress &, const BinaryArray &extra_nonce,
	    BlockTemplate *, Difficulty *, Height *, size_t *) const;
	bool add_mined_block(const BinaryArray &raw_block_template, RawBlock *, api::BlockHeader *);

	static api::BlockHeader fill_genesis(Hash genesis_bid, const BlockTemplate &);

	void dump_outputs_quality(size_t max_count) const;

	void fill_statistics(api::cnd::GetStatistics::Response &res) const override;
	std::vector<PublicKey> get_mixed_public_keys(const InputKey &in) const;

protected:
	void check_standalone_consensus(const PreparedBlock &pb, api::BlockHeader *info, const api::BlockHeader &prev_info,
	    bool check_pow) const override;
	void redo_block(const Hash &bhash, const Block &, const api::BlockHeader &) override;  // throws ConsensusError
	void undo_block(const Hash &bhash, const Block &, Height) override;

private:
	class DeltaState : public IBlockChainState {
		std::map<KeyImage, Height> m_keyimages;  // sorted to speed up bulk saving to DB
		std::map<Amount, std::vector<std::tuple<uint64_t, PublicKey, bool>>> m_global_amounts;
		std::vector<OutputIndexData> m_ordered_global_amounts;
		//		std::vector<std::pair<Amount, size_t>> m_spent_outputs;
		Height m_block_height;  // Every delta state corresponds to some height
		Timestamp m_block_timestamp;
		Timestamp m_block_median_timestamp;
		const IBlockChainState *m_parent_state;  // const parent to prevent accidental parent modification
	public:
		explicit DeltaState(Height block_height, Timestamp block_timestamp, Timestamp block_median_timestamp,
		    const IBlockChainState *parent_state)
		    : m_block_height(block_height)
		    , m_block_timestamp(block_timestamp)
		    , m_block_median_timestamp(block_median_timestamp)
		    , m_parent_state(parent_state) {}
		Height get_block_height() const { return m_block_height; }
		Height get_block_timestamp() const { return m_block_timestamp; }
		Height get_block_median_timestamp() const { return m_block_median_timestamp; }
		void apply(IBlockChainState *parent_state) const;  // Apply modifications to (non-const) parent
		void clear(Height new_block_height);               // We use it for memory_state
		const std::map<KeyImage, Height> &get_keyimages() const { return m_keyimages; }

		void store_keyimage(const KeyImage &, Height) override;
		void delete_keyimage(const KeyImage &) override;
		bool read_keyimage(const KeyImage &, Height *) const override;

		size_t push_amount_output(Amount, BlockOrTimestamp, Height, const PublicKey &, bool is_amethyst) override;
		void pop_amount_output(Amount, BlockOrTimestamp, const PublicKey &) override;
		size_t next_stack_index_for_amount(Amount) const override;
		bool read_amount_output(Amount, size_t stack_index, OutputIndexData *) const override;
	};

	void store_keyimage(const KeyImage &, Height) override;
	void delete_keyimage(const KeyImage &) override;
	bool read_keyimage(const KeyImage &, Height *) const override;

	size_t push_amount_output(Amount, BlockOrTimestamp, Height, const PublicKey &, bool is_amethyst) override;
	void pop_amount_output(Amount, BlockOrTimestamp, const PublicKey &) override;
	size_t next_stack_index_for_amount(Amount) const override;
	bool read_amount_output(Amount, size_t stack_index, OutputIndexData *) const override;
	bool read_hidden_amount_map(Amount, size_t stack_index, size_t *hidden_index) const;
	bool read_hidden_amount_output(size_t hidden_index, OutputIndexData *) const;
	void spend_output(OutputIndexData &&, size_t hidden_index, size_t trigger_input_index, size_t level, bool spent);

	void redo_transaction(uint8_t major_block_version, bool generating, const Transaction &, DeltaState *,
	    BlockGlobalIndices *, Hash *newest_referenced_bid,
	    bool check_sigs) const;  // throws ConsensusError
	void redo_block(
	    const Block &, const api::BlockHeader &, DeltaState *, BlockGlobalIndices *) const;  // throws ConsensusError

	void undo_transaction(IBlockChainState *delta_state, Height, const Transaction &);

	const size_t m_max_pool_size;
	mutable crypto::CryptoNightContext m_hash_crypto_context;
	mutable std::unordered_map<Amount, size_t> m_next_stack_index;
	// Read from db on first use, write on modification

	void remove_from_pool(Hash tid);

	size_t m_tx_pool_version = 2;  // Incremented every time pool changes, reset to 2 on redo block. 2 is selected
	                               // because wallet resets to 1, so after both reset pool versions do not equal
	PoolTransMap m_memory_state_tx;
	std::map<KeyImage, Hash> m_memory_state_ki_tx;
	std::set<std::pair<Amount, Hash>> m_memory_state_fee_tx;
	size_t m_memory_state_total_size = 0;

	mutable std::map<Hash, std::pair<BinaryArray, Height>> m_mining_transactions;
	// We remember them for several blocks
	void clear_mining_transactions() const;
	size_t m_next_global_key_output_index = 0;
	size_t m_next_nz_input_index          = 0;
	void process_input(const Hash &tid, size_t iid, const InputKey &input);
	void unprocess_input(const InputKey &input);

	Timestamp m_next_median_timestamp        = 0;
	size_t m_next_median_size                = 0;
	size_t m_next_median_block_capacity_vote = 0;
	void tip_changed() override;  // Updates values above
	void on_reorganization(
	    const std::map<Hash, std::pair<Transaction, BinaryArray>> &undone_transactions, bool undone_blocks) override;
	Timestamp calculate_next_median_timestamp(const api::BlockHeader &prev_info) const;
	size_t calculate_next_median_size(const api::BlockHeader &prev_info) const;
	size_t calculate_next_median_block_capacity_vote(const api::BlockHeader &prev_info) const;

	RingCheckerMulticore m_ring_checker;
	std::chrono::steady_clock::time_point m_log_redo_block_timestamp;
};

}  // namespace cn
