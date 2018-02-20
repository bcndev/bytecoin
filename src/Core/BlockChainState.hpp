// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include <condition_variable>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include "BlockChain.hpp"
#include "crypto/hash.hpp"
#include "logging/LoggerMessage.hpp"

namespace bytecoin {

class Config;

class IBlockChainState {
public:
	virtual ~IBlockChainState() {}
	virtual void store_keyimage(const KeyImage &, Height) = 0;
	virtual void delete_keyimage(const KeyImage &)     = 0;
	virtual bool read_keyimage(const KeyImage &) const = 0;

	virtual uint32_t push_amount_output(
	    Amount, UnlockMoment, Height block_height, Timestamp block_unlock_timestamp, const PublicKey &) = 0;
	virtual void pop_amount_output(Amount, UnlockMoment, const PublicKey &) = 0;
	virtual uint32_t next_global_index_for_amount(Amount) const = 0;
	virtual bool read_amount_output(Amount, uint32_t global_index, UnlockMoment &, PublicKey &) const = 0;
};

struct RingSignatureArg {
	Hash tx_prefix_hash;
	KeyImage key_image;
	std::vector<PublicKey> output_keys;
	std::vector<Signature> signatures;
};

class RingCheckerMulticore {
	std::vector<std::thread> threads;
	mutable std::mutex mu;
	mutable std::condition_variable have_work;
	mutable std::condition_variable result_ready;
	bool quit = false;

	size_t total_counter = 0;
	size_t ready_counter = 0;
	std::vector<std::string> errors;

	std::deque<RingSignatureArg> args;
	int work_counter = 0;
	void thread_run();

public:
	RingCheckerMulticore();
	~RingCheckerMulticore();
	void cancel_work();
	std::string start_work_get_error(IBlockChainState *state, const Currency &currency, const Block &block,
	    Height unlock_height, Timestamp unlock_timestamp);  // can fail immediately
	bool signatures_valid() const;
};

class BlockChainState : public BlockChain, private IBlockChainState {
public:
	BlockChainState(logging::ILogger &, const Config &, const Currency &);

	const Currency &get_currency() const { return m_currency; };
	uint32_t get_next_effective_median_size() const;

	std::vector<api::Output> get_outputs_by_amount(Amount, size_t anonymity, Height, Timestamp) const;
	typedef std::vector<std::vector<uint32_t>> BlockGlobalIndices;
	bool read_block_output_global_indices(const Hash &bid, BlockGlobalIndices &) const;

	BroadcastAction add_transaction(const Transaction &, Timestamp now);
	uint32_t get_tx_pool_version() const { return m_tx_pool_version; }
	typedef std::map<Hash, Transaction> TransMap;
	const TransMap &get_memory_state_transactions() const { return m_memory_state_tx; }

	bool create_mining_block_template(
	    BlockTemplate &, const AccountPublicAddress &, const BinaryArray &extra_nonce, Difficulty &, Height &) const;
	BroadcastAction add_mined_block(const BinaryArray &raw_block_template, RawBlock &, api::BlockHeader &);
	Timestamp read_first_seen_timestamp(const Hash &tid) const;  // 0 if does not exist

	static api::BlockHeader fill_genesis(Hash genesis_bid, const BlockTemplate &);

protected:
	std::string get_standalone_consensus_error(
	    const PreparedBlock &pb, api::BlockHeader &info, const api::BlockHeader &prev_info) const;
	virtual bool check_standalone_consensus(
	    const PreparedBlock &pb, api::BlockHeader &info, const api::BlockHeader &prev_info) const override;
	virtual bool redo_block(const Hash &bhash, const Block &, const api::BlockHeader &) override;
	virtual void undo_block(const Hash &bhash, const Block &, Height) override;

private:
	class DeltaState : public IBlockChainState {
		std::map<KeyImage, Height> m_keyimages;  // sorted to speed up bulk saving to DB
		std::map<Amount, std::vector<std::pair<uint64_t, PublicKey>>> m_global_amounts;

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

		virtual void store_keyimage(const KeyImage &, Height) override;
		virtual void delete_keyimage(const KeyImage &) override;
		virtual bool read_keyimage(const KeyImage &) const override;

		virtual uint32_t push_amount_output(
		    Amount, UnlockMoment, Height block_height, Timestamp block_unlock_timestamp, const PublicKey &) override;
		virtual void pop_amount_output(Amount, UnlockMoment, const PublicKey &) override;
		virtual uint32_t next_global_index_for_amount(Amount) const override;
		virtual bool read_amount_output(Amount, uint32_t global_index, UnlockMoment &, PublicKey &) const override;
	};

	virtual void store_keyimage(const KeyImage &, Height) override;
	virtual void delete_keyimage(const KeyImage &) override;
	virtual bool read_keyimage(const KeyImage &) const override;

	virtual uint32_t push_amount_output(
	    Amount, UnlockMoment, Height block_height, Timestamp block_unlock_timestamp, const PublicKey &) override;
	virtual void pop_amount_output(Amount, UnlockMoment, const PublicKey &) override;
	virtual uint32_t next_global_index_for_amount(Amount) const override;
	virtual bool read_amount_output(Amount, uint32_t global_index, UnlockMoment &, PublicKey &) const override;

	std::string redo_transaction_get_error(bool generating, const Transaction &, DeltaState *, BlockGlobalIndices &,
	    bool check_sigs, Amount &fee, bool &fatal) const;
	bool redo_block(const Block &, const api::BlockHeader &, DeltaState *, BlockGlobalIndices &) const;

	void undo_transaction(IBlockChainState *delta_state, Height, const Transaction &);

	const Config &m_config;
	const Currency &m_currency;
	logging::LoggerRef m_log;
	mutable crypto::CryptoNightContext m_hash_crypto_context;
	mutable std::unordered_map<Amount, uint32_t>
	    m_next_gi_for_amount;  // Read from db on first use, write on modification

	void update_first_seen_timestamp(const Hash &tid, Timestamp now);  // 0 to delete

	BroadcastAction add_transaction(const Hash &tid, const Transaction &tx, Height unlock_height,
	    Timestamp unlock_timestamp, size_t max_pool_complexity, bool check_sigs);
	void remove_from_pool(Hash tid);

	uint32_t m_tx_pool_version = 2;  // Incremented every time pool changes, reset to 2 on redo block. 2 is selected
	                                 // because wallet resets to 1, so after both reset pool versions do not equal
	TransMap m_memory_state_tx;
	std::map<KeyImage, Hash> m_memory_state_ki_tx;
	std::map<Amount, std::set<Hash>> m_memory_state_fee_tx;
	size_t m_memory_state_total_complexity;
	mutable std::map<Hash, std::pair<Transaction, Height>> m_mining_transactions;
	// We remember them for several blocks
	void clear_mining_transactions() const;

	Timestamp m_next_median_timestamp = 0;
	Timestamp m_next_unlock_timestamp = 0;
	uint32_t m_next_median_size       = 0;
	virtual void tip_changed() override;  // Updates values above
	void calculate_consensus_values(Height height_delta, uint32_t &next_median_size, Timestamp &next_median_timestamp,
	    Timestamp &next_unlock_timestamp) const;

	RingCheckerMulticore ring_checker;
};

}  // namespace bytecoin
