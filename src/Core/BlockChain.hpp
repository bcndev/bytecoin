// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include <deque>
#include "CryptoNote.hpp"
#include "Currency.hpp"
#include "platform/DB.hpp"
#include "platform/ExclusiveLock.hpp"
#include "rpc_api.hpp"

namespace byterub {

enum class BroadcastAction { BROADCAST_ALL, NOTHING, BAN };

struct PreparedBlock {
	BinaryArray block_data;
	RawBlock raw_block;
	Block block;
	Hash bid;
	Hash base_transaction_hash;
	size_t coinbase_tx_size  = 0;
	size_t parent_block_size = 0;
	Hash long_block_hash;  // only if context != nullptr

	explicit PreparedBlock(BinaryArray &&ba, crypto::CryptoNightContext *context);
	explicit PreparedBlock(RawBlock &&rba, crypto::CryptoNightContext *context);  // we get raw blocks from p2p
	PreparedBlock() {}
};

class BlockChain {
public:
	typedef platform::DB DB;

	explicit BlockChain(const Hash &genesis_bid, const std::string &coin_folder);
	virtual ~BlockChain() {}

	const std::string &get_coin_folder() const { return m_coin_folder; }
	const Hash &get_genesis_bid() const { return m_genesis_bid; }
	// Read blockchain state
	Hash get_tip_bid() const { return m_tip_bid; }
	Height get_tip_height() const { return m_tip_height; }
	const api::BlockHeader &get_tip() const;

	std::pair<std::deque<api::BlockHeader>::const_iterator, std::deque<api::BlockHeader>::const_iterator>
	get_tip_segment(Height height_delta, Height window, bool add_genesis) const;

	bool read_chain(Height height, Hash &bid) const;
	bool read_block(const Hash &bid, RawBlock &rb) const;
	bool has_block(const Hash &bid) const;
	bool read_header(const Hash &bid, api::BlockHeader &info) const;
	bool read_transaction(const Hash &tid, Transaction &tx, Height &height, size_t &index_in_block) const;

	// Modify blockchain state. byterub header does not contain enough info for consensus calcs, so we cannot have
	// header chain without block chain
	BroadcastAction add_block(const PreparedBlock &pb, api::BlockHeader &info);

	// Facilitate sync and download
	std::vector<Hash> get_sparse_chain() const;
	std::vector<api::BlockHeader> get_sync_headers(const std::vector<Hash> &sparse_chain, size_t max_count) const;
	std::vector<Hash> get_sync_headers_chain(
	    const std::vector<Hash> &sparse_chain, Height &start_height, size_t max_count) const;

	Height find_blockchain_supplement(const std::vector<Hash> &remote_block_ids) const;
	Height get_timestamp_lower_bound_block_index(Timestamp) const;

	void test_undo_everything();
	void test_print_structure() const;
	void test_prune_oldest();
	void db_commit();

	bool internal_import();  // import some existing blocks from inside DB
	Height internal_import_known_height() const { return m_internal_import_known_height; }

protected:
	bool read_next_internal_block(Hash &bid) const;
	virtual bool check_standalone_consensus(
	    const PreparedBlock &pb, api::BlockHeader &info, const api::BlockHeader &prev_info) const = 0;
	virtual bool redo_block(const Hash &bhash, const Block &block, const api::BlockHeader &info)  = 0;
	virtual void undo_block(const Hash &bhash, const Block &block, Height height)                 = 0;
	bool redo_block(const Hash &bhash, const RawBlock &raw_block, const Block &block, const api::BlockHeader &info,
	    const Hash &base_transaction_hash);
	void undo_block(const Hash &bhash, const RawBlock &raw_block, const Block &block, Height height);
	virtual void tip_changed() {}  // Quick hack to allow BlockChainState to update next block params

	const Hash m_genesis_bid;
	const std::string m_coin_folder;
	Hash get_common_block(
	    const Hash &bid1, const Hash &bid2, std::vector<Hash> *chain1, std::vector<Hash> *chain2) const;

	DB m_db;

	Hash read_chain(Height height) const;
	api::BlockHeader read_header(const Hash &bid) const;

private:
	Hash m_tip_bid;
	Difficulty m_tip_cumulative_difficulty = 0;
	Height m_tip_height                    = -1;
	Height m_internal_import_known_height  = 0;
	void read_tip();
	void push_chain(Hash bid, Difficulty cumulative_difficulty);
	void pop_chain();
	mutable std::deque<api::BlockHeader> m_tip_segment;
	// We cache recent headers for quick calculation in block windows

	void store_block(const Hash &bid, const BinaryArray &block_data);

	// bid->header, header is stored in DB only if previous block is stored
	void store_header(const Hash &bid, const api::BlockHeader &header);

	bool reorganize_blocks(
	    const Hash &switch_to_chain, const PreparedBlock &recent_pb, const api::BlockHeader &recent_info);

	void check_children_counter(Difficulty cd, const Hash &bid, int value);
	void modify_children_counter(Difficulty cd, const Hash &bid, int delta);
	bool get_oldest_tip(Difficulty &cd, Hash &bid) const;
	bool prune_branch(Difficulty cd, Hash bid);
};

}  // namespace byterub
