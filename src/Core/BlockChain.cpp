// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "BlockChain.hpp"

#include <iostream>
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "Currency.hpp"
#include "TransactionExtra.hpp"
#include "common/Math.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "crypto/crypto.hpp"
#include "rpc_api.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace cn;
using namespace platform;

const std::string BlockChain::version_current = "8";
// We increment when making incompatible changes to indices.

// We use suffixes so all keys related to the same block are close to each other in DB
static const std::string BLOCK_PREFIX             = "b";
static const std::string BLOCK_SUFFIX             = "b";
static const std::string HEADER_PREFIX            = "b";
static const std::string HEADER_SUFFIX            = "h";
static const std::string TRANSACTION_PREFIX       = "t";
static const std::string TIP_CHAIN_PREFIX         = "c";
static const std::string TIMESTAMP_BLOCK_PREFIX   = "T";
static const std::string CHECKPOINT_PREFIX_STABLE = "CS";
static const std::string CHECKPOINT_PREFIX_LATEST = "CL";

static const std::string CHILDREN_PREFIX = "x-ch/";
static const std::string CD_TIPS_PREFIX  = "x-tips/";
// We store bid->children counter, with counter=1 default (absent from index)
// We store cumulative_difficulty->bid for bids with no children

Block::Block(const RawBlock &rb) {
	BlockTemplate &bheader = header;
	seria::from_binary(bheader, rb.block);
	transactions.reserve(rb.transactions.size());
	for (auto &&raw_transaction : rb.transactions) {
		Transaction transaction;
		seria::from_binary(transaction, raw_transaction);
		transactions.push_back(std::move(transaction));
	}
}

PreparedBlock::PreparedBlock(BinaryArray &&ba, const Currency &currency, crypto::CryptoNightContext *context)
    : block_data(std::move(ba)) {
	try {
		seria::from_binary(raw_block, block_data);
		prepare(currency, context);
	} catch (const std::exception &ex) {
		error = ConsensusError{common::what(ex)};
		return;
	}
}

PreparedBlock::PreparedBlock(RawBlock &&rba, const Currency &currency, crypto::CryptoNightContext *context)
    : raw_block(rba) {
	try {
		block_data = seria::to_binary(raw_block);
		prepare(currency, context);
	} catch (const std::exception &ex) {
		error = ConsensusError{common::what(ex)};
		return;
	}
}

void PreparedBlock::prepare(const Currency &currency, crypto::CryptoNightContext *context) {
	block           = Block{raw_block};
	auto body_proxy = get_body_proxy_from_template(block.header);
	bid             = cn::get_block_hash(block.header, body_proxy);
	if (block.header.is_merge_mined())
		parent_block_size = seria::binary_size(block.header.root_block);
	coinbase_tx_size      = seria::binary_size(block.header.base_transaction);
	block_header_size     = seria::binary_size(static_cast<BlockHeader>(block.header));
	base_transaction_hash = get_transaction_hash(block.header.base_transaction);
	if (context) {
		auto ba  = currency.get_block_pow_hashing_data(block.header, body_proxy);
		pow_hash = context->cn_slow_hash(ba.data(), ba.size());
	}
	if (block.header.transaction_hashes.size() != raw_block.transactions.size()) {
		error = ConsensusError{"Wrong transcation count in block template"};
		return;
	}
	// Transactions are in block
	for (size_t i = 0; i != block.transactions.size(); ++i) {
		Hash tid = get_transaction_hash(block.transactions.at(i));
		if (tid != block.header.transaction_hashes.at(i)) {
			error = ConsensusError{"Transaction from block template absent in block"};
			return;
		}
	}
}

BlockChain::BlockChain(logging::ILogger &log, const Config &config, const Currency &currency, bool read_only)
    : m_genesis_bid(currency.genesis_block_hash)
    , m_db(read_only ? platform::O_READ_EXISTING : platform::O_OPEN_ALWAYS, config.get_data_folder() + "/blockchain")
    , m_archive(read_only || !config.is_archive, config.get_data_folder() + "/archive")
    , m_log(log, "BlockChainState")
    , m_config(config)
    , m_currency(currency) {
	invariant(CheckpointDifficulty{}.size() == currency.get_checkpoint_keys_count(), "");
	std::string version;
	if (!m_db.get("$version", version)) {
		DB::Cursor cur = m_db.begin(std::string());
		if (!cur.end())
			throw std::runtime_error("Blockchain database format unknown version, please delete " + m_db.get_path());
		version = version_current;
		m_db.put("$version", version, false);
	}
	if (version != version_current)
		return;  // BlockChainState will upgrade DB, we must not continue or risk crashing
	Hash stored_genesis_bid;
	if (get_chain(0, &stored_genesis_bid)) {
		if (stored_genesis_bid != m_genesis_bid)
			throw std::runtime_error("Database starts with different genesis_block");
		DB::Cursor cur2 = m_db.rbegin(TIP_CHAIN_PREFIX);
		m_tip_height = cur2.end() ? -1 : common::integer_cast<Height>(common::read_varint_sqlite4(cur2.get_suffix()));
		seria::from_binary(m_tip_bid, cur2.get_value_array());
		api::BlockHeader tip_header = read_header(m_tip_bid);
		m_tip_cumulative_difficulty = tip_header.cumulative_difficulty;
		m_header_tip_window.push_back(tip_header);
	}
	BinaryArray cha;
	if (m_db.get("internal_import_chain", cha)) {
		seria::from_binary(m_internal_import_chain, cha);
		m_log(logging::INFO) << "BlockChain continue internal import of blocks, count="
		                     << m_internal_import_chain.size();
	}
	//	m_db.debug_print_index_size(BLOCK_PREFIX);
	//	m_db.debug_print_index_size(TRANSACTION_PREFIX);
	//	m_db.debug_print_index_size(TIP_CHAIN_PREFIX);
	//	m_db.debug_print_index_size(TIMESTAMP_BLOCK_PREFIX);

	//	m_db.debug_print_index_size(CHECKPOINT_PREFIX_STABLE);
	//	m_db.debug_print_index_size(CHECKPOINT_PREFIX_LATEST);
	//	m_db.debug_print_index_size(CHILDREN_PREFIX);
	//	m_db.debug_print_index_size(CD_TIPS_PREFIX);
}

void BlockChain::db_commit() {
	m_log(logging::INFO) << "BlockChain::db_commit started... tip_height=" << m_tip_height
	                     << " m_header_cache.size=" << m_header_cache.size();
	m_db.commit_db_txn();
	m_header_cache.clear();  // Most simple cache policy ever
	m_archive.db_commit();
	m_log(logging::INFO) << "BlockChain::db_commit finished...";
}

bool BlockChain::add_block(
    const PreparedBlock &pb, api::BlockHeader *info, bool just_mined, const std::string &source_address) {
	*info            = api::BlockHeader();
	bool have_header = get_header(pb.bid, info);
	bool have_block  = has_block(pb.bid);
	if (have_block && have_header) {
		if (info->height > m_currency.last_hard_checkpoint().height)
			m_archive.add(Archive::BLOCK, pb.block_data, pb.bid, source_address);
		return false;
	}
	api::BlockHeader prev_info;
	prev_info.height = -1;
	if (pb.bid != m_genesis_bid && !get_header(pb.block.header.previous_block_hash, &prev_info))
		return false;  // Not interested in orphan headers
	info->major_version       = pb.block.header.major_version;
	info->minor_version       = pb.block.header.minor_version;
	info->timestamp           = pb.block.header.timestamp;
	info->previous_block_hash = pb.block.header.previous_block_hash;
	info->binary_nonce        = pb.block.header.nonce;
	info->hash                = pb.bid;
	info->height              = prev_info.height + 1;
	// Rest fields are filled by check_standalone_consensus
	check_standalone_consensus(pb, info, prev_info, true);  // throws ConsensusError
	if (!add_blod(*info)) {  // Has parent that does not pass through last hard checkpoint
		if (info->height > m_currency.last_hard_checkpoint().height)
			m_archive.add(Archive::BLOCK, pb.block_data, pb.bid, source_address);
		return false;
	}
	try {
		if (!have_block) {                       // have block, but not header during internal_import
			store_block(pb.bid, pb.block_data);  // Do not commit between here and
			// reorganize_blocks or invariant might be dead
			if (info->height > m_currency.last_hard_checkpoint().height)
				m_archive.add(Archive::BLOCK, pb.block_data, pb.bid, source_address);
		}
		store_header(pb.bid, *info);
		if (pb.bid == m_genesis_bid) {
			redo_block(pb.bid, pb.block_data, pb.raw_block, pb.block, *info, pb.base_transaction_hash);
			push_chain(*info);
			if (m_config.paranoid_checks)
				debug_check_transaction_invariants(pb.raw_block, pb.block, *info, pb.base_transaction_hash);
		} else {
			modify_children_counter(prev_info.cumulative_difficulty, pb.block.header.previous_block_hash, 1);
		}
		check_children_counter(info->cumulative_difficulty, pb.bid, 1);
		modify_children_counter(info->cumulative_difficulty, pb.bid, -1);  // -1 from default 1 gives 0
		if (info->hash == m_currency.last_hard_checkpoint().hash)
			build_blods();
		auto tip_check_cd = get_checkpoint_difficulty(get_tip_bid());
		auto bid_check_cd = get_checkpoint_difficulty(info->hash);
		if (compare(bid_check_cd, info->cumulative_difficulty, just_mined, tip_check_cd,
		        get_tip_cumulative_difficulty()) > 0) {
			if (get_tip_bid() == pb.block.header.previous_block_hash) {  // most common case optimization
				redo_block(pb.bid, pb.block_data, pb.raw_block, pb.block, *info, pb.base_transaction_hash);
				push_chain(*info);
				if (m_config.paranoid_checks)
					debug_check_transaction_invariants(pb.raw_block, pb.block, *info, pb.base_transaction_hash);
			} else
				reorganize_blocks(pb.bid, pb, *info);
		}
	} catch (const ConsensusError &) {
		throw;  // The only exception which is safe here
	} catch (const std::exception &ex) {
		m_log(logging::ERROR) << "Exception while reorganizing blockchain, probably out of disk space ex.what="
		                      << common::what(ex) << ", database corrupted, please delete " << m_db.get_path();
		std::exit(api::BYTECOIND_DATABASE_ERROR);
	}
	if (get_tip_height() % m_config.db_commit_every_n_blocks ==
	    m_config.db_commit_every_n_blocks - 1)  // no commit on genesis
		db_commit();
	return info->hash == get_tip_bid();
}

void BlockChain::debug_check_transaction_invariants(const RawBlock &raw_block, const Block &block,
    const api::BlockHeader &info, const Hash &base_transaction_hash) const {
	BinaryArray binary_tx;
	Transaction rtx;
	Height bhe;
	Hash bha;
	size_t iib;
	invariant(get_transaction(base_transaction_hash, &binary_tx, &bhe, &bha, &iib), "tx index invariant failed 1");
	seria::from_binary(rtx, binary_tx);
	invariant(get_transaction_hash(rtx) == base_transaction_hash && bhe == info.height && bha == info.hash && iib == 0,
	    "tx index invariant failed 2");
	for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
		Hash tid = block.header.transaction_hashes.at(tx_index);
		invariant(get_transaction(tid, &binary_tx, &bhe, &bha, &iib), "tx index invariant failed 3");
		seria::from_binary(rtx, binary_tx);
		invariant(seria::to_binary(rtx) == raw_block.transactions.at(tx_index) && bhe == info.height &&
		              bha == info.hash && iib == tx_index + 1 &&
		              binary_tx.size() == raw_block.transactions.at(tx_index).size(),
		    "tx index invariant failed 4");
	}
}

bool BlockChain::reorganize_blocks(const Hash &switch_to_chain,
    const PreparedBlock &recent_pb,
    const api::BlockHeader &recent_info) {
	// Header chain is better than block chain, undo upto splitting block
	std::vector<Hash> chain1, chain2;
	Hash common = get_common_block(get_tip_bid(), switch_to_chain, &chain1, &chain2);
	for (auto &&chha : chain2) {
		if (!has_block(chha))
			return false;  // Full new chain not yet downloaded
	}
	std::map<Hash, std::pair<Transaction, BinaryArray>> undone_transactions;
	size_t undone_transactions_binary_size = 0;
	bool undone_blocks                     = false;
	while (get_tip_bid() != common) {
		RawBlock raw_block;
		invariant(get_block(get_tip_bid(), &raw_block),
		    "Block to undo not found or failed to convert" + common::pod_to_hex(get_tip_bid()));
		Block block(raw_block);
		undone_blocks = true;
		undo_block(get_tip_bid(), raw_block, block, m_tip_height);
		if (undone_transactions_binary_size < m_config.max_undo_transactions_size)
			for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
				Hash tid = block.header.transaction_hashes.at(tx_index);
				undone_transactions_binary_size += raw_block.transactions.at(tx_index).size();
				undone_transactions.insert(
				    std::make_pair(tid, std::make_pair(std::move(block.transactions.at(tx_index)),
				                            std::move(raw_block.transactions.at(tx_index)))));
			}
		pop_chain(block.header.previous_block_hash);
		tip_changed();
	}
	// Now redo all blocks we have in storage, will ask for the rest of blocks
	// We catch consensus error from redo_block
	// when invalid block on longest subchain, we should make no attempt to download the rest
	// we will forever stuck on this block until longer chain appears, that does not include it
	try {
		while (!chain2.empty()) {
			Hash chha = chain2.back();
			chain2.pop_back();
			if (chha == recent_pb.bid) {
				invariant(recent_pb.block.header.previous_block_hash == get_tip_bid(),
				    "Unexpected block prev, invariant dead");
				redo_block(recent_pb.bid, recent_pb.block_data, recent_pb.raw_block, recent_pb.block, recent_info,
				    recent_pb.base_transaction_hash);
				push_chain(recent_info);
				for (auto &&tid : recent_pb.block.header.transaction_hashes)
					undone_transactions.erase(tid);
				if (m_config.paranoid_checks)
					debug_check_transaction_invariants(
					    recent_pb.raw_block, recent_pb.block, recent_info, recent_pb.base_transaction_hash);
			} else {
				BinaryArray block_data;
				RawBlock raw_block;
				invariant(get_block(chha, &block_data, &raw_block), "");
				Block block(raw_block);
				invariant(block.header.previous_block_hash == get_tip_bid(), "Unexpected block prev, invariant dead");
				api::BlockHeader info      = read_header(chha);
				Hash base_transaction_hash = get_transaction_hash(block.header.base_transaction);

				redo_block(chha, block_data, raw_block, block, info, base_transaction_hash);
				push_chain(info);
				for (auto &&tid : block.header.transaction_hashes)
					undone_transactions.erase(tid);
				if (m_config.paranoid_checks)
					debug_check_transaction_invariants(raw_block, block, info, base_transaction_hash);
			}
		}
	} catch (const ConsensusError &) {
		// The only exception which is safe here
		on_reorganization(undone_transactions, undone_blocks);
		return false;
	}
	on_reorganization(undone_transactions, undone_blocks);
	return true;
}

Hash BlockChain::get_common_block(
    const Hash &bid1, const Hash &bid2, std::vector<Hash> *chain1, std::vector<Hash> *chain2) const {
	Hash hid1            = bid1;
	Hash hid2            = bid2;
	api::BlockHeader ha1 = read_header(hid1);
	api::BlockHeader ha2 = read_header(hid2);
	if (chain1)
		chain1->clear();
	if (chain2)
		chain2->clear();
	while (ha1.height > ha2.height) {
		if (chain1)
			chain1->push_back(hid1);
		hid1 = ha1.previous_block_hash;
		ha1  = read_header(hid1);
	}
	while (ha2.height > ha1.height) {
		if (chain2)
			chain2->push_back(hid2);
		hid2 = ha2.previous_block_hash;
		ha2  = read_header(hid2);
	}
	while (hid1 != hid2) {
		if (chain1)
			chain1->push_back(hid1);
		hid1 = ha1.previous_block_hash;
		ha1  = read_header(hid1);

		if (chain2)
			chain2->push_back(hid2);
		hid2 = ha2.previous_block_hash;
		ha2  = read_header(hid2);
	}
	return hid1;
}

std::vector<Hash> BlockChain::get_sparse_chain(Height max_jump) const {
	std::vector<Hash> result;
	auto tip_path = get_sparse_chain(m_genesis_bid, m_tip_bid, max_jump);
	for (const auto &el : tip_path)
		result.push_back(el.hash);
	return result;
}

std::vector<HardCheckpoint> BlockChain::get_sparse_chain(Hash start, Hash end, Height max_jump) const {
	std::vector<HardCheckpoint> tip_path;

	api::BlockHeader header_end;
	if (!get_header(end, &header_end) || !in_chain(header_end.height, header_end.hash))
		return tip_path;
	api::BlockHeader header_start;
	if (!get_header(start, &header_start) || !in_chain(header_start.height, header_start.hash))
		return tip_path;
	Height jump  = 1;
	Height delta = 0;
	while (header_end.height >= delta + header_start.height) {
		tip_path.push_back(HardCheckpoint{header_end.height - delta, read_chain(header_end.height - delta)});
		if (tip_path.size() >= 10) {
			jump *= 2;
			if (tip_path.back().height > m_currency.last_hard_checkpoint().height && jump > max_jump)
				jump = max_jump;  // no big jumps above last hard checkpoint
		}
		delta += jump;
	}
	if (tip_path.back().hash != start)
		tip_path.push_back(HardCheckpoint{header_start.height, header_start.hash});
	return tip_path;
}

Height BlockChain::get_timestamp_lower_bound_height(Timestamp ts) const {
	auto middle    = common::write_varint_sqlite4(ts);
	DB::Cursor cur = m_db.begin(TIMESTAMP_BLOCK_PREFIX, middle);
	if (cur.end())
		return m_tip_height;
	const char *be = cur.get_suffix().data();
	const char *en = be + cur.get_suffix().size();
	common::read_varint_sqlite4(be, en);  // We ignore result, auto actual_ts =
	return common::integer_cast<Height>(common::read_varint_sqlite4(be, en));
}

std::vector<Hash> BlockChain::get_sync_headers_chain(
    const std::vector<Hash> &locator, Height *start_height, size_t max_count) const {
	std::vector<Hash> result;
	for (auto &&lit : locator) {
		api::BlockHeader header;
		if (!get_header(lit, &header))
			continue;
		while (header.height != 0) {
			Hash ha;
			if (get_chain(header.height, &ha) && ha == header.hash)
				break;
			header = read_header(header.previous_block_hash);
		}
		Height min_height = header.height;
		*start_height     = min_height;
		for (; result.size() < max_count && min_height <= m_tip_height; min_height += 1) {
			result.push_back(read_chain(min_height));
		}
		return result;
	}
	throw std::runtime_error("No common block found in get_sync_headers_chain");
}

struct APITransactionPos {
	Height height = 0;
	size_t offset = 0;
	size_t size   = 0;
	size_t index  = 0;
};

namespace seria {
void ser_members(APITransactionPos &v, ISeria &s) {
	seria_kv("height", v.height, s);
	seria_kv("offset", v.offset, s);
	seria_kv("size", v.size, s);
	seria_kv("index", v.index, s);
}
}  // namespace seria

bool BlockChain::has_transaction(const Hash &tid) const {
	DB::Value value;
	auto txkey = TRANSACTION_PREFIX + DB::to_binary_key(tid.data, sizeof(tid.data));
	return m_db.get(txkey, value);
}

bool BlockChain::get_transaction(
    const Hash &tid, BinaryArray *binary_tx, Height *block_height, Hash *block_hash, size_t *index_in_block) const {
	auto txkey = TRANSACTION_PREFIX + DB::to_binary_key(tid.data, sizeof(tid.data));
	BinaryArray ba;
	if (!m_db.get(txkey, ba))
		return false;
	APITransactionPos tpos;
	seria::from_binary(tpos, ba);
	Hash bid = read_chain(tpos.height);
	DB::Value block_val;
	auto key = BLOCK_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + BLOCK_SUFFIX;
	invariant(m_db.get(key, block_val), "block must be there if transaction is there");
	invariant(tpos.offset + tpos.size <= block_val.size(), "Transaction offset corrupted");
	*block_hash     = bid;
	*block_height   = tpos.height;
	*index_in_block = tpos.index;
	binary_tx->assign(block_val.data() + tpos.offset, block_val.data() + tpos.offset + tpos.size);
	return true;
}

void BlockChain::redo_block(const Hash &bhash, const BinaryArray &block_data, const RawBlock &raw_block,
    const Block &block, const api::BlockHeader &info, const Hash &base_transaction_hash) {
	redo_block(bhash, block, info);
	auto tikey = TIMESTAMP_BLOCK_PREFIX + common::write_varint_sqlite4(info.timestamp) +
	             common::write_varint_sqlite4(info.height);
	m_db.put(tikey, std::string(), true);

	APITransactionPos tpos;
	tpos.height = info.height;
	auto bkey  = TRANSACTION_PREFIX + DB::to_binary_key(base_transaction_hash.data, sizeof(base_transaction_hash.data));
	tpos.index = 0;
	BinaryArray coinbase_ba = seria::to_binary(block.header.base_transaction);
	auto ptr                = common::slow_memmem(block_data.data() + tpos.offset + tpos.size,
        block_data.size() - tpos.offset - tpos.size, coinbase_ba.data(), coinbase_ba.size());
	invariant(ptr, "binary coinbase tx not found in binary block");
	tpos.offset = ptr - block_data.data();
	tpos.size   = coinbase_ba.size();
	m_db.put(bkey, seria::to_binary(tpos), true);
	for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
		Hash tid              = block.header.transaction_hashes.at(tx_index);
		tpos.index            = tx_index + 1;
		bkey                  = TRANSACTION_PREFIX + DB::to_binary_key(tid.data, sizeof(tid.data));
		const auto &binary_tx = raw_block.transactions.at(tx_index);
		ptr                   = common::slow_memmem(block_data.data() + tpos.offset + tpos.size,
            block_data.size() - tpos.offset - tpos.size, binary_tx.data(), binary_tx.size());
		invariant(ptr, "binary tx not found in binary block");
		tpos.offset = ptr - block_data.data();
		tpos.size   = binary_tx.size();
		m_db.put(bkey, seria::to_binary(tpos), true);
	}
}
void BlockChain::undo_block(const Hash &bhash, const RawBlock &, const Block &block, Height height) {
	//	if (!m_tip_segment.empty())
	//		m_tip_segment.pop_back();
	undo_block(bhash, block, height);

	auto tikey = TIMESTAMP_BLOCK_PREFIX + common::write_varint_sqlite4(block.header.timestamp) +
	             common::write_varint_sqlite4(height);
	m_db.del(tikey, true);

	Hash tid  = get_transaction_hash(block.header.base_transaction);
	auto bkey = TRANSACTION_PREFIX + DB::to_binary_key(tid.data, sizeof(tid.data));
	m_db.del(bkey, true);
	for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
		tid  = block.header.transaction_hashes.at(tx_index);
		bkey = TRANSACTION_PREFIX + DB::to_binary_key(tid.data, sizeof(tid.data));
		m_db.del(bkey, true);
	}
}

void BlockChain::store_block(const Hash &bid, const BinaryArray &block_data) {
	auto key = BLOCK_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + BLOCK_SUFFIX;
	m_db.put(key, block_data, true);
}

bool BlockChain::get_block(const Hash &bid, BinaryArray *block_data, RawBlock *raw_block) const {
	BinaryArray rb;
	auto key = BLOCK_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + BLOCK_SUFFIX;
	if (!m_db.get(key, rb))
		return false;
	if (raw_block)
		seria::from_binary(*raw_block, rb);
	if (block_data)
		*block_data = std::move(rb);
	return true;
}

bool BlockChain::get_block(const Hash &bid, RawBlock *raw_block) const { return get_block(bid, nullptr, raw_block); }

bool BlockChain::has_block(const Hash &bid) const {
	platform::DB::Value ms;
	auto key = BLOCK_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + BLOCK_SUFFIX;
	if (!m_db.get(key, ms))
		return false;
	return true;
}

void BlockChain::store_header(const Hash &bid, const api::BlockHeader &header) {
	auto key       = HEADER_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + HEADER_SUFFIX;
	BinaryArray ba = seria::to_binary(header);
	m_db.put(key, ba, true);
}

const api::BlockHeader *BlockChain::read_header_fast(const Hash &bid, Height hint) const {
	if (get_tip_height() != Height(-1) && hint <= get_tip_height() &&
	    hint >= get_tip_height() - m_header_tip_window.size() + 1) {
		const auto &candidate = m_header_tip_window.at(m_header_tip_window.size() - 1 - (get_tip_height() - hint));
		if (candidate.hash == bid) {
			return &candidate;  // fastest lookup is in tip window
		}
	}
	auto cit = m_header_cache.find(bid);
	if (cit != m_header_cache.end()) {
		return &cit->second;
	}
	Hash bbid = bid;  // next lines can modify bid, because it can be reference to header inside cache
	if (m_header_cache.size() > m_currency.largest_window() * 20) {
		m_log(logging::TRACE) << "BlockChain header cache reached max size and cleared";
		m_header_cache.clear();  // very simple policy
	}
	BinaryArray rb;
	auto key = HEADER_PREFIX + DB::to_binary_key(bbid.data, sizeof(bbid.data)) + HEADER_SUFFIX;
	if (!m_db.get(key, rb))
		return nullptr;
	api::BlockHeader header;
	seria::from_binary(header, rb);
	cit = m_header_cache.insert(std::make_pair(bbid, std::move(header))).first;
	return &cit->second;
}

bool BlockChain::get_header(const Hash &bid, api::BlockHeader *header, Height hint) const {
	const api::BlockHeader *result = read_header_fast(bid, hint);
	if (result)
		*header = *result;
	return result != nullptr;
}

bool BlockChain::get_header_data(const Hash &bid, BinaryArray *block_data, Height hint) const {
	auto key = HEADER_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + HEADER_SUFFIX;
	return m_db.get(key, *block_data);
}

api::BlockHeader BlockChain::read_header(const Hash &bid, Height hint) const {
	api::BlockHeader result;
	invariant(get_header(bid, &result, hint), "Expected header was not found" + common::pod_to_hex(bid));
	return result;
}

const api::BlockHeader &BlockChain::get_tip() const {
	invariant(!m_header_tip_window.empty() && m_tip_bid == m_header_tip_window.back().hash, "tip window corrupted");
	return m_header_tip_window.back();
}

void BlockChain::for_each_reversed_tip_segment(const api::BlockHeader &prev_info, Height window, bool add_genesis,
    std::function<void(const api::BlockHeader &header)> &&fun) const {
	if (prev_info.height == Height(-1))
		return;
	const api::BlockHeader *header = &prev_info;
	size_t count                   = 0;
	while (count < window && header->height != 0) {
		fun(*header);
		count += 1;
		header = read_header_fast(header->previous_block_hash, header->height - 1);
		invariant(header, "");
	}
	if (count < window && add_genesis) {
		invariant(
		    header->height == 0, "Invariant dead - window size not reached, but genesis not found in get_tip_segment");
		fun(*header);
		count += 1;
	}
}

// std::vector<api::BlockHeader> BlockChain::get_tip_segment(
//    const api::BlockHeader &prev_info, Height window, bool add_genesis) const {
//	std::vector<api::BlockHeader> result;
//	result.reserve(window);
//	for_each_reversed_tip_segment(
//	    prev_info, window, add_genesis, [&](const api::BlockHeader &header) { result.push_back(header); });
//	std::reverse(result.begin(), result.end());
//	return result;
//}

void BlockChain::push_chain(const api::BlockHeader &header) {
	m_tip_height += 1;
	BinaryArray ba = seria::to_binary(header.hash);
	m_db.put(TIP_CHAIN_PREFIX + common::write_varint_sqlite4(m_tip_height), ba, true);
	m_tip_bid                   = header.hash;
	m_tip_cumulative_difficulty = header.cumulative_difficulty;
	m_header_tip_window.push_back(header);
	while (m_header_tip_window.size() > m_currency.largest_window() * 2)
		m_header_tip_window.pop_front();
	tip_changed();
}

void BlockChain::pop_chain(const Hash &new_tip_bid) {
	invariant(m_tip_height != 0 && !m_header_tip_window.empty(), "pop_chain tip_height == 0");
	m_header_tip_window.pop_back();
	m_db.del(TIP_CHAIN_PREFIX + common::write_varint_sqlite4(m_tip_height), true);
	m_tip_height -= 1;
	m_tip_bid = new_tip_bid;
	invariant(read_chain(m_tip_height) == m_tip_bid,
	    "After undo tip does not match get_chain " + common::pod_to_hex(m_tip_bid));
	if (m_header_tip_window.empty()) {
		api::BlockHeader tip_header = read_header(m_tip_bid);
		m_header_tip_window.push_back(tip_header);
	}
	m_tip_cumulative_difficulty = get_tip().cumulative_difficulty;
}

// After upgrading to future versions, remove version from index key
bool BlockChain::get_chain(Height height, Hash *bid) const {
	BinaryArray ba;
	if (!m_db.get(TIP_CHAIN_PREFIX + common::write_varint_sqlite4(height), ba))
		return false;
	seria::from_binary(*bid, ba);
	return true;
}

bool BlockChain::in_chain(Height height, Hash bid) const {
	Hash ha;
	return get_chain(height, &ha) && ha == bid;
}
bool BlockChain::in_chain(Hash bid) const {
	auto header = read_header_fast(bid, 0);
	return header ? in_chain(header->height, bid) : false;
}

Hash BlockChain::read_chain(Height height) const {
	Hash ha;
	invariant(get_chain(height, &ha), "read_header_chain failed");
	return ha;
}

void BlockChain::check_children_counter(CumulativeDifficulty cd, const Hash &bid, int value) {
	auto key    = CHILDREN_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data));
	auto cd_key = CD_TIPS_PREFIX + common::write_varint_sqlite4(cd.hi) + common::write_varint_sqlite4(cd.lo) +
	              DB::to_binary_key(bid.data, sizeof(bid.data));
	int counter = 1;  // default is 1 when not stored in db
	BinaryArray rb;
	if (m_db.get(key, rb))
		seria::from_binary(counter, rb);
	invariant(counter == value, "check_children_counter index corrupted");
	invariant(counter != 0 || m_db.get(cd_key, rb), "check_children_counter tip is not in index");
	invariant(counter == 0 || !m_db.get(cd_key, rb), "check_children_counter non-tip is in index");
}

void BlockChain::modify_children_counter(CumulativeDifficulty cd, const Hash &bid, int delta) {
	auto key    = CHILDREN_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data));
	auto cd_key = CD_TIPS_PREFIX + common::write_varint_sqlite4(cd.hi) + common::write_varint_sqlite4(cd.lo) +
	              DB::to_binary_key(bid.data, sizeof(bid.data));
	size_t counter = 1;  // default is 1 when not stored in db
	BinaryArray rb;
	if (m_db.get(key, rb))
		seria::from_binary(counter, rb);
	counter += delta;
	if (counter == 1) {
		m_db.del(key, false);
	} else {
		BinaryArray ba = seria::to_binary(counter);
		m_db.put(key, ba, false);
	}
	if (counter == 0) {
		m_db.put(cd_key, std::string(), false);
	} else {
		m_db.del(cd_key, false);
	}
}

bool BlockChain::get_oldest_tip(CumulativeDifficulty *cd, Hash *bid) const {
	DB::Cursor cur = m_db.begin(CD_TIPS_PREFIX);
	if (cur.end())
		return false;
	const std::string &suf = cur.get_suffix();
	const char *be         = suf.data();
	const char *en         = be + suf.size();
	cd->hi                 = common::read_varint_sqlite4(be, en);
	cd->lo                 = common::read_varint_sqlite4(be, en);
	invariant(en - be == sizeof(bid->data), "CD_TIPS_PREFIX corrupted");
	DB::from_binary_key(cur.get_suffix(), cur.get_suffix().size() - sizeof(bid->data), bid->data, sizeof(bid->data));
	return true;
}

void BlockChain::for_each_tip(std::function<bool(CumulativeDifficulty cd, Hash bid)> &&fun) const {
	for (DB::Cursor cur = m_db.rbegin(CD_TIPS_PREFIX); !cur.end(); cur.next()) {
		const std::string &suf = cur.get_suffix();
		const char *be         = suf.data();
		const char *en         = be + suf.size();
		CumulativeDifficulty cd;
		cd.hi = common::read_varint_sqlite4(be, en);
		cd.lo = common::read_varint_sqlite4(be, en);
		Hash tip_bid;
		invariant(en - be == sizeof(tip_bid.data), "CD_TIPS_PREFIX corrupted");
		DB::from_binary_key(
		    cur.get_suffix(), cur.get_suffix().size() - sizeof(tip_bid.data), tip_bid.data, sizeof(tip_bid.data));
		if (!fun(cd, tip_bid))
			break;
	}
}

bool BlockChain::prune_branch(CumulativeDifficulty cd, Hash bid) {
	if (bid == m_tip_bid)
		return false;
	check_children_counter(cd, bid, 0);
	auto checkpoints = get_stable_checkpoints();
	for (auto cit = checkpoints.begin(); cit != checkpoints.end(); ++cit)
		if (cit->is_enabled() && cit->hash == bid)
			return false;
	auto bit = m_blods.find(bid);
	if (bit != m_blods.end()) {
		if (!bit->second.children.empty())
			return false;
		if (bit->second.parent) {
			auto rit =
			    std::remove(bit->second.parent->children.begin(), bit->second.parent->children.end(), &bit->second);
			invariant(rit != bit->second.parent->children.end(), "");
			bit->second.parent->children.erase(rit, bit->second.parent->children.end());
		}
		m_blods.erase(bit);
	}
	api::BlockHeader me = read_header(bid);
	modify_children_counter(cd, bid, 1);
	if (bid != m_genesis_bid) {
		api::BlockHeader pa = read_header(me.previous_block_hash);
		modify_children_counter(pa.cumulative_difficulty, me.previous_block_hash, -1);
	}
	auto key = BLOCK_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + BLOCK_SUFFIX;
	m_db.del(key, true);
	auto key2 = HEADER_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + HEADER_SUFFIX;
	m_db.del(key2, true);
	//	m_header_tip_window.clear();
	//	api::BlockHeader tip_header = read_header(m_tip_bid);
	//	m_header_tip_window.push_back(tip_header);
	m_header_cache.erase(bid);
	return true;
}

bool BlockChain::test_prune_oldest() {
	CumulativeDifficulty cd{};
	Hash bid;
	invariant(get_oldest_tip(&cd, &bid), "");
	return prune_branch(cd, bid);
}

void BlockChain::test_print_tips() const {
	CumulativeDifficulty ocd;
	Hash obid;
	if (get_oldest_tip(&ocd, &obid))
		std::cout << "oldest tip cd=" << ocd << " bid=" << obid << std::endl;
	std::cout << "---- BlockTree structure ----" << std::endl;
	for (DB::Cursor cur = m_db.begin(CHILDREN_PREFIX); !cur.end(); cur.next()) {
		Hash bid;
		DB::from_binary_key(cur.get_suffix(), 0, bid.data, sizeof(bid.data));
		size_t counter = 1;
		seria::from_binary(counter, cur.get_value_array());
		api::BlockHeader info = read_header(bid);
		std::cout << "branch height=" << info.height << " bid=" << bid << " children=" << counter << std::endl;
	}
	for_each_tip([&](CumulativeDifficulty cd, Hash bid) -> bool {
		api::BlockHeader info = read_header(bid);
		std::cout << "tip height=" << info.height << " bid=" << bid << " CD=" << cd << std::endl;
		return true;
	});
}

void BlockChain::test_print_structure(Height n_confirmations) const {
	CumulativeDifficulty ocd;
	Hash obid;
	if (get_oldest_tip(&ocd, &obid))
		std::cout << "oldest tip cd=" << ocd << " bid=" << obid << std::endl;
	std::cout << "---- BlockTree structure + additional info ----" << std::endl;
	for (DB::Cursor cur = m_db.begin(CHILDREN_PREFIX); !cur.end(); cur.next()) {
		Hash bid;
		DB::from_binary_key(cur.get_suffix(), 0, bid.data, sizeof(bid.data));
		size_t counter = 1;
		seria::from_binary(counter, cur.get_value_array());

		std::cout << "children=" << counter << " bid=" << bid << std::endl;
	}
	size_t total_forked_transactions      = 0;
	size_t total_possible_ds_transactions = 0;
	Amount total_possible_ds_amount       = 0;
	size_t total_forked_blocks            = 0;
	size_t total_forked_blocks_not_found  = 0;
	std::cout << "---- All side chains ----" << std::endl;
	for_each_tip([&](CumulativeDifficulty cd, Hash bid) -> bool {
		Height t_height = Height(-1);
		while (true) {
			api::BlockHeader header = read_header(bid);
			if (t_height == Height(-1))
				t_height = header.height;
			if (in_chain(header.height, header.hash))
				break;  // Reached main trunk
			const bool confirmed = t_height >= header.height + n_confirmations;
			std::cout << "    sideblock height=" << header.height << " depth=" << t_height - header.height
			          << (confirmed ? " (confirmed)" : "") << " bid=" << bid << std::endl;
			RawBlock rb;
			if (confirmed) {
				total_forked_blocks += 1;
				if (get_block(bid, &rb)) {
					Block block(rb);
					for (size_t tx_pos = 0; tx_pos != block.header.transaction_hashes.size(); ++tx_pos) {
						Hash tid = block.header.transaction_hashes.at(tx_pos);
						total_forked_transactions += 1;
						BinaryArray binary_tx;
						Height height = 0;
						Hash block_hash;
						size_t index_in_block = 0;
						if (!get_transaction(tid, &binary_tx, &height, &block_hash, &index_in_block)) {
							Amount input_amount = 0;
							for (const auto &input : block.transactions.at(tx_pos).inputs)
								if (input.type() == typeid(InputKey)) {
									const InputKey &in = boost::get<InputKey>(input);
									input_amount += in.amount;
								}
							total_possible_ds_transactions += 1;
							total_possible_ds_amount += input_amount;
							std::cout << "        Potential ds tx amount=" << input_amount << " tid=" << tid
							          << std::endl;
						}
					}
				} else
					total_forked_blocks_not_found += 1;
			}
			bid = header.previous_block_hash;
		}
		return true;
	});
	//	std::cout << "n_confirmations=" << n_confirmations << std::endl;
	std::cout << "---- Side chains stats for n_confirmations=" << n_confirmations << "----" << std::endl;
	std::cout << "total forked blocks=" << total_forked_blocks << ", not found " << total_forked_blocks_not_found
	          << std::endl;
	std::cout << "total forked transactions=" << total_forked_transactions << ", possible ds "
	          << total_possible_ds_transactions << " total amount=" << total_possible_ds_amount << std::endl;
}

void BlockChain::start_internal_import() {
	m_log(logging::INFO) << "Blockchain database has old format, preparing for internal block import...";
	if (m_internal_import_chain.empty()) {
		const std::vector<std::string> former_prefixes{
		    TIP_CHAIN_PREFIX + "B/", TIP_CHAIN_PREFIX + "1/", TIP_CHAIN_PREFIX + "/", TIP_CHAIN_PREFIX};
		for (auto &&prefix : former_prefixes) {
			std::vector<Hash> main_chain;
			for (Height ha = 0;; ha += 1) {
				BinaryArray ba;
				if (!m_db.get(prefix + common::write_varint_sqlite4(ha), ba))
					break;
				Hash bid;
				seria::from_binary(bid, ba);
				main_chain.push_back(bid);
			}
			if (main_chain.size() > m_internal_import_chain.size())
				m_internal_import_chain = main_chain;
		}
	}
	// we could wish to advance version on half-imported chain
	std::set<Hash> main_chain_bids{m_internal_import_chain.begin(), m_internal_import_chain.end()};
	m_log(logging::INFO) << "Found " << m_internal_import_chain.size() << " blocks from main chain";
	size_t erased = 0, skipped = 0;
	const size_t total_items          = m_db.get_approximate_items_count();
	const std::string total_items_str = (total_items == std::numeric_limits<size_t>::max())
	                                        ? "unknown"
	                                        : common::to_string((total_items + 999999) / 1000000);
	for (DB::Cursor cur = m_db.rbegin(std::string()); !cur.end();) {
		if ((erased + skipped) % 1000000 == 0)
			m_log(logging::INFO) << "Processing " << (erased + skipped) / 1000000 << "/" << total_items_str
			                     << " million DB records";
		if (cur.get_suffix().find(BLOCK_PREFIX) == 0 &&
		    cur.get_suffix().substr(cur.get_suffix().size() - BLOCK_SUFFIX.size()) == BLOCK_SUFFIX) {
			Hash bid;
			DB::from_binary_key(cur.get_suffix(), BLOCK_PREFIX.size(), bid.data, sizeof(bid.data));
			if (main_chain_bids.count(bid) != 0) {
				cur.next();
				skipped += 1;
				continue;  // block in main chain
			}
			BinaryArray block_data;
			if (get_block(bid, &block_data, nullptr))
				m_archive.add(Archive::BLOCK, block_data, bid, "start_internal_import");
		}
		cur.erase();
		erased += 1;
	}
	m_db.put("internal_import_chain", seria::to_binary(m_internal_import_chain), true);  // we've just erased it :)
	m_log(logging::INFO) << "Deleted " << erased << " records, skipped " << skipped << " records";
}

bool BlockChain::internal_import() {
	auto idea_start = std::chrono::high_resolution_clock::now();
	try {
		while (true) {
			if (get_tip_height() + 1 >= m_internal_import_chain.size())
				break;
			const Hash bid = m_internal_import_chain.at(get_tip_height() + 1);
			RawBlock rb;
			if (!get_block(bid, &rb)) {
				m_log(logging::WARNING) << "Block not found during internal import for height=" << get_tip_height() + 1
				                        << " bid=" << bid;
				break;
			}
			PreparedBlock pb(std::move(rb), m_currency, nullptr);
			api::BlockHeader info;
			if (!add_block(pb, &info, false, "internal_import")) {
				m_log(logging::WARNING) << "Block corrupted during internal import for height=" << get_tip_height() + 1
				                        << " bid=" << bid;
				break;
			}
			//		if (get_tip_height() % m_config.db_commit_every_n_blocks == 0)
			//			db_commit();
			auto idea_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			    std::chrono::high_resolution_clock::now() - idea_start);
			if (idea_ms.count() > 200)
				return true;  // import in chunks of 0.2 seconds
		}
	} catch (const std::exception &ex) {
		m_log(logging::WARNING) << "Block corrupted during internal import for height=" << get_tip_height() + 1
		                        << " exception=" << common::what(ex);
	}
	m_log(logging::INFO) << "Finished internal importing of blocks, will continue downloading...";
	m_internal_import_chain.clear();
	m_db.del("internal_import_chain", true);
	db_commit();
	return false;
}

void BlockChain::test_undo_everything(Height new_tip_height) {
	for (DB::Cursor cur = m_db.begin(CHECKPOINT_PREFIX_STABLE); !cur.end(); cur.erase()) {
	}
	for (DB::Cursor cur = m_db.begin(CHECKPOINT_PREFIX_LATEST); !cur.end(); cur.erase()) {
	}
	test_print_tips();
	while (test_prune_oldest()) {  // prunning side branches
	}
	test_print_tips();

	while (true) {
		RawBlock raw_block;
		invariant(get_block(get_tip_bid(), &raw_block), "");
		Block block(raw_block);
		undo_block(get_tip_bid(), raw_block, block, m_tip_height);
		if (get_tip_bid() == m_genesis_bid)
			break;
		pop_chain(block.header.previous_block_hash);
		tip_changed();
		while (test_prune_oldest()) {  // prunning main branch
		}
		if (get_tip_height() % m_config.db_commit_every_n_blocks == 0)
			db_commit();
	}
	invariant(m_header_tip_window.size() == 1 && m_tip_height == 0, "");
	m_header_tip_window.clear();
	m_db.del(TIP_CHAIN_PREFIX + common::write_varint_sqlite4(m_tip_height), true);
	m_tip_height -= 1;
	m_tip_bid                   = Hash{};
	m_tip_cumulative_difficulty = 0;
	test_prune_oldest();  // no while, after pruning genesis, invariant will fail
	m_db.del("$version", true);
	std::cout << "---- After undo everything ---- " << std::endl;
	int counter = 0;
	for (DB::Cursor cur = m_db.begin(std::string()); !cur.end(); cur.next()) {
		std::cout << DB::clean_key(cur.get_suffix()) << std::endl;
		if (counter++ > 1000)  // In case of incomplete undo, prevent too much output
			break;
	}
	invariant(counter == 0, "Undo unsuccessfull");
}

std::vector<SignedCheckpoint> BlockChain::get_latest_checkpoints() const {
	std::vector<SignedCheckpoint> result;
	for (DB::Cursor cur = m_db.begin(CHECKPOINT_PREFIX_LATEST); !cur.end(); cur.next()) {
		result.push_back(SignedCheckpoint{});
		seria::from_binary(result.back(), cur.get_value_array());
	}
	return result;
}

std::vector<SignedCheckpoint> BlockChain::get_stable_checkpoints() const {
	std::vector<SignedCheckpoint> result;
	for (DB::Cursor cur = m_db.begin(CHECKPOINT_PREFIX_STABLE); !cur.end(); cur.next()) {
		result.push_back(SignedCheckpoint{});
		seria::from_binary(result.back(), cur.get_value_array());
	}
	return result;
}

bool BlockChain::add_checkpoint(const SignedCheckpoint &checkpoint, const std::string &source_address) {
	if (checkpoint.height <= m_currency.last_hard_checkpoint().height && checkpoint.is_enabled())
		return false;  // Height is ignored when disabling key_id
	PublicKey public_key =
	    m_currency.get_checkpoint_public_key(checkpoint.key_id);  // returns empty key if out of range
	auto key_latest               = CHECKPOINT_PREFIX_LATEST + common::write_varint_sqlite4(checkpoint.key_id);
	auto key_stable               = CHECKPOINT_PREFIX_STABLE + common::write_varint_sqlite4(checkpoint.key_id);
	BinaryArray binary_checkpoint = seria::to_binary(checkpoint);
	BinaryArray ba;
	if (m_db.get(key_latest, ba)) {
		SignedCheckpoint previous_checkpoint;
		seria::from_binary(previous_checkpoint, ba);
		if (checkpoint.counter < previous_checkpoint.counter)
			return false;
		if (checkpoint.counter == previous_checkpoint.counter) {
			if (checkpoint.hash == previous_checkpoint.hash && checkpoint.height == previous_checkpoint.height &&
			    checkpoint.key_id == previous_checkpoint.key_id &&
			    checkpoint.signature == previous_checkpoint.signature) {
				m_archive.add(Archive::CHECKPOINT, binary_checkpoint,
				    crypto::cn_fast_hash(binary_checkpoint.data(), binary_checkpoint.size()), source_address);
			}
			return false;
		}
	}
	if (!crypto::check_signature(checkpoint.get_message_hash(), public_key, checkpoint.signature))
		return false;
	m_db.put(key_latest, binary_checkpoint, false);
	m_archive.add(Archive::CHECKPOINT, binary_checkpoint,
	    crypto::cn_fast_hash(binary_checkpoint.data(), binary_checkpoint.size()), source_address);
	if (checkpoint.is_enabled()) {
		auto bit = m_blods.find(checkpoint.hash);
		if (bit == m_blods.end())
			return true;  // orphan checkpoint
	}
	m_db.put(key_stable, binary_checkpoint, false);
	update_key_count_max_heights();
	auto tip_check_cd = get_checkpoint_difficulty(get_tip_bid());
	for_each_tip([&](CumulativeDifficulty cd, Hash bid) -> bool {
		auto bid_check_cd = get_checkpoint_difficulty(bid);
		if (compare(bid_check_cd, cd, false, tip_check_cd, get_tip_cumulative_difficulty()) <= 0)
			return true;
		api::BlockHeader header = read_header(bid);
		RawBlock raw_block;
		if (!get_block(bid, &raw_block))
			return true;
		PreparedBlock pb(std::move(raw_block), m_currency, nullptr);
		reorganize_blocks(bid, pb, header);
		tip_check_cd = get_checkpoint_difficulty(get_tip_bid());
		return true;
	});
	return true;
}

int BlockChain::compare(const CheckpointDifficulty &a, CumulativeDifficulty ca, bool a_just_mined,
    const CheckpointDifficulty &b, CumulativeDifficulty cb) {
	for (size_t i = a.size(); i-- > 0;)
		if (a.at(i) != b.at(i))
			return int(a.at(i)) - int(b.at(i));
	if (ca < cb)
		return -1;
	if (ca > cb)
		return 1;
	if (a_just_mined)
		return 1;
	return 0;
}

bool BlockChain::add_blod_impl(const api::BlockHeader &header) {
	auto bit = m_blods.find(header.hash);
	if (bit != m_blods.end())
		return true;  // Strange, but nop
	bit = m_blods.find(header.previous_block_hash);
	if (bit == m_blods.end())
		return false;
	Blod &blod  = m_blods[header.hash];
	blod.height = header.height;
	blod.hash   = header.hash;
	blod.parent = &bit->second;
	bit->second.children.push_back(&blod);
	blod.checkpoint_difficulty = blod.parent->checkpoint_difficulty;

	if (m_currency.wish_to_upgrade()) {
		blod.vote_for_upgrade       = uint8_t(m_currency.is_upgrade_vote(header.major_version, header.minor_version));
		blod.upgrade_decided_height = blod.parent->upgrade_decided_height;
		if (!blod.upgrade_decided_height) {
			blod.votes_for_upgrade_in_voting_window = blod.parent->votes_for_upgrade_in_voting_window;
			blod.votes_for_upgrade_in_voting_window.push_back(blod.vote_for_upgrade);
			if (blod.votes_for_upgrade_in_voting_window.size() > m_currency.upgrade_voting_window)
				blod.votes_for_upgrade_in_voting_window.pop_front();
			invariant(blod.votes_for_upgrade_in_voting_window.size() <= m_currency.upgrade_voting_window, "");
			size_t count = std::count(blod.votes_for_upgrade_in_voting_window.begin(),
			    blod.votes_for_upgrade_in_voting_window.end(), uint8_t(1));
			if (count >= m_currency.upgrade_votes_required()) {
				blod.upgrade_decided_height = blod.height + m_currency.upgrade_window;
				m_log(logging::INFO) << logging::Green << "Consensus upgrade votes gathered on height=" << header.height
				                     << " upgrade_decided_height=" << blod.upgrade_decided_height
				                     << " bid=" << header.hash;
				blod.votes_for_upgrade_in_voting_window.clear();
			}
		}
	}
	return true;
}

bool BlockChain::add_blod(const api::BlockHeader &header) {
	if (m_blods.empty())  // Allow any blocks if main does not pass through last sw checkpoint yet
		return true;
	add_blod_impl(header);
	// We inherit from parent and rebuild only if we pass through one of checlpoints
	for (auto &&ch : get_latest_checkpoints())
		if (ch.is_enabled() && header.hash == ch.hash) {  // disabled are made stable in add_checkpoint
			auto key_stable = CHECKPOINT_PREFIX_STABLE + common::write_varint_sqlite4(ch.key_id);
			m_db.put(key_stable, seria::to_binary(ch), false);
		}
	for (auto &&ch : get_stable_checkpoints())
		if (ch.is_enabled() && header.hash == ch.hash) {
			update_key_count_max_heights();
			return true;
		}
	return true;
}

void BlockChain::build_blods() {
	if (!m_blods.empty())
		return;  // build only once per daemon launch
	api::BlockHeader last_hard_checkpoint_header;
	if (!get_header(m_currency.last_hard_checkpoint().hash, &last_hard_checkpoint_header))
		return;
	invariant(last_hard_checkpoint_header.hash == m_currency.genesis_block_hash ||
	              last_hard_checkpoint_header.major_version == 1 + m_currency.upgrade_heights.size(),
	    "When adding checkpoint after consensus update, always update currency.upgrade_heights");

	std::set<Hash> bad_header_hashes;   // sidechains that do not pass through last hard checkpoint
	std::set<Hash> good_header_hashes;  // sidechains that pass through last hard checkpoint
	std::vector<api::BlockHeader> good_headers;
	for_each_tip([&](CumulativeDifficulty cd, Hash tip_bid) -> bool {
		std::vector<api::BlockHeader> side_chain;
		api::BlockHeader header = read_header(tip_bid);
		while (true) {
			if (good_header_hashes.count(header.hash) != 0) {
				std::reverse(side_chain.begin(), side_chain.end());
				for (auto &&ha : side_chain) {
					good_header_hashes.insert(ha.hash);
					good_headers.push_back(ha);
				}
				break;
			}
			if (bad_header_hashes.count(header.hash) != 0) {
				for (auto &&ha : side_chain)
					bad_header_hashes.insert(ha.hash);
				break;
			}
			if (header.height < m_currency.last_hard_checkpoint().height)
				break;
			side_chain.push_back(header);
			if (header.height == m_currency.last_hard_checkpoint().height) {
				if (header.hash == m_currency.last_hard_checkpoint().hash) {
					std::reverse(side_chain.begin(), side_chain.end());
					for (auto &&ha : side_chain) {
						good_header_hashes.insert(ha.hash);
						good_headers.push_back(ha);
					}
				} else {
					for (auto &&ha : side_chain)
						bad_header_hashes.insert(ha.hash);
				}
				break;
			}
			header = read_header(header.previous_block_hash);
		}
		return true;
	});
	for (auto &&ha : good_headers) {  // They are conveniently sorted parent to child and can be applied sequentially
		if (!add_blod_impl(ha)) {
			invariant(ha.hash == m_currency.last_hard_checkpoint().hash, "");
			Blod &blod  = m_blods[ha.hash];
			blod.height = ha.height;
			blod.hash   = ha.hash;
			if (m_currency.wish_to_upgrade()) {
				blod.vote_for_upgrade = uint8_t(m_currency.is_upgrade_vote(ha.major_version, ha.minor_version));
				Height first_height =
				    m_currency.last_hard_checkpoint().height < m_currency.upgrade_voting_window - 1
				        ? 0
				        : m_currency.last_hard_checkpoint().height - (m_currency.upgrade_voting_window - 1);
				for (Height h = first_height; h != m_currency.last_hard_checkpoint().height; ++h) {
					auto header = read_header(read_chain(h), h);
					auto vote   = uint8_t(m_currency.is_upgrade_vote(header.major_version, header.minor_version));
					blod.votes_for_upgrade_in_voting_window.push_back(vote);
				}
				blod.votes_for_upgrade_in_voting_window.push_back(blod.vote_for_upgrade);
				//				size_t count = std::count(blod.votes_for_upgrade_in_voting_window.begin(),
				//				    blod.votes_for_upgrade_in_voting_window.end(), uint8_t(1));
			}
		}
	}
	update_key_count_max_heights();
}

void BlockChain::fill_statistics(api::cnd::GetStatistics::Response &res) const {
	res.checkpoints = get_latest_checkpoints();

	if (!m_currency.wish_to_upgrade())
		return;
	auto bit = m_blods.find(get_tip_bid());
	if (bit == m_blods.end())
		return;
	res.upgrade_decided_height     = bit->second.upgrade_decided_height;
	auto count                     = std::count(bit->second.votes_for_upgrade_in_voting_window.begin(),
        bit->second.votes_for_upgrade_in_voting_window.end(), uint8_t(1));
	res.upgrade_votes_in_top_block = static_cast<Height>(count);
}

bool BlockChain::fill_next_block_versions(
    const api::BlockHeader &prev_info, uint8_t *major_mm, uint8_t *major_cm) const {
	*major_cm = *major_mm = m_currency.get_block_major_version_for_height(prev_info.height + 1);
#if bytecoin_ALLOW_CM
	if (*major_cm >= m_currency.amethyst_block_version)
		*major_cm += 1;
#endif
	if (!m_currency.wish_to_upgrade())
		return true;
	if (m_blods.empty())
		return true;
	auto bit = m_blods.find(prev_info.hash);
	if (bit == m_blods.end())
		return false;
	if (!bit->second.upgrade_decided_height || prev_info.height + 1 < bit->second.upgrade_decided_height)
		return true;
	*major_cm = *major_mm = m_currency.upgrade_desired_major;
#if bytecoin_ALLOW_CM
	if (*major_cm >= m_currency.amethyst_block_version)
		*major_cm += 1;
#endif
	return true;
}

void BlockChain::update_key_count_max_heights() {
	// We use simplest O(n) algo, will optimize later and use this one as a reference
	for (auto &&bit : m_blods) {
		bit.second.checkpoint_key_ids.reset();
		bit.second.checkpoint_difficulty = CheckpointDifficulty{};
	}
	auto checkpoints = get_stable_checkpoints();
	for (const auto &cit : checkpoints)
		if (cit.is_enabled()) {
			auto bit = m_blods.find(cit.hash);
			if (bit == m_blods.end())
				continue;
			for (Blod *b = &bit->second; b; b = b->parent)
				b->checkpoint_key_ids.set(cit.key_id);
		}
	std::vector<Blod *> to_visit;
	auto bit = m_blods.find(m_currency.last_hard_checkpoint().hash);
	if (bit != m_blods.end())
		to_visit.push_back(&bit->second);
	while (!to_visit.empty()) {
		Blod *blod = to_visit.back();
		to_visit.pop_back();
		size_t key_count = blod->checkpoint_key_ids.count();
		if (blod->parent)
			blod->checkpoint_difficulty = blod->parent->checkpoint_difficulty;
		if (key_count > 0)
			blod->checkpoint_difficulty.at(key_count - 1) = blod->height;
		to_visit.insert(to_visit.end(), blod->children.begin(), blod->children.end());
	}
}

BlockChain::CheckpointDifficulty BlockChain::get_checkpoint_difficulty(Hash hash) const {
	auto bit = m_blods.find(hash);
	if (bit == m_blods.end())
		return CheckpointDifficulty{};
	return bit->second.checkpoint_difficulty;
}
