// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "BlockChain.hpp"

#include <boost/lexical_cast.hpp>
#include <iostream>
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "Currency.hpp"
#include "DifficultyCheck.hpp"
#include "TransactionExtra.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "crypto/crypto.hpp"
#include "rpc_api.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace bytecoin;
using namespace platform;

const std::string BlockChain::version_current = "5";
// We increment when making incompatible changes to indices.

// We use suffixes so all keys related to the same block are close to each other in DB
static const std::string BLOCK_PREFIX             = "b";
static const std::string BLOCK_SUFFIX             = "b";
static const std::string HEADER_PREFIX            = "b";
static const std::string HEADER_SUFFIX            = "h";
static const std::string TRANSATION_PREFIX        = "t";
static const std::string TIP_CHAIN_PREFIX         = "c";
static const std::string TIMESTAMP_BLOCK_PREFIX   = "T";
static const std::string CHECKPOINT_PREFIX_STABLE = "CS";
static const std::string CHECKPOINT_PREFIX_LATEST = "CL";

static const std::string CHILDREN_PREFIX = "x-ch/";
static const std::string CD_TIPS_PREFIX  = "x-tips/";
// We store bid->children counter, with counter=1 default (absent from index)
// We store cumulative_difficulty->bid for bids with no children

static const size_t COMMIT_EVERY_N_BLOCKS = 50000;  // We do not want to create too large transactions

static const std::string delete_blockchain_message = "database corrupted, please delete ";

bool Block::from_raw_block(const RawBlock &raw_block) {
	try {
		BlockTemplate &bheader = header;
		seria::from_binary(bheader, raw_block.block);
		transactions.resize(0);
		transactions.reserve(raw_block.transactions.size());
		for (auto &&raw_transaction : raw_block.transactions) {
			Transaction transaction;
			seria::from_binary(transaction, raw_transaction);
			transactions.push_back(std::move(transaction));
		}
	} catch (...) {
		return false;
	}
	return true;
}

bool Block::to_raw_block(RawBlock &raw_block) const {
	try {
		const BlockTemplate &bheader = header;
		raw_block.block              = seria::to_binary(bheader);
		raw_block.transactions.resize(0);
		raw_block.transactions.reserve(transactions.size());
		for (auto &&transaction : transactions) {
			BinaryArray raw_transaction = seria::to_binary(transaction);
			raw_block.transactions.push_back(std::move(raw_transaction));
		}
	} catch (...) {
		return false;
	}
	return true;
}

PreparedBlock::PreparedBlock(BinaryArray &&ba, crypto::CryptoNightContext *context) : block_data(std::move(ba)) {
	seria::from_binary(raw_block, block_data);
	if (block.from_raw_block(raw_block))
		bid = bytecoin::get_block_hash(block.header);
	if (block.header.major_version >= 2)
		parent_block_size = seria::binary_size(block.header.parent_block);
	coinbase_tx_size      = seria::binary_size(block.header.base_transaction);
	base_transaction_hash = get_transaction_hash(block.header.base_transaction);
	if (context)
		long_block_hash = bytecoin::get_block_long_hash(block.header, *context);
}

PreparedBlock::PreparedBlock(RawBlock &&rba, crypto::CryptoNightContext *context) : raw_block(rba) {
	block_data = seria::to_binary(raw_block);
	if (block.from_raw_block(raw_block))
		bid = bytecoin::get_block_hash(block.header);
	if (block.header.major_version >= 2)
		parent_block_size = seria::binary_size(block.header.parent_block);
	coinbase_tx_size      = seria::binary_size(block.header.base_transaction);
	base_transaction_hash = get_transaction_hash(block.header.base_transaction);
	if (context)
		long_block_hash = bytecoin::get_block_long_hash(block.header, *context);
}

BlockChain::BlockChain(logging::ILogger &log, const Config &config, const Currency &currency, bool read_only)
    : m_genesis_bid(currency.genesis_block_hash)
    , m_db(read_only, config.get_data_folder() + "/blockchain")
    , m_archive(read_only || !config.is_archive, config.get_data_folder() + "/archive")
    , m_log(log, "BlockChainState")
    , m_config(config)
    , m_currency(currency) {
	invariant(CheckPointDifficulty{}.size() == currency.get_checkpoint_keys_count(), "");
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
	if (read_chain(0, &stored_genesis_bid)) {
		if (stored_genesis_bid != m_genesis_bid)
			throw std::runtime_error("Database starts with different genesis_block");
		read_tip();
	}
	BinaryArray cha;
	if (m_db.get("internal_import_chain", cha))
		seria::from_binary(m_internal_import_chain, cha);
}

void BlockChain::db_commit() {
	m_log(logging::INFO) << "BlockChain::db_commit started... tip_height=" << m_tip_height
	                     << " header_cache.size=" << header_cache.size() << std::endl;
	m_db.commit_db_txn();
	header_cache.clear();  // Most simple cache policy ever
	m_archive.db_commit();
	m_log(logging::INFO) << "BlockChain::db_commit finished..." << std::endl;
}

BroadcastAction BlockChain::add_block(
    const PreparedBlock &pb, api::BlockHeader *info, const std::string &source_address) {
	*info            = api::BlockHeader();
	bool have_header = read_header(pb.bid, info);
	bool have_block  = has_block(pb.bid);
	if (have_block && have_header) {
		if (info->height > m_currency.last_sw_checkpoint().first)
			m_archive.add(Archive::BLOCK, pb.block_data, pb.bid, source_address);
		return BroadcastAction::NOTHING;
	}
	api::BlockHeader prev_info;
	prev_info.height = -1;
	if (pb.bid != m_genesis_bid && !read_header(pb.block.header.previous_block_hash, &prev_info))
		return BroadcastAction::NOTHING;  // Not interested in orphan headers
	info->major_version       = pb.block.header.major_version;
	info->minor_version       = pb.block.header.minor_version;
	info->timestamp           = pb.block.header.timestamp;
	info->previous_block_hash = pb.block.header.previous_block_hash;
	info->nonce               = pb.block.header.nonce;
	info->hash                = pb.bid;
	info->height              = prev_info.height + 1;
	// Rest fields are filled by check_standalone_consensus
	std::string check_error = check_standalone_consensus(pb, info, prev_info, true);
	Hash first_difficulty_check_hash;
	invariant(
	    common::pod_from_hex(difficulty_check[0].hash, first_difficulty_check_hash), "DifficultyCheck table corrupted");
	if (info->hash == first_difficulty_check_hash &&
	    info->cumulative_difficulty != difficulty_check[0].cumulative_difficulty) {
		m_log(logging::ERROR) << "Reached first difficulty checkpoint with wrong cumulative_difficulty "
		                      << info->cumulative_difficulty << ", should be "
		                      << difficulty_check[0].cumulative_difficulty << ", " << delete_blockchain_message
		                      << m_db.get_path() << std::endl;
		std::exit(api::BYTECOIND_DATABASE_ERROR);
	}
	if (!check_error.empty())
		return BroadcastAction::BAN;  // TODO - return check_error
	if (!add_blod(*info)) {           // Has parent that does not pass through last SW checkpoint
		if (info->height > m_currency.last_sw_checkpoint().first)
			m_archive.add(Archive::BLOCK, pb.block_data, pb.bid, source_address);
		return BroadcastAction::NOTHING;
	}
	try {
		if (!have_block) {
			store_block(pb.bid, pb.block_data);  // Do not commit between here and
			// reorganize_blocks or invariant might be dead
			if (info->height > m_currency.last_sw_checkpoint().first)
				m_archive.add(Archive::BLOCK, pb.block_data, pb.bid, source_address);
		}
		store_header(pb.bid, *info);
		if (pb.bid == m_genesis_bid) {
			invariant(redo_block(pb.bid, pb.block_data, pb.raw_block, pb.block, *info, pb.base_transaction_hash),
			    "Failed to apply genesis block");
			push_chain(*info);
			//			debug_check_transaction_invariants(pb.raw_block, pb.block, *info, pb.base_transaction_hash);
		} else {
			modify_children_counter(prev_info.cumulative_difficulty, pb.block.header.previous_block_hash, 1);
		}
		check_children_counter(info->cumulative_difficulty, pb.bid, 1);
		modify_children_counter(info->cumulative_difficulty, pb.bid, -1);  // -1 from default 1 gives 0
		auto tip_check_cd = get_checkpoint_difficulty(get_tip_bid());
		auto bid_check_cd = get_checkpoint_difficulty(info->hash);
		if (compare(bid_check_cd, info->cumulative_difficulty, tip_check_cd, get_tip_cumulative_difficulty()) > 0) {
			if (get_tip_bid() == pb.block.header.previous_block_hash) {  // most common case optimization
				if (!redo_block(pb.bid, pb.block_data, pb.raw_block, pb.block, *info, pb.base_transaction_hash))
					return BroadcastAction::BAN;
				push_chain(*info);
				//				debug_check_transaction_invariants(pb.raw_block, pb.block, *info,
				// pb.base_transaction_hash);
			} else
				reorganize_blocks(pb.bid, pb, *info);
		}
		build_blods();  // In case we just passed the last checkpoint, otherwise it is nop
	} catch (const std::exception &ex) {
		m_log(logging::ERROR) << "Exception while reorganizing blockchain, probably out of disk space ex.what="
		                      << ex.what() << ", " << delete_blockchain_message << m_db.get_path() << std::endl;
		std::exit(api::BYTECOIND_DATABASE_ERROR);
	}
	if (get_tip_height() % COMMIT_EVERY_N_BLOCKS == COMMIT_EVERY_N_BLOCKS - 1)  // no commit on genesis
		db_commit();
	return info->hash == get_tip_bid() ? BroadcastAction::BROADCAST_ALL : BroadcastAction::NOTHING;
}

void BlockChain::debug_check_transaction_invariants(const RawBlock &raw_block, const Block &block,
    const api::BlockHeader &info, const Hash &base_transaction_hash) const {
	Transaction rtx;
	Height bhe;
	Hash bha;
	size_t iib;
	uint32_t bs;
	invariant(read_transaction(base_transaction_hash, &rtx, &bhe, &bha, &iib, &bs), "tx index invariant failed 1");
	invariant(get_transaction_hash(rtx) == base_transaction_hash && bhe == info.height && bha == info.hash && iib == 0,
	    "tx index invariant failed 2");
	for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
		Hash tid = block.header.transaction_hashes.at(tx_index);
		invariant(read_transaction(tid, &rtx, &bhe, &bha, &iib, &bs), "tx index invariant failed 3");
		invariant(seria::to_binary(rtx) == raw_block.transactions.at(tx_index) && bhe == info.height &&
		              bha == info.hash && iib == tx_index + 1 && bs == raw_block.transactions.at(tx_index).size(),
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
	bool undone_blocks = false;
	while (get_tip_bid() != common) {
		RawBlock raw_block;
		Block block;
		invariant(read_block(get_tip_bid(), &raw_block) && block.from_raw_block(raw_block),
		    "Block to undo not found or failed to convert" + common::pod_to_hex(get_tip_bid()));
		undone_blocks = true;
		undo_block(get_tip_bid(), raw_block, block, m_tip_height);
		for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
			Hash tid = block.header.transaction_hashes.at(tx_index);
			undone_transactions.insert(std::make_pair(tid, std::make_pair(std::move(block.transactions.at(tx_index)),
			                                                   std::move(raw_block.transactions.at(tx_index)))));
		}
		pop_chain(block.header.previous_block_hash);
		tip_changed();
	}
	// Now redo all blocks we have in storage, will ask for the rest of blocks
	bool result = true;
	while (!chain2.empty()) {
		Hash chha = chain2.back();
		chain2.pop_back();
		if (chha == recent_pb.bid) {
			invariant(
			    recent_pb.block.header.previous_block_hash == get_tip_bid(), "Unexpected block prev, invariant dead");
			if (!redo_block(recent_pb.bid, recent_pb.block_data, recent_pb.raw_block, recent_pb.block, recent_info,
			        recent_pb.base_transaction_hash)) {
				// invalid block on longest subchain, make no attempt to download the
				// rest
				// we will forever stuck on this block until longer chain appears, that
				// does not include it
				result = false;
				break;
			}
			push_chain(recent_info);
			for (auto &&tid : recent_pb.block.header.transaction_hashes)
				undone_transactions.erase(tid);
			//			debug_check_transaction_invariants(recent_pb.raw_block, recent_pb.block, recent_info,
			// recent_pb.base_transaction_hash);
		} else {
			BinaryArray block_data;
			RawBlock raw_block;
			Block block;
			if (!read_block(chha, &block_data, &raw_block) || !block.from_raw_block(raw_block)) {
				result = false;
				break;  // Strange, we checked has_block, somehow "bad block" got into DB. TODO - throw?
			}
			invariant(block.header.previous_block_hash == get_tip_bid(), "Unexpected block prev, invariant dead");
			api::BlockHeader info      = read_header(chha);
			Hash base_transaction_hash = get_transaction_hash(block.header.base_transaction);
			// if redo fails, we will forever stuck on this block until longer chain
			// appears, that does not include it
			if (!redo_block(chha, block_data, raw_block, block, info, base_transaction_hash)) {
				result = false;
				break;
			}
			push_chain(info);
			for (auto &&tid : block.header.transaction_hashes)
				undone_transactions.erase(tid);
			//			debug_check_transaction_invariants(raw_block, block, info, base_transaction_hash);
		}
	}
	on_reorganization(undone_transactions, undone_blocks);
	return result;
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

std::vector<Hash> BlockChain::get_sparse_chain() const {
	std::vector<Hash> tip_path;

	uint32_t jump = 0;
	while (m_tip_height >= jump) {
		tip_path.push_back(read_chain(m_tip_height - jump));
		if (tip_path.size() <= 10)
			jump += 1;
		else
			jump += (1 << (tip_path.size() - 10));
	}
	if (tip_path.back() != m_genesis_bid)
		tip_path.push_back(m_genesis_bid);
	return tip_path;
}

std::vector<api::BlockHeader> BlockChain::get_sync_headers(const std::vector<Hash> &locator, size_t max_count) const {
	std::vector<api::BlockHeader> result;
	Height start_height     = 0;
	std::vector<Hash> chain = get_sync_headers_chain(locator, &start_height, max_count);
	result.reserve(chain.size());
	for (auto &&c : chain) {
		result.push_back(read_header(c));
	}
	return result;
}

uint32_t BlockChain::find_blockchain_supplement(const std::vector<Hash> &remote_block_ids) const {
	for (auto &&lit : remote_block_ids) {
		api::BlockHeader header;
		if (!read_header(lit, &header))
			continue;
		if (header.height > m_tip_height)
			continue;
		return header.height;
	}
	return 0;  // Not possible if genesis blocks match
}

Height BlockChain::get_timestamp_lower_bound_block_index(Timestamp ts) const {
	auto middle    = common::write_varint_sqlite4(ts);
	DB::Cursor cur = m_db.begin(TIMESTAMP_BLOCK_PREFIX, middle);
	if (cur.end())
		return m_tip_height;
	const char *be = cur.get_suffix().data();
	const char *en = be + cur.get_suffix().size();
	common::read_varint_sqlite4(be, en);  // We ignore result, auto actual_ts =
	return boost::lexical_cast<Height>(common::read_varint_sqlite4(be, en));
}

std::vector<Hash> BlockChain::get_sync_headers_chain(const std::vector<Hash> &locator,
    Height *start_height,
    size_t max_count) const {
	std::vector<Hash> result;
	for (auto &&lit : locator) {
		api::BlockHeader header;
		if (!read_header(lit, &header))
			continue;
		if (header.height > m_tip_height) {  // Asker has better chain then we do
			*start_height = m_tip_height + 1;
			return result;
		}
		uint32_t min_height = header.height;
		Hash loc_ha         = lit;
		for (; min_height != 0; min_height -= 1) {
			Hash ha = read_chain(min_height);
			if (ha == loc_ha)
				break;
			loc_ha = header.previous_block_hash;
			header = read_header(loc_ha);
		}
		*start_height = min_height;
		for (; result.size() < max_count && min_height <= m_tip_height; min_height += 1) {
			result.push_back(read_chain(min_height));
		}
		return result;
	}
	*start_height = m_tip_height + 1;
	return result;
}

struct APIRawBlockHeightDifficulty {
	RawBlock &raw_block;
	Height &height;
	Difficulty &cd;
	APIRawBlockHeightDifficulty(RawBlock &raw_block, Height &height, Difficulty &cd)
	    : raw_block(raw_block), height(height), cd(cd) {}
};

namespace seria {
void ser_members(APIRawBlockHeightDifficulty &v, ISeria &s) {
	seria_kv("height", v.height, s);
	seria_kv("cd", v.cd, s);
	seria_kv("raw_block", v.raw_block, s);
}
}  // namespace seria

struct APITransactionPos {
	Height height   = 0;
	uint32_t offset = 0;
	uint32_t size   = 0;
	uint32_t index  = 0;
};

namespace seria {
void ser_members(APITransactionPos &v, ISeria &s) {
	seria_kv("height", v.height, s);
	seria_kv("offset", v.offset, s);
	seria_kv("size", v.size, s);
	seria_kv("index", v.index, s);
}
}  // namespace seria

bool BlockChain::read_transaction(const Hash &tid, Transaction *tx, Height *block_height, Hash *block_hash,
    size_t *index_in_block, uint32_t *binary_size) const {
	auto txkey = TRANSATION_PREFIX + DB::to_binary_key(tid.data, sizeof(tid.data));
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
	*binary_size    = tpos.size;
	BinaryArray tbody(block_val.data() + tpos.offset, block_val.data() + tpos.offset + tpos.size);
	seria::from_binary(*tx, tbody);  // TODO save copy
	return true;
}

bool BlockChain::redo_block(const Hash &bhash, const BinaryArray &block_data, const RawBlock &raw_block,
    const Block &block, const api::BlockHeader &info, const Hash &base_transaction_hash) {
	if (!redo_block(bhash, block, info))
		return false;
	auto tikey = TIMESTAMP_BLOCK_PREFIX + common::write_varint_sqlite4(info.timestamp) +
	             common::write_varint_sqlite4(info.height);
	m_db.put(tikey, std::string(), true);

	APITransactionPos tpos;
	tpos.height = info.height;
	auto bkey   = TRANSATION_PREFIX + DB::to_binary_key(base_transaction_hash.data, sizeof(base_transaction_hash.data));
	tpos.index  = 0;
	BinaryArray coinbase_ba = seria::to_binary(block.header.base_transaction);
	auto ptr                = common::slow_memmem(block_data.data() + tpos.offset + tpos.size,
	    block_data.size() - tpos.offset - tpos.size, coinbase_ba.data(), coinbase_ba.size());
	invariant(ptr, "binary coinbase tx not found in binary block");
	tpos.offset = static_cast<uint32_t>(ptr - block_data.data());
	tpos.size   = static_cast<uint32_t>(coinbase_ba.size());
	m_db.put(bkey, seria::to_binary(tpos), true);
	for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
		Hash tid              = block.header.transaction_hashes.at(tx_index);
		tpos.index            = static_cast<uint32_t>(tx_index + 1);
		bkey                  = TRANSATION_PREFIX + DB::to_binary_key(tid.data, sizeof(tid.data));
		const auto &binary_tx = raw_block.transactions.at(tx_index);
		ptr                   = common::slow_memmem(block_data.data() + tpos.offset + tpos.size,
		    block_data.size() - tpos.offset - tpos.size, binary_tx.data(), binary_tx.size());
		invariant(ptr, "binary tx not found in binary block");
		tpos.offset = static_cast<uint32_t>(ptr - block_data.data());
		tpos.size   = static_cast<uint32_t>(binary_tx.size());
		m_db.put(bkey, seria::to_binary(tpos), true);
	}
	return true;
}
void BlockChain::undo_block(const Hash &bhash, const RawBlock &, const Block &block, Height height) {
	//	if (!m_tip_segment.empty())
	//		m_tip_segment.pop_back();
	undo_block(bhash, block, height);

	auto tikey = TIMESTAMP_BLOCK_PREFIX + common::write_varint_sqlite4(block.header.timestamp) +
	             common::write_varint_sqlite4(height);
	m_db.del(tikey, true);

	Hash tid  = get_transaction_hash(block.header.base_transaction);
	auto bkey = TRANSATION_PREFIX + DB::to_binary_key(tid.data, sizeof(tid.data));
	m_db.del(bkey, true);
	for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
		tid  = block.header.transaction_hashes.at(tx_index);
		bkey = TRANSATION_PREFIX + DB::to_binary_key(tid.data, sizeof(tid.data));
		m_db.del(bkey, true);
	}
}

void BlockChain::store_block(const Hash &bid, const BinaryArray &block_data) {
	auto key = BLOCK_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + BLOCK_SUFFIX;
	m_db.put(key, block_data, true);
}

bool BlockChain::read_block(const Hash &bid, BinaryArray *block_data, RawBlock *raw_block) const {
	BinaryArray rb;
	auto key = BLOCK_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + BLOCK_SUFFIX;
	if (!m_db.get(key, rb))
		return false;
	seria::from_binary(*raw_block, rb);
	*block_data = std::move(rb);
	return true;
}

bool BlockChain::read_block(const Hash &bid, RawBlock *raw_block) const {
	BinaryArray rb;
	return read_block(bid, &rb, raw_block);
}

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

bool BlockChain::read_header(const Hash &bid, api::BlockHeader *header, Height hint) const {
	if (get_tip_height() != Height(-1) && hint <= get_tip_height() &&
	    hint >= get_tip_height() - m_header_tip_window.size() + 1) {
		const auto &candidate = m_header_tip_window.at(m_header_tip_window.size() - 1 - (get_tip_height() - hint));
		if (candidate.hash == bid) {
			*header = candidate;  // fastest lookup is in tip window
			return true;
		}
	}
	auto cit = header_cache.find(bid);
	if (cit != header_cache.end()) {
		*header = cit->second;
		return true;
	}
	if (header_cache.size() > m_currency.largest_window() * 10) {
		m_log(logging::INFO) << "BlockChain header cache reached max size and cleared" << std::endl;
		header_cache.clear();  // very simple policy
	}
	BinaryArray rb;
	auto key = HEADER_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + HEADER_SUFFIX;
	if (!m_db.get(key, rb))
		return false;
	Hash bbid = bid;  // next line can modify bid, because it can be reference to header.previous_block_hash
	seria::from_binary(*header, rb);
	header_cache.insert(std::make_pair(bbid, *header));
	return true;
}

api::BlockHeader BlockChain::read_header(const Hash &bid, Height hint) const {
	api::BlockHeader result;
	invariant(read_header(bid, &result, hint), "Expected header was not found" + common::pod_to_hex(bid));
	return result;
}

const api::BlockHeader &BlockChain::get_tip() const {
	invariant(!m_header_tip_window.empty() && m_tip_bid == m_header_tip_window.back().hash, "tip window corrupted");
	return m_header_tip_window.back();
}

std::vector<api::BlockHeader> BlockChain::get_tip_segment(
    const api::BlockHeader &prev_info, Height window, bool add_genesis) const {
	std::vector<api::BlockHeader> result;
	result.reserve(window);
	if (prev_info.height == Height(-1))
		return result;
	api::BlockHeader pi = prev_info;
	while (result.size() < window && pi.height != 0) {
		result.push_back(pi);
		pi = read_header(pi.previous_block_hash, pi.height - 1);
	}
	if (result.size() < window && add_genesis) {
		invariant(pi.height == 0, "Invariant dead - window size not reached, but genesis not found in get_tip_segment");
		result.push_back(pi);
	}
	std::reverse(result.begin(), result.end());
	return result;
}

void BlockChain::read_tip() {
	DB::Cursor cur2 = m_db.rbegin(TIP_CHAIN_PREFIX);
	m_tip_height    = cur2.end() ? -1 : boost::lexical_cast<Height>(common::read_varint_sqlite4(cur2.get_suffix()));
	seria::from_binary(m_tip_bid, cur2.get_value_array());
	api::BlockHeader tip_header = read_header(m_tip_bid);
	m_tip_cumulative_difficulty = tip_header.cumulative_difficulty;
	m_header_tip_window.clear();
	m_header_tip_window.push_back(tip_header);
}

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
	    "After undo tip does not match read_chain " + common::pod_to_hex(m_tip_bid));
	if (m_header_tip_window.empty()) {
		api::BlockHeader tip_header = read_header(m_tip_bid);
		m_header_tip_window.push_back(tip_header);
	}
	m_tip_cumulative_difficulty = get_tip().cumulative_difficulty;
}

// After upgrading to future versions, remove version from index key
bool BlockChain::read_chain(uint32_t height, Hash *bid) const {
	BinaryArray ba;
	if (!m_db.get(TIP_CHAIN_PREFIX + common::write_varint_sqlite4(height), ba))
		return false;
	seria::from_binary(*bid, ba);
	return true;
}

bool BlockChain::in_chain(Height height, Hash bid) const {
	Hash ha;
	return read_chain(height, &ha) && ha == bid;
}

Hash BlockChain::read_chain(uint32_t height) const {
	Hash ha;
	invariant(read_chain(height, &ha), "read_header_chain failed");
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
	uint32_t counter = 1;  // default is 1 when not stored in db
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

void BlockChain::for_each_tip(std::function<bool(CumulativeDifficulty cd, Hash bid)> fun) const {
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
	api::BlockHeader me = read_header(bid);
	api::BlockHeader pa = read_header(me.previous_block_hash);
	modify_children_counter(cd, bid, 1);
	modify_children_counter(pa.cumulative_difficulty, me.previous_block_hash, -1);
	auto key = BLOCK_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + BLOCK_SUFFIX;
	m_db.del(key, true);
	auto key2 = HEADER_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + HEADER_SUFFIX;
	m_db.del(key2, true);
	return true;
}

void BlockChain::test_prune_oldest() {
	for (int i = 0; i != 10; ++i) {
		CumulativeDifficulty cd{};
		Hash bid;
		if (!get_oldest_tip(&cd, &bid))
			return;
		prune_branch(cd, bid);
	}
}

void BlockChain::test_print_structure(Height n_confirmations) const {
	CumulativeDifficulty ocd;
	Hash obid;
	if (get_oldest_tip(&ocd, &obid))
		std::cout << "oldest tip cd=" << ocd << " bid=" << obid << std::endl;
	std::cout << "---- BlockTree tips and forking nodes ----" << std::endl;
	for (DB::Cursor cur = m_db.begin(CHILDREN_PREFIX); !cur.end(); cur.next()) {
		Hash bid;
		DB::from_binary_key(cur.get_suffix(), 0, bid.data, sizeof(bid.data));
		uint32_t counter = 1;
		seria::from_binary(counter, cur.get_value_array());

		std::cout << "childrens=" << counter << " bid=" << bid << std::endl;
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
			Block block;
			if (confirmed) {
				total_forked_blocks += 1;
				if (read_block(bid, &rb) && block.from_raw_block(rb)) {
					for (size_t tx_pos = 0; tx_pos != block.header.transaction_hashes.size(); ++tx_pos) {
						Hash tid = block.header.transaction_hashes.at(tx_pos);
						total_forked_transactions += 1;
						Transaction tx;
						Height height = 0;
						Hash block_hash;
						size_t index_in_block = 0;
						uint32_t binary_size  = 0;
						if (!read_transaction(tid, &tx, &height, &block_hash, &index_in_block, &binary_size)) {
							Amount input_amount = 0;
							for (const auto &input : block.transactions.at(tx_pos).inputs)
								if (input.type() == typeid(KeyInput)) {
									const KeyInput &in = boost::get<KeyInput>(input);
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
	m_log(logging::INFO) << "Blockchain database has old format, preparing for internal block import..." << std::endl;
	if (m_internal_import_chain.empty()) {
		const std::vector<std::string> former_prefixes{
		    TIP_CHAIN_PREFIX + "B/", TIP_CHAIN_PREFIX + "1/", TIP_CHAIN_PREFIX + "/", TIP_CHAIN_PREFIX};
		for (auto && prefix : former_prefixes) {
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
	m_log(logging::INFO) << "Found " << m_internal_import_chain.size() << " blocks from main chain" << std::endl;
	size_t erased = 0, skipped = 0;
	size_t total_items = m_db.get_approximate_items_count();
	for (DB::Cursor cur = m_db.rbegin(std::string()); !cur.end();) {
		if ((erased + skipped) % 1000000 == 0)
			m_log(logging::INFO) << "Processing " << (erased + skipped) / 1000000 << "/"
			                     << (total_items + 999999) / 1000000 << " million DB records" << std::endl;
		if (cur.get_suffix().find(BLOCK_PREFIX) == 0 &&
		    cur.get_suffix().substr(cur.get_suffix().size() - BLOCK_SUFFIX.size()) == BLOCK_SUFFIX) {
			Hash bid;
			DB::from_binary_key(cur.get_suffix(), BLOCK_PREFIX.size(), bid.data, sizeof(bid.data));
			if (main_chain_bids.count(bid) != 0) {
				cur.next();
				skipped += 1;
				continue;  // block in main chain
			}
		}
		cur.erase();
		erased += 1;
	}
	m_db.put("internal_import_chain", seria::to_binary(m_internal_import_chain), true);  // we've just erased it :)
	m_log(logging::INFO) << "Deleted " << erased << " records, skipped " << skipped << " records" << std::endl;
}

bool BlockChain::internal_import() {
	auto idea_start = std::chrono::high_resolution_clock::now();
	while (true) {
		if (get_tip_height() + 1 >= m_internal_import_chain.size())
			break;
		const Hash bid = m_internal_import_chain.at(get_tip_height() + 1);
		RawBlock rb;
		if (!read_block(bid, &rb)) {
			m_log(logging::WARNING) << "Block not found during internal import for height=" << get_tip_height() + 1
			                        << " bid=" << bid << std::endl;
			break;
		}
		PreparedBlock pb(std::move(rb), nullptr);
		api::BlockHeader info;
		if (add_block(pb, &info, std::string()) != BroadcastAction::BROADCAST_ALL) {
			m_log(logging::WARNING) << "Block corrupted  during internal import for height=" << get_tip_height() + 1
			                        << " bid=" << bid << std::endl;
			break;
		}
		//		if (get_tip_height() % COMMIT_EVERY_N_BLOCKS == 0)
		//			db_commit();
		auto idea_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		    std::chrono::high_resolution_clock::now() - idea_start);
		if (idea_ms.count() > 200)
			return true;  // import in chunks of 0.2 seconds
	}
	m_log(logging::INFO) << "Finished internal importing of blocks, will continue downloading..." << std::endl;
	m_internal_import_chain.clear();
	m_db.del("internal_import_chain", true);
	db_commit();
	return false;
}

void BlockChain::test_undo_everything(Height new_tip_height) {
	while (get_tip_height() > new_tip_height) {
		RawBlock raw_block;
		Block block;
		if (!read_block(get_tip_bid(), &raw_block) || !block.from_raw_block(raw_block))
			break;
		undo_block(get_tip_bid(), raw_block, block, m_tip_height);
		if (get_tip_bid() == m_genesis_bid)
			break;
		pop_chain(block.header.previous_block_hash);
		tip_changed();
		if (get_tip_height() % COMMIT_EVERY_N_BLOCKS == 1)
			db_commit();
	}
	std::cout << "---- After undo everything ---- " << std::endl;
	//
	//	$version
	//	T00
	//	a}?FFFFF0
	//	c/0
	//	t'40gGOBMhv;@IX6{@yYbN1}J64V.]$z5
	//	x-ch/7o4%rJZ=8Qe9zz8NCg@F{@G`f>KWmKf=
	//	x-tips/0|yg2dz7o4%rJZ=8Qe9zz8NCg@F{@G`f>KWmKf=
	int counter = 0;
	for (DB::Cursor cur = m_db.begin(std::string()); !cur.end(); cur.next()) {
		if (cur.get_suffix().find(BLOCK_PREFIX) == 0)
			continue;
		if (cur.get_suffix().find(HEADER_PREFIX) == 0)
			continue;
		if (cur.get_suffix().find("f") == 0)
			continue;
		std::cout << DB::clean_key(cur.get_suffix()) << std::endl;
		if (counter++ > 1000)
			break;
	}
}

std::vector<SignedCheckPoint> BlockChain::get_latest_checkpoints() const {
	std::vector<SignedCheckPoint> result;
	for (DB::Cursor cur = m_db.begin(CHECKPOINT_PREFIX_LATEST); !cur.end(); cur.next()) {
		result.push_back(SignedCheckPoint{});
		seria::from_binary(result.back(), cur.get_value_array());
	}
	return result;
}

std::vector<SignedCheckPoint> BlockChain::get_stable_checkpoints() const {
	std::vector<SignedCheckPoint> result;
	for (DB::Cursor cur = m_db.begin(CHECKPOINT_PREFIX_STABLE); !cur.end(); cur.next()) {
		result.push_back(SignedCheckPoint{});
		seria::from_binary(result.back(), cur.get_value_array());
	}
	return result;
}

bool BlockChain::add_checkpoint(const SignedCheckPoint &checkpoint, const std::string &source_address) {
	if (checkpoint.height <= m_currency.last_sw_checkpoint().first &&
	    checkpoint.counter != std::numeric_limits<uint64_t>::max())
		return false;  // Height is ignored when disabling key_id
	PublicKey public_key =
	    m_currency.get_checkpoint_public_key(checkpoint.key_id);  // returns empty key if out of range
	auto key_latest               = CHECKPOINT_PREFIX_LATEST + common::write_varint_sqlite4(checkpoint.key_id);
	auto key_stable               = CHECKPOINT_PREFIX_STABLE + common::write_varint_sqlite4(checkpoint.key_id);
	BinaryArray binary_checkpoint = seria::to_binary(checkpoint);
	BinaryArray ba;
	if (m_db.get(key_latest, ba)) {
		SignedCheckPoint previous_checkpoint;
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
	if (checkpoint.counter != std::numeric_limits<uint64_t>::max()) {  // Disabling key_id
		auto bit = blods.find(checkpoint.hash);
		if (bit == blods.end())
			return true;  // orphan checkpoint
	}
	m_db.put(key_stable, binary_checkpoint, false);
	update_key_count_max_heights();
	auto tip_check_cd = get_checkpoint_difficulty(get_tip_bid());
	for_each_tip([&](CumulativeDifficulty cd, Hash bid) -> bool {
		auto bid_check_cd = get_checkpoint_difficulty(bid);
		if (compare(bid_check_cd, cd, tip_check_cd, get_tip_cumulative_difficulty()) <= 0)
			return true;
		api::BlockHeader header = read_header(bid);
		RawBlock raw_block;
		if (!read_block(bid, &raw_block))
			return true;
		PreparedBlock pb(std::move(raw_block), nullptr);
		reorganize_blocks(bid, pb, header);
		tip_check_cd = get_checkpoint_difficulty(get_tip_bid());
		return true;
	});
	return true;
}

int BlockChain::compare(
    const CheckPointDifficulty &a, CumulativeDifficulty ca, const CheckPointDifficulty &b, CumulativeDifficulty cb) {
	//	invariant(a.size() == b.size(), "size mismatch in BlockChain::compare");
	for (size_t i = a.size(); i-- > 0;)
		if (a.at(i) != b.at(i))
			return int(a.at(i)) - int(b.at(i));
	if (ca < cb)
		return -1;
	if (ca > cb)
		return 1;
	return 0;
}

bool BlockChain::add_blod(const api::BlockHeader &header) {
	if (blods.empty()) // Allow any blocks if main does not pass through last sw checkpoint yet
		return true;
	auto bit = blods.find(header.hash);
	if (bit != blods.end())
		return true;  // Strange, but nop
	bit = blods.find(header.previous_block_hash);
	if (bit == blods.end())
		return false;
	Blod &blod  = blods[header.hash];
	blod.height = header.height;
	blod.hash   = header.hash;
	blod.parent = &bit->second;
	bit->second.children.push_back(&blod);
	blod.checkpoint_difficulty = blod.parent->checkpoint_difficulty;
	// We inherit from parent and rebuild only if we pass through one of checlpoints
	for (auto &&ch : get_latest_checkpoints())
		if (ch.counter != std::numeric_limits<uint64_t>::max()) {  // disabled are made stable in add_checkpoint
			if (header.hash == ch.hash) {
				auto key_stable = CHECKPOINT_PREFIX_STABLE + common::write_varint_sqlite4(ch.key_id);
				m_db.put(key_stable, seria::to_binary(ch), false);
			}
		}
	for (auto &&ch : get_stable_checkpoints())
		if (ch.counter != std::numeric_limits<uint64_t>::max()) {  // skip disabled keys
			if (header.hash == ch.hash) {
				update_key_count_max_heights();
				return true;
			}
		}
	return true;
}

void BlockChain::build_blods() {
	if (!blods.empty())
		return;  // build only once per daemon launch
	if (!in_chain(m_currency.last_sw_checkpoint().first, m_currency.last_sw_checkpoint().second))
		return;                         // build only after main chain passes through last SW checkpoint
	std::set<Hash> bad_header_hashes;   // sidechains that do not pass through last SW checkpoint
	std::set<Hash> good_header_hashes;  // sidechains that pass through last SW checkpoint
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
			if (header.height < m_currency.last_sw_checkpoint().first)
				break;
			side_chain.push_back(header);
			if (header.height == m_currency.last_sw_checkpoint().first) {
				if (header.hash == m_currency.last_sw_checkpoint().second) {
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
		Blod &blod  = blods[ha.hash];
		blod.height = ha.height;
		blod.hash   = ha.hash;
		auto bit    = blods.find(ha.previous_block_hash);
		if (bit == blods.end())
			continue;
		blod.parent = &bit->second;
		bit->second.children.push_back(&blod);
	}
	update_key_count_max_heights();
}

void BlockChain::update_key_count_max_heights() {
	// We use simplest O(n) algo, will optimize later and use this one as a reference
	for (auto &&bit : blods) {
		bit.second.checkpoint_key_ids.reset();
		bit.second.checkpoint_difficulty = CheckPointDifficulty{};
	}
	auto checkpoints = get_stable_checkpoints();
	for (auto cit = checkpoints.begin(); cit != checkpoints.end(); ++cit)
		if (cit->counter != std::numeric_limits<uint64_t>::max()) {  // skip disabled keys
			auto bit = blods.find(cit->hash);
			if (bit == blods.end())
				continue;
			for (Blod *b = &bit->second; b; b = b->parent)
				b->checkpoint_key_ids.set(cit->key_id);
		}
	std::vector<Blod *> to_visit;
	auto bit = blods.find(m_currency.last_sw_checkpoint().second);
	if (bit != blods.end())
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

BlockChain::CheckPointDifficulty BlockChain::get_checkpoint_difficulty(Hash hash) const {
	auto bit = blods.find(hash);
	if (bit == blods.end())
		return CheckPointDifficulty{};
	return bit->second.checkpoint_difficulty;
}
