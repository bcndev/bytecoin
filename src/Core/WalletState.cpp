// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletState.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "TransactionExtra.hpp"
#include "common/string.hpp"
#include "crypto/crypto.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

static const std::string version_current = "2";

static const std::string TRANSACTION_PREFIX                = "tn/";
static const std::string HEIGHT_TRANSACTION_PREFIX         = "htn/";
static const std::string ADDRESS_HEIGHT_TRANSACTION_PREFIX = "ahtn/";

static const std::string TIP_CHAIN_PREFIX       = "ch/";
static const std::string KEYIMAGE_PREFIX        = "ki/";
static const std::string HEIGHT_KEYIMAGE_PREFIX = "hki/";
static const std::string UNSPENT_HEIGHT_PREFIX  = "un/";
static const std::string HEIGHT_UNSPENT_PREFIX  = "hun/";
static const std::string HEIGHT_OUTPUT_PREFIX   = "hout/";
static const std::string BALANCE_PREFIX         = "bal/";
static const std::string ADDRESS_BALANCE_PREFIX = "abal/";

static const std::string UNLOCK_BLOCK_PREFIX = "unlb/";
static const std::string UNLOCK_TIME_PREFIX  = "unlt/";

static const std::string ADDRESSES_PREFIX = "ad/";

using namespace bytecoin;
using namespace platform;

WalletPreparatorMulticore::WalletPreparatorMulticore() {
	auto th_count =
	    std::max<size_t>(2, 3 * std::thread::hardware_concurrency() / 4);  // we use more energy but have the
	                                                                       // same speed when using
	                                                                       // hyperthreading to max
	std::cout << "Starting multicore transaction preparator using " << th_count << "/"
	          << std::thread::hardware_concurrency() << " cpus" << std::endl;
	for (size_t i = 0; i != th_count; ++i)
		threads.emplace_back(&WalletPreparatorMulticore::thread_run, this);
}

WalletPreparatorMulticore::~WalletPreparatorMulticore() {
	{
		std::unique_lock<std::mutex> lock(mu);
		quit = true;
		have_work.notify_all();
	}
	for (auto &&th : threads)
		th.join();
}

PreparedWalletTransaction::PreparedWalletTransaction(TransactionPrefix &&ttx, const SecretKey &view_secret_key)
    : tx(std::move(ttx)) {
	PublicKey tx_public_key = get_transaction_public_key_from_extra(tx.extra);
	if (!generate_key_derivation(tx_public_key, view_secret_key, derivation))
		return;
	KeyPair tx_keys;
	size_t key_index   = 0;
	uint32_t out_index = 0;
	spend_keys.reserve(tx.outputs.size());
	for (const auto &output : tx.outputs) {
		if (output.target.type() == typeid(KeyOutput)) {
			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			PublicKey spend_key;
			underive_public_key(derivation, key_index, key_output.key,
			    spend_key);  // error indicated by spend_key == PublicKey{}
			spend_keys.push_back(spend_key);
			++key_index;
		}
		++out_index;
	}
}
PreparedWalletBlock::PreparedWalletBlock(BlockTemplate &&bc_header, std::vector<TransactionPrefix> &&bc_transactions,
    Hash base_transaction_hash, const SecretKey &view_secret_key)
    : base_transaction_hash(base_transaction_hash) {
	header           = bc_header;
	base_transaction = PreparedWalletTransaction(std::move(bc_header.base_transaction), view_secret_key);
	transactions.reserve(bc_transactions.size());
	for (size_t tx_index = 0; tx_index != bc_transactions.size(); ++tx_index) {
		transactions.emplace_back(std::move(bc_transactions.at(tx_index)), view_secret_key);
	}
}

void WalletPreparatorMulticore::thread_run() {
	while (true) {
		SecretKey view_secret_key;
		Height height          = 0;
		int local_work_counter = 0;
		api::bytecoind::SyncBlocks::SyncBlock sync_block;
		std::vector<std::vector<uint32_t>> global_indices;
		{
			std::unique_lock<std::mutex> lock(mu);
			if (quit)
				return;
			if (work.blocks.empty()) {
				have_work.wait(lock);
				continue;
			}
			local_work_counter = work_counter;
			view_secret_key    = work_secret_key;
			height             = work.start_height;
			sync_block         = std::move(work.blocks.front());
			work.start_height += 1;
			work.blocks.erase(work.blocks.begin());
		}
		PreparedWalletBlock result(std::move(sync_block.bc_header), std::move(sync_block.bc_transactions),
		    sync_block.base_transaction_hash, view_secret_key);
		{
			std::unique_lock<std::mutex> lock(mu);
			if (local_work_counter == work_counter) {
				prepared_blocks[height] = std::move(result);
				result_ready.notify_all();
			}
		}
	}
}

void WalletPreparatorMulticore::cancel_work() {
	std::unique_lock<std::mutex> lock(mu);
	work = api::bytecoind::SyncBlocks::Response();
	prepared_blocks.clear();
	work_counter += 1;
}

void WalletPreparatorMulticore::start_work(const api::bytecoind::SyncBlocks::Response &new_work,
    const SecretKey &view_secret_key) {
	std::unique_lock<std::mutex> lock(mu);
	work            = new_work;
	work_secret_key = view_secret_key;
	work_counter += 1;
	have_work.notify_all();
}

PreparedWalletBlock WalletPreparatorMulticore::get_ready_work(Height height) {
	while (true) {
		std::unique_lock<std::mutex> lock(mu);
		auto pit = prepared_blocks.find(height);
		if (pit == prepared_blocks.end()) {
			result_ready.wait(lock);
			continue;
		}
		PreparedWalletBlock result = std::move(pit->second);
		pit                        = prepared_blocks.erase(pit);
		return result;
	}
}

template<class T>
std::string toBinaryKey(const T &s) {
	static_assert(std::is_standard_layout<T>::value, "T must be Standard Layout");
	return common::to_hex(&s, sizeof(s));  // WalletState::DB::to_binary_key((const unsigned char *)&s, sizeof(s));
}

void WalletState::DeltaState::redo_transaction(
    Height, const Hash &tid, const TransactionPrefix &tx, const api::Transaction &ptx) {
	if (!m_transactions.insert(std::make_pair(tid, std::make_pair(tx, ptx))).second)
		throw std::logic_error("DeltaState::redo_transaction already exists. Invariant dead");
}

void WalletState::DeltaState::undo_transaction(Height, const Hash &tid) {
	if (m_transactions.erase(tid) != 1)
		throw std::logic_error("DeltaState::undo_transaction does not exist. Invariant dead");
}

void WalletState::DeltaState::redo_keyimage_output(
    const api::Output &output, Height block_height, Timestamp block_unlock_timestamp) {
	m_unspents[output.public_key].push_back(output);
}

void WalletState::DeltaState::undo_keyimage_output(const api::Output &output) {
	throw std::logic_error("DeltaState::undo_keyimage_output");  // We do not call
	                                                             // it on memory
	                                                             // states
}

void WalletState::DeltaState::redo_height_keyimage(Height height, const KeyImage &keyimage) {
	m_used_keyimages[keyimage] += 1;
}

void WalletState::DeltaState::undo_height_keyimage(Height height, const KeyImage &keyimage) {
	auto kit = m_used_keyimages.find(keyimage);
	if (kit == m_used_keyimages.end()) {
		std::cout << "DeltaState::undo_height_keyimage more keyimages undone than redone" << std::endl;
		return;
	}
	kit->second -= 1;
	if (kit->second < 0)
		std::cout << "DeltaState::undo_height_keyimage more keyimages undone than "
		             "redone 2"
		          << std::endl;
	if (kit->second <= 0)
		kit = m_used_keyimages.erase(kit);
}

void WalletState::DeltaState::apply(IWalletState *parent_state) const {
	for (auto &&pa : m_unspents)
		for (auto &&out : pa.second)
			parent_state->redo_keyimage_output(out, m_block_height, m_unlock_timestamp);
	for (auto &&ki : m_used_keyimages)
		parent_state->redo_height_keyimage(m_block_height, ki.first);
	for (auto &&tx : m_transactions)
		parent_state->redo_transaction(m_block_height, tx.first, tx.second.first, tx.second.second);
}

void WalletState::DeltaState::undo_transaction(const Hash &tid) {
	auto tit = m_transactions.find(tid);
	if (tit == m_transactions.end())
		return;
	const TransactionPrefix &tx = tit->second.first;
	for (const auto &output : tx.outputs) {
		if (output.target.type() == typeid(KeyOutput)) {
			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			auto uit                    = m_unspents.find(key_output.key);
			if (uit == m_unspents.end() || uit->second.empty())  // Actually should never be empty
				continue;                                        // Not our output
			uit->second.pop_back();                              // We can pop wrong output, but this is not
			                                                     // important - situation arises only in pool and
			                                                     // only during attack
			if (uit->second.empty())
				uit = m_unspents.erase(uit);
		}
	}
	for (const auto &input : tx.inputs) {
		if (input.type() == typeid(CoinbaseInput)) {
		} else if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			undo_height_keyimage(m_block_height, in.key_image);
		}
	}
	tit = m_transactions.erase(tit);
}

void WalletState::DeltaState::clear(Height new_block_height) {
	m_block_height = new_block_height;
	m_used_keyimages.clear();
	m_unspents.clear();
	m_transactions.clear();
}

void WalletState::DeltaState::set_height(Height new_block_height) { m_block_height = new_block_height; }

bool WalletState::DeltaState::is_spent(const api::Output &output) const {
	return m_used_keyimages.count(output.key_image) != 0;
}

WalletState::WalletState(Wallet &wallet, logging::ILogger &log, const Config &config, const Currency &currency)
    : m_genesis_bid(currency.genesis_block_hash)
    , m_config(config)
    , m_currency(currency)
    , m_log(log)
    , m_wallet(wallet)
    , m_db(config.get_data_folder("wallet_cache") + "/" + wallet.get_cache_name(),
          0x2000000000)  // 128 gb
    , log_redo_block(std::chrono::steady_clock::now())
    , m_memory_state(0, 0) {
	std::string version;
	m_db.get("$version", version);
	if (version != version_current) {
		std::cout << "Data format changed, old version=" << version << " current version=" << version_current
		          << ", deleting wallet cache..." << std::endl;
		for (DB::Cursor cur = m_db.rbegin(std::string()); !cur.end(); cur.erase()) {
		}
		m_db.put("$version", version_current, true);
	}
	if (!read_tips()) {
		BinaryArray ba = seria::to_binary(m_genesis_bid);
		m_db.put("$genesis_bid", ba, true);
		push_chain(BlockChainState::fill_genesis(m_genesis_bid, currency.genesis_block_template));
	}
	wallet_addresses_updated();
}

void WalletState::db_commit() {
	std::cout << "WalletState::db_commit started... tip_height=" << m_tip_height << std::endl;
	m_db.commit_db_txn();
	std::cout << "WalletState::db_commit finished..." << std::endl;
}

void WalletState::wallet_addresses_updated() {
	Timestamp undo_timestamp = std::numeric_limits<Timestamp>::max();
	for (auto rec : m_wallet.get_records()) {
		const WalletRecord &wa = rec.second;
		auto keyuns            = ADDRESSES_PREFIX + toBinaryKey(wa.spend_public_key);
		std::string st;
		if (!m_db.get(keyuns, st) || wa.creation_timestamp < boost::lexical_cast<Timestamp>(st)) {
			undo_timestamp = std::min(undo_timestamp, wa.creation_timestamp);
			m_db.put(keyuns, common::to_string(wa.creation_timestamp), false);
		}
	}
	// We never delete from ADDRESSES_PREFIX index, because it correctly reflects
	// scanned outputs, their spendable and
	// balances
	if (undo_timestamp == std::numeric_limits<Timestamp>::max()) {
		return;  // db.commit() not worth here, will just update addresses again in
		         // case of ctrl-c
	}
	while (m_tip_height + 1 > m_tail_height &&
	       get_tip().timestamp + m_currency.block_future_time_limit >=
	           undo_timestamp) {  // Undo excess blocks in case timestamps are out of
		                          // order
		undo_block(m_tip_height);
		pop_chain();
	}
	db_commit();
}

std::vector<WalletRecord> WalletState::generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct) {
	auto result = m_wallet.generate_new_addresses(sks, ct);
	if (result.size() != sks.size())  // most likely result is empty, because view-only
		return result;
	Timestamp undo_timestamp = std::numeric_limits<Timestamp>::max();
	for (size_t i = 0; i != std::min(result.size(), sks.size()); ++i) {
		const WalletRecord &wa = result.at(i);
		auto keyuns            = ADDRESSES_PREFIX + toBinaryKey(wa.spend_public_key);
		std::string st;
		if (!m_db.get(keyuns, st) || wa.creation_timestamp < boost::lexical_cast<Timestamp>(st)) {
			if (sks.at(i) != SecretKey{})  // Newly generated addresses never lead to undo
				undo_timestamp = std::min(undo_timestamp, wa.creation_timestamp);
			m_db.put(keyuns, common::to_string(wa.creation_timestamp), false);
		}
	}
	if (undo_timestamp == std::numeric_limits<Timestamp>::max()) {
		db_commit();
		return result;
	}
	while (m_tip_height + 1 > m_tail_height &&
	       get_tip().timestamp + m_currency.block_future_time_limit >=
	           undo_timestamp) {  // Undo excess blocks in case timestamps are out of
		                          // order
		undo_block(m_tip_height);
		pop_chain();
	}
	db_commit();
	return result;
}

bool WalletState::sync_with_blockchain(api::bytecoind::SyncBlocks::Response &resp) {
	if (resp.blocks.empty())  // Our creation timestamp > last block timestamp, so
		                      // no blocks
		return true;
	while (m_tip_height > resp.start_height + resp.blocks.size() - 1 &&
	       m_tip_height + 1 > m_tail_height) {  // first undo excess blocks at head
		undo_block(m_tip_height);
		pop_chain();
		m_tx_pool_version = 1;
	}
	while (m_tip_height >= resp.start_height &&
	       m_tip_height + 1 > m_tail_height) {  // then undo all blocks at head with different bids
		const api::BlockHeader &other_header = resp.blocks[m_tip_height - resp.start_height].header;
		if (m_tip.hash == other_header.hash)
			break;
		if (m_tip_height == 0)
			return false;  // Different genesis bid
		undo_block(m_tip_height);
		pop_chain();
		m_tx_pool_version = 1;
	}
	if (m_tip_height + 1 < resp.start_height)
		while (m_tip_height + 1 > m_tail_height) {  // undo everything
			undo_block(m_tip_height);
			pop_chain();
			m_tx_pool_version = 1;
		}
	if (m_tip_height + 1 == m_tail_height) {
		m_tail_height = resp.start_height;
		m_tip_height  = m_tail_height - 1;
	}
	preparator.cancel_work();
	preparator.start_work(resp, m_wallet.get_view_secret_key());
	while (m_tip_height + 1 < resp.start_height + resp.blocks.size()) {
		size_t bin                     = m_tip_height + 1 - resp.start_height;
		const api::BlockHeader &header = resp.blocks.at(bin).header;
		if (m_tip_height + 1 != m_tail_height && header.previous_block_hash != m_tip.hash)
			return false;
		if (header.timestamp + m_currency.block_future_time_limit >= m_wallet.get_oldest_timestamp()) {
			const auto &block_gi = resp.blocks.at(bin).global_indices;
			//			bool our_block = (m_tip_height + 1 == 1319239)
			//|| (m_tip_height + 1 == 1319242) || (m_tip_height + 1 == 1321529);
			//			if( our_block )
			//				test_print_everything("Before
			// redo_block");
			//			redo_block(header, block, block_gi, m_tip_height
			//+ 1);
			//			push_chain(header);
			//			if( our_block )
			//				test_print_everything("Before
			// undo_block");
			//			undo_block(m_tip_height);
			//			pop_chain();
			//			if( our_block )
			//				test_print_everything("After
			// undo_block");
			PreparedWalletBlock pb = preparator.get_ready_work(m_tip_height + 1);
			//			PreparedWalletBlock
			// pb(std::move(resp.blocks.at(bin).block),
			// m_wallet.get_view_secret_key());
			redo_block(header, pb, block_gi, m_tip_height + 1);
			auto now = std::chrono::steady_clock::now();
			if (std::chrono::duration_cast<std::chrono::milliseconds>(now - log_redo_block).count() > 1000) {
				log_redo_block = now;
				std::cout << "WalletState redo block, height=" << m_tip_height << "/"
				          << resp.status.top_known_block_height << std::endl;
			}
		}
		push_chain(header);
		m_tx_pool_version = 1;
	}
	return true;
}

std::vector<Hash> WalletState::get_tx_pool_hashes() const {
	return std::vector<Hash>(m_pool_hashes.begin(), m_pool_hashes.end());
}

bool WalletState::sync_with_blockchain(const api::bytecoind::SyncMemPool::Response &resp) {
	for (auto tid : resp.removed_hashes) {
		if (m_pool_hashes.erase(tid) != 0) {
		}
		m_memory_state.undo_transaction(tid);
	}
	for (size_t i = 0; i != resp.added_binary_transactions.size(); ++i) {
		Transaction tx;
		seria::from_binary(tx, resp.added_binary_transactions[i]);
		std::vector<uint32_t> global_indices(tx.outputs.size(), 0);
		Hash tid = get_transaction_hash(tx);
		if (!m_pool_hashes.insert(tid).second) {  // Already there
			continue;
		}
		PreparedWalletTransaction pwtx(std::move(tx), m_wallet.get_view_secret_key());
		if (!redo_transaction(
		        pwtx, global_indices, &m_memory_state, false, tid, Hash{}, resp.added_transactions.at(i).timestamp)) {
		}
	}
	m_tx_pool_version = resp.status.transaction_pool_version;
	return true;
}

void WalletState::add_transient_transaction(const Hash &tid, const TransactionPrefix &tx) {
	if (!m_pool_hashes.insert(tid).second) {  // Already there
		return;
	}
	std::vector<uint32_t> global_indices(tx.outputs.size(), 0);
	PreparedWalletTransaction pwtx(TransactionPrefix(tx), m_wallet.get_view_secret_key());
	if (!redo_transaction(pwtx, global_indices, &m_memory_state, false, tid, Hash{}, m_tip.timestamp)) {
	}  // just ignore result
}

std::vector<Hash> WalletState::get_sparse_chain() const {
	std::vector<Hash> tip_path;

	uint32_t jump = 0;
	if (m_tip_height + 1 > m_tail_height)
		while (m_tip_height >= jump + m_tail_height) {
			tip_path.push_back(read_chain(m_tip_height - jump).hash);
			if (tip_path.size() <= 10)
				jump += 1;
			else
				jump += (1 << (tip_path.size() - 10));
		}
	if (tip_path.empty() || tip_path.back() != m_genesis_bid)
		tip_path.push_back(m_genesis_bid);
	return tip_path;
}

void WalletState::test_undo_blocks() {
	int counter = 0;
	//	for (DB::Cursor cur = m_db.begin(std::string()); !cur.end(); cur.next()) {
	//		if (cur.get_suffix().find(ADDRESSES_PREFIX) == 0)
	//			continue;
	//		std::cout << DB::clean_key(cur.get_suffix()) << std::endl;
	//		if (counter++ > 2000)
	//			break;
	//	}
	while (m_tip_height + 1 > m_tail_height) {
		undo_block(m_tip_height);
		pop_chain();
	}
	std::cout << "---- After undo everything ---- " << std::endl;
	counter = 0;
	for (DB::Cursor cur = m_db.begin(std::string()); !cur.end(); cur.next()) {
		if (cur.get_suffix().find(ADDRESSES_PREFIX) == 0)
			continue;
		std::cout << DB::clean_key(cur.get_suffix()) << std::endl;
		if (counter++ > 2000)
			break;
	}
}

void WalletState::test_print_everything(const std::string &str) {
	std::cout << str << " tail:tip_height=" << m_tail_height << ":" << get_tip_height() << std::endl;
	for (DB::Cursor cur = m_db.begin(std::string()); !cur.end(); cur.next()) {
		if (cur.get_suffix().find(TIP_CHAIN_PREFIX) == 0)
			continue;
		if (cur.get_suffix().find(ADDRESSES_PREFIX) == 0)
			continue;
		std::cout << DB::clean_key(cur.get_suffix()) << std::endl;
	}
}

bool WalletState::redo_block(const api::BlockHeader &header, const PreparedWalletBlock &pb,
    const BlockChainState::BlockGlobalIndices &global_indices, Height height) {
	if (height != m_tip_height + 1)
		throw std::runtime_error("Redo of incorrect block");
	if (global_indices.size() != pb.transactions.size() + 1)
		return false;  // Bad node
	// order is important here. Unlock before redo, or will lock/unlock twice ->
	// invariant dead
	// If we are redoing first block, there is nothing to unlock
	lock_unlock(height - 1, height, m_tip.timestamp_unlock, header.timestamp_unlock, false);
	DeltaState delta_state(height, header.timestamp_unlock);
	Hash base_hash = pb.base_transaction_hash;  // get_transaction_hash(pb.base_transaction.tx);
	if (!redo_transaction(
	        pb.base_transaction, global_indices[0], &delta_state, true, base_hash, header.hash, pb.header.timestamp)) {
	}  // Just ignore
	bool our_block = (height == 1319239 || height == 1319242 || height == 1321529 || height == 1340382 ||
	                  height == 1341774 || height == 1355639 || height == 1357349);
	if (our_block) {
		//		AccountPublicAddress address{wallet.getRecords().begin()->first,
		// wallet.getViewPublicKey()};
		//		auto bal = get_balance(address, height);
		//		std::cout << "Our block! height=" << height << " balance= " <<
		// currency.formatAmount(bal.total()) <<
		// std::endl;
	}
	for (size_t tx_index = 0; tx_index != pb.transactions.size(); ++tx_index) {
		const Hash tid = pb.header.transaction_hashes.at(tx_index);
		if (m_pool_hashes.erase(tid) != 0) {
			//	std::cout << "RACE remove tx in redo_block tx=" <<
			// common::pod_to_hex(tid) << std::endl;
		}
		m_memory_state.undo_transaction(tid);
		if (!redo_transaction(pb.transactions.at(tx_index), global_indices.at(tx_index + 1), &delta_state, false, tid,
		        header.hash, pb.header.timestamp)) {
		}  // just ignore
	}
	try {
		delta_state.apply(this);
	} catch (const std::exception &ex) {
		std::cout << "Exception in delta_state.apply, probably out of disk space ex.what=" << ex.what() << std::endl;
		std::exit(api::BYTECOIND_DATABASE_ERROR);
	}
	if (our_block) {
		//		AccountPublicAddress address{wallet.getRecords().begin()->first,
		// wallet.getViewPublicKey()};
		//		auto bal = get_balance(address, height);
		//		std::cout << "Height = " << height << " balance= " <<
		// currency.formatAmount(bal.total()) << std::endl;
	}
	return true;
}

void WalletState::undo_block(Height height) {
	try {
		auto prefix = HEIGHT_KEYIMAGE_PREFIX + DB::to_ascending_key(height) + "/";
		for (DB::Cursor cur = m_db.begin(prefix); !cur.end(); cur.erase()) {
			KeyImage ki;
			DB::from_binary_key(cur.get_suffix(), 0, ki.data, sizeof(ki.data));
			undo_height_keyimage(height, ki);
		}
		prefix = HEIGHT_OUTPUT_PREFIX + DB::to_ascending_key(height) + "/";
		for (DB::Cursor cur = m_db.begin(prefix); !cur.end(); cur.erase()) {
			api::Output output;
			seria::from_binary(output, cur.get_value_array());
			undo_keyimage_output(output);
		}
		// Undo history here
		prefix = HEIGHT_TRANSACTION_PREFIX + DB::to_ascending_key(height) + "/";
		for (DB::Cursor cur = m_db.begin(prefix); !cur.end(); cur.erase()) {
			Hash tid;
			DB::from_binary_key(cur.get_suffix(), 0, tid.data, sizeof(tid.data));
			undo_transaction(height, tid);
		}

		api::BlockHeader prev_header;
		if (!read_chain(height - 1, prev_header))
			return;  // If we are just undone tail block, there should be no outputs, so
		// nothing to lock
		lock_unlock(height - 1, height, prev_header.timestamp_unlock, m_tip.timestamp_unlock, true);
	} catch (const std::exception &ex) {
		std::cout << "Exception in WalletState undo_block, probably out of disk space ex.what=" << ex.what()
		          << std::endl;
		std::exit(api::BYTECOIND_DATABASE_ERROR);
	}
}

bool WalletState::parse_raw_transaction(api::Transaction &ptx, const TransactionPrefix &tx, Hash tid) const {
	std::vector<uint32_t> global_indices(tx.outputs.size(), 0);
	Amount output_amount;
	PreparedWalletTransaction pwtx(TransactionPrefix(tx), m_wallet.get_view_secret_key());
	if (!parse_raw_transaction(ptx, output_amount, pwtx, tid, global_indices, get_tip_height(),
	        get_tip().timestamp_unlock))  // TODO +1 ?
		return false;
	Amount input_amount = 0;
	api::Transfer input_transfer;  // We do not know "from" addresses, so leave
	                               // address empty
	input_transfer.ours = true;
	for (const auto &input : tx.inputs) {
		if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			input_amount += in.amount;
			ptx.fee += in.amount;
			ptx.anonymity = std::min(ptx.anonymity, static_cast<uint32_t>(in.output_indexes.size() - 1));

			input_transfer.amount -= static_cast<SignedAmount>(in.amount);
		}
	}
	ptx.transfers.push_back(input_transfer);
	ptx.amount = std::max(input_amount, output_amount);
	if (ptx.anonymity == std::numeric_limits<uint32_t>::max())
		ptx.anonymity = 0;  // No key inputs
	return true;
}

bool WalletState::parse_raw_transaction(api::Transaction &ptx, Amount &output_amount,
    const PreparedWalletTransaction &pwtx, Hash tid, const std::vector<uint32_t> &global_indices, Height block_height,
    Timestamp block_unlock_timestamp) const {
	if (global_indices.size() != pwtx.tx.outputs.size())  // Bad node
		return false;
	const TransactionPrefix &tx = pwtx.tx;
	PublicKey tx_public_key     = get_transaction_public_key_from_extra(tx.extra);
	if (pwtx.derivation == KeyDerivation{})
		return false;
	Wallet::History history = m_wallet.load_history(tid);
	KeyPair tx_keys;
	ptx.hash         = tid;
	ptx.block_height = block_height;
	ptx.anonymity    = std::numeric_limits<uint32_t>::max();
	ptx.unlock_time  = tx.unlock_time;
	const bool tx_unlocked =
	    m_currency.is_transaction_spend_time_unlocked(ptx.unlock_time, block_height, block_unlock_timestamp);
	ptx.public_key = tx_public_key;
	ptx.extra      = tx.extra;
	get_payment_id_from_tx_extra(tx.extra, ptx.payment_id);
	size_t key_index   = 0;
	uint32_t out_index = 0;
	output_amount      = 0;
	// We combine outputs into transfers by address
	std::map<AccountPublicAddress, api::Transfer> transfer_map;
	for (const auto &output : tx.outputs) {
		const auto global_index = global_indices.at(out_index);
		output_amount += output.amount;
		ptx.fee -= output.amount;
		if (output.target.type() == typeid(KeyOutput)) {
			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			PublicKey spend_key         = pwtx.spend_keys.at(key_index);
			bool our_key                = false;
			if (spend_key != PublicKey{}) {
				auto sk = m_wallet.get_records().find(spend_key);
				if (sk != m_wallet.get_records().end()) {
					KeyPair in_ephemeral;
					if (derive_public_key(pwtx.derivation, out_index, spend_key, in_ephemeral.publicKey)) {
						derive_secret_key(
						    pwtx.derivation, out_index, sk->second.spend_secret_key, in_ephemeral.secretKey);
						//	std::cout << "My output!
						// outIndex=" << out_index << "amount=" << output.amount << std::endl;
						AccountPublicAddress address{spend_key, m_wallet.get_view_public_key()};
						api::Output out;
						out.amount               = output.amount;
						out.dust                 = Currency::is_dust(output.amount);
						out.global_index         = global_index;
						out.height               = block_height;
						out.index_in_transaction = out_index;
						generate_key_image(in_ephemeral.publicKey, in_ephemeral.secretKey, out.key_image);
						out.public_key             = key_output.key;
						out.transaction_public_key = tx_public_key;
						out.unlock_time            = tx.unlock_time;
						api::Transfer &transfer    = transfer_map[address];
						transfer.amount += output.amount;
						transfer.ours = true;
						transfer.outputs.push_back(out);
						our_key = true;
					}
				}
			}
			if (!our_key && !history.empty()) {
				if (tx_keys.secretKey == SecretKey{})
					tx_keys = TransactionBuilder::deterministic_keys_from_seed(tx, m_wallet.get_tx_derivation_seed());
				for (auto &&addr : history) {
					PublicKey guess_key{};
					TransactionBuilder::derive_public_key(addr, tx_keys.secretKey, out_index, guess_key);
					if (guess_key == key_output.key) {
						api::Output out;
						out.amount       = output.amount;
						out.dust         = Currency::is_dust(output.amount);
						out.global_index = global_index;
						out.height       = block_height;
						// We cannot generate key_image for others addresses
						out.index_in_transaction   = out_index;
						out.public_key             = key_output.key;
						out.transaction_public_key = tx_public_key;
						out.unlock_time            = tx.unlock_time;
						api::Transfer &transfer    = transfer_map[addr];
						transfer.amount += output.amount;
						transfer.ours = false;
						transfer.outputs.push_back(out);
					}
				}
			}
			++key_index;
		}
		++out_index;
	}
	for (auto &&tm : transfer_map) {
		tm.second.address = m_currency.account_address_as_string(tm.first);
		tm.second.locked  = !tx_unlocked;
		for (auto &&out : tm.second.outputs)
			out.address = tm.second.address;
		ptx.transfers.push_back(std::move(tm.second));
	}
	return true;
}

bool WalletState::redo_transaction(const PreparedWalletTransaction &pwtx, const std::vector<uint32_t> &global_indices,
    DeltaState *delta_state, bool is_base, Hash tid, Hash bid, Timestamp tx_timestamp) {
	api::Transaction ptx;
	Amount output_amount = 0;
	if (!parse_raw_transaction(ptx, output_amount, pwtx, tid, global_indices, delta_state->get_block_height(),
	        delta_state->get_unlock_timestamp()))
		return false;
	bool our_transaction = false;
	for (auto &&tr : ptx.transfers) {
		if (!tr.ours)
			continue;
		our_transaction = true;
		for (auto &&out : tr.outputs)
			delta_state->redo_keyimage_output(out, 0, 0);  // TODO - refactor
	}
	ptx.block_hash = bid;
	ptx.coinbase   = is_base;
	ptx.timestamp  = tx_timestamp;
	std::map<std::string, api::Transfer> transfer_map2;
	Amount input_amount = 0;
	for (const auto &input : pwtx.tx.inputs) {
		if (input.type() == typeid(CoinbaseInput)) {
			// Just ignore
		} else if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			input_amount += in.amount;
			ptx.fee += in.amount;
			ptx.anonymity = std::min(ptx.anonymity, static_cast<uint32_t>(in.output_indexes.size()));
			auto key      = KEYIMAGE_PREFIX + toBinaryKey(in.key_image);
			BinaryArray rb;
			if (m_db.get(key, rb)) {
				api::Output output;
				seria::from_binary(output, rb);

				api::Transfer &transfer = transfer_map2[output.address];
				transfer.amount -= static_cast<SignedAmount>(output.amount);
				transfer.ours = true;
				transfer.outputs.push_back(output);
				our_transaction = true;

				delta_state->redo_height_keyimage(delta_state->get_block_height(), in.key_image);
			}
		}
	}
	for (auto &&tm : transfer_map2) {
		tm.second.address = tm.first;
		ptx.transfers.push_back(tm.second);
	}
	ptx.amount = std::max(input_amount, output_amount);
	if (ptx.anonymity == std::numeric_limits<uint32_t>::max())
		ptx.anonymity = 0;  // No key inputs
	if (is_base)
		ptx.fee = 0;
	if (our_transaction)
		delta_state->redo_transaction(delta_state->get_block_height(), tid, pwtx.tx, ptx);
	return true;
}

bool WalletState::read_tips() {
	BinaryArray rb;
	if (!m_db.get("$genesis_bid", rb))
		return false;
	Hash other_genesis_bid;
	seria::from_binary(other_genesis_bid, rb);
	if (m_genesis_bid != other_genesis_bid)  // TODO - return error or clear DB
		throw std::runtime_error("Database holds different genesis bid");
	std::string val1;
	if (!m_db.get("$tip_height", val1))
		throw std::logic_error("Database holds no tip_height");
	m_tip_height = boost::lexical_cast<Height>(val1);
	if (!m_db.get("$tail_height", val1))
		throw std::logic_error("Database holds no tail_height");
	m_tail_height = boost::lexical_cast<Height>(val1);
	m_tip         = (m_tip_height + 1 == m_tail_height) ? api::BlockHeader{} : read_chain(m_tip_height);
	return true;
}

void WalletState::push_chain(const api::BlockHeader &header) {
	m_tip_height += 1;
	BinaryArray ba = seria::to_binary(header);
	m_db.put(TIP_CHAIN_PREFIX + DB::to_ascending_key(m_tip_height), ba, true);
	m_db.put("$tip_height", common::to_string(m_tip_height), false);
	m_tip = header;
	m_db.put("$tail_height", common::to_string(m_tail_height), false);
	m_memory_state.set_height(m_tip_height + 1);
}

void WalletState::pop_chain() {
	if (m_tip_height + 1 == m_tail_height)
		throw std::logic_error("pop_chain tip_height == -1");
	m_db.del(TIP_CHAIN_PREFIX + DB::to_ascending_key(m_tip_height), true);
	m_tip_height -= 1;
	m_db.put("$tip_height", common::to_string(m_tip_height), false);
	m_tip = (m_tip_height + 1 == m_tail_height) ? api::BlockHeader{} : read_chain(m_tip_height);
}

bool WalletState::read_chain(uint32_t height, api::BlockHeader &header) const {
	BinaryArray rb;
	if (!m_db.get(TIP_CHAIN_PREFIX + DB::to_ascending_key(height), rb))
		return false;
	seria::from_binary(header, rb);
	return true;
}

api::BlockHeader WalletState::read_chain(uint32_t height) const {
	api::BlockHeader ha;
	if (!read_chain(height, ha))
		throw std::logic_error("read_header_chain failed");
	return ha;
}

void WalletState::redo_transaction(
    Height height, const Hash &tid, const TransactionPrefix &tx, const api::Transaction &ptx) {
	auto cur = m_db.begin(TRANSACTION_PREFIX);
	if (cur.end())
		m_wallet.on_first_output_found(ptx.timestamp);
	auto trkey         = TRANSACTION_PREFIX + toBinaryKey(tid);
	auto hetrkey       = HEIGHT_TRANSACTION_PREFIX + DB::to_ascending_key(height) + "/" + toBinaryKey(tid);
	BinaryArray str_pa = seria::to_binary(std::make_pair(tx, ptx));
	BinaryArray str    = seria::to_binary(ptx);
	m_db.put(trkey, str_pa, true);
	m_db.put(hetrkey, str, true);
	std::set<std::string> addresses;
	for (auto &&transfer : ptx.transfers) {
		addresses.insert(transfer.address);
	}
	for (auto &&addr : addresses) {
		auto adtrkey =
		    ADDRESS_HEIGHT_TRANSACTION_PREFIX + addr + "/" + DB::to_ascending_key(height) + "/" + toBinaryKey(tid);
		m_db.put(adtrkey, str, true);
	}
}

void WalletState::undo_transaction(Height height, const Hash &tid) {
	auto trkey   = TRANSACTION_PREFIX + toBinaryKey(tid);
	auto hetrkey = HEIGHT_TRANSACTION_PREFIX + DB::to_ascending_key(height) + "/" + toBinaryKey(tid);
	BinaryArray data;
	if (!m_db.get(trkey, data))
		throw std::logic_error("Invariant dead - transaction does not exist in undo_transaction");
	std::pair<TransactionPrefix, api::Transaction> pa;
	seria::from_binary(pa, data);
	m_db.del(trkey, true);
	//	db.del(hetrkey, true); // Will be deleted during iteration
	std::set<std::string> addresses;
	for (auto &&transfer : pa.second.transfers) {
		addresses.insert(transfer.address);
	}
	for (auto &&addr : addresses) {
		auto adtrkey =
		    ADDRESS_HEIGHT_TRANSACTION_PREFIX + addr + "/" + DB::to_ascending_key(height) + "/" + toBinaryKey(tid);
		m_db.del(adtrkey, true);
	}
}

void WalletState::add_to_lock_index(const api::Output &output) {
	//	std::cout << "Lock am=" << output.amount / 1E8 << " gi=" <<
	// output.global_index << " un=" << output.unlock_time << std::endl;
	BinaryArray ba = seria::to_binary(output);

	std::string unkey;
	uint32_t clamped_unlock_time = static_cast<uint32_t>(std::min<UnlockMoment>(output.unlock_time, 0xFFFFFFFF));
	if (m_currency.is_transaction_spend_time_block(output.unlock_time))
		unkey = UNLOCK_BLOCK_PREFIX + DB::to_ascending_key(clamped_unlock_time) + "/" +
		        common::to_string(output.amount) + "/" + common::to_string(output.global_index);
	else
		unkey = UNLOCK_TIME_PREFIX + DB::to_ascending_key(clamped_unlock_time) + "/" +
		        common::to_string(output.amount) + "/" + common::to_string(output.global_index);
	m_db.put(unkey, ba, true);
}

bool WalletState::remove_from_lock_index(const api::Output &output, bool mustexist) {
	//	std::cout << "Unlock am=" << output.amount / 1E8 << " gi=" <<
	// output.global_index << " un=" << output.unlock_time << std::endl;
	std::string unkey;
	uint32_t clamped_unlock_time = static_cast<uint32_t>(std::min<UnlockMoment>(output.unlock_time, 0xFFFFFFFF));
	if (m_currency.is_transaction_spend_time_block(output.unlock_time))
		unkey = UNLOCK_BLOCK_PREFIX + DB::to_ascending_key(clamped_unlock_time) + "/" +
		        common::to_string(output.amount) + "/" + common::to_string(output.global_index);
	else
		unkey = UNLOCK_TIME_PREFIX + DB::to_ascending_key(clamped_unlock_time) + "/" +
		        common::to_string(output.amount) + "/" + common::to_string(output.global_index);
	std::string was_value;
	if (!mustexist && !m_db.get(unkey, was_value))
		return false;
	m_db.del(unkey, true);
	return true;
}

void WalletState::add_to_unspent_index(const api::Output &output) {
	//	if (output.unlock_time)
	//		std::cout << "Add unspent am=" << output.amount / 1E8 << " gi="
	//	<< output.global_index
	//		          << " un=" << output.unlock_time << std::endl;
	modify_balance(output, 0, 1);
	auto keyuns = UNSPENT_HEIGHT_PREFIX + output.address + "/" + DB::to_ascending_key(output.height) + "/" +
	              common::to_string(output.amount) + "/" + common::to_string(output.global_index);
	BinaryArray ba2 = seria::to_binary(output);
	m_db.put(keyuns, ba2, true);

	auto hekeyuns = HEIGHT_UNSPENT_PREFIX + DB::to_ascending_key(output.height) + "/" + output.address + "/" +
	                common::to_string(output.amount) + "/" + common::to_string(output.global_index);
	m_db.put(hekeyuns, ba2, true);
}

void WalletState::remove_from_unspent_index(const api::Output &output) {
	//	if (output.unlock_time)
	//		std::cout << "Remove unspent am=" << output.amount / 1E8 << "
	// gi=" << output.global_index
	//		          << " un=" << output.unlock_time << std::endl;
	modify_balance(output, 0, -1);
	auto keyuns = UNSPENT_HEIGHT_PREFIX + output.address + "/" + DB::to_ascending_key(output.height) + "/" +
	              common::to_string(output.amount) + "/" + common::to_string(output.global_index);
	m_db.del(keyuns, true);
	auto hekeyuns = HEIGHT_UNSPENT_PREFIX + DB::to_ascending_key(output.height) + "/" + output.address + "/" +
	                common::to_string(output.amount) + "/" + common::to_string(output.global_index);
	m_db.del(hekeyuns, true);
}

bool WalletState::is_unspent(const api::Output &output) const {
	BinaryArray ba = seria::to_binary(output);
	auto keyuns    = UNSPENT_HEIGHT_PREFIX + output.address + "/" + DB::to_ascending_key(output.height) + "/" +
	              common::to_string(output.amount) + "/" + common::to_string(output.global_index);
	return m_db.get(keyuns, ba);
}

static void combineBalance(api::Balance &balance, const api::Output &output, int lockedOp, int spendable_op) {
	Amount &mod = output.dust ? balance.spendable_dust : balance.spendable;
	if (lockedOp > 0)
		balance.locked_or_unconfirmed += output.amount;
	if (lockedOp < 0)
		balance.locked_or_unconfirmed -= output.amount;
	if (spendable_op > 0)
		mod += output.amount;
	if (spendable_op < 0)
		mod -= output.amount;
}

void WalletState::modify_balance(const api::Output &output, int locked_op, int spendable_op) {
	auto bakey  = ADDRESS_BALANCE_PREFIX + output.address;
	auto bakey2 = BALANCE_PREFIX;
	BinaryArray ba;
	api::Balance balance;
	api::Balance balance2;
	if (m_db.get(bakey, ba))
		seria::from_binary(balance, ba);
	if (m_db.get(bakey2, ba))
		seria::from_binary(balance2, ba);
	//	std::cout << "modify_balance " << output.amount << " lockedOp=" <<
	// locked_op << " spendableOp=" << spendable_op << std::endl;
	combineBalance(balance, output, locked_op, spendable_op);
	combineBalance(balance2, output, locked_op, spendable_op);
	if (balance.total() == 0)
		m_db.del(bakey, false);
	else
		m_db.put(bakey, seria::to_binary(balance), false);
	if (balance2.total() == 0)
		m_db.del(bakey2, false);
	else
		m_db.put(bakey2, seria::to_binary(balance2), false);
}

// Add new unspent
void WalletState::redo_keyimage_output(const api::Output &output,
    Height block_height,
    Timestamp block_unlock_timestamp) {
	BinaryArray ba = seria::to_binary(output);

	auto kikey = KEYIMAGE_PREFIX + toBinaryKey(output.key_image);
	BinaryArray ba2;
	if (m_db.get(kikey, ba2)) {
		// Protect against an attack with 2 identical output.public_key (and hence
		// keyimages) in 2 different transactions
		return;
	}
	m_db.put(kikey, ba, true);
	auto keyout = HEIGHT_OUTPUT_PREFIX + DB::to_ascending_key(output.height) + "/" + common::to_string(output.amount) +
	              "/" + common::to_string(output.global_index);
	m_db.put(keyout, ba, true);

	if (!m_currency.is_transaction_spend_time_unlocked(output.unlock_time, block_height, block_unlock_timestamp)) {
		add_to_lock_index(output);
		modify_balance(output, 1, 0);
		return;
	}
	add_to_unspent_index(output);
}

// Undo unspent
void WalletState::undo_keyimage_output(const api::Output &output) {
	auto kikey = KEYIMAGE_PREFIX + toBinaryKey(output.key_image);
	BinaryArray ba2;
	if (!m_db.get(kikey, ba2))
		throw std::logic_error("Keyimage not found for undo, invariant dead");
	api::Output was_output;
	seria::from_binary(was_output, ba2);
	if (output.amount != was_output.amount || output.global_index != was_output.global_index) {
		// Protect against an attack with 2 identical output.public_key (and hence
		// keyimages) in 2 different transactions
		// Subsequent outputs cannot have the same global_index, as global_index is
		// incremented on each output
		return;
	}
	m_db.del(kikey, true);

	if (!m_currency.is_transaction_spend_time_unlocked(output.unlock_time, m_tip_height, m_tip.timestamp_unlock)) {
		modify_balance(output, -1, 0);
		remove_from_lock_index(output, true);
		return;
	}
	remove_from_unspent_index(output);  // We remove height_unspent during iteration
}

// Unique in that it reads (begin, end] interval, not [begin, end) as most other
// funs. That is because block height 312
// unlocks output with unlock_time=312
void WalletState::read_unlock_index(std::map<std::pair<Amount, uint32_t>, api::Output> &add,
    const std::string &index_prefix, uint32_t begin, uint32_t end) const {
	if (begin >= end)  // optimization
		return;
	auto middle = DB::to_ascending_key(begin + 1) + "/";
	for (DB::Cursor cur = m_db.begin(index_prefix, middle); !cur.end(); cur.next()) {
		std::string svalue, rest;
		if (!common::split_string(cur.get_suffix(), "/", svalue, rest))
			throw std::logic_error("Invariant dead read_unlock_index corrupted");
		auto val = DB::from_ascending_key(svalue);
		if (val > end)
			break;
		api::Output output;
		seria::from_binary(output, cur.get_value_array());
		add.insert(std::make_pair(std::make_pair(output.amount, output.global_index), output));
	}
}

void WalletState::lock_unlock(Height prev_height, Height now_height, Timestamp prev, Timestamp now, bool lock) {
	std::map<std::pair<Amount, uint32_t>, api::Output> outputs;
	read_unlock_index(outputs, UNLOCK_BLOCK_PREFIX, prev_height + m_currency.locked_tx_allowed_delta_blocks,
	    now_height + m_currency.locked_tx_allowed_delta_blocks);
	read_unlock_index(outputs, UNLOCK_TIME_PREFIX, prev + m_currency.locked_tx_allowed_delta_seconds,
	    now + m_currency.locked_tx_allowed_delta_seconds);

	for (auto &&mit : outputs)
		if (lock) {
			remove_from_unspent_index(mit.second);
			modify_balance(mit.second, 1, 0);
		} else {
			modify_balance(mit.second, -1, 0);
			add_to_unspent_index(mit.second);
		}
}

// Spend unspent
void WalletState::redo_height_keyimage(Height height, const KeyImage &keyimage) {
	auto key = KEYIMAGE_PREFIX + toBinaryKey(keyimage);
	BinaryArray rb;
	if (m_db.get(key, rb)) {
		api::Output output;
		seria::from_binary(output, rb);

		// Code below is used temporarily to allow spending locked outputs (due to
		// changes to unlock code in new version)
		auto keyuns = UNSPENT_HEIGHT_PREFIX + output.address + "/" + DB::to_ascending_key(output.height) + "/" +
		              common::to_string(output.amount) + "/" + common::to_string(output.global_index);
		bool was_unlocked = m_db.get(keyuns, rb);
		if (was_unlocked)
			remove_from_unspent_index(output);
		bool was_in_lockindex = remove_from_lock_index(output, false);

		auto hekey = HEIGHT_KEYIMAGE_PREFIX + DB::to_ascending_key(height) + "/" + toBinaryKey(keyimage);
		m_db.put(hekey, seria::to_binary(std::make_pair(was_unlocked, was_in_lockindex)), true);
	}
}

// Undo spend
void WalletState::undo_height_keyimage(Height height, const KeyImage &keyimage) {
	auto key = KEYIMAGE_PREFIX + toBinaryKey(keyimage);
	BinaryArray rb;
	if (!m_db.get(key, rb))
		throw std::logic_error("Invariant dead undo_height_keyimage keyimage does not exist");
	api::Output output;
	seria::from_binary(output, rb);
	auto hekey = HEIGHT_KEYIMAGE_PREFIX + DB::to_ascending_key(height) + "/" + toBinaryKey(keyimage);
	BinaryArray ba;
	m_db.get(hekey, ba);
	std::pair<bool, bool> was_unlocked_was_in_lockindex{};
	seria::from_binary(was_unlocked_was_in_lockindex, ba);

	if (was_unlocked_was_in_lockindex.second)
		add_to_lock_index(output);
	if (was_unlocked_was_in_lockindex.first)
		add_to_unspent_index(output);
	//	auto hekey = HEIGHT_KEYIMAGE_PREFIX + DB::to_ascending_key(height) + "/"
	//+ DB::to_binary_key(keyimage.data,
	// sizeof(keyimage.data));
	//	db.del(hekey, true); // Removed during iteration in undo_block
}

std::vector<api::Output> WalletState::api_get_unspent(
    const std::string &address, Height height, Amount max_amount) const {
	std::vector<api::Output> result;
	auto prefix = HEIGHT_UNSPENT_PREFIX;
	if (!address.empty())
		prefix             = UNSPENT_HEIGHT_PREFIX + address + "/";
	auto unlocked_outputs  = api_get_unlocked_outputs(address, height, m_tip_height);
	Amount total_amount    = 0;
	const size_t min_count = 10000;  // We return up to 10k outputs after we find requested sum
	for (DB::Cursor cur = m_db.begin(prefix); !cur.end(); cur.next()) {
		std::string shei, rest;
		if (!common::split_string(cur.get_suffix(), "/", shei, rest))
			throw std::logic_error("Invariant dead api_get_unspent index corrupted");
		if (DB::from_ascending_key(shei) > height)
			break;
		api::Output item;
		seria::from_binary(item, cur.get_value_array());
		if (!m_memory_state.is_spent(item) &&
		    unlocked_outputs.count(std::make_pair(item.amount, item.global_index)) == 0)
			result.push_back(item);
		if (!item.dust)  // We ensure total can be spent with non-zero anonymity
			total_amount += item.amount;
		if (total_amount >= max_amount && result.size() >= min_count)
			break;
	}
	return result;
}

std::vector<api::Output> WalletState::api_get_locked_or_unconfirmed_unspent(const std::string &address,
    Height height) const {
	std::vector<api::Output> result;
	const auto &uns = m_memory_state.get_unspents();
	if (address.empty()) {
		for (auto &&auns : uns)
			for (auto &&out : auns.second)
				result.push_back(out);
	} else {
		for (auto &&auns : uns)
			for (auto &&out : auns.second)
				if (out.address == address)
					result.push_back(out);
	}
	auto prefix = HEIGHT_UNSPENT_PREFIX;
	if (!address.empty())
		prefix         = UNSPENT_HEIGHT_PREFIX + address + "/";
	std::string middle = common::to_string(height + 1) + "/";
	for (DB::Cursor cur = m_db.begin(prefix, middle); !cur.end(); cur.next()) {
		std::string shei, rest;
		if (!common::split_string(cur.get_suffix(), "/", shei, rest))
			throw std::logic_error(
			    "Invariant dead api_get_locked_or_unconfirmed_unspent index "
			    "corrupted");
		api::Output item;
		seria::from_binary(item, cur.get_value_array());
		if (!m_memory_state.is_spent(item))
			result.push_back(item);
	}
	std::map<std::pair<Amount, uint32_t>, api::Output> locked;
	read_unlock_index(locked, UNLOCK_BLOCK_PREFIX, m_tip_height, std::numeric_limits<Height>::max());
	read_unlock_index(locked, UNLOCK_TIME_PREFIX, m_tip.timestamp_unlock, std::numeric_limits<Height>::max());
	for (auto &&lou : locked) {
		if (!m_memory_state.is_spent(lou.second))
			result.push_back(lou.second);
	}
	return result;
}

std::vector<api::Block> WalletState::api_get_transfers(
    const std::string &address, Height &from_height, Height &to_height, bool forward, uint32_t desired_tx_count) const {
	std::vector<api::Block> result;
	if (from_height >= to_height)
		return result;
	auto prefix        = HEIGHT_TRANSACTION_PREFIX;
	std::string middle = DB::to_ascending_key(forward ? from_height + 1 : to_height) + "/";
	if (!address.empty())
		prefix = ADDRESS_HEIGHT_TRANSACTION_PREFIX + address + "/";
	api::Block current_block;
	size_t total_transactions_found = 0;
	for (DB::Cursor cur = forward ? m_db.begin(prefix, middle) : m_db.rbegin(prefix, middle); !cur.end(); cur.next()) {
		std::string shei, rest;
		if (!common::split_string(cur.get_suffix(), "/", shei, rest))
			throw std::logic_error("Invariant dead api_get_transfers index corrupted");
		Height height = DB::from_ascending_key(shei);
		if (forward && height > to_height)
			break;
		if (!forward && height <= from_height)
			break;
		api::Transaction tx;
		seria::from_binary(tx, cur.get_value_array());
		if (current_block.header.height != height && !current_block.transactions.empty()) {
			result.push_back(std::move(current_block));
			current_block = api::Block();
			if (total_transactions_found >= desired_tx_count) {
				if (forward)
					to_height = height - 1;
				else
					from_height = height;
				break;
			}
		}
		if (current_block.transactions.empty()) {
			read_chain(height, current_block.header);
		}
		current_block.transactions.push_back(std::move(tx));
		total_transactions_found += 1;
	}
	if (!current_block.transactions.empty()) {
		result.push_back(std::move(current_block));
	}
	return result;
}

bool WalletState::api_get_transaction(Hash tid, TransactionPrefix &tx, api::Transaction &ptx) const {
	auto trkey = TRANSACTION_PREFIX + toBinaryKey(tid);
	BinaryArray data;
	if (!m_db.get(trkey, data))
		return false;
	std::pair<TransactionPrefix, api::Transaction> pa;
	seria::from_binary(pa, data);
	tx  = std::move(pa.first);
	ptx = std::move(pa.second);
	return true;
}

bool WalletState::api_create_proof(SendProof &sp) const {
	TransactionPrefix tx;
	api::Transaction ptx;
	if (!api_get_transaction(sp.transaction_hash, tx, ptx)) {
		auto mit = m_memory_state.get_transactions().find(sp.transaction_hash);
		if (mit == m_memory_state.get_transactions().end())
			return false;
		tx  = mit->second.first;
		ptx = mit->second.second;
	}
	KeyPair tx_keys = TransactionBuilder::deterministic_keys_from_seed(tx, m_wallet.get_tx_derivation_seed());
	if (!crypto::generate_key_derivation(sp.address.view_public_key, tx_keys.secretKey, sp.derivation))
		return false;
	Hash message_hash = crypto::cn_fast_hash(sp.message.data(), sp.message.size());
	if (!crypto::generate_send_proof(tx_keys.publicKey, tx_keys.secretKey, sp.address.view_public_key, sp.derivation,
	        message_hash, sp.signature))
		return false;
	Amount total_amount = 0;
	size_t key_index    = 0;
	uint32_t out_index  = 0;
	for (const auto &output : tx.outputs) {
		if (output.target.type() == typeid(KeyOutput)) {
			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			PublicKey spend_key;
			if (underive_public_key(sp.derivation, key_index, key_output.key, spend_key) &&
			    spend_key == sp.address.spend_public_key) {
				total_amount += output.amount;
			}
			++key_index;
		}
		++out_index;
	}
	sp.amount = total_amount;
	return total_amount != 0;
}

api::Block WalletState::api_get_pool_as_history(const std::string &address) const {
	// TODO - filter by address?
	api::Block current_block;
	current_block.header.height = get_tip_height() + 1;
	for (auto &&hit : m_memory_state.get_transactions()) {
		current_block.transactions.push_back(hit.second.second);
		current_block.transactions.back().block_height = get_tip_height() + 1;
	}
	return current_block;
}

std::map<std::pair<Amount, uint32_t>, api::Output> WalletState::api_get_unlocked_outputs(const std::string &address,
    Height from_height,
    Height to_height) const {
	std::map<std::pair<Amount, uint32_t>, api::Output> locked;
	if (m_tip_height + 1 == m_tail_height)
		return locked;
	if (from_height >= to_height || from_height > m_tip_height || to_height <= m_tail_height)
		return locked;
	read_unlock_index(locked, UNLOCK_BLOCK_PREFIX, from_height, to_height);
	if (from_height <= m_tip_height) {
		Timestamp sta = from_height < m_tail_height ? 0 : read_chain(from_height).timestamp_unlock;
		Timestamp fin =
		    to_height > m_tip_height ? std::numeric_limits<Timestamp>::max() : read_chain(to_height).timestamp_unlock;
		read_unlock_index(locked, UNLOCK_TIME_PREFIX, sta, fin);
	}
	return locked;
}

api::Balance WalletState::get_balance(const std::string &address, Height height) const {
	auto bakey = BALANCE_PREFIX;
	if (!address.empty())
		bakey = ADDRESS_BALANCE_PREFIX + address;
	BinaryArray ba;
	api::Balance balance;
	if (m_db.get(bakey, ba))
		seria::from_binary(balance, ba);
	Height from_height = height;
	Height to_height   = get_tip_height();
	auto blocks        = api_get_transfers(address, from_height, to_height, true);
	for (auto &&hh : blocks) {
		for (auto &&tx : hh.transactions) {
			if (tx.unlock_time != 0)
				continue;
			for (auto &&tt : tx.transfers) {
				if (!tt.ours || (!address.empty() && address != tt.address))
					continue;
				if (tt.amount > 0)
					for (auto &&ou : tt.outputs) {
						if (is_unspent(ou) && !m_memory_state.is_spent(ou))
							combineBalance(balance, ou, 1, -1);
					}
			}
		}
	}
	auto unlocked_outputs = api_get_unlocked_outputs(address, height, m_tip_height);
	for (auto &&ou : unlocked_outputs) {  // TODO - correct behaviour of
		                                  // memory-pool-spent unlocked outputs
		if (!m_memory_state.is_spent(ou.second))
			combineBalance(balance, ou.second, 1, -1);
	}
	for (auto &&hit : m_memory_state.get_transactions()) {
		const api::Transaction &tx = hit.second.second;
		if (tx.unlock_time != 0)
			continue;
		for (auto &&tt : tx.transfers) {
			if (!tt.ours || (!address.empty() && address != tt.address))
				continue;
			if (tt.amount > 0)
				for (auto &&ou : tt.outputs)
					combineBalance(balance, ou, 1, 0);
			else
				for (auto &&ou : tt.outputs)
					combineBalance(balance, ou, 0, -1);
		}
	}
	return balance;
}
