// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletState.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "TransactionExtra.hpp"
#include "common/Base58.hpp"
#include "common/Varint.hpp"
#include "common/string.hpp"
#include "crypto/crypto.hpp"
#include "platform/PathTools.hpp"
#include "platform/Time.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

static const std::string ADDRESSES_PREFIX = "a";  // this is not undone

using namespace cn;
using namespace platform;

bool WalletState::DeltaState::add_incoming_output(const api::Output &output) {
	m_unspents[output.public_key].push_back(output);
	return true;
}

Amount WalletState::DeltaState::add_incoming_keyimage(Height height, const KeyImage &key_image) {
	auto tit = m_transactions.find(m_last_added_transaction);
	if (tit == m_transactions.end())
		return 0;
	if (tit->second.used_keyimages.insert(key_image).second)
		m_used_keyimages[key_image] += 1;
	return 0;  // It does not know
}

void WalletState::DeltaState::add_transaction(
    Height, const Hash &tid, const TransactionPrefix &tx, const api::Transaction &ptx) {
	invariant(m_transactions.insert(std::make_pair(tid, DeltaStateTransaction{tx, ptx, {}})).second,
	    "transaction already exists. Invariant dead");
	m_last_added_transaction = tid;
}

void WalletState::DeltaState::undo_transaction(const Hash &tid) {
	auto tit = m_transactions.find(tid);
	if (tit == m_transactions.end())
		return;
	const TransactionPrefix &tx = tit->second.tx;
	for (const auto &output : tx.outputs) {
		if (output.type() == typeid(OutputKey)) {
			const auto &key_output = boost::get<OutputKey>(output);
			auto uit               = m_unspents.find(key_output.public_key);
			if (uit == m_unspents.end())  // Actually should never be empty
				continue;                 // Not our output
			for (auto oit = uit->second.begin(); oit != uit->second.end(); ++oit)
				if (oit->amount == key_output.amount) {  // We need to pop right output, or balance will be trashed
					oit = uit->second.erase(oit);
					break;
				}
			if (uit->second.empty())
				uit = m_unspents.erase(uit);
		}
	}
	for (const auto &ki_or_pk : tit->second.used_keyimages) {
		auto kit = m_used_keyimages.find(ki_or_pk);
		invariant(kit != m_used_keyimages.end(), "");
		kit->second -= 1;
		invariant(kit->second >= 0, "");
		if (kit->second == 0)
			kit = m_used_keyimages.erase(kit);
	}
	tit = m_transactions.erase(tit);
}

void WalletState::DeltaState::apply(IWalletState *parent_state, Height height) const {
	for (const auto &tx : m_transactions)
		parent_state->add_transaction(height, tx.first, tx.second.tx, tx.second.atx);
	for (const auto &pk : m_unspents)
		for (const auto &output : pk.second)
			parent_state->add_incoming_output(output);
	for (const auto &ki : m_used_keyimages) {
		invariant(ki.second > 0, "DeltaState keyimages index corrupted");
		parent_state->add_incoming_keyimage(height, ki.first);
	}
	// TODO test before 3.5
}

void WalletState::DeltaState::clear() {
	m_used_keyimages.clear();
	m_unspents.clear();
	m_transactions.clear();
}

WalletState::WalletState(Wallet &wallet, logging::ILogger &log, const Config &config, const Currency &currency)
    : WalletStateBasic(log, config, currency, wallet.get_cache_name())
    , m_log_redo_block(std::chrono::steady_clock::now())
    , m_wallet(wallet) {
	wallet_addresses_updated();
	auto pq = m_wallet.payment_queue_get();
	for (const auto &body : pq) {
		Transaction tx;
		try {
			add_to_payment_queue(body, false);
		} catch (const std::exception &) {
			m_log(logging::WARNING) << "Error adding transaction to payment queue " << std::endl;
			continue;
		}
	}
}

void WalletState::wallet_addresses_updated() {
	Timestamp undo_timestamp = std::numeric_limits<Timestamp>::max();
	try {
		for (size_t i = 0; i != m_wallet.get_actual_records_count(); ++i) {
			WalletRecord wa;
			m_wallet.get_record(i, &wa, nullptr);
			auto keyuns =
			    ADDRESSES_PREFIX + DB::to_binary_key(wa.spend_public_key.data, sizeof(wa.spend_public_key.data));
			std::string st;
			if (!m_db.get(keyuns, st) || wa.creation_timestamp < boost::lexical_cast<Timestamp>(st)) {
				undo_timestamp = std::min(undo_timestamp, wa.creation_timestamp);
				m_db.put(keyuns, common::to_string(wa.creation_timestamp), false);
			}
		}
		// We never delete from ADDRESSES_PREFIX index, because it correctly reflects
		// scanned outputs, their spendable and balances
		if (undo_timestamp == std::numeric_limits<Timestamp>::max()) {
			return;  // db.commit() not worth here, will just update addresses again in case of ctrl-c
		}
		while (!empty_chain() && get_tip().timestamp + m_currency.block_future_time_limit >=
		                             undo_timestamp) {  // Undo excess blocks in case timestamps are out of order
			pop_chain();
		}
		fix_empty_chain();
	} catch (const std::exception &ex) {
		m_log(logging::ERROR)
		    << "Exception in wallet_addresses_updated, probably out of disk space or database corrupted error="
		    << common::what(ex) << " path=" << m_db.get_path() << std::endl;
		std::exit(api::BYTECOIND_DATABASE_ERROR);
	}
	fix_payment_queue_after_undo_redo();
	db_commit();
}

std::vector<WalletRecord> WalletState::generate_new_addresses(
    const std::vector<SecretKey> &sks, Timestamp ct, Timestamp now, std::vector<AccountAddress> *addresses) {
	bool rescan_from_ct = false;
	auto result         = m_wallet.generate_new_addresses(sks, ct, now, addresses, &rescan_from_ct);
	if (rescan_from_ct)
		wallet_addresses_updated();
	return result;
}

void WalletState::create_addresses(size_t count) {
	if (count <= m_wallet.get_actual_records_count())
		return;
	m_wallet.create_look_ahead_records(count);
	wallet_addresses_updated();
}

bool WalletState::add_to_payment_queue(const BinaryArray &binary_transaction, bool save_file) {
	Transaction tx;
	seria::from_binary(tx, binary_transaction);
	Hash tid            = get_transaction_hash(tx);
	auto &by_hash_index = payment_queue.get<by_hash>();
	auto git            = by_hash_index.find(tid);
	if (git != by_hash_index.end())
		return true;  // alredy here, nop
	if (save_file)
		m_wallet.payment_queue_add(tid, binary_transaction);
	TransactionPrefix tx_prefix;
	api::Transaction ptx;
	QueueEntry entry{tid, binary_transaction, 0, 0};
	//    std::cout << "by_hash_index.size=" << by_hash_index.size() << std::endl;
	m_pq_version += 1;
	if (api_get_transaction(tid, false, &tx_prefix, &ptx)) {
		entry.remove_height = ptx.block_height + m_config.payment_queue_confirmations;
		entry.fee_per_kb    = ptx.fee / binary_transaction.size();
		payment_queue.insert(entry);
		m_log(logging::INFO) << "Now PQ transaction " << tid << " is in BC, remove_height=" << entry.remove_height
		                     << " payment_queue.size=" << payment_queue.size() << std::endl;
		return true;
	}
	entry.fee_per_kb = get_tx_fee(tx) / binary_transaction.size();
	payment_queue.insert(entry);
	add_transaction_to_mempool(tid, std::move(tx), true);
	return true;
}

BinaryArray WalletState::get_next_from_sending_queue(Hash *previous_hash) {
	auto &by_hash_index = payment_queue.get<by_hash>();
	//	std::cout << "by_hash_index.size=" << by_hash_index.size() << std::endl;
	//	for(auto && bhit : by_hash_index)
	//		std::cout << "    " << bhit.hash << std::endl;
	auto git = by_hash_index.lower_bound(*previous_hash);
	if (git == by_hash_index.end())
		return BinaryArray{};
	if (git->hash == *previous_hash)  // Otherwise previous tx was removed
		++git;
	while (git != by_hash_index.end() && git->in_blockchain())
		++git;
	if (git == by_hash_index.end())
		return BinaryArray{};
	*previous_hash = git->hash;
	return git->binary_transaction;
}

void WalletState::process_payment_queue_send_error(Hash hash, const api::cnd::SendTransaction::Error &error) {
	if (error.code == api::cnd::SendTransaction::INVALID_TRANSACTION_BINARY_FORMAT ||
	    ((error.code == api::cnd::SendTransaction::OUTPUT_ALREADY_SPENT ||
	         error.code == api::cnd::SendTransaction::WRONG_OUTPUT_REFERENCE) &&
	        get_tip_height() > error.conflict_height + m_config.payment_queue_confirmations)) {
		m_log(logging::INFO) << "Removing transaction from PQ because send error " << error.what() << std::endl;
		auto &by_hash_index = payment_queue.get<by_hash>();
		auto git            = by_hash_index.find(hash);
		if (git != by_hash_index.end())
			by_hash_index.erase(git);
		remove_transaction_from_mempool(hash, true);
		m_wallet.payment_queue_remove(hash);
		m_pq_version += 1;
	}
}

const WalletState::QueueEntry *WalletState::find_in_payment_queue(const Hash &hash) {
	auto &by_hash_index = payment_queue.get<by_hash>();
	auto git            = by_hash_index.find(hash);
	if (git == by_hash_index.end())
		return nullptr;
	return &*git;
}

void WalletState::fix_payment_queue_after_undo_redo() {
	auto &by_hash_index = payment_queue.get<by_hash>();
	//    std::cout << "by_hash_index.size=" << by_hash_index.size() << std::endl;
	std::vector<Hash> added_to_bc;
	std::vector<Hash> removed_from_bc;
	bool pq_modified = false;
	for (auto git = by_hash_index.begin(); git != by_hash_index.end(); ++git) {
		if (git->in_blockchain() && !api_has_transaction(git->hash, false))
			removed_from_bc.push_back(git->hash);
		if (!git->in_blockchain() && api_has_transaction(git->hash, false))
			added_to_bc.push_back(git->hash);
	}
	for (auto tid : removed_from_bc) {
		auto git = by_hash_index.find(tid);
		if (git == by_hash_index.end())
			continue;
		QueueEntry entry = *git;
		by_hash_index.erase(git);
		entry.remove_height = 0;
		payment_queue.insert(entry);
		pq_modified = true;
		Transaction tx;
		seria::from_binary(tx, entry.binary_transaction);
		add_transaction_to_mempool(tid, std::move(tx), true);
	}
	for (auto tid : added_to_bc) {
		auto git = by_hash_index.find(tid);
		if (git == by_hash_index.end())
			continue;
		TransactionPrefix tx;
		api::Transaction ptx;
		if (!api_get_transaction(tid, false, &tx, &ptx))
			continue;
		QueueEntry entry = *git;
		by_hash_index.erase(git);
		entry.remove_height = ptx.block_height + m_config.payment_queue_confirmations;
		payment_queue.insert(entry);
		pq_modified = true;
		remove_transaction_from_mempool(tid, true);
	}
	auto &by_remove_height_index = payment_queue.get<by_remove_height>();
	//    std::cout << "by_remove_height_index.size=" << by_remove_height_index.size() << std::endl;
	auto git = by_remove_height_index.lower_bound(1);
	while (git != by_remove_height_index.end() && get_tip_height() >= git->remove_height) {
		m_wallet.payment_queue_remove(git->hash);
		git         = by_remove_height_index.erase(git);
		pq_modified = true;
	}
	if (pq_modified)
		m_pq_version += 1;
}

static void fill_tx_output_public_keys(std::vector<PublicKey> *output_public_keys, const TransactionPrefix &tx) {
	for (size_t out_index = 0; out_index != tx.outputs.size(); ++out_index) {
		const auto &output = tx.outputs.at(out_index);
		if (output.type() != typeid(OutputKey))
			continue;
		const auto &key_output = boost::get<OutputKey>(output);
		output_public_keys->push_back(key_output.public_key);
	}
}

void WalletState::add_transaction_to_mempool(Hash tid, Transaction &&tx, bool from_pq) {
	if (m_memory_state.get_transactions().count(tid) != 0)
		return;
	const auto now = platform::now_unix_timestamp();
	m_log(logging::INFO) << "Now " << (from_pq ? "PQ" : "node") << " transaction " << tid
	                     << " is in MS size before adding=" << m_memory_state.get_transactions().size() << std::endl;
	std::vector<size_t> global_indices(tx.outputs.size(), 0);
	PreparedWalletTransaction pwtx;
	std::vector<PublicKey> output_public_keys;
	fill_tx_output_public_keys(&output_public_keys, tx);
	if (m_wallet.scan_outputs_via_hw())
		m_wallet.get_hw()->precache_mul_by_view_secret_key(output_public_keys);
	pwtx = PreparedWalletTransaction(std::move(tx), m_wallet.get_output_handler(), m_wallet.get_view_secret_key());
	if (!redo_transaction(pwtx, global_indices, 0, &m_memory_state, false, tid, get_tip_height() + 1, Hash{}, now)) {
	}  // just ignore result
}

void WalletState::remove_transaction_from_mempool(Hash tid, bool from_pq) {
	if (m_pool_hashes.count(tid) != 0)
		return;
	const QueueEntry *entry = find_in_payment_queue(tid);
	if (entry && !entry->in_blockchain())
		return;
	m_log(logging::INFO) << "Removing " << (from_pq ? "PQ" : "node") << " transaction " << tid << " from MS"
	                     << std::endl;
	m_memory_state.undo_transaction(tid);
}

bool WalletState::sync_with_blockchain(api::cnd::SyncBlocks::Response &resp) {
	if (resp.blocks.empty())  // Our creation timestamp > last block timestamp, so
	                          // no blocks
		return true;
	try {
		while (get_tip_height() > resp.start_height + resp.blocks.size() - 1 && !empty_chain()) {
			// first undo excess blocks at head
			pop_chain();
			m_tx_pool_version = 1;
		}
		while (get_tip_height() >= resp.start_height && !empty_chain()) {
			// then undo all blocks at head with different bids
			const auto &other_header = resp.blocks[get_tip_height() - resp.start_height].header;
			if (get_tip_bid() == other_header.hash)
				break;
			if (get_tip_height() == 0)
				return false;  // Different genesis bid
			pop_chain();
			m_tx_pool_version = 1;
		}
		if (get_tip_height() < resp.start_height)
			while (!empty_chain()) {  // undo everything
				pop_chain();
				m_tx_pool_version = 1;
			}
		if (empty_chain())
			reset_chain(resp.start_height);
		if (!m_wallet.scan_outputs_via_hw()) {
			preparator.cancel_work();
			preparator.start_work(resp, m_wallet.get_output_handler(), m_wallet.get_view_secret_key());
		}
		while (get_tip_height() + 1 < resp.start_height + resp.blocks.size()) {
			size_t bin         = get_tip_height() + 1 - resp.start_height;
			const auto &header = resp.blocks.at(bin).header;
			if (!empty_chain() && header.previous_block_hash != get_tip_bid())
				return false;
			if (header.timestamp + m_currency.block_future_time_limit >= m_wallet.get_oldest_timestamp()) {
				auto &sync_block     = resp.blocks.at(bin);
				const auto &block_gi = sync_block.output_stack_indexes;
				PreparedWalletBlock pb;
				if (m_wallet.scan_outputs_via_hw()) {
					// TODO - very inefficient code for now
					// Also will repeat getting blocks for sync indefinetely when hw is disconnected
					std::vector<PublicKey> output_public_keys;
					fill_tx_output_public_keys(&output_public_keys, sync_block.raw_header.base_transaction);
					for (const auto &tx : sync_block.raw_transactions)
						fill_tx_output_public_keys(&output_public_keys, tx);
					m_wallet.get_hw()->precache_mul_by_view_secret_key(output_public_keys);
					pb = PreparedWalletBlock(std::move(sync_block.raw_header), std::move(sync_block.raw_transactions),
					    sync_block.transactions.at(0).hash, m_wallet.get_output_handler(),
					    m_wallet.get_view_secret_key());
				} else
					pb = preparator.get_ready_work(get_tip_height() + 1);
				//					pb = PreparedWalletBlock(std::move(sync_block.raw_header),
				// std::move(sync_block.raw_transactions), 					    sync_block.transactions.at(0).hash,
				// m_wallet.get_output_handler());
				redo_block(header, pb, block_gi, get_tip_height() + 1);
				//			push_chain(header);
				//			pop_chain();
				//			redo_block(header, pb, block_gi, m_tip_height + 1);
				auto now = std::chrono::steady_clock::now();
				if (std::chrono::duration_cast<std::chrono::milliseconds>(now - m_log_redo_block).count() > 1000 ||
				    get_tip_height() + 1 == resp.status.top_known_block_height) {
					m_log_redo_block = now;
					m_log(logging::INFO) << "WalletState redo block, height=" << get_tip_height() + 1 << "/"
					                     << resp.status.top_known_block_height << std::endl;
				}  // else
				   //	m_log(logging::TRACE) << "WalletState redo block, height=" << get_tip_height() + 1 << "/"
				   //	                      << resp.status.top_known_block_height << std::endl;
			}
			push_chain(header);
			m_tx_pool_version = 1;
			m_pq_version      = 1;
		}
		fix_empty_chain();
	} catch (const std::exception &ex) {
		m_log(logging::ERROR)
		    << "Exception in sync_with_blockchain, probably out of disk space or database corrupted error="
		    << common::what(ex) << " path=" << m_db.get_path() << std::endl;
		std::exit(api::BYTECOIND_DATABASE_ERROR);
	}
	fix_payment_queue_after_undo_redo();
	return true;
}

std::vector<Hash> WalletState::get_tx_pool_hashes() const {
	return std::vector<Hash>(m_pool_hashes.begin(), m_pool_hashes.end());
}

bool WalletState::sync_with_blockchain(api::cnd::SyncMemPool::Response &resp) {
	for (const auto &tid : resp.removed_hashes) {
		if (m_pool_hashes.erase(tid) != 0)
			remove_transaction_from_mempool(tid, false);
	}
	for (size_t i = 0; i != resp.added_raw_transactions.size(); ++i) {
		Transaction tx;
		static_cast<TransactionPrefix &>(tx) = std::move(resp.added_raw_transactions.at(i));
		//		if (i < resp.added_signatures.size())
		//			tx.signatures = std::move(resp.added_signatures[i]);
		//		seria::from_binary(tx, resp.added_binary_transactions[i]);
		Hash tid = resp.added_transactions.at(i).hash;  // get_transaction_hash(tx);
		m_pool_hashes.insert(tid);
		add_transaction_to_mempool(tid, std::move(tx), false);
	}
	m_tx_pool_version = resp.status.transaction_pool_version;
	return true;
}

bool WalletState::redo_block(const api::BlockHeader &header, const PreparedWalletBlock &pb,
    const BlockChainState::BlockGlobalIndices &global_indices, Height height) {
	invariant(height == get_tip_height() + 1, "Redo of incorrect block height");
	if (global_indices.size() != pb.transactions.size() + 1)
		return false;                                     // Bad node - TODO
	Hash base_hash           = pb.base_transaction_hash;  // get_transaction_hash(pb.base_transaction.tx);
	size_t key_outputs_count = get_tx_key_outputs_count(pb.base_transaction.tx);
	for (const auto &tx : pb.transactions)
		key_outputs_count += get_tx_key_outputs_count(tx.tx);
	DeltaState delta_state;
	size_t start_global_key_output_index = header.already_generated_key_outputs - key_outputs_count;
	if (!redo_transaction(pb.base_transaction, global_indices[0], start_global_key_output_index, &delta_state, true,
	        base_hash, get_tip_height() + 1, header.hash, pb.header.timestamp)) {
	}  // Just ignore - TODO
	start_global_key_output_index += get_tx_key_outputs_count(pb.base_transaction.tx);
	for (size_t tx_index = 0; tx_index != pb.transactions.size(); ++tx_index) {
		const Hash tid = pb.header.transaction_hashes.at(tx_index);
		if (m_pool_hashes.erase(tid) != 0)
			remove_transaction_from_mempool(tid, false);
		m_memory_state.undo_transaction(tid);
		if (!redo_transaction(pb.transactions.at(tx_index), global_indices.at(tx_index + 1),
		        start_global_key_output_index, &delta_state, false, tid, get_tip_height() + 1, header.hash,
		        pb.header.timestamp)) {
		}  // just ignore - TODO
		start_global_key_output_index += get_tx_key_outputs_count(pb.transactions.at(tx_index).tx);
	}
	invariant(header.already_generated_key_outputs == start_global_key_output_index, "");
	// no exceptions starting from here
	delta_state.apply(this, get_tip_height() + 1);
	unlock(height, header.timestamp_median);
	// till here
	// If ex has lock_time in the past, it will be added to lock index in redo, then immediately unlocked here
	return true;
}

// We return output transfers in ptx, input transfers in input_transfers
bool WalletState::parse_raw_transaction(bool is_base, api::Transaction *ptx,
    std::vector<api::Transfer> *input_transfers, std::vector<api::Transfer> *output_transfers,
    Amount *unrecognized_inputs_amount, const PreparedWalletTransaction &pwtx, Hash tid,
    const std::vector<size_t> &global_indices, size_t start_global_key_output_index, Height block_height) const {
	if (global_indices.size() != pwtx.tx.outputs.size())  // Bad node
		return false;  // Without global indices we cannot do anything with transaction
	const TransactionPrefix &tx = pwtx.tx;
	const bool is_tx_amethyst   = tx.version >= m_currency.amethyst_transaction_version;
	boost::optional<Wallet::History> history;
	KeyPair tx_keys;
	ptx->coinbase                  = is_base;
	ptx->hash                      = tid;
	ptx->inputs_hash               = pwtx.inputs_hash;
	ptx->prefix_hash               = pwtx.prefix_hash;
	ptx->block_height              = block_height;
	ptx->anonymity                 = std::numeric_limits<size_t>::max();
	ptx->unlock_block_or_timestamp = tx.unlock_block_or_timestamp;
	ptx->public_key                = extra_get_transaction_public_key(tx.extra);
	ptx->extra                     = tx.extra;
	extra_get_payment_id(tx.extra, ptx->payment_id);

	bool our_inputs  = false;
	bool our_outputs = false;

	std::map<std::string, api::Transfer> transfer_map_inputs;
	*unrecognized_inputs_amount = 0;
	Amount input_amount         = 0;
	for (size_t in_index = 0; in_index != tx.inputs.size(); ++in_index) {
		const auto &input = tx.inputs.at(in_index);
		if (input.type() == typeid(InputKey)) {
			const InputKey &in = boost::get<InputKey>(input);
			if (!add_amount(input_amount, in.amount))
				return false;
			ptx->anonymity = std::min(ptx->anonymity, in.output_indexes.size() - 1);
			api::Output existing_output;

			if (try_adding_incoming_keyimage(in.key_image, &existing_output)) {
				api::Transfer &transfer = transfer_map_inputs[existing_output.address];
				transfer.amount -= static_cast<SignedAmount>(existing_output.amount);
				transfer.ours = true;
				transfer.outputs.push_back(existing_output);
				our_inputs = true;
				continue;
			}
			*unrecognized_inputs_amount += in.amount;
		}
	}
	for (auto &&tm : transfer_map_inputs) {
		tm.second.address          = tm.first;
		tm.second.transaction_hash = tid;
		input_transfers->push_back(tm.second);
	}
	// We combine outputs into transfers by address
	Amount output_amount = 0;
	std::map<AccountAddress, api::Transfer> transfer_map_outputs[2];  // We index by ours
	for (size_t out_index = 0; out_index != tx.outputs.size(); ++out_index) {
		const auto &output = tx.outputs.at(out_index);
		if (output.type() != typeid(OutputKey))
			continue;
		const auto &key_output         = boost::get<OutputKey>(output);
		const auto &address_S          = pwtx.address_public_keys.at(out_index);
		const auto &output_secret_hash = pwtx.output_secret_hashes.at(out_index);
		if (!add_amount(output_amount, key_output.amount))
			return false;
		api::Output out;
		out.global_index = start_global_key_output_index;
		start_global_key_output_index += 1;
		out.amount                    = key_output.amount;
		out.stack_index               = global_indices.at(out_index);
		out.height                    = block_height;
		out.index_in_transaction      = out_index;
		out.public_key                = key_output.public_key;
		out.transaction_hash          = tid;
		out.unlock_block_or_timestamp = tx.unlock_block_or_timestamp;

		AccountAddress address;
		size_t record_index = 0;
		SecretKey output_secret_key_s;
		SecretKey output_secret_key_a;
		if (m_wallet.detect_our_output(tx.version, pwtx.derivation, out_index, address_S, output_secret_hash,
		        key_output, &out.amount, &output_secret_key_s, &output_secret_key_a, &address, &record_index,
		        &out.key_image)) {
			//			out.dust = m_currency.is_dust(key_output.amount);
			api::Transfer &transfer = transfer_map_outputs[true][address];
			if (transfer.address.empty())
				transfer.address = m_currency.account_address_as_string(address);
			out.address = transfer.address;
			if (try_add_incoming_output(out)) {
				transfer.amount += out.amount;
				transfer.outputs.push_back(out);
			}
			our_outputs = true;
			continue;
		}
		if (!our_inputs)
			continue;
		if (TransactionBuilder::detect_not_our_output(&m_wallet, is_tx_amethyst, tid, pwtx.inputs_hash, &history,
		        &tx_keys, out_index, key_output, &address)) {
			//			out.dust                = m_currency.is_dust(key_output.amount);
			api::Transfer &transfer = transfer_map_outputs[false][address];
			if (transfer.address.empty())
				transfer.address = m_currency.account_address_as_string(address);
			out.address = transfer.address;
			transfer.amount += key_output.amount;
			transfer.outputs.push_back(out);
		} else {
			if (is_tx_amethyst && m_wallet.can_view_outgoing_addresses())
				m_log(logging::WARNING) << "Auditor warning - failed to detect destination address for output #"
				                        << out_index << " in tx " << tid << std::endl;
		}
	}
	for (bool ours : {false, true})
		for (auto &&tm : transfer_map_outputs[ours]) {
			tm.second.locked           = ptx->unlock_block_or_timestamp != 0;
			tm.second.ours             = ours;
			tm.second.transaction_hash = tid;
			if (tm.second.amount != 0)  // We use map as a map of addresses
				output_transfers->push_back(std::move(tm.second));
		}
	ptx->amount = output_amount;
	if (output_amount > input_amount && !is_base)
		return false;
	if (input_amount >= output_amount)
		ptx->fee = input_amount - output_amount;
	if (ptx->anonymity == std::numeric_limits<size_t>::max())
		ptx->anonymity = 0;  // No key inputs
	return our_outputs || our_inputs;
}

bool WalletState::parse_raw_transaction(bool is_base, api::Transaction &ptx, Transaction &&tx, Hash tid) const {
	std::vector<size_t> global_indices(tx.outputs.size(), 0);
	Amount unrecognized_inputs_amount = 0;
	PreparedWalletTransaction pwtx;
	std::vector<PublicKey> output_public_keys;
	fill_tx_output_public_keys(&output_public_keys, tx);
	if (m_wallet.scan_outputs_via_hw())
		m_wallet.get_hw()->precache_mul_by_view_secret_key(output_public_keys);
	pwtx = PreparedWalletTransaction(std::move(tx), m_wallet.get_output_handler(), m_wallet.get_view_secret_key());
	std::vector<api::Transfer> input_transfers;
	std::vector<api::Transfer> output_transfers;
	parse_raw_transaction(is_base, &ptx, &input_transfers, &output_transfers, &unrecognized_inputs_amount, pwtx, tid,
	    global_indices, 0, get_tip_height());
	// We do not know "from" addresses, so leave address empty
	ptx.transfers.insert(ptx.transfers.end(), input_transfers.begin(), input_transfers.end());
	ptx.transfers.insert(ptx.transfers.end(), output_transfers.begin(), output_transfers.end());
	if (unrecognized_inputs_amount != 0) {
		api::Transfer input_transfer;
		input_transfer.amount = -static_cast<SignedAmount>(unrecognized_inputs_amount);
		input_transfer.ours   = true;
		ptx.transfers.push_back(input_transfer);
	}
	return true;
}

const std::map<KeyImage, int> &WalletState::get_mempool_keyimages() const {
	return m_memory_state.get_used_keyimages();
}

void WalletState::on_first_transaction_found(Timestamp ts) { m_wallet.on_first_output_found(ts); }

bool WalletState::redo_transaction(const PreparedWalletTransaction &pwtx, const std::vector<size_t> &global_indices,
    size_t start_global_key_output_index, IWalletState *delta_state, bool is_base, Hash tid, Height block_height,
    Hash bid, Timestamp tx_timestamp) const {
	api::Transaction ptx;
	Amount unrecognized_inputs_amount = 0;
	std::vector<api::Transfer> input_transfers;
	std::vector<api::Transfer> output_transfers;
	if (!parse_raw_transaction(is_base, &ptx, &input_transfers, &output_transfers, &unrecognized_inputs_amount, pwtx,
	        tid, global_indices, start_global_key_output_index, block_height))
		return false;  // not ours
	ptx.block_hash = bid;
	ptx.timestamp  = tx_timestamp;
	ptx.transfers.insert(ptx.transfers.end(), input_transfers.begin(), input_transfers.end());
	ptx.transfers.insert(ptx.transfers.end(), output_transfers.begin(), output_transfers.end());
	delta_state->add_transaction(block_height, tid, pwtx.tx, ptx);
	for (auto &&tr : output_transfers) {  // add and fix outputs
		if (!tr.ours)
			continue;
		for (auto &&out : tr.outputs) {
			invariant(delta_state->add_incoming_output(out), "");  // TODO - double check before 3.5
		}
	}
	for (auto &&tr : input_transfers) {
		for (auto &&out : tr.outputs) {
			delta_state->add_incoming_keyimage(block_height, out.key_image);
		}
	}
	// order of add_transaction is important - DeltaState associates subsequent add_ with last added transaction
	return true;
}

std::vector<api::Output> WalletState::api_get_locked_or_unconfirmed_unspent(
    const std::string &address, Height confirmed_height) const {
	auto result = WalletStateBasic::api_get_locked_or_unconfirmed_unspent(address, confirmed_height);
	for (auto &&uns : m_memory_state.get_unspents())
		for (auto &&out : uns.second)
			if (address.empty() || address == out.address)
				result.push_back(out);
	return result;
}
api::Balance WalletState::get_balance(const std::string &address, Height confirmed_height) const {
	auto balance = WalletStateBasic::get_balance(address, confirmed_height);
	for (auto &&uns : m_memory_state.get_unspents())
		for (auto &&out : uns.second)
			if (address.empty() || address == out.address)
				combine_balance(balance, out, 1, 0);
	return balance;
}

bool WalletState::api_has_transaction(Hash tid, bool check_pool) const {
	if (check_pool) {
		auto mit = m_memory_state.get_transactions().find(tid);
		if (mit != m_memory_state.get_transactions().end())
			return true;
	}
	return has_transaction(tid);
}

bool WalletState::api_get_transaction(Hash tid, bool check_pool, TransactionPrefix *tx, api::Transaction *atx) const {
	if (check_pool) {
		auto mit = m_memory_state.get_transactions().find(tid);
		if (mit != m_memory_state.get_transactions().end()) {
			*tx  = mit->second.tx;
			*atx = mit->second.atx;
			return true;
		}
	}
	return get_transaction(tid, tx, atx);
}

std::string WalletState::api_create_proof(const TransactionPrefix &tx,
    const std::vector<std::vector<PublicKey>> &mixed_public_keys, const std::string &addr_str, const Hash &tid,
    const std::string &message) const {
	const Hash tx_inputs_hash = get_transaction_inputs_hash(tx);
	const Hash message_hash   = crypto::cn_fast_hash(message.data(), message.size());
	AccountAddress address;
	if (!m_currency.parse_account_address_string(addr_str, &address))
		throw api::ErrorAddress(api::ErrorAddress::ADDRESS_FAILED_TO_PARSE, "Failed to parse wallet address", addr_str);
	if (tx.version < m_currency.amethyst_transaction_version) {
		if (address.type() != typeid(AccountAddressSimple))
			return std::string();  // TODO - throw?
		SendproofAmethyst sp;
		sp.version          = tx.version;
		sp.address_simple   = boost::get<AccountAddressSimple>(address);
		sp.message          = message;
		sp.transaction_hash = tid;
		KeyPair tx_keys =
		    TransactionBuilder::transaction_keys_from_seed(tx_inputs_hash, m_wallet.get_tx_derivation_seed());
		const auto &addr = boost::get<AccountAddressSimple>(address);
		sp.derivation    = crypto::generate_key_derivation(addr.V, tx_keys.secret_key);
		sp.signature =
		    crypto::generate_sendproof(tx_keys.public_key, tx_keys.secret_key, addr.V, sp.derivation, message_hash);
		Amount total_amount = 0;
		for (size_t out_index = 0; out_index != tx.outputs.size(); ++out_index) {
			const auto &output = tx.outputs.at(out_index);
			if (output.type() != typeid(OutputKey))
				continue;
			const auto &key_output    = boost::get<OutputKey>(output);
			const PublicKey address_S = underive_address_S(sp.derivation, out_index, key_output.public_key);
			if (address_S != addr.S)
				continue;
			total_amount += key_output.amount;
		}
		if (total_amount == 0)
			return std::string();
		const auto body = seria::to_binary(sp);
		return common::base58::encode_addr(m_currency.sendproof_base58_prefix, body);
	}
	SendproofAmethyst sp;
	sp.version          = m_currency.amethyst_transaction_version;
	sp.message          = message;
	sp.transaction_hash = tid;
	Amount total_amount = 0;
	std::vector<KeyPair> all_output_det_keys;
	for (size_t out_index = 0; out_index != tx.outputs.size(); ++out_index) {
		const auto &output = tx.outputs.at(out_index);
		if (output.type() != typeid(OutputKey))
			continue;
		const auto &key_output = boost::get<OutputKey>(output);
		KeyPair output_seed_keys;
		if (m_wallet.get_hw()) {
			m_wallet.get_hw()->generate_output_seed(tx_inputs_hash, out_index, &output_seed_keys.public_key);
		} else {
			output_seed_keys = TransactionBuilder::deterministic_keys_from_seed(
			    tx_inputs_hash, m_wallet.get_tx_derivation_seed(), common::get_varint_data(out_index));
		}
		OutputKey should_be_output = TransactionBuilder::create_output(
		    true, address, SecretKey{}, tx_inputs_hash, out_index, output_seed_keys.public_key);
		if (should_be_output.public_key != key_output.public_key ||
		    should_be_output.encrypted_secret != key_output.encrypted_secret ||
		    should_be_output.encrypted_address_type != key_output.encrypted_address_type)
			continue;  // output to different address or crypto protocol violated
		sp.elements.push_back(SendproofAmethyst::Element{out_index, output_seed_keys.public_key});
		all_output_det_keys.push_back(output_seed_keys);
		total_amount += key_output.amount;
	}
	const auto proof_body = seria::to_binary(sp);
	//	std::cout << "Proof body: " << common::to_hex(proof_body) << std::endl;
	const auto proof_prefix_hash = crypto::cn_fast_hash(proof_body);
	//	std::cout << "Proof hash: " << proof_prefix_hash << std::endl;
	if (tx.inputs.empty() || tx.inputs.at(0).type() != typeid(InputKey) || mixed_public_keys.empty())
		return std::string();  // TODO - throw?
	const InputKey &in = boost::get<InputKey>(tx.inputs.at(0));
	if (in.output_indexes.size() != mixed_public_keys.at(0).size())
		return std::string();  // TODO - throw?
	HeightGi heamgi;
	if (!read_by_keyimage(in.key_image, &heamgi))
		return std::string();  // TODO - throw?

	TransactionPrefix other_tx;
	api::Transaction other_atx;
	if (!get_transaction(heamgi.transaction_hash, &other_tx, &other_atx) ||
	    heamgi.index_in_transaction >= other_tx.outputs.size())
		return std::string();
	const auto &key_output = boost::get<OutputKey>(other_tx.outputs.at(heamgi.index_in_transaction));
	Hash other_inputs_hash = get_transaction_inputs_hash(other_tx);
	size_t sec_index       = static_cast<size_t>(
        std::find(mixed_public_keys.at(0).begin(), mixed_public_keys.at(0).end(), key_output.public_key) -
        mixed_public_keys.at(0).begin());
	if (sec_index == mixed_public_keys.at(0).size())
		return std::string();

	KeyDerivation other_kd = crypto::generate_key_derivation(other_atx.public_key, m_wallet.get_view_secret_key());
	size_t record_index    = 0;
	SecretKey output_secret_key_s;
	SecretKey output_secret_key_a;
	SecretKey output_secret_hash;
	if (!m_wallet.prepare_input_for_spend(other_tx.version, other_kd, other_inputs_hash, heamgi.index_in_transaction,
	        key_output, &output_secret_hash, &output_secret_key_s, &output_secret_key_a, &record_index)) {
		throw json_rpc::Error(json_rpc::INTERNAL_ERROR, "No keys in wallet to sign sendproof");
	}

	std::vector<SecretKey> all_secret_keys_s{output_secret_key_s};
	std::vector<SecretKey> all_secret_keys_a{output_secret_key_a};
	std::vector<size_t> all_sec_indexes{sec_index};
	std::vector<KeyImage> all_keyimages{in.key_image};
	std::vector<std::vector<PublicKey>> all_output_keys{mixed_public_keys.at(0)};
	std::vector<SecretKey> output_secret_hashes{output_secret_hash};
	std::vector<size_t> address_indexes{record_index};

	RingSignatureAmethyst rsa;
	if (m_wallet.get_hw()) {
		if (proof_body.empty())
			return std::string();
		BinaryArray body_minus_guard(proof_body.begin() + 1, proof_body.end());
		m_wallet.get_hw()->proof_start(body_minus_guard);
		rsa = m_wallet.get_hw()->generate_ring_signature_auditable(
		    proof_prefix_hash, output_secret_hashes, address_indexes, all_keyimages, all_output_keys, all_sec_indexes);
	} else {
		rsa = generate_ring_signature_auditable(
		    proof_prefix_hash, all_keyimages, all_output_keys, all_secret_keys_s, all_secret_keys_a, all_sec_indexes);
	}

	invariant(crypto::check_ring_signature_auditable(proof_prefix_hash, all_keyimages, all_output_keys, rsa), "");
	TransactionPrefix fake_prefix;
	fake_prefix.version = tx.version;
	fake_prefix.inputs.push_back(in);
	BinaryArray sig_body = seria::to_binary(rsa, fake_prefix);
	//	std::cout << "Sig body: " << common::to_hex(sig_body) << std::endl;

	BinaryArray total_body = proof_body;
	common::append(total_body, sig_body);

	return common::base58::encode_addr(m_currency.sendproof_base58_prefix, total_body);
}

api::Block WalletState::api_get_pool_as_history(const std::string &address) const {
	// TODO - faster filter by address
	api::Block current_block;
	current_block.header.height = get_tip_height() + 1;
	for (const auto &hit : m_memory_state.get_transactions()) {
		auto tx         = hit.second.atx;
		tx.block_height = get_tip_height() + 1;
		if (!address.empty()) {
			for (auto tit = tx.transfers.begin(); tit != tx.transfers.end();)
				if (tit->address == address)
					++tit;
				else
					tit = tx.transfers.erase(tit);
			if (tx.transfers.empty())
				continue;
		}
		current_block.transactions.push_back(std::move(tx));
	}
	return current_block;
}
