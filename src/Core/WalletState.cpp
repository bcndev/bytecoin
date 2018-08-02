// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletState.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "common/string.hpp"
#include "crypto/crypto.hpp"
#include "platform/PathTools.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

static const std::string ADDRESSES_PREFIX = "a";  // this is not undone

using namespace bytecoin;
using namespace platform;

Amount WalletState::DeltaState::add_incoming_output(const api::Output &output) {
	m_unspents[output.public_key].push_back(output);
	return output.amount;
}

Amount WalletState::DeltaState::add_incoming_keyimage(Height height, const KeyImage &key_image) {
	//	m_used_keyimages[key_image] += 1; // We add all keyimages, not only recognized keyimages when using mem pool
	return 0;  // It does not know
}

void WalletState::DeltaState::add_transaction(
    Height, const Hash &tid, const TransactionPrefix &tx, const api::Transaction &ptx) {
	invariant(m_transactions.insert(std::make_pair(tid, std::make_pair(tx, ptx))).second,
	    "transaction already exists. Invariant dead");
	for (const auto &input : tx.inputs) {
		if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			m_used_keyimages[in.key_image] += 1;
		}
	}
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
			if (uit == m_unspents.end())  // Actually should never be empty
				continue;                 // Not our output
			for (auto oit = uit->second.begin(); oit != uit->second.end(); ++oit)
				if (oit->amount == output.amount) {  // We need to pop right output, or balance will be trashed
					oit = uit->second.erase(oit);
					break;
				}
			if (uit->second.empty())
				uit = m_unspents.erase(uit);
		}
	}
	for (const auto &input : tx.inputs) {
		if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			auto kit           = m_used_keyimages.find(in.key_image);
			invariant(kit != m_used_keyimages.end(), "");
			kit->second -= 1;
			invariant(kit->second >= 0, "");
			if (kit->second == 0)
				kit = m_used_keyimages.erase(kit);
		}
	}
	tit = m_transactions.erase(tit);
}

void WalletState::DeltaState::clear() {
	m_used_keyimages.clear();
	m_unspents.clear();
	m_transactions.clear();
}

// bool WalletState::DeltaState::is_spent(const api::Output &output) const {
//	return m_used_keyimages.count(output.key_image) != 0;
//}

WalletState::WalletState(Wallet &wallet, logging::ILogger &log, const Config &config, const Currency &currency)
    : WalletStateBasic(log, config, currency, wallet.get_cache_name())
    , log_redo_block(std::chrono::steady_clock::now())
    , m_wallet(wallet) {
	wallet_addresses_updated();
	platform::remove_file(m_wallet.get_payment_queue_folder() + "/tmp.tx");
	for (const auto &file : platform::get_filenames_in_folder(wallet.get_payment_queue_folder())) {
		common::BinaryArray body;
		if (!platform::load_file(wallet.get_payment_queue_folder() + "/" + file, body))
			continue;
		Transaction tx;
		try {
			add_to_payment_queue(body, false);
		} catch (const std::exception &) {
			m_log(logging::WARNING) << "Error adding transaction to payment queue from file " << file << std::endl;
			continue;
		}
	}
}

void WalletState::wallet_addresses_updated() {
	Timestamp undo_timestamp = std::numeric_limits<Timestamp>::max();
	try {
		for (auto rec : m_wallet.get_records()) {
			const WalletRecord &wa = rec.second;
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
		while (!empty_chain() &&
		       get_tip().timestamp + m_currency.block_future_time_limit >=
		           undo_timestamp) {  // Undo excess blocks in case timestamps are out of order
			pop_chain();
		}
		fix_empty_chain();
	} catch (const std::exception &ex) {
		m_log(logging::ERROR)
		    << "Exception in wallet_addresses_updated, probably out of disk space or database corrupted error="
		    << ex.what() << " path=" << m_db.get_path() << std::endl;
		std::exit(api::BYTECOIND_DATABASE_ERROR);
	}
	fix_payment_queue_after_undo_redo();
	db_commit();
}

std::vector<WalletRecord> WalletState::generate_new_addresses(
    const std::vector<SecretKey> &sks, Timestamp ct, Timestamp now) {
	bool rescan_from_ct = false;
	auto result         = m_wallet.generate_new_addresses(sks, ct, now, &rescan_from_ct);
	if (rescan_from_ct)
		wallet_addresses_updated();
	return result;
}

bool WalletState::add_to_payment_queue(const BinaryArray &binary_transaction, bool save_file) {
	Transaction tx;
	seria::from_binary(tx, binary_transaction);
	Hash tid            = get_transaction_hash(tx);
	auto &by_hash_index = payment_queue.get<by_hash>();
	auto git            = by_hash_index.find(tid);
	if (git != by_hash_index.end())
		return true;  // alredy here, nop
	const std::string file = m_wallet.get_payment_queue_folder() + "/" + common::pod_to_hex(tid) + ".tx";
	if (save_file) {
		platform::create_folder_if_necessary(m_wallet.get_payment_queue_folder());
		if (!platform::atomic_save_file(file, binary_transaction.data(), binary_transaction.size(),
		        m_wallet.get_payment_queue_folder() + "/tmp.tx"))
			m_log(logging::WARNING) << "Failed to save transaction " << tid << " to file " << file << std::endl;
		else
			m_log(logging::INFO) << "Saved transaction " << tid << " to file " << file << std::endl;
	}
	TransactionPrefix tx_prefix;
	api::Transaction ptx;
	QueueEntry entry{tid, binary_transaction, 0, 0};
	//    std::cout << "by_hash_index.size=" << by_hash_index.size() << std::endl;
	m_pq_version += 1;
	if (api_get_transaction(tid, false, &tx_prefix, &ptx)) {
		entry.remove_height = ptx.block_height + m_currency.expected_blocks_per_day();
		m_log(logging::INFO) << "Now PQ transaction " << tid << " is in BC, remove_height=" << entry.remove_height
		                     << std::endl;
		entry.fee_per_kb = ptx.fee / binary_transaction.size();
		payment_queue.insert(entry);
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

void WalletState::process_payment_queue_send_error(Hash hash, const api::bytecoind::SendTransaction::Error &error) {
	if (error.code == api::bytecoind::SendTransaction::OUTPUT_ALREADY_SPENT ||
	    error.code == api::bytecoind::SendTransaction::WRONG_OUTPUT_REFERENCE) {
		if (get_tip_height() > error.conflict_height + m_currency.expected_blocks_per_day()) {
			auto &by_hash_index = payment_queue.get<by_hash>();
			auto git            = by_hash_index.find(hash);
			if (git != by_hash_index.end())
				by_hash_index.erase(git);
			remove_transaction_from_mempool(hash, true);
			const std::string file = m_wallet.get_payment_queue_folder() + "/" + common::pod_to_hex(hash) + ".tx";
			if (!platform::remove_file(file))
				m_log(logging::WARNING) << "Failed to remove PQ transaction " << hash << " from file " << file
				                        << std::endl;
			else
				m_log(logging::INFO) << "Removed PQ transaction " << hash << " from file " << file << std::endl;
			platform::remove_file(m_wallet.get_payment_queue_folder());  // When it becomes empty
			m_pq_version += 1;
		}
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
		entry.remove_height = ptx.block_height + m_currency.expected_blocks_per_day();
		payment_queue.insert(entry);
		pq_modified = true;
		remove_transaction_from_mempool(tid, true);
	}
	auto &by_remove_height_index = payment_queue.get<by_remove_height>();
	//    std::cout << "by_remove_height_index.size=" << by_remove_height_index.size() << std::endl;
	auto git = by_remove_height_index.lower_bound(1);
	while (git != by_remove_height_index.end() && get_tip_height() >= git->remove_height) {
		const std::string file = m_wallet.get_payment_queue_folder() + "/" + common::pod_to_hex(git->hash) + ".tx";
		if (!platform::remove_file(file))
			m_log(logging::WARNING) << "Failed to remove PQ transaction " << git->hash << " from file " << file
			                        << std::endl;
		else
			m_log(logging::INFO) << "Removed PQ transaction " << git->hash << " from file " << file << std::endl;
		platform::remove_file(m_wallet.get_payment_queue_folder());  // When it becomes empty
		git         = by_remove_height_index.erase(git);
		pq_modified = true;
	}
	if (pq_modified)
		m_pq_version += 1;
}

void WalletState::add_transaction_to_mempool(Hash tid, TransactionPrefix &&tx, bool from_pq) {
	if (m_memory_state.get_transactions().count(tid) != 0)
		return;
	m_log(logging::INFO) << "Now " << (from_pq ? "PQ" : "node") << " transaction " << tid << " is in MS " << std::endl;
	std::vector<uint32_t> global_indices(tx.outputs.size(), 0);
	PreparedWalletTransaction pwtx(TransactionPrefix(tx), m_wallet.get_view_secret_key());
	if (!redo_transaction(
	        pwtx, global_indices, &m_memory_state, false, tid, get_tip_height() + 1, Hash{}, get_tip().timestamp)) {
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

bool WalletState::sync_with_blockchain(api::bytecoind::SyncBlocks::Response &resp) {
	if (resp.blocks.empty())  // Our creation timestamp > last block timestamp, so
		                      // no blocks
		return true;
	try {
		while (get_tip_height() > resp.start_height + resp.blocks.size() - 1 &&
		       !empty_chain()) {  // first undo excess blocks at head
			pop_chain();
			m_tx_pool_version = 1;
		}
		while (get_tip_height() >= resp.start_height &&
		       !empty_chain()) {  // then undo all blocks at head with different bids
			const api::BlockHeader &other_header = resp.blocks[get_tip_height() - resp.start_height].header;
			if (get_tip_bid() == other_header.hash)
				break;
			if (get_tip_height() == 0)
				return false;  // Different genesis bid
			pop_chain();
			m_tx_pool_version = 1;
		}
		if (get_tip_height() + 1 < resp.start_height)
			while (!empty_chain()) {  // undo everything
				pop_chain();
				m_tx_pool_version = 1;
			}
		if (empty_chain())
			reset_chain(resp.start_height);
		preparator.cancel_work();
		preparator.start_work(resp, m_wallet.get_view_secret_key());
		while (get_tip_height() + 1 < resp.start_height + resp.blocks.size()) {
			size_t bin                     = get_tip_height() + 1 - resp.start_height;
			const api::BlockHeader &header = resp.blocks.at(bin).header;
			if (!empty_chain() && header.previous_block_hash != get_tip_bid())  // TODO - investigate first condition
				return false;
			if (header.timestamp + m_currency.block_future_time_limit >= m_wallet.get_oldest_timestamp()) {
				const auto &block_gi   = resp.blocks.at(bin).global_indices;
				PreparedWalletBlock pb = preparator.get_ready_work(get_tip_height() + 1);
				// PreparedWalletBlock pb(std::move(resp.blocks.at(bin).block), m_wallet.get_view_secret_key());
				redo_block(header, pb, block_gi, get_tip_height() + 1);
				//			push_chain(header);
				//			pop_chain();
				//			redo_block(header, pb, block_gi, m_tip_height + 1);
				auto now = std::chrono::steady_clock::now();
				if (std::chrono::duration_cast<std::chrono::milliseconds>(now - log_redo_block).count() > 1000) {
					log_redo_block = now;
					m_log(logging::INFO) << "WalletState redo block, height=" << get_tip_height() << "/"
					                     << resp.status.top_known_block_height << std::endl;
				} else
					m_log(logging::TRACE) << "WalletState redo block, height=" << get_tip_height() << "/"
					                      << resp.status.top_known_block_height << std::endl;
			}
			push_chain(header);
			m_tx_pool_version = 1;
			m_pq_version      = 1;
		}
		fix_empty_chain();
	} catch (const std::exception &ex) {
		m_log(logging::ERROR)
		    << "Exception in sync_with_blockchain, probably out of disk space or database corrupted error=" << ex.what()
		    << " path=" << m_db.get_path() << std::endl;
		std::exit(api::BYTECOIND_DATABASE_ERROR);
	}
	fix_payment_queue_after_undo_redo();
	return true;
}

std::vector<Hash> WalletState::get_tx_pool_hashes() const {
	return std::vector<Hash>(m_pool_hashes.begin(), m_pool_hashes.end());
}

bool WalletState::sync_with_blockchain(api::bytecoind::SyncMemPool::Response &resp) {
	for (const auto & tid : resp.removed_hashes) {
		if (m_pool_hashes.erase(tid) != 0)
			remove_transaction_from_mempool(tid, false);
	}
	for (size_t i = 0; i != resp.added_raw_transactions.size(); ++i) {
		TransactionPrefix &tx = resp.added_raw_transactions[i];
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
		return false;                           // Bad node - TODO
	Hash base_hash = pb.base_transaction_hash;  // get_transaction_hash(pb.base_transaction.tx);
	if (!redo_transaction(pb.base_transaction, global_indices[0], this, true, base_hash, get_tip_height() + 1,
	        header.hash, pb.header.timestamp)) {
	}  // Just ignore - TODO
	for (size_t tx_index = 0; tx_index != pb.transactions.size(); ++tx_index) {
		const Hash tid = pb.header.transaction_hashes.at(tx_index);
		if (m_pool_hashes.erase(tid) != 0)
			remove_transaction_from_mempool(tid, false);
		m_memory_state.undo_transaction(tid);
		if (!redo_transaction(pb.transactions.at(tx_index), global_indices.at(tx_index + 1), this, false, tid,
		        get_tip_height() + 1, header.hash, pb.header.timestamp)) {
		}  // just ignore - TODO
	}
	unlock(height, header.timestamp_median);
	// If ex has lock_time in the past, it will be added to lock index in redo, then immediately unlocked here
	return true;
}

// We return output transfers in ptx, input transfers in input_transfers
bool WalletState::parse_raw_transaction(api::Transaction *ptx, std::vector<api::Transfer> *input_transfers,
    Amount *unrecognized_inputs_amount, const PreparedWalletTransaction &pwtx, Hash tid,
    const std::vector<uint32_t> &global_indices, Height block_height) const {
	if (global_indices.size() != pwtx.tx.outputs.size())  // Bad node
		return false;  // Without global indices we cannot do anything with transaction
	const TransactionPrefix &tx = pwtx.tx;
	PublicKey tx_public_key     = get_transaction_public_key_from_extra(tx.extra);
	if (pwtx.derivation == KeyDerivation{})
		return false;
	Wallet::History history = m_wallet.load_history(tid);
	KeyPair tx_keys;
	ptx->hash         = tid;
	ptx->block_height = block_height;
	ptx->anonymity    = std::numeric_limits<uint32_t>::max();
	ptx->unlock_time  = tx.unlock_time;
	ptx->public_key   = tx_public_key;
	ptx->extra        = tx.extra;
	get_payment_id_from_tx_extra(tx.extra, ptx->payment_id);

	uint32_t out_index   = 0;
	Amount output_amount = 0;
	size_t key_index     = 0;
	bool our_transaction = false;
	// We combine outputs into transfers by address
	std::map<AccountPublicAddress, api::Transfer> transfer_map_outputs[2];  // We index by ours
	for (const auto &output : tx.outputs) {
		output_amount += output.amount;
		ptx->fee -= output.amount;
		if (output.target.type() == typeid(KeyOutput)) {
			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			PublicKey spend_key         = pwtx.spend_keys.at(key_index);
			bool our_key                = false;
			if (spend_key != PublicKey{}) {
				auto sk = m_wallet.get_records().find(spend_key);
				if (sk != m_wallet.get_records().end()) {
					KeyPair in_ephemeral;
					if (derive_public_key(pwtx.derivation, out_index, spend_key, in_ephemeral.public_key)) {
						derive_secret_key(
						    pwtx.derivation, out_index, sk->second.spend_secret_key, in_ephemeral.secret_key);
						//	std::cout << "My output!
						// out_index=" << out_index << "amount=" << output.amount << std::endl;
						AccountPublicAddress address{spend_key, m_wallet.get_view_public_key()};
						api::Output out;
						out.amount               = output.amount;
						out.global_index         = global_indices.at(out_index);
						out.dust                 = Currency::is_dust(output.amount);
						out.height               = block_height;
						out.index_in_transaction = out_index;
						if (sk->second.spend_secret_key != SecretKey{})
							generate_key_image(in_ephemeral.public_key, in_ephemeral.secret_key, out.key_image);
						out.public_key             = key_output.key;
						out.transaction_public_key = tx_public_key;
						out.unlock_time            = tx.unlock_time;
						api::Transfer &transfer    = transfer_map_outputs[true][address];
						if (transfer.address.empty())
							transfer.address           = m_currency.account_address_as_string(address);
						out.address                    = transfer.address;
						Amount confirmed_balance_delta = 0;
						if (try_add_incoming_output(out, &confirmed_balance_delta)) {
							transfer.amount += confirmed_balance_delta;
							transfer.outputs.push_back(out);
						}
						our_transaction = true;
						our_key         = true;
					}
				}
			}
			if (!our_key && !history.empty()) {
				if (tx_keys.secret_key == SecretKey{})  // do expensive calcs once and only if needed
					tx_keys = TransactionBuilder::deterministic_keys_from_seed(tx, m_wallet.get_tx_derivation_seed());
				for (auto &&addr : history) {
					PublicKey guess_key{};
					TransactionBuilder::derive_public_key(addr, tx_keys.secret_key, out_index, guess_key);
					if (guess_key == key_output.key) {
						api::Output out;
						out.amount       = output.amount;
						out.global_index = global_indices.at(out_index);
						out.dust         = Currency::is_dust(output.amount);
						out.height       = block_height;
						// We cannot generate key_image for others addresses
						out.index_in_transaction   = out_index;
						out.public_key             = key_output.key;
						out.transaction_public_key = tx_public_key;
						out.unlock_time            = tx.unlock_time;
						api::Transfer &transfer    = transfer_map_outputs[false][addr];
						if (transfer.address.empty())
							transfer.address = m_currency.account_address_as_string(addr);
						out.address          = transfer.address;
						transfer.amount += output.amount;
						transfer.outputs.push_back(out);
					}
				}
			}
			++key_index;
		}
		++out_index;
	}
	for (bool ours : {false, true})
		for (auto &&tm : transfer_map_outputs[ours]) {
			tm.second.locked = ptx->unlock_time != 0;
			tm.second.ours   = ours;
			if (tm.second.amount != 0)  // We use map as a map of addresses
				ptx->transfers.push_back(std::move(tm.second));
		}
	std::map<std::string, api::Transfer> transfer_map_inputs;
	*unrecognized_inputs_amount = 0;
	Amount input_amount         = 0;
	for (const auto &input : tx.inputs) {
		if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			input_amount += in.amount;
			ptx->fee += in.amount;
			ptx->anonymity = std::min(ptx->anonymity, static_cast<uint32_t>(in.output_indexes.size() - 1));
			api::Output existing_output;
			if (try_adding_incoming_keyimage(in.key_image, &existing_output)) {
				api::Transfer &transfer = transfer_map_inputs[existing_output.address];
				transfer.amount -= static_cast<SignedAmount>(existing_output.amount);
				transfer.ours = true;
				transfer.outputs.push_back(existing_output);
				our_transaction = true;
			} else
				*unrecognized_inputs_amount += in.amount;
		}
	}
	for (auto &&tm : transfer_map_inputs) {
		tm.second.address = tm.first;
		input_transfers->push_back(tm.second);
	}
	ptx->amount = std::max(input_amount, output_amount);
	if (ptx->anonymity == std::numeric_limits<uint32_t>::max())
		ptx->anonymity = 0;  // No key inputs
	return our_transaction;
}

bool WalletState::parse_raw_transaction(api::Transaction &ptx, const TransactionPrefix &tx, Hash tid) const {
	std::vector<uint32_t> global_indices(tx.outputs.size(), 0);
	Amount unrecognized_inputs_amount = 0;
	PreparedWalletTransaction pwtx(TransactionPrefix(tx), m_wallet.get_view_secret_key());
	std::vector<api::Transfer> input_transfers;
	parse_raw_transaction(
	    &ptx, &input_transfers, &unrecognized_inputs_amount, pwtx, tid, global_indices, get_tip_height());
	// We do not know "from" addresses, so leave address empty
	ptx.transfers.insert(ptx.transfers.end(), input_transfers.begin(), input_transfers.end());
	if (unrecognized_inputs_amount != 0) {
		api::Transfer input_transfer;
		input_transfer.amount = -static_cast<SignedAmount>(unrecognized_inputs_amount);
		input_transfer.ours   = true;
		ptx.transfers.push_back(input_transfer);
	}
	return true;
}

const std::map<KeyImage, int> &WalletState::get_used_key_images() const { return m_memory_state.get_used_key_images(); }

void WalletState::on_first_transaction_found(Timestamp ts) { m_wallet.on_first_output_found(ts); }

bool WalletState::redo_transaction(const PreparedWalletTransaction &pwtx, const std::vector<uint32_t> &global_indices,
    IWalletState *delta_state, bool is_base, Hash tid, Height block_height, Hash bid, Timestamp tx_timestamp) {
	api::Transaction ptx;
	Amount unrecognized_inputs_amount = 0;
	std::vector<api::Transfer> input_transfers;
	if (!parse_raw_transaction(
	        &ptx, &input_transfers, &unrecognized_inputs_amount, pwtx, tid, global_indices, block_height))
		return false;  // not ours
	if (is_base)
		ptx.fee    = 0;
	ptx.block_hash = bid;
	ptx.coinbase   = is_base;
	ptx.timestamp  = tx_timestamp;
	for (auto &&tr : ptx.transfers) {  // add and fix outputs
		if (!tr.ours)
			continue;
		for (auto &&out : tr.outputs) {
			Amount adjusted_amount = delta_state->add_incoming_output(out);
			out.amount             = adjusted_amount;
		}
	}
	for (auto &&tr : input_transfers) {
		for (auto &&out : tr.outputs) {
			delta_state->add_incoming_keyimage(block_height, out.key_image);
		}
	}
	ptx.transfers.insert(ptx.transfers.end(), input_transfers.begin(), input_transfers.end());
	delta_state->add_transaction(block_height, tid, pwtx.tx, ptx);
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

bool WalletState::api_get_transaction(Hash tid, bool check_pool, TransactionPrefix *tx, api::Transaction *ptx) const {
	if (check_pool) {
		auto mit = m_memory_state.get_transactions().find(tid);
		if (mit != m_memory_state.get_transactions().end()) {
			*tx  = mit->second.first;
			*ptx = mit->second.second;
			return true;
		}
	}
	return get_transaction(tid, tx, ptx);
}

bool WalletState::api_create_proof(SendProof &sp) const {
	TransactionPrefix tx;
	api::Transaction ptx;
	if (!api_get_transaction(sp.transaction_hash, true, &tx, &ptx))
		return false;
	KeyPair tx_keys = TransactionBuilder::deterministic_keys_from_seed(tx, m_wallet.get_tx_derivation_seed());
	if (!crypto::generate_key_derivation(sp.address.view_public_key, tx_keys.secret_key, sp.derivation))
		return false;
	Hash message_hash = crypto::cn_fast_hash(sp.message.data(), sp.message.size());
	if (!crypto::generate_sendproof(tx_keys.public_key, tx_keys.secret_key, sp.address.view_public_key, sp.derivation,
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
	// TODO - faster filter by address
	api::Block current_block;
	current_block.header.height = get_tip_height() + 1;
	for (auto &&hit : m_memory_state.get_transactions()) {
		current_block.transactions.push_back(hit.second.second);
		auto &tx        = current_block.transactions.back();
		tx.block_height = get_tip_height() + 1;
		if (!address.empty()) {
			for (auto tit = tx.transfers.begin(); tit != tx.transfers.end();)
				if (tit->address == address)
					++tit;
				else
					tit = tx.transfers.erase(tit);
		}
	}
	return current_block;
}
