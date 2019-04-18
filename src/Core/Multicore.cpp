// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Multicore.hpp"
#include "BlockChainState.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "Currency.hpp"
#include "TransactionExtra.hpp"
#include "crypto/crypto.hpp"
#include "platform/Network.hpp"

using namespace cn;

BlockPreparatorMulticore::BlockPreparatorMulticore(const Currency &currency, platform::EventLoop *main_loop)
    : currency(currency), main_loop(main_loop) {
	auto th_count = std::max<size_t>(2, 3 * std::thread::hardware_concurrency() / 4);
	// we use more energy but have the same speed when using hyperthreading
	//	std::cout << "Starting multicore ring checker using " << th_count << "/" << std::thread::hardware_concurrency()
	//	          << " cpus" << std::endl;
	for (size_t i = 0; i != th_count; ++i)
		threads.emplace_back(&BlockPreparatorMulticore::thread_run, this);
}
BlockPreparatorMulticore::~BlockPreparatorMulticore() {
	{
		std::unique_lock<std::mutex> lock(mu);
		quit = true;
		have_work.notify_all();
	}
	for (auto &&th : threads)
		th.join();
}
void BlockPreparatorMulticore::thread_run() {
	crypto::CryptoNightContext ctx;
	while (true) {
		std::tuple<Hash, bool, RawBlock> local_work;
		{
			std::unique_lock<std::mutex> lock(mu);
			if (quit)
				return;
			if (work.empty()) {
				have_work.wait(lock);
				continue;
			}
			local_work = std::move(work.front());
			work.pop_front();
		}
		PreparedBlock pb(std::move(std::get<2>(local_work)), currency, std::get<1>(local_work) ? &ctx : nullptr);
		{
			std::unique_lock<std::mutex> lock(mu);
			prepared_blocks[std::get<0>(local_work)] = std::move(pb);
			main_loop->wake();  // so we start processing on_idle
			                    //			prepared_blocks_ready.notify_all();
		}
	}
}

void BlockPreparatorMulticore::add_block(Hash bid, bool check_pow, RawBlock &&rb) {
	std::unique_lock<std::mutex> lock(mu);
	work.push_back(std::make_tuple(bid, check_pow, std::move(rb)));
	have_work.notify_all();
}

bool BlockPreparatorMulticore::get_prepared_block(Hash bid, PreparedBlock *pb) {
	std::unique_lock<std::mutex> lock(mu);
	auto pid = prepared_blocks.find(bid);
	if (pid == prepared_blocks.end())
		return false;
	*pb = std::move(pid->second);
	pid = prepared_blocks.erase(pid);
	return true;
}

bool BlockPreparatorMulticore::has_prepared_block(Hash bid) const {
	std::unique_lock<std::mutex> lock(mu);
	auto pid = prepared_blocks.find(bid);
	return pid != prepared_blocks.end();
}

RingCheckerMulticore::RingCheckerMulticore() {
	auto th_count = std::max<size_t>(2, 3 * std::thread::hardware_concurrency() / 4);
	// we use more energy but have the same speed when using hyperthreading
	//	std::cout << "Starting multicore ring checker using " << th_count << "/" << std::thread::hardware_concurrency()
	//	          << " cpus" << std::endl;
	for (size_t i = 0; i != th_count; ++i)
		threads.emplace_back(&RingCheckerMulticore::thread_run, this);
}

RingCheckerMulticore::~RingCheckerMulticore() {
	{
		std::unique_lock<std::mutex> lock(mu);
		quit = true;
		have_work.notify_all();
	}
	for (auto &&th : threads)
		th.join();
}

void RingCheckerMulticore::thread_run() {
	while (true) {
		RingSignatureArg arg;
		RingSignatureArgA arga;
		Height newest_referenced_height = 0;
		int local_work_counter          = 0;
		{
			std::unique_lock<std::mutex> lock(mu);
			if (quit)
				return;
			if (args.empty() && argsa.empty()) {
				have_work.wait(lock);
				continue;
			}
			local_work_counter = work_counter;
			if (!args.empty()) {
				arg                      = std::move(args.front());
				newest_referenced_height = arg.newest_referenced_height;
				args.pop_front();
			} else {
				arga                     = std::move(argsa.front());
				newest_referenced_height = arga.newest_referenced_height;
				argsa.pop_front();
			}
		}
		bool result = false;
		try {
			if (!arg.output_keys.empty()) {
				result = crypto::check_ring_signature(
				    arg.tx_prefix_hash, arg.key_image, arg.output_keys, arg.input_signature);
			} else {
				result = crypto::check_ring_signature_amethyst(
				    arga.tx_prefix_hash, arga.key_images, arga.output_keys, arga.input_signature);
			}
		} catch (const std::exception &) {  // even invariant violations will mean bad signature
			                                // TODO - pass exception text up
		}
		{
			std::unique_lock<std::mutex> lock(mu);
			if (local_work_counter == work_counter) {
				ready_counter += 1;
				if (!result)
					errors.push_back(ConsensusErrorBadOutputOrSignature{
					    "Bad signature or output reference changed", newest_referenced_height});
				result_ready.notify_all();
			}
		}
	}
}
void RingCheckerMulticore::cancel_work() {
	std::unique_lock<std::mutex> lock(mu);
	args.clear();
	argsa.clear();
	work_counter += 1;
}

void RingCheckerMulticore::start_work(IBlockChainState *state, const Currency &currency, const Block &block,
    Height unlock_height, Timestamp block_timestamp, Timestamp block_median_timestamp) {
	{
		std::unique_lock<std::mutex> lock(mu);
		args.clear();
		argsa.clear();
		errors.clear();
		ready_counter = 0;
		work_counter += 1;
	}
	total_counter = 0;
	for (auto &&transaction : block.transactions) {
		Hash tx_prefix_hash = get_transaction_prefix_hash(transaction);
		RingSignatureArgA arga;
		for (size_t input_index = 0; input_index != transaction.inputs.size(); ++input_index) {
			const auto &input               = transaction.inputs.at(input_index);
			Height newest_referenced_height = 0;
			if (input.type() == typeid(InputKey)) {
				const InputKey &in = boost::get<InputKey>(input);
				Height height      = 0;
				if (state->read_keyimage(in.key_image, &height))
					throw ConsensusErrorOutputSpent("Output already spent", in.key_image, height);
				std::vector<size_t> absolute_indexes;
				if (!relative_output_offsets_to_absolute(&absolute_indexes, in.output_indexes))
					throw ConsensusError("Output indexes invalid in input");
				std::vector<PublicKey> output_keys(absolute_indexes.size());
				for (size_t i = 0; i != absolute_indexes.size(); ++i) {
					IBlockChainState::OutputIndexData unp;
					if (!state->read_amount_output(in.amount, absolute_indexes[i], &unp))
						throw ConsensusErrorOutputDoesNotExist(
						    "Output does not exist", input_index, absolute_indexes[i]);
					if (!currency.is_transaction_unlocked(block.header.major_version, unp.unlock_block_or_timestamp,
					        unlock_height, block_timestamp, block_median_timestamp))
						throw ConsensusErrorBadOutputOrSignature("Output locked", unp.height);
					output_keys[i]           = unp.public_key;
					newest_referenced_height = std::max(newest_referenced_height, unp.height);
				}
				// As soon as first arg is ready, other thread can start work while we
				// continue reading from slow DB
				if (transaction.signatures.type() == typeid(RingSignatures)) {
					auto &signatures = boost::get<RingSignatures>(transaction.signatures);
					RingSignatureArg arg;
					arg.tx_prefix_hash           = tx_prefix_hash;
					arg.newest_referenced_height = newest_referenced_height;
					arg.key_image                = in.key_image;
					arg.output_keys              = std::move(output_keys);
					arg.input_signature          = signatures.signatures.at(input_index);
					total_counter += 1;
					std::unique_lock<std::mutex> lock(mu);
					args.push_back(std::move(arg));
					have_work.notify_all();
				} else if (transaction.signatures.type() == typeid(RingSignatureAmethyst)) {
					auto &signatures = boost::get<RingSignatureAmethyst>(transaction.signatures);
					arga.output_keys.push_back(std::move(output_keys));
					arga.newest_referenced_height = std::max(arga.newest_referenced_height, newest_referenced_height);
					arga.key_images.push_back(in.key_image);
					if (arga.input_signature.rr.empty())
						arga.input_signature = signatures;
				} else
					throw ConsensusError("Unknown signatures type");
			}
		}
		if (!arga.output_keys.empty()) {
			arga.tx_prefix_hash = tx_prefix_hash;
			total_counter += 1;
			std::unique_lock<std::mutex> lock(mu);
			argsa.push_back(std::move(arga));
			have_work.notify_all();
		}
	}
}

std::vector<ConsensusErrorBadOutputOrSignature> RingCheckerMulticore::move_errors() {
	while (true) {
		std::unique_lock<std::mutex> lock(mu);
		if (ready_counter != total_counter) {
			result_ready.wait(lock);
			continue;
		}
		return std::move(errors);
	}
}

WalletPreparatorMulticore::WalletPreparatorMulticore(hardware::HardwareWallet *hw_copy,
    Wallet::OutputHandler &&o_handler, const SecretKey &view_secret_key, platform::EventLoop *main_loop)
    : hw_copy(hw_copy), m_o_handler(std::move(o_handler)), m_view_secret_key(view_secret_key), m_main_loop(main_loop) {
	if (hw_copy && m_view_secret_key == SecretKey{}) {
		// Access to HW is serialised, more than 1 thread will gain nothing except complexity
		threads.emplace_back(&WalletPreparatorMulticore::thread_run, this);
		m_o_handler = std::bind(&WalletPreparatorMulticore::hw_output_handler, this, _1, _2, _3, _4, _5, _6, _7);
	} else {
		auto th_count = std::max<size_t>(2, std::thread::hardware_concurrency());
		// we use more energy but have the same speed when using hyperthreading to max
		// std::cout << "Starting multicore transaction preparator using " << th_count << "/"
		// << std::thread::hardware_concurrency() << " cpus" << std::endl;
		for (size_t i = 0; i != th_count; ++i)
			threads.emplace_back(&WalletPreparatorMulticore::thread_run, this);
	}
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

PreparedWalletTransaction::PreparedWalletTransaction(const Hash &tid, size_t size, TransactionPrefix &&ttx,
    const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key)
    : tid(tid), size(size), tx(std::move(ttx)) {
	prepare(o_handler, view_secret_key);
}

PreparedWalletTransaction::PreparedWalletTransaction(const Hash &tid, size_t size, Transaction &&tx,
    const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key)
    : PreparedWalletTransaction(
          tid, size, std::move(static_cast<TransactionPrefix &&>(tx)), o_handler, view_secret_key) {}

void PreparedWalletTransaction::prepare(const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key) {
	// We ignore results of most crypto calls here and absence of tx_public_key
	// All errors will lead to spend_key not found in our wallet for legacy crypto
	PublicKey tx_public_key = extra_get_transaction_public_key(tx.extra);
	derivation              = generate_key_derivation(tx_public_key, view_secret_key);

	prefix_hash = get_transaction_prefix_hash(tx);
	inputs_hash = get_transaction_inputs_hash(tx);

	KeyPair tx_keys;
	address_public_keys.resize(tx.outputs.size());
	output_secret_hash_args.resize(tx.outputs.size());
	for (size_t out_index = 0; out_index != tx.outputs.size(); ++out_index) {
		const auto &output = tx.outputs.at(out_index);
		if (output.type() != typeid(OutputKey))
			continue;
		const auto &key_output = boost::get<OutputKey>(output);
		o_handler(tx.version, derivation, inputs_hash, out_index, key_output, &address_public_keys.at(out_index),
		    &output_secret_hash_args.at(out_index));
	}
}

void PreparedWalletBlock::prepare(const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key) {
	transactions.reserve(this->raw_block.transactions.size());
	const Hash base_transaction_hash   = raw_block.transactions.at(0).hash;
	const size_t base_transaction_size = raw_block.transactions.at(0).size;
	// We pass copies because we wish to keep raw_block as is
	transactions.emplace_back(base_transaction_hash, base_transaction_size,
	    Transaction(raw_block.raw_header.base_transaction), o_handler, view_secret_key);
	for (size_t tx_index = 0; tx_index != raw_block.raw_transactions.size(); ++tx_index) {
		const Hash transaction_hash = raw_block.transactions.at(tx_index + 1).hash;
		const size_t size           = raw_block.transactions.at(tx_index + 1).size;
		transactions.emplace_back(transaction_hash, size, TransactionPrefix(raw_block.raw_transactions.at(tx_index)),
		    o_handler, view_secret_key);
	}
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

static void fill_tx_output_public_keys(std::vector<PublicKey> *output_public_keys, const api::RawBlock &b) {
	fill_tx_output_public_keys(output_public_keys, b.raw_header.base_transaction);
	for (const auto &tx : b.raw_transactions)
		fill_tx_output_public_keys(output_public_keys, tx);
}

void WalletPreparatorMulticore::hw_output_handler(uint8_t tx_version, const KeyDerivation &kd,
    const Hash &tx_inputs_hash, size_t output_index, const OutputKey &key_output, PublicKey *address_S,
    BinaryArray *output_secret_hash_arg) {
	invariant(!result_pks.empty(), "");
	auto Pv = result_pks.front();
	result_pks.pop_front();
	*address_S = unlinkable_underive_address_S_step2(
	    Pv, tx_inputs_hash, output_index, key_output.public_key, key_output.encrypted_secret, output_secret_hash_arg);
}

void WalletPreparatorMulticore::thread_run() {
	while (true) {
		WorkItem *sync_block = nullptr;
		std::deque<crypto::PublicKey> local_source_pks;
		{
			std::unique_lock<std::mutex> lock(mu);
			if (quit)
				return;
			if (!wallet_connected) {
				have_work.wait(lock);
				continue;
			}
			for (auto &w : work)
				if (w->status == WAITING) {
					w->status  = BUSY;
					sync_block = w.get();
					break;
				}
			if (!sync_block) {
				have_work.wait(lock);
				continue;
			}
			if (hw_copy && m_view_secret_key == SecretKey{}) {
				const size_t max_cou =
				    std::min<size_t>(source_pks.size(), sync_block->pks_count + hw_copy->get_scan_outputs_max_batch());
				local_source_pks.assign(source_pks.begin(), source_pks.begin() + max_cou);
			}
		}
		try {
			if (hw_copy && m_view_secret_key == SecretKey{}) {
				while (result_pks.size() < sync_block->pks_count) {
					invariant(!local_source_pks.empty(), "");
					const size_t cou = std::min<size_t>(local_source_pks.size(), hw_copy->get_scan_outputs_max_batch());
					std::vector<PublicKey> chunk{local_source_pks.begin(), local_source_pks.begin() + cou};
					auto result = hw_copy->scan_outputs(chunk);  // Will throw here if HW disconnected
					local_source_pks.erase(local_source_pks.begin(), local_source_pks.begin() + cou);
					result_pks.insert(result_pks.end(), result.begin(), result.end());
				}
			}
			if (sync_block->is_tx) {
				sync_block->pwtx.prepare(m_o_handler, m_view_secret_key);
			} else {
				sync_block->block.prepare(m_o_handler, m_view_secret_key);
			}
			std::unique_lock<std::mutex> lock(mu);
			sync_block->status = PREPARED;
			source_pks.insert(source_pks.begin(), local_source_pks.begin(), local_source_pks.end());
		} catch (const std::runtime_error &ex) {
			std::unique_lock<std::mutex> lock(mu);
			wallet_connected   = false;
			sync_block->status = WAITING;
			source_pks.insert(source_pks.begin(), local_source_pks.begin(), local_source_pks.end());
		}
		m_main_loop->wake();
	}
}

void WalletPreparatorMulticore::add_work(std::vector<api::RawBlock> &&new_work) {
	std::unique_lock<std::mutex> lock(mu);
	for (auto &&b : new_work) {
		total_block_size += b.header.transactions_size;
		std::vector<PublicKey> output_public_keys;
		if (hw_copy && m_view_secret_key == SecretKey{}) {
			fill_tx_output_public_keys(&output_public_keys, b);
			source_pks.insert(source_pks.end(), output_public_keys.begin(), output_public_keys.end());
		}
		auto pb             = std::make_unique<WorkItem>();
		pb->is_tx           = false;
		pb->block.raw_block = std::move(b);
		pb->pks_count       = output_public_keys.size();
		pb->status          = WAITING;
		work.push_back(std::move(pb));
	}
	if (wallet_connected)
		have_work.notify_all();
}

void WalletPreparatorMulticore::add_work(const Hash &tid, size_t size, TransactionPrefix &&new_work) {
	std::unique_lock<std::mutex> lock(mu);

	total_mempool_count += 1;
	std::vector<PublicKey> output_public_keys;
	if (hw_copy && m_view_secret_key == SecretKey{}) {
		fill_tx_output_public_keys(&output_public_keys, new_work);
		source_pks.insert(source_pks.end(), output_public_keys.begin(), output_public_keys.end());
	}
	auto pb       = std::make_unique<WorkItem>();
	pb->is_tx     = true;
	pb->pwtx.tid  = tid;
	pb->pwtx.size = size;
	pb->pwtx.tx   = std::move(new_work);
	pb->pks_count = output_public_keys.size();
	pb->status    = WAITING;
	work.push_back(std::move(pb));
	if (wallet_connected)
		have_work.notify_all();
}

bool WalletPreparatorMulticore::is_wallet_connected() {
	std::unique_lock<std::mutex> lock(mu);
	return wallet_connected;
}

void WalletPreparatorMulticore::wallet_reconnected() {
	std::unique_lock<std::mutex> lock(mu);
	wallet_connected = true;
	have_work.notify_all();
}

void WalletPreparatorMulticore::get_ready_work(
    std::deque<PreparedWalletBlock> *blocks, std::deque<PreparedWalletTransaction> *transactions) {
	blocks->clear();
	transactions->clear();
	std::unique_lock<std::mutex> lock(mu);
	if (!wallet_connected)
		return;
	while (!work.empty() && work.front()->status == PREPARED) {
		if (work.front()->is_tx) {
			total_mempool_count -= 1;
			transactions->push_back(std::move(work.front()->pwtx));
		} else {
			total_block_size -= work.front()->block.raw_block.header.transactions_size;
			blocks->push_back(std::move(work.front()->block));
		}
		work.pop_front();
	}
}

void WalletPreparatorMulticore::return_ready_work(std::deque<PreparedWalletBlock> &&ppb) {
	std::unique_lock<std::mutex> lock(mu);
	wallet_connected = false;
	while (!ppb.empty()) {
		total_block_size += ppb.back().raw_block.header.transactions_size;
		auto pb   = std::make_unique<WorkItem>();
		pb->is_tx = false;
		pb->block = std::move(ppb.back());
		// We will have pks_count missing, but this does not matter for PREPARED block
		pb->status = PREPARED;
		work.push_front(std::move(pb));
	}
}

void WalletPreparatorMulticore::return_ready_work(std::deque<PreparedWalletTransaction> &&ppb) {
	std::unique_lock<std::mutex> lock(mu);
	wallet_connected = false;
	while (!ppb.empty()) {
		total_mempool_count += 1;
		auto pb   = std::make_unique<WorkItem>();
		pb->is_tx = true;
		pb->pwtx  = std::move(ppb.back());
		// We will have pks_count missing, but this does not matter for PREPARED transaction
		pb->status = PREPARED;
		work.push_front(std::move(pb));
	}
}
