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
		RingSignatureArg3 arg3;
		Height newest_referenced_height = 0;
		int local_work_counter          = 0;
		{
			std::unique_lock<std::mutex> lock(mu);
			if (quit)
				return;
			if (args.empty() && args3.empty()) {
				have_work.wait(lock);
				continue;
			}
			local_work_counter = work_counter;
			if (!args.empty()) {
				arg                      = std::move(args.front());
				newest_referenced_height = arg.newest_referenced_height;
				args.pop_front();
			} else {
				arg3                     = std::move(args3.front());
				newest_referenced_height = arg3.newest_referenced_height;
				args3.pop_front();
			}
		}
		bool result = false;
		if (!arg.output_keys.empty()) {
			result = crypto::check_ring_signature(arg.tx_prefix_hash, arg.key_image, arg.output_keys.data(),
			    arg.output_keys.size(), arg.input_signature, arg.key_image_subgroup_check);
		} else {
			result = crypto::check_ring_signature3(
			    arg3.tx_prefix_hash, arg3.key_images, arg3.output_keys, arg3.input_signature);
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
	args3.clear();
	work_counter += 1;
}

void RingCheckerMulticore::start_work(IBlockChainState *state, const Currency &currency, const Block &block,
    Height unlock_height, Timestamp block_timestamp, Timestamp block_median_timestamp, bool key_image_subgroup_check) {
	{
		std::unique_lock<std::mutex> lock(mu);
		args.clear();
		args3.clear();
		errors.clear();
		ready_counter = 0;
		work_counter += 1;
	}
	total_counter = 0;
	for (auto &&transaction : block.transactions) {
		Hash tx_prefix_hash = get_transaction_prefix_hash(transaction);
		RingSignatureArg3 arg3;
		for (size_t input_index = 0; input_index != transaction.inputs.size(); ++input_index) {
			const auto &input               = transaction.inputs.at(input_index);
			Height newest_referenced_height = 0;
			if (input.type() == typeid(InputKey)) {
				const InputKey &in = boost::get<InputKey>(input);
				Height height      = 0;
				if (state->read_keyimage(in.key_image, &height))
					throw ConsensusErrorOutputSpent("Output already spent", in.key_image, height);
				std::vector<size_t> global_indexes;
				if (!relative_output_offsets_to_absolute(&global_indexes, in.output_indexes))
					throw ConsensusError("Output indexes invalid in input");
				std::vector<PublicKey> output_keys(global_indexes.size());
				for (size_t i = 0; i != global_indexes.size(); ++i) {
					IBlockChainState::UnlockTimePublickKeyHeightSpent unp;
					if (!state->read_amount_output(in.amount, global_indexes[i], &unp))
						throw ConsensusErrorOutputDoesNotExist("Output does not exist", input_index, global_indexes[i]);
					if (unp.auditable && global_indexes.size() != 1)
						throw ConsensusErrorBadOutputOrSignature("Auditable output mixed", unp.height);
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
					arg.key_image_subgroup_check = key_image_subgroup_check;
					arg.tx_prefix_hash           = tx_prefix_hash;
					arg.newest_referenced_height = newest_referenced_height;
					arg.key_image                = in.key_image;
					arg.output_keys              = std::move(output_keys);
					arg.input_signature          = signatures.signatures.at(input_index);
					total_counter += 1;
					std::unique_lock<std::mutex> lock(mu);
					args.push_back(std::move(arg));
					have_work.notify_all();
				} else if (transaction.signatures.type() == typeid(RingSignature3)) {
					auto &signatures = boost::get<RingSignature3>(transaction.signatures);
					arg3.output_keys.push_back(std::move(output_keys));
					arg3.newest_referenced_height = std::max(arg3.newest_referenced_height, newest_referenced_height);
					arg3.key_images.push_back(in.key_image);
					if (arg3.input_signature.r.empty())
						arg3.input_signature = signatures;
				} else
					throw ConsensusError("Unknown signatures type");
			}
		}
		if (!arg3.output_keys.empty()) {
			arg3.tx_prefix_hash = tx_prefix_hash;
			total_counter += 1;
			std::unique_lock<std::mutex> lock(mu);
			args3.push_back(std::move(arg3));
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

WalletPreparatorMulticore::WalletPreparatorMulticore() {
	auto th_count = std::max<size_t>(2, 3 * std::thread::hardware_concurrency() / 4);
	// we use more energy but have the same speed when using hyperthreading to max
	// std::cout << "Starting multicore transaction preparator using " << th_count << "/"
	// << std::thread::hardware_concurrency() << " cpus" << std::endl;
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

PreparedWalletTransaction::PreparedWalletTransaction(
    TransactionPrefix &&ttx, TransactionSignatures &&sigs, const Wallet::OutputHandler &o_handler)
    : tx(std::move(ttx)), sigs(std::move(sigs)) {
	// We ignore results of most crypto calls here and absence of tx_public_key
	// All errors will lead to spend_key not found in our wallet
	PublicKey tx_public_key = extra_get_transaction_public_key(tx.extra);
	prefix_hash             = get_transaction_prefix_hash(tx);
	inputs_hash             = get_transaction_inputs_hash(tx);

	KeyPair tx_keys;
	spend_keys.resize(tx.outputs.size());
	output_secret_scalars.resize(tx.outputs.size());
	for (size_t out_index = 0; out_index != tx.outputs.size(); ++out_index) {
		const auto &output = tx.outputs.at(out_index);
		if (output.type() != typeid(OutputKey))
			continue;
		const auto &key_output = boost::get<OutputKey>(output);
		o_handler(tx_public_key, &derivation, inputs_hash, out_index, key_output, &spend_keys.at(out_index),
		    &output_secret_scalars.at(out_index));
	}
}

PreparedWalletTransaction::PreparedWalletTransaction(Transaction &&tx, const Wallet::OutputHandler &o_handler)
    : PreparedWalletTransaction(std::move(static_cast<TransactionPrefix &&>(tx)), std::move(tx.signatures), o_handler) {
}

PreparedWalletBlock::PreparedWalletBlock(BlockTemplate &&bc_header, std::vector<TransactionPrefix> &&raw_transactions,
    std::vector<TransactionSignatures> &&signatures, Hash base_transaction_hash, const Wallet::OutputHandler &o_handler)
    : base_transaction_hash(base_transaction_hash) {
	header = bc_header;
	base_transaction =
	    PreparedWalletTransaction(std::move(bc_header.base_transaction), TransactionSignatures{}, o_handler);
	transactions.reserve(raw_transactions.size());
	for (size_t tx_index = 0; tx_index != raw_transactions.size(); ++tx_index) {
		transactions.emplace_back(std::move(raw_transactions.at(tx_index)),
		    tx_index < signatures.size() ? std::move(signatures.at(tx_index)) : TransactionSignatures{}, o_handler);
	}
}

void WalletPreparatorMulticore::thread_run() {
	while (true) {
		Wallet::OutputHandler o_handler;
		Height height          = 0;
		int local_work_counter = 0;
		api::RawBlock sync_block;
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
			o_handler          = m_o_handler;
			height             = work.start_height;
			sync_block         = std::move(work.blocks.front());
			work.start_height += 1;
			work.blocks.erase(work.blocks.begin());
		}
		PreparedWalletBlock result(std::move(sync_block.raw_header), std::move(sync_block.raw_transactions),
		    std::move(sync_block.signatures), sync_block.transactions.at(0).hash, o_handler);
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
	work = api::cnd::SyncBlocks::Response();
	prepared_blocks.clear();
	work_counter += 1;
}

void WalletPreparatorMulticore::start_work(
    const api::cnd::SyncBlocks::Response &new_work, Wallet::OutputHandler &&o_handler) {
	std::unique_lock<std::mutex> lock(mu);
	work        = new_work;
	m_o_handler = std::move(o_handler);
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
