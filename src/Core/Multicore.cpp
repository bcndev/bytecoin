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
			main_loop->wake([]() {});  // so we start processing on_idle
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
