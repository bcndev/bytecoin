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
		WorkItem local_work;
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
		boost::variant<ConsensusError, PreparedBlock> result = ConsensusError{""};
		try {
			result = PreparedBlock{std::move(local_work.rb), currency, local_work.check_pow ? &ctx : nullptr};
		} catch (const ConsensusError &ex) {
			result = ex;
		} catch (const std::runtime_error &ex) {
			result = ConsensusError{"Runtime error - " + common::what(ex)};
		} catch (const std::logic_error &ex) {  // TODO - terminate app
			result = ConsensusError{"Logic error - " + common::what(ex)};
		}
		{
			std::unique_lock<std::mutex> lock(mu);
			prepared_blocks.insert(std::make_pair(local_work.hash, std::move(result)));
			main_loop->wake([]() {});  // so we start processing on_idle
		}
	}
}

void BlockPreparatorMulticore::add_block(Hash bid, bool check_pow, RawBlock &&rb) {
	std::unique_lock<std::mutex> lock(mu);
	work.push_back(WorkItem{bid, check_pow, std::move(rb)});
	have_work.notify_all();
}

bool BlockPreparatorMulticore::get_prepared_block(Hash bid, boost::variant<ConsensusError, PreparedBlock> *pb) {
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

bool RingSignatureCheckArgs::check() const {
	try {
		if (signatures.type() == typeid(RingSignatureAmethyst)) {
			auto &sigs = boost::get<RingSignatureAmethyst>(signatures);
			return crypto::check_ring_signature_amethyst(tx_prefix_hash, key_images, output_keys, sigs);
		}
		if (signatures.type() == typeid(RingSignatures)) {
			auto &sigs = boost::get<RingSignatures>(signatures);
			if (sigs.signatures.empty() || sigs.signatures.size() != key_images.size())
				return false;
			for (size_t input_index = 0; input_index != sigs.signatures.size(); ++input_index) {
				if (!check_ring_signature(tx_prefix_hash, key_images.at(input_index), output_keys.at(input_index),
				        sigs.signatures.at(input_index)))
					return false;
			}
			return true;
		}
		// We never call check() for coinbase. If attacker manages to trick code into setting
		// non coinbase transaction signatures to blank, we will return false
	} catch (const std::exception &) {
		// even invariant violations will mean bad signature
		// TODO - pass exception text up
	}
	return false;  // Unknown signatures type or blank
}

void RingCheckerMulticore::thread_run() {
	while (true) {
		RingSignatureCheckArgs args;
		int local_batch_counter = 0;
		{
			std::unique_lock<std::mutex> lock(mu);
			if (quit)
				return;
			if (work.empty()) {
				have_work.wait(lock);
				continue;
			}
			local_batch_counter = batch_counter;
			args                = std::move(work.front());
			work.pop_front();
		}
		bool result = args.check();  // never throws
		std::unique_lock<std::mutex> lock(mu);
		if (local_batch_counter == batch_counter) {
			ready_counter += 1;
			if (!result)
				errors.push_back(ConsensusErrorBadOutputOrSignature{
				    "Bad signature or output reference changed", args.newest_referenced_height});
			result_ready.notify_all();
		}
	}
}
void RingCheckerMulticore::start_batch() {
	total_counter = 0;
	std::unique_lock<std::mutex> lock(mu);
	work.clear();
	batch_counter += 1;
	ready_counter = 0;
}

void RingCheckerMulticore::add_work(RingSignatureCheckArgs &&args) {
	total_counter += 1;
	std::unique_lock<std::mutex> lock(mu);
	work.push_back(std::move(args));
	have_work.notify_all();
}

std::vector<ConsensusErrorBadOutputOrSignature> RingCheckerMulticore::move_batch_errors() {
	while (true) {
		std::unique_lock<std::mutex> lock(mu);
		if (ready_counter != total_counter) {
			result_ready.wait(lock);
			continue;
		}
		return std::move(errors);
	}
}
