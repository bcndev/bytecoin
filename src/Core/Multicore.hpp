// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include "BlockChain.hpp"  // for PreparedBlock
#include "CryptoNote.hpp"
#include "rpc_api.hpp"

// Experimental machinery to offload heavy calcs to other cores
// Without making any critical part of the Core multithreaded
// We do it by confining threads to "boxes"
namespace platform {
class EventLoop;
}
namespace cn {

class IBlockChainState;  // We will read keyimages and outputs from it
class Currency;

class BlockPreparatorMulticore {
	const Currency &currency;

	std::vector<std::thread> threads;
	mutable std::mutex mu;
	std::condition_variable have_work;
	platform::EventLoop *main_loop = nullptr;
	//	std::condition_variable prepared_blocks_ready;
	bool quit = false;

	struct WorkItem {
		Hash hash;
		bool check_pow = false;
		RawBlock rb;
	};
	std::deque<WorkItem> work;
	std::map<Hash, boost::variant<ConsensusError, PreparedBlock>> prepared_blocks;

	void thread_run();

public:
	explicit BlockPreparatorMulticore(const Currency &currency, platform::EventLoop *main_loop);
	~BlockPreparatorMulticore();

	void add_block(Hash bid, bool check_pow, RawBlock &&rb);
	bool get_prepared_block(Hash bid, boost::variant<ConsensusError, PreparedBlock> *pb);
	bool has_prepared_block(Hash bid) const;
};

struct RingSignatureCheckArgs {
	Hash tx_prefix_hash;
	Height newest_referenced_height = 0;
	std::vector<KeyImage> key_images;
	std::vector<std::vector<PublicKey>> output_keys;
	std::vector<std::vector<PublicKey>> amount_commitments;
	std::vector<std::vector<Amount>> amounts;
	TransactionSignatures signatures;

	bool check() const;
};

class RingCheckerMulticore {
	std::vector<std::thread> threads;
	size_t total_counter = 0;

	mutable std::mutex mu;  // everything below is protected by mutex
	mutable std::condition_variable have_work;
	mutable std::condition_variable result_ready;
	bool quit = false;

	size_t ready_counter = 0;
	std::vector<ConsensusErrorBadOutputOrSignature> errors;

	std::deque<RingSignatureCheckArgs> work;
	int batch_counter = 0;
	void thread_run();

public:
	RingCheckerMulticore();
	~RingCheckerMulticore();
	void start_batch();
	void add_work(RingSignatureCheckArgs &&args);
	std::vector<ConsensusErrorBadOutputOrSignature> move_batch_errors();
};

}  // namespace cn
