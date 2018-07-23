// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include "CryptoNote.hpp"
#include "rpc_api.hpp"

// Experimental machinery to offload heavy calcs to other cores
// Without making any critical part of the Core multithreaded
// We do it by confining threads to "boxes"
namespace bytecoin {

class IBlockChainState;  // We will read keyimages and outputs from it
class Currency;

struct RingSignatureArg {
	Hash tx_prefix_hash;
	KeyImage key_image;
	std::vector<PublicKey> output_keys;
	std::vector<Signature> signatures;
};

class RingCheckerMulticore {
	std::vector<std::thread> threads;
	mutable std::mutex mu;
	mutable std::condition_variable have_work;
	mutable std::condition_variable result_ready;
	bool quit = false;

	size_t total_counter = 0;
	size_t ready_counter = 0;
	std::vector<std::string> errors;

	std::deque<RingSignatureArg> args;
	int work_counter = 0;
	void thread_run();

public:
	RingCheckerMulticore();
	~RingCheckerMulticore();
	void cancel_work();
	std::string start_work_get_error(IBlockChainState *state, const Currency &currency, const Block &block,
	    Height unlock_height, Timestamp unlock_timestamp);  // can fail immediately
	bool signatures_valid() const;
};

struct PreparedWalletTransaction {
	TransactionPrefix tx;
	KeyDerivation derivation;
	std::vector<PublicKey> spend_keys;

	PreparedWalletTransaction() {}
	PreparedWalletTransaction(TransactionPrefix &&tx, const SecretKey &view_secret_key);
};

struct PreparedWalletBlock {
	BlockTemplate header;
	PreparedWalletTransaction base_transaction;
	Hash base_transaction_hash;
	std::vector<PreparedWalletTransaction> transactions;
	PreparedWalletBlock() {}
	PreparedWalletBlock(BlockTemplate &&bc_header, std::vector<TransactionPrefix> &&raw_transactions,
	    Hash base_transaction_hash, const SecretKey &view_secret_key);
};

class WalletPreparatorMulticore {
	std::vector<std::thread> threads;
	std::mutex mu;
	std::condition_variable have_work;
	std::condition_variable result_ready;
	bool quit = false;

	std::map<Height, PreparedWalletBlock> prepared_blocks;
	api::bytecoind::SyncBlocks::Response work;
	int work_counter = 0;
	SecretKey work_secret_key;
	void thread_run();

public:
	WalletPreparatorMulticore();
	~WalletPreparatorMulticore();
	void cancel_work();
	void start_work(const api::bytecoind::SyncBlocks::Response &new_work, const SecretKey &view_secret_key);
	PreparedWalletBlock get_ready_work(Height height);
};
}
