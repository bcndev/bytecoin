// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include "BlockChain.hpp"  // for PreparedBlock
#include "CryptoNote.hpp"
#include "Wallet.hpp"  // for OutputHandler
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
class Wallet;

namespace hardware {
class HardwareWallet;
}

class BlockPreparatorMulticore {
	const Currency &currency;

	std::vector<std::thread> threads;
	mutable std::mutex mu;
	std::condition_variable have_work;
	platform::EventLoop *main_loop = nullptr;
	//	std::condition_variable prepared_blocks_ready;
	bool quit = false;

	std::deque<std::tuple<Hash, bool, RawBlock>> work;
	std::map<Hash, PreparedBlock> prepared_blocks;

	void thread_run();

public:
	explicit BlockPreparatorMulticore(const Currency &currency, platform::EventLoop *main_loop);
	~BlockPreparatorMulticore();

	void add_block(Hash bid, bool check_pow, RawBlock &&rb);
	bool get_prepared_block(Hash bid, PreparedBlock *pb);
	bool has_prepared_block(Hash bid) const;
};

struct RingSignatureArg {
	Hash tx_prefix_hash;
	Height newest_referenced_height = 0;
	KeyImage key_image;
	std::vector<PublicKey> output_keys;
	RingSignature input_signature;
};

struct RingSignatureArgA {
	Hash tx_prefix_hash;
	Height newest_referenced_height = 0;
	std::vector<KeyImage> key_images;
	std::vector<PublicKey> ps;
	std::vector<std::vector<PublicKey>> output_keys;
	RingSignatureAmethyst input_signature;
};

class RingCheckerMulticore {
	std::vector<std::thread> threads;
	mutable std::mutex mu;
	mutable std::condition_variable have_work;
	mutable std::condition_variable result_ready;
	bool quit = false;

	size_t total_counter = 0;
	size_t ready_counter = 0;
	std::vector<ConsensusErrorBadOutputOrSignature> errors;

	std::deque<RingSignatureArg> args;
	std::deque<RingSignatureArgA> argsa;
	int work_counter = 0;
	void thread_run();

public:
	RingCheckerMulticore();
	~RingCheckerMulticore();
	void cancel_work();
	void start_work(IBlockChainState *state, const Currency &currency, const Block &block, Height unlock_height,
	    Timestamp block_timestamp, Timestamp block_median_timestamp);  // can throw ConsensusError immediately
	std::vector<ConsensusErrorBadOutputOrSignature> move_errors();
};

struct PreparedWalletTransaction {
	Hash tid;
	size_t size = 0;
	TransactionPrefix tx;
	Hash prefix_hash;
	Hash inputs_hash;
	KeyDerivation derivation;  // Will be KeyDerivation{} if invalid or no tx_public_key
	std::vector<PublicKey> address_public_keys;
	std::vector<BinaryArray> output_secret_hash_args;

	PreparedWalletTransaction() = default;
	PreparedWalletTransaction(const Hash &tid, size_t size, TransactionPrefix &&tx,
	    const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key);
	PreparedWalletTransaction(const Hash &tid, size_t size, Transaction &&tx, const Wallet::OutputHandler &o_handler,
	    const SecretKey &view_secret_key);

	// TODO - remove constructors and always use prepare()?
	void prepare(const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key);
};

struct PreparedWalletBlock {
	api::RawBlock raw_block;
	std::vector<PreparedWalletTransaction> transactions;
	// base_transaction will be inserted before other transactions

	void prepare(const Wallet::OutputHandler &o_handler, const SecretKey &view_secret_key);
	//	PreparedWalletBlock() = default;
	//	PreparedWalletBlock(api::RawBlock && raw_block, const Wallet::OutputHandler &o_handler, const SecretKey
	//&view_secret_key);
};

// We add mempool processing here because it is slow for HW wallet to process outputs by one
// We combine both blocks and mempool processing in single class
// because access to HW wallet should be synced anyway.
class WalletPreparatorMulticore {
	std::vector<std::thread> threads;
	std::mutex mu;
	std::condition_variable have_work;
	bool quit = false;

	enum Status { WAITING, BUSY, PREPARED };
	struct WorkItem {
		PreparedWalletTransaction pwtx;
		PreparedWalletBlock block;
		bool is_tx       = false;
		Status status    = WAITING;
		size_t pks_count = 0;
	};

	std::deque<std::unique_ptr<WorkItem>> work;
	std::deque<crypto::PublicKey> source_pks;
	std::deque<crypto::PublicKey> result_pks;  // not synced, access from 1 worker thread

	bool wallet_connected      = true;
	size_t total_block_size    = 0;
	size_t total_mempool_count = 0;

	hardware::HardwareWallet *hw_copy;
	Wallet::OutputHandler m_o_handler;
	SecretKey m_view_secret_key;
	platform::EventLoop *m_main_loop;
	void thread_run();

	void hw_output_handler(uint8_t tx_version, const KeyDerivation &kd, const Hash &tx_inputs_hash, size_t output_index,
	    const OutputKey &key_output, PublicKey *address_S, BinaryArray *output_secret_hash_arg);

public:
	WalletPreparatorMulticore(hardware::HardwareWallet *hw_copy, Wallet::OutputHandler &&o_handler,
	    const SecretKey &view_secret_key, platform::EventLoop *main_loop);
	~WalletPreparatorMulticore();
	void add_work(std::vector<api::RawBlock> &&new_work);
	void add_work(const Hash &tid, size_t size, TransactionPrefix &&new_work);
	bool is_wallet_connected();
	void wallet_reconnected();
	size_t get_total_block_size() const { return total_block_size; }
	size_t get_total_mempool_count() const { return total_mempool_count; }
	void get_ready_work(std::deque<PreparedWalletBlock> *blocks, std::deque<PreparedWalletTransaction> *transactions);
	void return_ready_work(std::deque<PreparedWalletBlock> &&ppb);
	void return_ready_work(std::deque<PreparedWalletTransaction> &&ppb);
};

}  // namespace cn
