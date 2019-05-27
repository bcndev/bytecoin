// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "CryptoNote.hpp"
#include "Wallet.hpp"            // for OutputHandler
#include "WalletStateBasic.hpp"  // for PreparedWallet*
#include "rpc_api.hpp"

namespace cn { namespace hardware {
class HardwareWallet;
}}  // namespace cn::hardware
// Experimental machinery to offload heavy calcs to other cores
// Without making any critical part of the Core multithreaded
// We do it by confining threads to "boxes"

#ifdef __EMSCRIPTEN__
#define cn_SINGLE_THREAD_MULTICORE_WALLET
#else
//#define cn_SINGLE_THREAD_MULTICORE_WALLET
#endif

#ifdef cn_SINGLE_THREAD_MULTICORE_WALLET

#include "platform/Network.hpp"

namespace cn {

class WalletPreparatorMulticore {
	struct Worker {
		size_t total_work_size = 0;
	};
	std::vector<Worker> workers;

	struct WorkItem {
		bool is_tx             = false;
		size_t total_work_size = 0;
		PreparedWalletTransaction pwtx;
		PreparedWalletBlock block;
		bool status_busy = false;
	};

	std::deque<WorkItem> work;
	std::deque<WorkItem> sent_work;
	//	std::deque<PreparedWalletBlock> ready_work_block;
	//	std::deque<PreparedWalletTransaction> ready_work_tx;

	size_t total_block_size    = 0;
	size_t total_mempool_count = 0;

	Wallet::OutputHandler m_o_handler;
	bool is_amethyst = true;  // TODO
	SecretKey m_view_secret_key;
	SecretKey m_inv_view_secret_key;
	std::function<bool(const PreparedWalletBlock &)> b_handler;
	std::function<bool(const PreparedWalletTransaction &)> t_handler;
	std::function<void()> c_handler;

	platform::Timer debug_timer;
	void on_debug_timer();

	void send_work();
	void broadcast_received_work();
	void post_block_prepare(size_t wi, common::BinaryArray &&ba);
	void post_transaction_prepare(size_t wi, common::BinaryArray &&ba);

public:
	WalletPreparatorMulticore(hardware::HardwareWallet *hw_copy, Wallet::OutputHandler &&o_handler,
	    const SecretKey &view_secret_key, std::function<bool(const PreparedWalletBlock &)> &&b_handler,
	    std::function<bool(const PreparedWalletTransaction &)> &&t_handler, std::function<void()> &&c_handler);
	~WalletPreparatorMulticore();
	void add_work(std::vector<api::cnd::SyncBlocks::RawBlockCompact> &&new_work);
	void add_work(const Hash &tid, size_t size, TransactionPrefix &&new_work);
	bool is_wallet_connected() { return true; }
	void wallet_reconnected() {}
	size_t get_total_block_size() const { return total_block_size; }
	size_t get_total_mempool_count() const { return total_mempool_count; }

	void on_block_prepared(size_t wi, const void *data, size_t size);
	void on_transaction_prepared(size_t wi, const void *data, size_t size);
};

}  // namespace cn

#else

#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include "platform/Network.hpp"

namespace cn {

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
		Status status    = WAITING;
		size_t pks_count = 0;
		bool is_tx       = false;
		PreparedWalletTransaction pwtx;
		PreparedWalletBlock block;
	};

	std::deque<std::unique_ptr<WorkItem>> work;
	std::deque<crypto::PublicKey> source_pks;
	std::deque<crypto::PublicKey> result_pks;  // not synced, access from 1 worker thread

	std::deque<std::unique_ptr<WorkItem>> ready_work;
	bool wallet_connected      = true;
	size_t total_block_size    = 0;
	size_t total_mempool_count = 0;

	hardware::HardwareWallet *hw_copy;
	Wallet::OutputHandler m_o_handler;
	SecretKey m_view_secret_key;
	std::function<bool(const PreparedWalletBlock &)> b_handler;
	std::function<bool(const PreparedWalletTransaction &)> t_handler;
	std::function<void()> c_handler;
	platform::SafeMessage message;
	void thread_run();
	void on_message();

	void hw_output_handler(uint8_t tx_version, const KeyDerivation &kd, const Hash &tx_inputs_hash, size_t output_index,
	    const OutputKey &key_output, PublicKey *address_S, PublicKey *output_shared_secret);

public:
	WalletPreparatorMulticore(hardware::HardwareWallet *hw_copy, Wallet::OutputHandler &&o_handler,
	    const SecretKey &view_secret_key, std::function<bool(const PreparedWalletBlock &)> &&b_handler,
	    std::function<bool(const PreparedWalletTransaction &)> &&t_handler, std::function<void()> &&c_handler);
	~WalletPreparatorMulticore();
	void add_work(std::vector<api::cnd::SyncBlocks::RawBlockCompact> &&new_work);
	void add_work(const Hash &tid, size_t size, TransactionPrefix &&new_work);
	bool is_wallet_connected();
	void wallet_reconnected();
	size_t get_total_block_size() const { return total_block_size; }
	size_t get_total_mempool_count() const { return total_mempool_count; }
};

}  // namespace cn

#endif
