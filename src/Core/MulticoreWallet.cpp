// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "MulticoreWallet.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "Currency.hpp"
#include "TransactionExtra.hpp"
#include "crypto/crypto.hpp"
#include "hardware/HardwareWallet.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace cn;

#ifdef __EMSCRIPTEN__

#include <thread>  // for hardware concurency
#include "crypto/crypto.hpp"
#include "crypto/crypto_helpers.hpp"

struct WPMessageBlock {
	SecretKey view_secret_key;
	SecretKey inv_view_secret_key;
	bool is_amethyst = false;
	PreparedWalletBlock block;
	size_t worker_num = 0;
};

struct WPMessageTransaction {
	SecretKey view_secret_key;
	SecretKey inv_view_secret_key;
	bool is_amethyst = false;
	PreparedWalletTransaction tx;
	size_t worker_num = 0;
};

namespace seria {
void ser_members(PreparedWalletTransaction &v, ISeria &s) {
	seria_kv("tid", v.tid, s);
	seria_kv("size", v.size, s);
	seria_kv("tx", v.tx, s);
	seria_kv("prefix_hash", v.prefix_hash, s);
	seria_kv("inputs_hash", v.inputs_hash, s);
	seria_kv("derivation", v.derivation, s);
	seria_kv("address_public_keys", v.address_public_keys, s);
	seria_kv("output_shared_secrets", v.output_shared_secrets, s);
}
void ser_members(PreparedWalletBlock &v, ISeria &s) {
	seria_kv("raw_block", v.raw_block, s);
	seria_kv("transactions", v.transactions, s);
}
void ser_members(WPMessageTransaction &v, ISeria &s) {
	seria_kv("view_secret_key", v.view_secret_key, s);
	seria_kv("inv_view_secret_key", v.inv_view_secret_key, s);
	seria_kv("is_amethyst", v.is_amethyst, s);
	seria_kv("tx", v.tx, s);
	seria_kv("worker_num", v.worker_num, s);
}
void ser_members(WPMessageBlock &v, ISeria &s) {
	seria_kv("view_secret_key", v.view_secret_key, s);
	seria_kv("inv_view_secret_key", v.inv_view_secret_key, s);
	seria_kv("is_amethyst", v.is_amethyst, s);
	seria_kv("block", v.block, s);
	seria_kv("worker_num", v.worker_num, s);
}
}  // namespace seria

extern "C" EMSCRIPTEN_KEEPALIVE void worker_block_prepare(const void *data, size_t size) {
	//	std::cout << "worker_block_prepare" << size << std::endl;
	WPMessageBlock msg;
	common::MemoryInputStream str(data, size);
	seria::from_binary(msg, str);
	invariant(msg.is_amethyst, "TODO - implement legacy crypto");
	auto vsk_copy                 = msg.view_secret_key;
	Wallet::OutputHandler handler = [vsk_copy](uint8_t tx_version, const KeyDerivation &kd, const Hash &tx_inputs_hash,
	                                    size_t output_index, const OutputKey &key_output, PublicKey *address_S,
	                                    PublicKey *output_shared_secret) {
		*address_S = crypto::unlinkable_underive_address_S(vsk_copy, tx_inputs_hash, output_index,
		    key_output.public_key, key_output.encrypted_secret, output_shared_secret);
	};
	msg.block.prepare(handler, msg.view_secret_key);
	auto ba = seria::to_binary(msg);
	//	std::cout << "emscripten_worker_respond" << size << std::endl;
	emscripten_worker_respond(reinterpret_cast<char *>(ba.data()), ba.size());
}

extern "C" EMSCRIPTEN_KEEPALIVE void worker_transaction_prepare(const void *data, size_t size) {
	//	std::cout << "worker_transaction_prepare" << size << std::endl;
	WPMessageTransaction msg;
	common::MemoryInputStream str(data, size);
	seria::from_binary(msg, str);
	invariant(msg.is_amethyst, "TODO - implement legacy crypto");
	auto vsk_copy                 = msg.view_secret_key;
	Wallet::OutputHandler handler = [vsk_copy](uint8_t tx_version, const KeyDerivation &kd, const Hash &tx_inputs_hash,
	                                    size_t output_index, const OutputKey &key_output, PublicKey *address_S,
	                                    PublicKey *output_shared_secret) {
		*address_S = crypto::unlinkable_underive_address_S(vsk_copy, tx_inputs_hash, output_index,
		    key_output.public_key, key_output.encrypted_secret, output_shared_secret);
	};
	msg.tx.prepare(handler, msg.view_secret_key);
	auto ba = seria::to_binary(msg);
	//	std::cout << "emscripten_transaction_respond" << size << std::endl;
	emscripten_worker_respond(reinterpret_cast<char *>(ba.data()), ba.size());
}

WalletPreparatorMulticore::WalletPreparatorMulticore(hardware::HardwareWallet *hw_copy,
    Wallet::OutputHandler &&o_handler, const SecretKey &view_secret_key,
    std::function<bool(const PreparedWalletBlock &)> &&b_handler,
    std::function<bool(const PreparedWalletTransaction &)> &&t_handler, std::function<void()> &&c_handler)
    : m_o_handler(std::move(o_handler))
    , m_view_secret_key(view_secret_key)
    , b_handler(std::move(b_handler))
    , t_handler(std::move(t_handler))
    , c_handler(std::move(c_handler)) {
	m_inv_view_secret_key = crypto::sc_invert(m_view_secret_key);
	auto th_count         = std::max<size_t>(2, std::thread::hardware_concurrency());
	std::cout << "Starting " << th_count << " workers for wallet processing" << std::endl;
	workers.resize(th_count);
	for (auto &w : workers)
		w.handle = emscripten_create_worker("bin/walletworker.js");
}

WalletPreparatorMulticore::~WalletPreparatorMulticore() {
	// TODO - destory workers
}

void WalletPreparatorMulticore::add_work(std::vector<api::cnd::SyncBlocks::RawBlockCompact> &&new_work) {
	for (auto &&b : new_work) {
		total_block_size += b.header.transactions_size;
		work.push_back(WorkItem{});
		work.back().is_tx           = false;
		work.back().block.raw_block = std::move(b);
		work.back().total_work_size = b.header.transactions_size;
	}
	send_work();
}

void WalletPreparatorMulticore::add_work(const Hash &tid, size_t size, TransactionPrefix &&new_work) {
	total_mempool_count += 1;
	work.push_back(WorkItem{});
	work.back().is_tx           = true;
	work.back().pwtx.tid        = tid;
	work.back().pwtx.size       = size;
	work.back().pwtx.tx         = std::move(new_work);
	work.back().total_work_size = size;
	send_work();
}

void WalletPreparatorMulticore::send_work() {
	while (!work.empty() && !workers.empty()) {
		size_t least_i         = 0;
		size_t least_work_sent = workers[0].total_work_size;
		size_t total_work_sent = least_work_sent;
		for (size_t i = 1; i != workers.size(); ++i) {
			total_work_sent += workers[i].total_work_size;
			if (workers[i].total_work_size < least_work_sent) {
				least_work_sent = workers[i].total_work_size;
				least_i         = i;
			}
		}
		if (total_work_sent > 200000 * workers.size())  // TODO
			break;
		sent_work.push_back(std::move(work.front()));
		work.pop_front();
		sent_work.back().status_busy = true;
		workers[least_i].total_work_size += sent_work.back().total_work_size;
		if (sent_work.back().is_tx) {
			WPMessageTransaction msg;
			msg.tx                  = sent_work.back().pwtx;
			msg.view_secret_key     = m_view_secret_key;
			msg.inv_view_secret_key = m_inv_view_secret_key;
			msg.is_amethyst         = is_amethyst;
			msg.worker_num          = least_i;
			auto ba                 = seria::to_binary(msg);
			//    std::cout << "emscripten_call_worker transaction " << ba.size() << std::endl;
			emscripten_call_worker(workers.at(least_i).handle, "worker_transaction_prepare",
			    reinterpret_cast<char *>(ba.data()), ba.size(),
			    &WalletPreparatorMulticore::on_transaction_prepared_handler, reinterpret_cast<void *>(this));
		} else {
			WPMessageBlock msg;
			msg.block               = sent_work.back().block;
			msg.view_secret_key     = m_view_secret_key;
			msg.inv_view_secret_key = m_inv_view_secret_key;
			msg.is_amethyst         = is_amethyst;
			msg.worker_num          = least_i;
			auto ba                 = seria::to_binary(msg);
			//    std::cout << "emscripten_call_worker block " << ba.size() << std::endl;
			emscripten_call_worker(workers.at(least_i).handle, "worker_block_prepare",
			    reinterpret_cast<char *>(ba.data()), ba.size(), &WalletPreparatorMulticore::on_block_prepared_handler,
			    reinterpret_cast<void *>(this));
		}
	}
}

void WalletPreparatorMulticore::broadcast_received_work() {
	while (!sent_work.empty() && !sent_work.front().status_busy) {
		if (sent_work.front().is_tx) {
			if (!t_handler(sent_work.front().pwtx)) {
				//				wallet_connected = false;
				c_handler();
				return;
			}
			total_mempool_count -= 1;
		} else {
			total_block_size -= sent_work.front().block.raw_block.header.transactions_size;
			if (!b_handler(sent_work.front().block)) {
				//				wallet_connected = false;
				c_handler();
				return;
			}
		}
		sent_work.pop_front();
	}
	c_handler();
	send_work();
}

void WalletPreparatorMulticore::on_block_prepared_handler(char *data, int size, void *arg) {
	//    std::cout << "on_block_prepared_handler " << size << std::endl;
	reinterpret_cast<WalletPreparatorMulticore *>(arg)->on_block_prepared(data, static_cast<size_t>(size));
}
void WalletPreparatorMulticore::on_transaction_prepared_handler(char *data, int size, void *arg) {
	//    std::cout << "on_transaction_prepared_handler " << size << std::endl;
	reinterpret_cast<WalletPreparatorMulticore *>(arg)->on_transaction_prepared(data, static_cast<size_t>(size));
}

void WalletPreparatorMulticore::on_block_prepared(const char *data, size_t size) {
	WPMessageBlock msg;
	common::MemoryInputStream str(data, size);
	seria::from_binary(msg, str);
	for (auto &sw : sent_work) {
		if (sw.status_busy && !sw.is_tx && sw.block.raw_block.header.hash == msg.block.raw_block.header.hash) {
			sw.block       = std::move(msg.block);
			sw.status_busy = false;
			workers.at(msg.worker_num).total_work_size -= sw.total_work_size;
			break;
		}
	}
	if (!sent_work.empty() && !sent_work.front().status_busy)
		broadcast_received_work();
}

void WalletPreparatorMulticore::on_transaction_prepared(const char *data, size_t size) {
	WPMessageTransaction msg;
	common::MemoryInputStream str(data, size);
	seria::from_binary(msg, str);
	for (auto &sw : sent_work) {
		if (sw.status_busy && sw.is_tx && sw.pwtx.tid == msg.tx.tid) {
			sw.pwtx        = std::move(msg.tx);
			sw.status_busy = false;
			workers.at(msg.worker_num).total_work_size -= sw.total_work_size;
			break;
		}
	}
	if (!sent_work.empty() && !sent_work.front().status_busy)
		broadcast_received_work();
}

#else

WalletPreparatorMulticore::WalletPreparatorMulticore(hardware::HardwareWallet *hw_copy,
    Wallet::OutputHandler &&o_handler, const SecretKey &view_secret_key,
    std::function<bool(const PreparedWalletBlock &)> &&b_handler,
    std::function<bool(const PreparedWalletTransaction &)> &&t_handler, std::function<void()> &&c_handler)
    : hw_copy(hw_copy)
    , m_o_handler(std::move(o_handler))
    , m_view_secret_key(view_secret_key)
    , b_handler(std::move(b_handler))
    , t_handler(std::move(t_handler))
    , c_handler(std::move(c_handler))
    , message(std::bind(&WalletPreparatorMulticore::on_message, this)) {
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

static void fill_tx_output_public_keys(std::vector<PublicKey> *output_public_keys, const TransactionPrefix &tx) {
	for (size_t out_index = 0; out_index != tx.outputs.size(); ++out_index) {
		const auto &output = tx.outputs.at(out_index);
		if (output.type() != typeid(OutputKey))
			continue;
		const auto &key_output = boost::get<OutputKey>(output);
		output_public_keys->push_back(key_output.public_key);
	}
	auto encrypted_messages = extra::get_encrypted_messages(tx.extra);
	for (size_t m_index = 0; m_index != encrypted_messages.size(); ++m_index)
		output_public_keys->push_back(encrypted_messages.at(m_index).output.public_key);
}

static void fill_tx_output_public_keys(
    std::vector<PublicKey> *output_public_keys, const api::cnd::SyncBlocks::RawBlockCompact &b) {
	fill_tx_output_public_keys(output_public_keys, b.base_transaction);
	for (const auto &tx : b.raw_transactions)
		fill_tx_output_public_keys(output_public_keys, tx);
}

void WalletPreparatorMulticore::hw_output_handler(uint8_t tx_version, const KeyDerivation &kd,
    const Hash &tx_inputs_hash, size_t output_index, const OutputKey &key_output, PublicKey *address_S,
    PublicKey *output_shared_secret) {
	invariant(!result_pks.empty(), "");
	auto Pv = result_pks.front();
	result_pks.pop_front();
	*address_S = unlinkable_underive_address_S_step2(
	    Pv, tx_inputs_hash, output_index, key_output.public_key, key_output.encrypted_secret, output_shared_secret);
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
		} catch (const std::runtime_error &) {
			std::unique_lock<std::mutex> lock(mu);
			wallet_connected   = false;
			sync_block->status = WAITING;
			source_pks.insert(source_pks.begin(), local_source_pks.begin(), local_source_pks.end());
		}
		message.fire();
	}
}

void WalletPreparatorMulticore::add_work(std::vector<api::cnd::SyncBlocks::RawBlockCompact> &&new_work) {
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

void WalletPreparatorMulticore::on_message() {
	{
		std::unique_lock<std::mutex> lock(mu);
		if (!wallet_connected)
			return;
		while (!work.empty() && work.front()->status == PREPARED) {
			ready_work.push_back(std::move(work.front()));
			work.pop_front();
		}
	}
	while (!ready_work.empty()) {
		if (ready_work.front()->is_tx) {
			if (!t_handler(ready_work.front()->pwtx)) {
				wallet_connected = false;
				c_handler();
				return;
			}
			total_mempool_count -= 1;
		} else {
			total_block_size -= ready_work.front()->block.raw_block.header.transactions_size;
			if (!b_handler(ready_work.front()->block)) {
				wallet_connected = false;
				c_handler();
				return;
			}
		}
		ready_work.pop_front();
	}
	c_handler();
}

#endif
