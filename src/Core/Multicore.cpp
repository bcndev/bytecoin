// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Multicore.hpp"
#include "BlockChainState.hpp"
#include "Currency.hpp"
#include "TransactionExtra.hpp"
#include "crypto/crypto.hpp"

using namespace bytecoin;

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
		int local_work_counter = 0;
		{
			std::unique_lock<std::mutex> lock(mu);
			if (quit)
				return;
			if (args.empty()) {
				have_work.wait(lock);
				continue;
			}
			local_work_counter = work_counter;
			arg                = std::move(args.front());
			args.pop_front();
		}
		std::vector<const PublicKey *> output_key_pointers;
		output_key_pointers.reserve(arg.output_keys.size());
		std::for_each(arg.output_keys.begin(), arg.output_keys.end(),
		    [&output_key_pointers](const PublicKey &key) { output_key_pointers.push_back(&key); });
		bool key_corrupted = false;
		bool result        = check_ring_signature(arg.tx_prefix_hash, arg.key_image, output_key_pointers.data(),
		    output_key_pointers.size(), arg.signatures.data(), true, &key_corrupted);
		{
			std::unique_lock<std::mutex> lock(mu);
			if (local_work_counter == work_counter) {
				ready_counter += 1;
				if (!result && key_corrupted)  // TODO - db corrupted
					errors.push_back("INPUT_CORRUPTED_SIGNATURES");
				if (!result && !key_corrupted)
					errors.push_back("INPUT_INVALID_SIGNATURES");
				result_ready.notify_all();
			}
		}
	}
}
void RingCheckerMulticore::cancel_work() {
	std::unique_lock<std::mutex> lock(mu);
	args.clear();
	work_counter += 1;
}

std::string RingCheckerMulticore::start_work_get_error(IBlockChainState *state, const Currency &currency,
    const Block &block, Height unlock_height, Timestamp unlock_timestamp) {
	{
		std::unique_lock<std::mutex> lock(mu);
		args.clear();
		errors.clear();
		//		args.reserve(block.transactions.size());
		ready_counter = 0;
		work_counter += 1;
	}
	total_counter = 0;
	for (auto &&transaction : block.transactions) {
		Hash tx_prefix_hash = get_transaction_prefix_hash(transaction);
		size_t input_index  = 0;
		for (const auto &input : transaction.inputs) {
			if (input.type() == typeid(CoinbaseInput)) {
			} else if (input.type() == typeid(KeyInput)) {
				const KeyInput &in = boost::get<KeyInput>(input);
				RingSignatureArg arg;
				arg.tx_prefix_hash = tx_prefix_hash;
				arg.key_image      = in.key_image;
				arg.signatures     = transaction.signatures[input_index];
				Height height      = 0;
				if (state->read_keyimage(in.key_image, &height))
					return "INPUT_KEYIMAGE_ALREADY_SPENT";
				if (in.output_indexes.empty())
					return "INPUT_UNKNOWN_TYPE";
				std::vector<uint32_t> global_indexes(in.output_indexes.size());
				global_indexes[0] = in.output_indexes[0];
				for (size_t i = 1; i < in.output_indexes.size(); ++i) {
					global_indexes[i] = global_indexes[i - 1] + in.output_indexes[i];
				}
				arg.output_keys.resize(global_indexes.size());
				for (size_t i = 0; i != global_indexes.size(); ++i) {
					IBlockChainState::UnlockTimePublickKeyHeightSpent unp;
					if (!state->read_amount_output(in.amount, global_indexes[i], &unp))
						return "INPUT_INVALID_GLOBAL_INDEX";
					if (!currency.is_transaction_spend_time_unlocked(unp.unlock_time, unlock_height, unlock_timestamp))
						return "INPUT_SPEND_LOCKED_OUT";
					arg.output_keys[i] = unp.public_key;
				}
				// As soon as first arg is ready, other thread can start work while we
				// continue reading from slow DB
				total_counter += 1;
				std::unique_lock<std::mutex> lock(mu);
				args.push_back(std::move(arg));
				have_work.notify_all();
			}
			input_index++;
		}
	}
	return std::string();
}

bool RingCheckerMulticore::signatures_valid() const {
	while (true) {
		std::unique_lock<std::mutex> lock(mu);
		if (ready_counter != total_counter) {
			result_ready.wait(lock);
			continue;
		}
		return errors.empty();
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

PreparedWalletTransaction::PreparedWalletTransaction(TransactionPrefix &&ttx, const SecretKey &view_secret_key)
    : tx(std::move(ttx)) {
	PublicKey tx_public_key = get_transaction_public_key_from_extra(tx.extra);
	if (!generate_key_derivation(tx_public_key, view_secret_key, derivation))
		return;
	KeyPair tx_keys;
	size_t key_index   = 0;
	uint32_t out_index = 0;
	spend_keys.reserve(tx.outputs.size());
	for (const auto &output : tx.outputs) {
		if (output.target.type() == typeid(KeyOutput)) {
			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			PublicKey spend_key;
			underive_public_key(derivation, key_index, key_output.key,
			    spend_key);  // error indicated by spend_key not in our wallet
			spend_keys.push_back(spend_key);
			++key_index;
		}
		++out_index;
	}
}

PreparedWalletBlock::PreparedWalletBlock(BlockTemplate &&bc_header, std::vector<TransactionPrefix> &&raw_transactions,
    Hash base_transaction_hash, const SecretKey &view_secret_key)
    : base_transaction_hash(base_transaction_hash) {
	header           = bc_header;
	base_transaction = PreparedWalletTransaction(std::move(bc_header.base_transaction), view_secret_key);
	transactions.reserve(raw_transactions.size());
	for (size_t tx_index = 0; tx_index != raw_transactions.size(); ++tx_index) {
		transactions.emplace_back(std::move(raw_transactions.at(tx_index)), view_secret_key);
	}
}

void WalletPreparatorMulticore::thread_run() {
	while (true) {
		SecretKey view_secret_key;
		Height height          = 0;
		int local_work_counter = 0;
		api::bytecoind::GetRawBlock::Response sync_block;
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
			view_secret_key    = work_secret_key;
			height             = work.start_height;
			sync_block         = std::move(work.blocks.front());
			work.start_height += 1;
			work.blocks.erase(work.blocks.begin());
		}
		PreparedWalletBlock result(std::move(sync_block.raw_header), std::move(sync_block.raw_transactions),
		    sync_block.base_transaction_hash, view_secret_key);
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
	work = api::bytecoind::SyncBlocks::Response();
	prepared_blocks.clear();
	work_counter += 1;
}

void WalletPreparatorMulticore::start_work(const api::bytecoind::SyncBlocks::Response &new_work,
    const SecretKey &view_secret_key) {
	std::unique_lock<std::mutex> lock(mu);
	work            = new_work;
	work_secret_key = view_secret_key;
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
