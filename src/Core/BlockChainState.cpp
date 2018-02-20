// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include "BlockChainState.hpp"
#include <condition_variable>
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionExtra.hpp"
#include "common/Math.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "crypto/crypto.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

static const std::string KEYIMAGE_PREFIX             = "i";
static const std::string AMOUNT_OUTPUT_PREFIX        = "a";
static const std::string BLOCK_GLOBAL_INDICES_PREFIX = "b";
static const std::string BLOCK_GLOBAL_INDICES_SUFFIX = "g";
static const std::string FIRST_SEEN_PREFIX           = "f";

const bool create_unlock_index               = false;
static const std::string UNLOCK_BLOCK_PREFIX = "u";
static const std::string UNLOCK_TIME_PREFIX  = "U";
// We store locked outputs in separate indexes

const size_t MAX_POOL_COMPLEXITY = 100000;  // ~1000 "normal" transactions

using namespace bytecoin;
using namespace platform;

static size_t get_complexity(const Transaction &tx) {  // For pool
	size_t result = 0;
	result += 20 * tx.inputs.size();  // ring signature checking is expensive
	result += tx.outputs.size();
	for (const auto &input : tx.inputs) {
		if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			result += 10 * in.output_indexes.size();  // ring signature checking is expensive
		}
	}
	return result;
}

void BlockChainState::DeltaState::store_keyimage(const KeyImage &keyimage, Height height) {
	if (!m_keyimages.insert(std::make_pair(keyimage, height)).second)
		throw std::logic_error("store_keyimage already exists. Invariant dead");
}

void BlockChainState::DeltaState::delete_keyimage(const KeyImage &keyimage) {
	if (m_keyimages.erase(keyimage) != 1)
		throw std::logic_error("store_keyimage does not exist. Invariant dead");
}

bool BlockChainState::DeltaState::read_keyimage(const KeyImage &keyimage) const {
	auto kit = m_keyimages.find(keyimage);
	if (kit == m_keyimages.end())
		return m_parent_state->read_keyimage(keyimage);
	return true;
}

uint32_t BlockChainState::DeltaState::push_amount_output(Amount amount, UnlockMoment unlock_time, Height block_height,
    Timestamp block_unlock_timestamp, const PublicKey &pk) {
	uint32_t pg = m_parent_state->next_global_index_for_amount(amount);
	auto &ga    = m_global_amounts[amount];
	ga.push_back(std::make_pair(unlock_time, pk));
	return pg + static_cast<uint32_t>(ga.size()) - 1;
}

void BlockChainState::DeltaState::pop_amount_output(Amount amount, UnlockMoment unlock_time, const PublicKey &pk) {
	std::vector<std::pair<uint64_t, PublicKey>> &el = m_global_amounts[amount];
	if (el.empty())
		throw std::logic_error("DeltaState::pop_amount_output underflow");
	if (el.back().first != unlock_time || el.back().second != pk)
		throw std::logic_error("DeltaState::pop_amount_output wrong element");
	el.pop_back();
}

uint32_t BlockChainState::DeltaState::next_global_index_for_amount(Amount amount) const {
	uint32_t pg = m_parent_state->next_global_index_for_amount(amount);
	auto git    = m_global_amounts.find(amount);
	return (git == m_global_amounts.end()) ? pg : static_cast<uint32_t>(git->second.size()) + pg;
}

bool BlockChainState::DeltaState::read_amount_output(Amount amount,
    uint32_t global_index,
    UnlockMoment &unlock_time,
    PublicKey &pk) const {
	uint32_t pg = m_parent_state->next_global_index_for_amount(amount);
	if (global_index < pg)
		return m_parent_state->read_amount_output(amount, global_index, unlock_time, pk);
	global_index -= pg;
	auto git = m_global_amounts.find(amount);
	if (git == m_global_amounts.end() || global_index >= git->second.size())
		return false;
	unlock_time = git->second[global_index].first;
	pk          = git->second[global_index].second;
	return true;
}

void BlockChainState::DeltaState::apply(IBlockChainState *parent_state) const {
	for (auto &&ki : m_keyimages)
		parent_state->store_keyimage(ki.first, ki.second);
	for (auto &&amp : m_global_amounts)
		for (auto &&el : amp.second)
			parent_state->push_amount_output(amp.first, el.first, m_block_height, m_unlock_timestamp, el.second);
}

void BlockChainState::DeltaState::clear(Height new_block_height) {
	m_block_height = new_block_height;
	m_keyimages.clear();
	m_global_amounts.clear();
}

api::BlockHeader BlockChainState::fill_genesis(Hash genesis_bid, const BlockTemplate &g) {
	api::BlockHeader result;
	result.major_version       = g.major_version;
	result.minor_version       = g.minor_version;
	result.previous_block_hash = g.previous_block_hash;
	result.timestamp           = g.timestamp;
	result.nonce               = g.nonce;
	result.hash                = genesis_bid;
	return result;
}

BlockChainState::BlockChainState(logging::ILogger &log, const Config &config, const Currency &currency)
    : BlockChain(currency.genesis_block_hash, config.get_coin_directory())
    , m_config(config)
    , m_currency(currency)
    , m_log(log, "BlockChainState")
    , m_memory_state_total_complexity(0) {
	if (get_tip_height() == (Height)-1) {
		Block genesis_block;
		genesis_block.header = currency.genesis_block_template;
		RawBlock raw_block;
		if (!genesis_block.to_raw_block(raw_block))
			throw std::logic_error("Genesis block failed to convert into raw block");
		PreparedBlock pb(std::move(raw_block), nullptr);
		api::BlockHeader info;
		if (add_block(pb, info) == BroadcastAction::BAN)
			throw std::logic_error("Genesis block failed to add");
	}
	BlockChainState::tip_changed();
}

bool BlockChainState::check_standalone_consensus(
    const PreparedBlock &pb, api::BlockHeader &info, const api::BlockHeader &prev_info) const {
	auto err = get_standalone_consensus_error(pb, info, prev_info);
	return err.empty();
}

std::string BlockChainState::get_standalone_consensus_error(
    const PreparedBlock &pb, api::BlockHeader &info, const api::BlockHeader &prev_info) const {
	const auto &block = pb.block;
	if (block.transactions.size() != block.header.transaction_hashes.size())
		return "WRONG_TRANSACTIONS_COUNT";
	info.size_median      = m_next_median_size;
	info.timestamp_median = m_next_median_timestamp;
	info.timestamp_unlock = m_next_unlock_timestamp;

	if (get_tip_height() != prev_info.height)  // Optimization for most common case
		calculate_consensus_values(
		    get_tip_height() - prev_info.height, info.size_median, info.timestamp_median, info.timestamp_unlock);

	auto next_block_granted_full_reward_zone = m_currency.block_granted_full_reward_zone_by_block_version(
	    block.header.major_version);  // We will check version later in this fun
	info.effective_size_median = std::max(info.size_median, next_block_granted_full_reward_zone);

	size_t cumulative_size = 0;
	for (auto &&raw_tx : pb.raw_block.transactions) {
		if (raw_tx.size() > m_currency.max_transaction_allowed_size(info.effective_size_median)) {
			//            log(Logging::INFO) << "Raw transaction size " <<
			//            binary_transaction.size() << " is too big.";
			return "RAW_TRANSACTION_SIZE_TOO_BIG";
		}
		cumulative_size += raw_tx.size();
	}
	info.block_size                = static_cast<uint32_t>(pb.coinbase_tx_size + cumulative_size);
	auto max_block_cumulative_size = m_currency.max_block_cumulative_size(info.height);
	if (info.block_size > max_block_cumulative_size)
		return "CUMULATIVE_BLOCK_SIZE_TOO_BIG";

	// block at UPGRADE_HEIGHT still has old version.
	if (block.header.major_version != m_currency.get_block_major_version_for_height(info.height))
		return "WRONG_VERSION";

	if (block.header.major_version >= 2) {
		if (block.header.major_version == 2 && block.header.parent_block.major_version > 1)
			return "PARENT_BLOCK_WRONG_VERSION";
		size_t pasi = pb.parent_block_size;
		if (pasi > 2048)
			return "PARENT_BLOCK_SIZE_TOO_BIG";
	}
	const uint64_t now = time(nullptr);  // It would be better to pass now through Node
	if (block.header.timestamp > now + m_currency.block_future_time_limit)
		return "TIMESTAMP_TOO_FAR_IN_FUTURE";
	if (block.header.timestamp < info.timestamp_median)
		return "TIMESTAMP_TOO_FAR_IN_PAST";

	if (block.header.base_transaction.inputs.size() != 1)
		return "INPUT_WRONG_COUNT";

	if (block.header.base_transaction.inputs[0].type() != typeid(CoinbaseInput))
		return "INPUT_UNEXPECTED_TYPE";

	if (boost::get<CoinbaseInput>(block.header.base_transaction.inputs[0]).block_index != info.height)
		return "BASE_INPUT_WRONG_BLOCK_INDEX";

	if (block.header.base_transaction.unlock_time != info.height + m_currency.mined_money_unlock_window)
		return "WRONG_TRANSACTION_UNLOCK_TIME";

	const bool check_keys = !m_currency.is_in_checkpoint_zone(info.height);
	uint64_t miner_reward = 0;
	for (const auto &output : block.header.base_transaction.outputs) {
		if (output.amount == 0)
			return "OUTPUT_ZERO_AMOUNT";
		if (output.target.type() == typeid(KeyOutput)) {
			if (check_keys && !key_isvalid(boost::get<KeyOutput>(output.target).key))
				return "OUTPUT_INVALID_KEY";
		} else
			return "OUTPUT_UNKNOWN_TYPE";

		if (std::numeric_limits<uint64_t>::max() - output.amount < miner_reward)
			return "OUTPUTS_AMOUNT_OVERFLOW";
		miner_reward += output.amount;
	}
	{
		std::vector<Timestamp> timestamps;
		std::vector<Difficulty> difficulties;
		Height blocks_count    = std::min(prev_info.height, m_currency.difficulty_blocks_count());
		auto timestamps_window = get_tip_segment(get_tip_height() - prev_info.height, blocks_count, false);
		size_t actual_count    = timestamps_window.second - timestamps_window.first;
		timestamps.resize(actual_count);
		difficulties.resize(actual_count);
		size_t pos = 0;
		for (auto it = timestamps_window.first; it != timestamps_window.second; ++it, ++pos) {
			timestamps.at(pos)   = it->timestamp;
			difficulties.at(pos) = it->cumulative_difficulty;
		}
		info.difficulty            = m_currency.next_difficulty(timestamps, difficulties);
		info.cumulative_difficulty = prev_info.cumulative_difficulty + info.difficulty;
	}

	if (info.difficulty == 0)
		return "DIFFICULTY_OVERHEAD";

	Amount cumulative_fee = 0;
	for (const auto &tx : block.transactions) {
		Amount fee = 0;
		if (!get_tx_fee(tx, fee))
			return "WRONG_AMOUNT";
		cumulative_fee += fee;
	}

	int64_t emission_change      = 0;
	auto already_generated_coins = prev_info.already_generated_coins;

	if (!m_currency.get_block_reward(block.header.major_version, info.effective_size_median, 0, already_generated_coins,
	        0, info.base_reward, emission_change) ||
	    !m_currency.get_block_reward(block.header.major_version, info.effective_size_median, info.block_size,
	        already_generated_coins, cumulative_fee, info.reward, emission_change)) {
		//        log(Logging::WARNING) << "Block " << cachedBlock.getBlockHash() <<
		//        " has too big cumulative size";
		return "CUMULATIVE_BLOCK_SIZE_TOO_BIG";
	}

	if (miner_reward != info.reward) {
		//        log(Logging::WARNING) << "Block reward mismatch for block " <<
		//        cachedBlock.getBlockHash()
		//        << ". Expected reward: " << reward << ", got reward: " <<
		//        minerReward;
		return "BLOCK_REWARD_MISMATCH";
	}
	info.already_generated_coins        = prev_info.already_generated_coins + emission_change;
	info.already_generated_transactions = prev_info.already_generated_transactions + block.transactions.size() + 1;
	info.total_fee_amount               = cumulative_fee;
	info.transactions_cumulative_size   = static_cast<uint32_t>(cumulative_size);
	bool is_checkpoint;
	if (m_currency.is_in_checkpoint_zone(info.height)) {
		if (!m_currency.check_block_checkpoint(info.height, info.hash, is_checkpoint))
			return "CHECKPOINT_BLOCK_HASH_MISMATCH";
	} else {
		Hash long_hash = pb.long_block_hash != Hash{} ? pb.long_block_hash
		                                              : get_block_long_hash(block.header, m_hash_crypto_context);
		if (!m_currency.check_proof_of_work(long_hash, block.header, info.difficulty))
			return "PROOF_OF_WORK_TOO_WEAK";
	}
	return std::string();
}

void BlockChainState::calculate_consensus_values(Height height_delta, uint32_t &next_median_size,
    Timestamp &next_median_timestamp, Timestamp &next_unlock_timestamp) const {
	std::vector<uint32_t> last_blocks_sizes;
	auto window = get_tip_segment(height_delta, m_currency.reward_blocks_window, true);
	last_blocks_sizes.reserve(m_currency.reward_blocks_window);
	for (auto it = window.first; it != window.second; ++it)
		last_blocks_sizes.push_back(it->block_size);
	next_median_size = common::median_value(last_blocks_sizes);

	window = get_tip_segment(height_delta, m_currency.timestamp_check_window, false);
	if (window.second - window.first >= static_cast<ptrdiff_t>(m_currency.timestamp_check_window)) {
		std::vector<Timestamp> timestamps;
		timestamps.reserve(m_currency.timestamp_check_window);
		for (auto it = window.first; it != window.second; ++it)
			timestamps.push_back(it->timestamp);
		next_median_timestamp = common::median_value(timestamps);  // sorts timestamps
		next_unlock_timestamp = timestamps[timestamps.size() / 2];
		// unlike medianValue, here we select lesser of 2 middle values for
		// even-sized array, so
		// that m_next_unlock_timestamp will never decrease with block number
		if (next_unlock_timestamp < m_currency.block_future_time_limit)
			next_unlock_timestamp = 0;
		else
			next_unlock_timestamp -= m_currency.block_future_time_limit;
	} else {
		next_median_timestamp = 0;
		next_unlock_timestamp = 0;
	}
}

void BlockChainState::tip_changed() {
	calculate_consensus_values(0, m_next_median_size, m_next_median_timestamp, m_next_unlock_timestamp);
}

bool BlockChainState::create_mining_block_template(BlockTemplate &b, const AccountPublicAddress &adr,
    const BinaryArray &extra_nonce, Difficulty &difficulty, Height &height) const {
	clear_mining_transactions();
	height = get_tip_height() + 1;
	{
		std::vector<Timestamp> timestamps;
		std::vector<Difficulty> difficulties;
		Height blocks_count = std::min(get_tip_height(), m_currency.difficulty_blocks_count());
		timestamps.reserve(blocks_count);
		difficulties.reserve(blocks_count);
		auto timestamps_window = get_tip_segment(0, blocks_count, false);
		for (auto it = timestamps_window.first; it != timestamps_window.second; ++it) {
			timestamps.push_back(it->timestamp);
			difficulties.push_back(it->cumulative_difficulty);
		}
		difficulty = m_currency.next_difficulty(timestamps, difficulties);
	}
	if (difficulty == 0) {
		//    log(Logging::ERROR, Logging::BrightRed) << "difficulty overhead.";
		return false;
	}

	b               = BlockTemplate{};
	b.major_version = m_currency.get_block_major_version_for_height(height);

	if (b.major_version == 1) {
		b.minor_version = m_currency.upgrade_height_v2 == Height(-1) ? 1 : 0;
	} else if (b.major_version >= 2) {
		if (m_currency.upgrade_height_v3 == Height(-1)) {
			b.minor_version = (b.major_version == 2) ? 1 : 0;
		} else {
			b.minor_version = 0;
		}

		b.parent_block.major_version     = 1;
		b.parent_block.minor_version     = 0;
		b.parent_block.transaction_count = 1;

		TransactionExtraMergeMiningTag mm_tag{};
		if (!append_merge_mining_tag_to_extra(b.parent_block.base_transaction.extra, mm_tag)) {
			m_log(logging::ERROR) << logging::BrightRed << "Failed to append merge mining tag to extra of "
			                                               "the parent block miner transaction";
			return false;
		}
	}

	b.previous_block_hash = get_tip_bid();
	b.timestamp           = std::max(static_cast<Timestamp>(time(nullptr)), m_next_median_timestamp);

	auto next_block_granted_full_reward_zone =
	    m_currency.block_granted_full_reward_zone_by_block_version(b.major_version);
	auto effective_size_median     = std::max(m_next_median_size, next_block_granted_full_reward_zone);
	Amount already_generated_coins = get_tip().already_generated_coins;

	auto max_total_size      = (125 * effective_size_median) / 100;
	auto max_cumulative_size = m_currency.max_block_cumulative_size(height);
	max_total_size           = std::min(max_total_size, max_cumulative_size) - m_currency.miner_tx_blob_reserved_size;

	std::vector<Hash> pool_hashes;
	for (auto &&msf : m_memory_state_fee_tx)
		for (auto &&ha : msf.second)
			pool_hashes.push_back(ha);
	size_t txs_size = 0;
	Amount fee      = 0;
	DeltaState memory_state(height, b.timestamp, this);  // will be get_tip().timestamp_unlock after fork
	// technically we should give unlock timestamp of next block, but more
	// conservative also works

	for (; !pool_hashes.empty(); pool_hashes.pop_back()) {
		auto tit = m_memory_state_tx.find(pool_hashes.back());
		if (tit == m_memory_state_tx.end()) {
			m_log(logging::ERROR) << "Transaction " << common::pod_to_hex(pool_hashes.back())
			                      << " is in pool index, but not in pool";
			assert(false);
			continue;
		}
		size_t block_size_limit = max_total_size;
		size_t tx_size          = seria::binary_size(tit->second);  // TODO - remember size in tx index
		if (txs_size + tx_size > block_size_limit)
			continue;
		Amount single_fee = 0;
		bool fatal        = false;
		BlockGlobalIndices global_indices;
		std::string result =
		    redo_transaction_get_error(false, tit->second, &memory_state, global_indices, true, single_fee,
		        fatal);  // nextMedianTimestamp
		if (!result.empty()) {
			m_log(logging::ERROR) << "Transaction " << common::pod_to_hex(tit->first)
			                      << " is in pool, but could not be redone result=" << result << std::endl;
			continue;
		}
		txs_size += tx_size;
		fee += single_fee;
		b.transaction_hashes.emplace_back(tit->first);
		m_mining_transactions.insert(std::make_pair(tit->first, std::make_pair(tit->second, height)));
		m_log(logging::TRACE) << "Transaction " << common::pod_to_hex(tit->first) << " included to block template";
	}

	// two-phase miner transaction generation: we don't know exact block size
	// until we prepare block, but we don't know
	// reward until we know
	// block size, so first miner transaction generated with fake amount of money,
	// and with phase we know think we know
	// expected block size
	// make blocks coin-base tx looks close to real coinbase tx to get truthful
	// blob size
	bool r = m_currency.construct_miner_tx(b.major_version, height, effective_size_median, already_generated_coins,
	    txs_size, fee, adr, b.base_transaction, extra_nonce, 11);
	if (!r) {
		m_log(logging::ERROR) << logging::BrightRed << "Failed to construct miner tx, first chance";
		return false;
	}

	size_t cumulative_size   = txs_size + seria::binary_size(b.base_transaction);
	const size_t TRIES_COUNT = 10;
	for (size_t try_count = 0; try_count < TRIES_COUNT; ++try_count) {
		r = m_currency.construct_miner_tx(b.major_version, height, effective_size_median, already_generated_coins,
		    cumulative_size, fee, adr, b.base_transaction, extra_nonce, 11);
		if (!r) {
			m_log(logging::ERROR) << logging::BrightRed << "Failed to construct miner tx, second chance";
			return false;
		}

		size_t coinbase_blob_size = seria::binary_size(b.base_transaction);
		if (coinbase_blob_size > cumulative_size - txs_size) {
			cumulative_size = txs_size + coinbase_blob_size;
			continue;
		}

		if (coinbase_blob_size < cumulative_size - txs_size) {
			size_t delta = cumulative_size - txs_size - coinbase_blob_size;
			common::append(b.base_transaction.extra, delta, 0);
			// here could be 1 byte difference, because of extra field counter is
			// varint, and it can become from
			// 1-byte len to 2-bytes len.
			if (cumulative_size != txs_size + seria::binary_size(b.base_transaction)) {
				if (cumulative_size + 1 != txs_size + seria::binary_size(b.base_transaction)) {
					m_log(logging::ERROR)
					    << logging::BrightRed << "unexpected case: cumulative_size=" << cumulative_size
					    << " + 1 is not equal txs_cumulative_size=" << txs_size
					    << " + get_object_blobsize(b.baseTransaction)=" << seria::binary_size(b.base_transaction);
					return false;
				}

				b.base_transaction.extra.resize(b.base_transaction.extra.size() - 1);
				if (cumulative_size != txs_size + seria::binary_size(b.base_transaction)) {
					// ooh, not lucky, -1 makes varint-counter size smaller, in that case
					// we continue to grow with
					// cumulative_size
					m_log(logging::TRACE)
					    << logging::BrightRed << "Miner tx creation have no luck with delta_extra size = " << delta
					    << " and " << delta - 1;
					cumulative_size += delta - 1;
					continue;
				}

				m_log(logging::DEBUGGING)
				    << logging::BrightGreen << "Setting extra for block: " << b.base_transaction.extra.size()
				    << ", try_count=" << try_count;
			}
		}
		if (cumulative_size != txs_size + seria::binary_size(b.base_transaction)) {
			m_log(logging::ERROR) << logging::BrightRed << "unexpected case: cumulative_size=" << cumulative_size
			                      << " is not equal txs_cumulative_size=" << txs_size
			                      << " + get_object_blobsize(b.baseTransaction)="
			                      << seria::binary_size(b.base_transaction);
			return false;
		}
		return true;
	}
	m_log(logging::ERROR) << logging::BrightRed << "Failed to create_block_template with " << TRIES_COUNT << " tries";
	return false;
}

uint32_t BlockChainState::get_next_effective_median_size() const {
	uint8_t next_major_version = m_currency.get_block_major_version_for_height(get_tip_height() + 1);
	auto next_block_granted_full_reward_zone =
	    m_currency.block_granted_full_reward_zone_by_block_version(next_major_version);
	return std::max(m_next_median_size, next_block_granted_full_reward_zone);
}

BroadcastAction BlockChainState::add_mined_block(
    const BinaryArray &raw_block_template, RawBlock &raw_block, api::BlockHeader &info) {
	BlockTemplate block_template;
	seria::from_binary(block_template, raw_block_template);
	raw_block.block = std::move(raw_block_template);

	raw_block.transactions.reserve(block_template.transaction_hashes.size());
	raw_block.transactions.clear();
	for (const auto &tx_hash : block_template.transaction_hashes) {
		auto tit              = m_memory_state_tx.find(tx_hash);
		const Transaction *tx = nullptr;
		if (tit != m_memory_state_tx.end())
			tx = &(tit->second);
		else {
			auto tit2 = m_mining_transactions.find(tx_hash);
			if (tit2 == m_mining_transactions.end()) {
				m_log(logging::WARNING) << "The transaction " << common::pod_to_hex(tx_hash)
				                        << " is absent in transaction pool on submit mined block";
				return BroadcastAction::NOTHING;
			}
			tx = &(tit2->second.first);
		}
		raw_block.transactions.emplace_back(seria::to_binary(*tx));
	}
	PreparedBlock pb(std::move(raw_block), nullptr);
	raw_block = pb.raw_block;
	return add_block(pb, info);
}

void BlockChainState::clear_mining_transactions() const {
	for (auto tit = m_mining_transactions.begin(); tit != m_mining_transactions.end();)
		if (get_tip_height() > tit->second.second + 3)  // Remember txs for 3 blocks
			tit = m_mining_transactions.erase(tit);
		else
			++tit;
}

static std::string validateSemantic(bool generating, const Transaction &tx, uint64_t &fee, bool check_output_key) {
	if (tx.inputs.empty())
		return "EMPTY_INPUTS";
	uint64_t summary_output_amount = 0;
	for (const auto &output : tx.outputs) {
		if (output.amount == 0)
			return "OUTPUT_ZERO_AMOUNT";
		if (output.target.type() == typeid(KeyOutput)) {
			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			if (check_output_key && !key_isvalid(key_output.key))
				return "OUTPUT_INVALID_KEY";
		} else
			return "OUTPUT_UNKNOWN_TYPE";
		if (std::numeric_limits<uint64_t>::max() - output.amount < summary_output_amount)
			return "OUTPUTS_AMOUNT_OVERFLOW";
		summary_output_amount += output.amount;
	}
	uint64_t summary_input_amount = 0;
	std::unordered_set<KeyImage> ki;
	std::set<std::pair<uint64_t, uint32_t>> outputs_usage;
	for (const auto &input : tx.inputs) {
		uint64_t amount = 0;
		if (input.type() == typeid(CoinbaseInput)) {
			if (!generating)
				return "INPUT_UNKNOWN_TYPE";
		} else if (input.type() == typeid(KeyInput)) {
			if (generating)
				return "INPUT_UNKNOWN_TYPE";
			const KeyInput &in = boost::get<KeyInput>(input);
			amount             = in.amount;
			if (!ki.insert(in.key_image).second)
				return "INPUT_IDENTICAL_KEYIMAGES";
			if (in.output_indexes.empty())
				return "INPUT_EMPTY_OUTPUT_USAGE";
			// outputIndexes are packed here, first is absolute, others are offsets to
			// previous,
			// so first can be zero, others can't
			if (std::find(++std::begin(in.output_indexes), std::end(in.output_indexes), 0) !=
			    std::end(in.output_indexes)) {
				return "INPUT_IDENTICAL_OUTPUT_INDEXES";
			}
		} else
			return "INPUT_UNKNOWN_TYPE";
		if (std::numeric_limits<uint64_t>::max() - amount < summary_input_amount)
			return "INPUTS_AMOUNT_OVERFLOW";
		summary_input_amount += amount;
	}
	if (summary_output_amount > summary_input_amount && !generating)
		return "WRONG_AMOUNT";
	if (tx.signatures.size() != tx.inputs.size() && !generating)
		return "INPUT_UNKNOWN_TYPE";
	if (!tx.signatures.empty() && generating)
		return "INPUT_UNKNOWN_TYPE";
	fee = summary_input_amount - summary_output_amount;
	return std::string();
}

BroadcastAction BlockChainState::add_transaction(const Transaction &tx, Timestamp now) {
	auto thash            = get_transaction_hash(tx);
	Timestamp g_timestamp = read_first_seen_timestamp(thash);
	if (g_timestamp != 0 && now > g_timestamp + m_config.mempool_tx_live_time)
		return BroadcastAction::NOTHING;
	return add_transaction(thash, tx, get_tip_height() + 1, get_tip().timestamp, MAX_POOL_COMPLEXITY, true);
}

BroadcastAction BlockChainState::add_transaction(const Hash &tid, const Transaction &tx, Height unlock_height,
    Timestamp unlock_timestamp, size_t max_pool_complexity, bool check_sigs) {
	const size_t my_size = seria::binary_size(tx);
	if (m_memory_state_tx.count(tid) != 0)
		return BroadcastAction::NOTHING;
	DeltaState memory_state(unlock_height, unlock_timestamp, this);  // timestamp_unlock after fork

	Amount my_fee = 0;
	bool fatal    = false;
	BlockGlobalIndices global_indices;
	std::string result = redo_transaction_get_error(false, tx, &memory_state, global_indices, check_sigs, my_fee,
	    fatal);  // nextMedianTimestamp
	if (!result.empty()) {
		return BroadcastAction::NOTHING;  // TODO - ban if fatal
	}
	// Only good transactions are recorded in tx_first_seen, because they require
	// space there
	update_first_seen_timestamp(tid, unlock_timestamp);
	const Amount my_fee_per_byte = my_fee / my_size;
	for (auto &&ki : memory_state.get_keyimages()) {
		auto tit = m_memory_state_ki_tx.find(ki.first);
		if (tit == m_memory_state_ki_tx.end())
			continue;
		const Transaction &other_tx     = m_memory_state_tx.at(tit->second);
		const Amount other_fee          = bytecoin::get_tx_fee(other_tx);  // TODO - optimize get fee
		const size_t other_size         = seria::binary_size(other_tx);
		const Amount other_fee_per_byte = other_fee / other_size;
		if (my_fee_per_byte < other_fee_per_byte)
			return BroadcastAction::NOTHING;
		if (my_fee_per_byte == other_fee_per_byte &&
		    tid < tit->second)  // Deterministic behaviour so tx pools have tendency
			                    // to stay the same
			return BroadcastAction::NOTHING;
		Hash rhash = tit->second;
		remove_from_pool(rhash);
	}
	bool all_inserted = true;
	for (auto &&ki : memory_state.get_keyimages()) {
		if (!m_memory_state_ki_tx.insert(std::make_pair(ki.first, tid)).second)
			all_inserted = false;
	}
	if (!m_memory_state_tx.insert(std::make_pair(tid, tx)).second)
		all_inserted = false;
	if (!m_memory_state_fee_tx[my_fee_per_byte].insert(tid).second)
		all_inserted = false;
	if (!all_inserted)  // insert all before throw
		throw std::logic_error("Invariant dead, memory_state_fee_tx empty");
	max_pool_complexity = std::max(max_pool_complexity, m_memory_state_total_complexity);
	// We do not reset pool complexity immediately after undo_block
	m_memory_state_total_complexity += get_complexity(tx);
	while (m_memory_state_total_complexity > max_pool_complexity) {
		if (m_memory_state_fee_tx.empty())
			throw std::logic_error("Invariant dead, memory_state_fee_tx empty");
		auto &be = m_memory_state_fee_tx.begin()->second;
		if (be.empty())
			throw std::logic_error("Invariant dead, memory_state_fee_tx empty set");
		Hash rhash = *(be.begin());
		remove_from_pool(rhash);
	}
	m_tx_pool_version += 1;
	return BroadcastAction::BROADCAST_ALL;
}

void BlockChainState::remove_from_pool(Hash tid) {
	auto tit = m_memory_state_tx.find(tid);
	if (tit == m_memory_state_tx.end())
		return;
	bool all_erased       = true;
	const Transaction &tx = tit->second;
	for (const auto &input : tx.inputs) {
		if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			if (m_memory_state_ki_tx.erase(in.key_image) != 1)
				all_erased = false;
		}
	}
	const Amount my_fee          = bytecoin::get_tx_fee(tx);  // TODO - optimize get fee
	const size_t my_size         = seria::binary_size(tx);
	const Amount my_fee_per_byte = my_fee / my_size;
	if (m_memory_state_fee_tx[my_fee_per_byte].erase(tid) != 1)
		all_erased = false;
	if (m_memory_state_fee_tx[my_fee_per_byte].empty())
		m_memory_state_fee_tx.erase(my_fee_per_byte);
	m_memory_state_total_complexity -= get_complexity(tx);
	m_memory_state_tx.erase(tit);
	if (!all_erased)
		throw std::logic_error("Invariant dead, remove_memory_pool failed to erase everything");
	// We do not increment m_tx_pool_version, because removing tx from pool is
	// always followed by reset or increment
}

Timestamp BlockChainState::read_first_seen_timestamp(const Hash &tid) const {
	Timestamp ta = 0;
	auto key     = FIRST_SEEN_PREFIX + DB::to_binary_key(tid.data, sizeof(tid.data));
	BinaryArray ba;
	if (m_db.get(key, ba))
		seria::from_binary(ta, ba);
	return ta;
}

void BlockChainState::update_first_seen_timestamp(const Hash &tid, Timestamp now) {
	auto key = FIRST_SEEN_PREFIX + DB::to_binary_key(tid.data, sizeof(tid.data));
	if (now != 0)
		m_db.put(key, seria::to_binary(now), false);
	else
		m_db.del(key, false);
}

RingCheckerMulticore::RingCheckerMulticore() {
	auto th_count = std::max<size_t>(2, std::thread::hardware_concurrency() / 2);  // we use more energy but have the
	                                                                               // same speed when using
	                                                                               // hyperthreading
	std::cout << "Starting multicore ring checker using " << th_count << "/" << std::thread::hardware_concurrency()
	          << " cpus" << std::endl;
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
				if (state->read_keyimage(in.key_image))
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
					UnlockMoment unlock_time = 0;
					if (!state->read_amount_output(in.amount, global_indexes[i], unlock_time, arg.output_keys[i]))
						return "INPUT_INVALID_GLOBAL_INDEX";
					if (!currency.is_transaction_spend_time_unlocked(unlock_time, unlock_height, unlock_timestamp))
						return "INPUT_SPEND_LOCKED_OUT";
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

std::string BlockChainState::redo_transaction_get_error(bool generating, const Transaction &transaction,
    DeltaState *delta_state, BlockGlobalIndices &global_indices, bool check_sigs, Amount &fee, bool &fatal) const {
	const bool check_outputs = check_sigs;
	std::string error        = validateSemantic(generating, transaction, fee, check_outputs);
	fatal                    = false;  // for now we do not distinguish between fatal and non-fatal
	                                   // errors
	if (!error.empty())
		return error;
	Hash tx_prefix_hash;
	if (check_sigs)
		tx_prefix_hash = get_transaction_prefix_hash(transaction);
	DeltaState tx_delta(delta_state->get_block_height(), delta_state->get_unlock_timestamp(), delta_state);
	global_indices.resize(global_indices.size() + 1);
	auto &my_indices = global_indices.back();
	my_indices.reserve(transaction.outputs.size());

	size_t input_index = 0;
	for (const auto &input : transaction.inputs) {
		if (input.type() == typeid(CoinbaseInput)) {
		} else if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);

			if (check_sigs || check_outputs) {
				if (tx_delta.read_keyimage(in.key_image))
					return "INPUT_KEYIMAGE_ALREADY_SPENT";
				if (in.output_indexes.empty())
					return "INPUT_UNKNOWN_TYPE";
				std::vector<uint32_t> global_indexes(in.output_indexes.size());
				global_indexes[0] = in.output_indexes[0];
				for (size_t i = 1; i < in.output_indexes.size(); ++i) {
					global_indexes[i] = global_indexes[i - 1] + in.output_indexes[i];
				}
				std::vector<PublicKey> output_keys(global_indexes.size());
				for (size_t i = 0; i != global_indexes.size(); ++i) {
					UnlockMoment unlock_time = 0;
					if (!tx_delta.read_amount_output(in.amount, global_indexes[i], unlock_time, output_keys[i]))
						return "INPUT_INVALID_GLOBAL_INDEX";
					if (!m_currency.is_transaction_spend_time_unlocked(
					        unlock_time, delta_state->get_block_height(), delta_state->get_unlock_timestamp()))
						return "INPUT_SPEND_LOCKED_OUT";
				}
				std::vector<const PublicKey *> output_key_pointers;
				output_key_pointers.reserve(output_keys.size());
				std::for_each(output_keys.begin(), output_keys.end(),
				    [&output_key_pointers](const PublicKey &key) { output_key_pointers.push_back(&key); });
				bool key_corrupted = false;
				if (check_sigs &&
				    !check_ring_signature(tx_prefix_hash, in.key_image, output_key_pointers.data(),
				        output_key_pointers.size(), transaction.signatures[input_index].data(), true, &key_corrupted)) {
					if (key_corrupted)  // TODO - db corrupted
						return "INPUT_CORRUPTED_SIGNATURES";
					return "INPUT_INVALID_SIGNATURES";
				}
			}
			tx_delta.store_keyimage(in.key_image, delta_state->get_block_height());
		} else
			return "INPUT_UNKNOWN_TYPE";
		input_index++;
	}
	for (const auto &output : transaction.outputs) {
		if (output.target.type() == typeid(KeyOutput)) {
			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			auto global_index           = tx_delta.push_amount_output(output.amount, transaction.unlock_time, 0, 0,
			    key_output.key);  // DeltaState ignores unlock point
			my_indices.push_back(global_index);
		} else
			return "OUTPUT_UNKNOWN_TYPE";
	}
	tx_delta.apply(delta_state);  // delta_state might be memory pool, we protect
	                              // it from half-modification
	return std::string();
}

void BlockChainState::undo_transaction(IBlockChainState *delta_state, Height, const Transaction &tx) {
	for (auto oit = tx.outputs.rbegin(); oit != tx.outputs.rend(); ++oit) {
		if (oit->target.type() == typeid(KeyOutput)) {
			delta_state->pop_amount_output(oit->amount, tx.unlock_time, boost::get<KeyOutput>(oit->target).key);
		}
	}
	for (auto iit = tx.inputs.rbegin(); iit != tx.inputs.rend(); ++iit) {
		if (iit->type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(*iit);
			delta_state->delete_keyimage(in.key_image);
		}
	}
}

bool BlockChainState::redo_block(const Block &block,
    const api::BlockHeader &info,
    DeltaState *delta_state,
    BlockGlobalIndices &global_indices) const {
	// We will need info.timestamp_unlock after first hard fork
	Amount fee = 0;
	bool fatal = false;
	std::string result =
	    redo_transaction_get_error(true, block.header.base_transaction, delta_state, global_indices, false, fee, fatal);
	if (!result.empty())
		return false;
	SignedAmount sum_fee = 0;
	for (auto tit = block.transactions.begin(); tit != block.transactions.end(); ++tit) {
		std::string result = redo_transaction_get_error(false, *tit, delta_state, global_indices, false, fee, fatal);
		if (!result.empty())
			return false;
		sum_fee += fee;
	}
	return true;
}

bool BlockChainState::redo_block(const Hash &bhash, const Block &block, const api::BlockHeader &info) {
	DeltaState delta(info.height, info.timestamp, this);
	BlockGlobalIndices global_indices;
	global_indices.reserve(block.transactions.size() + 1);
	const bool check_sigs = !m_currency.is_in_checkpoint_zone(info.height + 1);
	if (check_sigs && !ring_checker.start_work_get_error(this, m_currency, block, info.height, info.timestamp).empty())
		return false;
	if (!redo_block(block, info, &delta, global_indices))
		return false;
	if (check_sigs && !ring_checker.signatures_valid())
		return false;
	delta.apply(this);
	m_tx_pool_version = 2;

	auto key =
	    BLOCK_GLOBAL_INDICES_PREFIX + DB::to_binary_key(bhash.data, sizeof(bhash.data)) + BLOCK_GLOBAL_INDICES_SUFFIX;
	BinaryArray ba = seria::to_binary(global_indices);
	m_db.put(key, ba, true);

	for (auto th : block.header.transaction_hashes) {
		remove_from_pool(th);
		update_first_seen_timestamp(th, 0);
	}
	if (info.height % 100 == 0)
		std::cout << "redo_block {" << block.transactions.size() << "} height=" << info.height
		          << " bid=" << common::pod_to_hex(bhash) << " old tip_bid=" << common::pod_to_hex(get_tip_bid())
		          << std::endl;
	return true;
}

void BlockChainState::undo_block(const Hash &bhash, const Block &block, Height height) {
	if (height % 100 == 0)
		std::cout << "undo_block height=" << height << " bid=" << common::pod_to_hex(bhash)
		          << " new tip_bid=" << common::pod_to_hex(block.header.previous_block_hash) << std::endl;
	for (auto tit = block.transactions.rbegin(); tit != block.transactions.rend(); ++tit) {
		undo_transaction(this, height, *tit);
	}
	undo_transaction(this, height, block.header.base_transaction);

	auto key =
	    BLOCK_GLOBAL_INDICES_PREFIX + DB::to_binary_key(bhash.data, sizeof(bhash.data)) + BLOCK_GLOBAL_INDICES_SUFFIX;
	m_db.del(key, true);

	// Now put transactions to pool
	for (auto tit = block.transactions.begin(); tit != block.transactions.end(); ++tit) {
		if (m_memory_state_total_complexity < MAX_POOL_COMPLEXITY * 2) {
			auto thash = get_transaction_hash(*tit);
			// undo is rare, otherwise we'd optimize to use
			// block.header.transactionHashes
			add_transaction(thash, *tit, height, get_tip().timestamp + m_currency.block_future_time_limit * 2,
			    std::numeric_limits<size_t>::max(), false);
			// we use increased timestamp so that just unlocked transactions will not
			// be thrown out of the pool
			// we set no limit on complexity to overshoot MAX_POOL_COMPLEXITY * 2 and
			// stop doing work in case of large undo
		}
	}
}

bool BlockChainState::read_block_output_global_indices(const Hash &bid, BlockGlobalIndices &indices) const {
	BinaryArray rb;
	auto key =
	    BLOCK_GLOBAL_INDICES_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + BLOCK_GLOBAL_INDICES_SUFFIX;
	if (!m_db.get(key, rb))
		return false;
	seria::from_binary(indices, rb);
	return true;
}

std::vector<api::Output> BlockChainState::get_outputs_by_amount(
    Amount amount, size_t anonymity, Height height, Timestamp time) const {
	std::vector<api::Output> result;
	uint32_t total_count = next_global_index_for_amount(amount);
	// We might need better algorithm if we have lots of locked amounts
	if (total_count <= anonymity) {
		for (uint32_t i = 0; i != total_count; ++i) {
			api::Output item;
			item.amount       = amount;
			item.global_index = i;
			if (!read_amount_output(amount, i, item.unlock_time, item.public_key))
				throw std::logic_error("Invariant dead - global amount < total_count not found");
			if (m_currency.is_transaction_spend_time_unlocked(item.unlock_time, height, time))
				result.push_back(item);
		}
		return result;
	}
	std::set<uint32_t> tried_or_added;
	uint32_t attempts = 0;
	for (; result.size() < anonymity && attempts < anonymity * 10; ++attempts) {  // TODO - 10
		uint32_t num = crypto::rand<uint32_t>();
		num %= total_count;  // 0 handled in if above
		if (!tried_or_added.insert(num).second)
			continue;
		api::Output item;
		item.amount       = amount;
		item.global_index = num;
		if (!read_amount_output(amount, num, item.unlock_time, item.public_key))
			throw std::logic_error("Invariant dead - num < total_count not found");
		if (m_currency.is_transaction_spend_time_unlocked(item.unlock_time, height, time))
			result.push_back(item);
	}
	return result;
}

void BlockChainState::store_keyimage(const KeyImage &keyimage, Height height) {
	auto key = KEYIMAGE_PREFIX + DB::to_binary_key(keyimage.data, sizeof(keyimage.data));
	m_db.put(key, std::string(), true);
}

void BlockChainState::delete_keyimage(const KeyImage &keyimage) {
	auto key = KEYIMAGE_PREFIX + DB::to_binary_key(keyimage.data, sizeof(keyimage.data));
	m_db.del(key, true);
}

bool BlockChainState::read_keyimage(const KeyImage &keyimage) const {
	auto key = KEYIMAGE_PREFIX + DB::to_binary_key(keyimage.data, sizeof(keyimage.data));
	BinaryArray rb;
	return m_db.get(key, rb);
}

uint32_t BlockChainState::push_amount_output(Amount amount,
    UnlockMoment unlock_time,
    Height block_height,
    Timestamp block_unlock_timestamp,
    const PublicKey &pk) {
	uint32_t my_gi = next_global_index_for_amount(amount);
	auto key       = AMOUNT_OUTPUT_PREFIX + common::write_varint_sqlite4(amount) + common::write_varint_sqlite4(my_gi);
	BinaryArray ba = seria::to_binary(std::make_pair(unlock_time, pk));
	m_db.put(key, ba, true);

	if (create_unlock_index &&
	    !m_currency.is_transaction_spend_time_unlocked(unlock_time, block_height, block_unlock_timestamp)) {
		std::string unkey;
		uint32_t clamped_unlock_time = static_cast<uint32_t>(std::min<UnlockMoment>(unlock_time, 0xFFFFFFFF));
		if (m_currency.is_transaction_spend_time_block(unlock_time))
			unkey = UNLOCK_BLOCK_PREFIX;
		else
			unkey = UNLOCK_TIME_PREFIX;
		unkey += common::write_varint_sqlite4(amount) + common::write_varint_sqlite4(clamped_unlock_time) +
		         common::write_varint_sqlite4(my_gi);
		m_db.put(unkey, std::string(), true);
	}
	m_next_gi_for_amount[amount] += 1;
	return my_gi;
}

void BlockChainState::pop_amount_output(Amount amount, UnlockMoment unlock_time, const PublicKey &pk) {
	uint32_t next_gi = next_global_index_for_amount(amount);
	if (next_gi == 0)
		throw std::logic_error("BlockChainState::pop_amount_output underflow");
	next_gi -= 1;
	m_next_gi_for_amount[amount] -= 1;
	auto key = AMOUNT_OUTPUT_PREFIX + common::write_varint_sqlite4(amount) + common::write_varint_sqlite4(next_gi);

	UnlockMoment was_unlock_time = 0;
	PublicKey was_pk;
	if (!read_amount_output(amount, next_gi, was_unlock_time, was_pk))
		throw std::logic_error("BlockChainState::pop_amount_output element does not exist");
	if (was_unlock_time != unlock_time || was_pk != pk)
		throw std::logic_error("BlockChainState::pop_amount_output popping wrong element");
	m_db.del(key, true);

	if (create_unlock_index &&
	    !m_currency.is_transaction_spend_time_unlocked(unlock_time, get_tip_height(), get_tip().timestamp_unlock)) {
		std::string unkey;
		uint32_t clamped_unlock_time = static_cast<uint32_t>(std::min<UnlockMoment>(unlock_time, 0xFFFFFFFF));
		if (m_currency.is_transaction_spend_time_block(unlock_time))
			unkey = UNLOCK_BLOCK_PREFIX;
		else
			unkey = UNLOCK_TIME_PREFIX;
		unkey += common::write_varint_sqlite4(amount) + common::write_varint_sqlite4(clamped_unlock_time) +
		         common::write_varint_sqlite4(next_gi);
		m_db.del(unkey, true);
	}
}

uint32_t BlockChainState::next_global_index_for_amount(Amount amount) const {
	auto it = m_next_gi_for_amount.find(amount);
	if (it != m_next_gi_for_amount.end())
		return it->second;
	std::string prefix = AMOUNT_OUTPUT_PREFIX + common::write_varint_sqlite4(amount);
	DB::Cursor cur2    = m_db.rbegin(prefix);
	uint32_t alt_in = cur2.end() ? 0 : boost::lexical_cast<Height>(common::read_varint_sqlite4(cur2.get_suffix())) + 1;
	m_next_gi_for_amount[amount] = alt_in;
	return alt_in;
}

bool BlockChainState::read_amount_output(
    Amount amount, uint32_t global_index, UnlockMoment &unlock_time, PublicKey &pk) const {
	auto key = AMOUNT_OUTPUT_PREFIX + common::write_varint_sqlite4(amount) + common::write_varint_sqlite4(global_index);
	BinaryArray rb;
	if (!m_db.get(key, rb))
		return false;
	std::pair<uint64_t, PublicKey> was;
	seria::from_binary(was, rb);
	unlock_time = was.first;
	pk          = was.second;
	return true;
}
