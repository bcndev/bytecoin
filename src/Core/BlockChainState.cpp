// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "BlockChainState.hpp"
#include <condition_variable>
#include <random>
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "Currency.hpp"
#include "TransactionExtra.hpp"
#include "common/Math.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "crypto/crypto.hpp"
#include "platform/Time.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

static const std::string KEYIMAGE_PREFIX             = "i";
static const std::string AMOUNT_OUTPUT_PREFIX        = "a";
static const std::string BLOCK_GLOBAL_INDICES_PREFIX = "b";
static const std::string BLOCK_GLOBAL_INDICES_SUFFIX = "g";

static const std::string UNLOCK_BLOCK_PREFIX = "u";
static const std::string UNLOCK_TIME_PREFIX  = "U";
// We store locked outputs in separate indexes

const size_t MAX_POOL_SIZE = 2000000;  // ~1000 "normal" transactions with 10 inputs and 10 outputs

using namespace bytecoin;
using namespace platform;

namespace seria {
void ser_members(IBlockChainState::UnlockTimePublickKeyHeightSpent &v, ISeria &s) {
	seria_kv("unlock_block_or_timestamp", v.unlock_block_or_timestamp, s);
	seria_kv("public_key", v.public_key, s);
	seria_kv("height", v.height, s);
	seria_kv("spent", v.spent, s);
}
}  // namespace seria

BlockChainState::PoolTransaction::PoolTransaction(
    const Transaction &tx, const BinaryArray &binary_tx, Amount fee, Timestamp timestamp)
    : tx(tx), binary_tx(binary_tx), fee(fee), timestamp(timestamp) {}

void BlockChainState::DeltaState::store_keyimage(const KeyImage &key_image, Height height) {
	invariant(m_keyimages.insert(std::make_pair(key_image, height)).second, common::pod_to_hex(key_image));
}

void BlockChainState::DeltaState::delete_keyimage(const KeyImage &key_image) {
	invariant(m_keyimages.erase(key_image) == 1, common::pod_to_hex(key_image));
}

bool BlockChainState::DeltaState::read_keyimage(const KeyImage &key_image, Height *height) const {
	auto kit = m_keyimages.find(key_image);
	if (kit == m_keyimages.end())
		return m_parent_state->read_keyimage(key_image, height);
	*height = m_block_height;
	return true;
}

uint32_t BlockChainState::DeltaState::push_amount_output(
    Amount amount, BlockOrTimestamp unlock_time, Height block_height, const PublicKey &pk) {
	uint32_t pg = m_parent_state->next_global_index_for_amount(amount);
	auto &ga    = m_global_amounts[amount];
	ga.push_back(std::make_pair(unlock_time, pk));
	return pg + static_cast<uint32_t>(ga.size()) - 1;
}

void BlockChainState::DeltaState::pop_amount_output(Amount amount, BlockOrTimestamp unlock_time, const PublicKey &pk) {
	std::vector<std::pair<uint64_t, PublicKey>> &el = m_global_amounts[amount];
	invariant(!el.empty(), "DeltaState::pop_amount_output underflow");
	invariant(el.back().first == unlock_time && el.back().second == pk, "DeltaState::pop_amount_output wrong element");
	el.pop_back();
}

uint32_t BlockChainState::DeltaState::next_global_index_for_amount(Amount amount) const {
	uint32_t pg = m_parent_state->next_global_index_for_amount(amount);
	auto git    = m_global_amounts.find(amount);
	return (git == m_global_amounts.end()) ? pg : static_cast<uint32_t>(git->second.size()) + pg;
}

bool BlockChainState::DeltaState::read_amount_output(
    Amount amount, uint32_t global_index, UnlockTimePublickKeyHeightSpent *unp) const {
	uint32_t pg = m_parent_state->next_global_index_for_amount(amount);
	if (global_index < pg)
		return m_parent_state->read_amount_output(amount, global_index, unp);
	global_index -= pg;
	auto git = m_global_amounts.find(amount);
	if (git == m_global_amounts.end() || global_index >= git->second.size())
		return false;
	unp->unlock_block_or_timestamp = git->second[global_index].first;
	unp->public_key                = git->second[global_index].second;
	unp->height                    = m_block_height;
	unp->spent = false;  // Spending just created outputs inside mempool or block is prohibited, simplifying logic
	return true;
}
void BlockChainState::DeltaState::spend_output(Amount amount, uint32_t global_index) {
	m_spent_outputs.push_back(std::make_pair(amount, global_index));
}

void BlockChainState::DeltaState::apply(IBlockChainState *parent_state) const {
	for (auto &&ki : m_keyimages)
		parent_state->store_keyimage(ki.first, ki.second);
	for (auto &&amp : m_global_amounts)
		for (auto &&el : amp.second)
			parent_state->push_amount_output(amp.first, el.first, m_block_height, el.second);
	for (auto &&mo : m_spent_outputs)
		parent_state->spend_output(mo.first, mo.second);
}

void BlockChainState::DeltaState::clear(Height new_block_height) {
	m_block_height = new_block_height;
	m_keyimages.clear();
	m_global_amounts.clear();
	m_spent_outputs.clear();
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

static std::string validate_semantic(bool generating, const Transaction &tx, uint64_t *fee, bool check_output_key) {
	if (tx.inputs.empty())
		return "EMPTY_INPUTS";
	uint64_t summary_output_amount = 0;
	for (const auto &output : tx.outputs) {
		if (output.amount == 0)
			return "OUTPUT_ZERO_AMOUNT";
		if (output.target.type() == typeid(KeyOutput)) {
			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			if (check_output_key && !key_isvalid(key_output.public_key))
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
			// output_indexes are packed here, first is absolute, others are offsets to
			// previous, so first can be zero, others can't
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
	*fee = summary_input_amount - summary_output_amount;
	return std::string();
}

BlockChainState::BlockChainState(logging::ILogger &log, const Config &config, const Currency &currency, bool read_only)
    : BlockChain(log, config, currency, read_only), log_redo_block_timestamp(std::chrono::steady_clock::now()) {
	std::string version;
	m_db.get("$version", version);
	if (version == "B" || version == "1" || version == "2" || version == "3" || version == "4") {
		start_internal_import();
		version = version_current;
		m_db.put("$version", version, false);
		db_commit();
	}
	// Upgrades from 5 should restart internal import if m_internal_import_chain is not empty
	if (version != version_current)
		throw std::runtime_error("Blockchain database format unknown (version=" + version + "), please delete " +
		                         config.get_data_folder() + "/blockchain");
	if (get_tip_height() == (Height)-1) {
		Block genesis_block;
		genesis_block.header = currency.genesis_block_template;
		RawBlock raw_block;
		invariant(genesis_block.to_raw_block(raw_block), "Genesis block failed to convert into raw block");
		PreparedBlock pb(std::move(raw_block), m_currency, nullptr);
		api::BlockHeader info;
		invariant(add_block(pb, &info, std::string()) != BroadcastAction::BAN, "Genesis block failed to add");
	}
	BlockChainState::tip_changed();
	m_log(logging::INFO) << "BlockChainState::BlockChainState height=" << get_tip_height()
	                     << " cumulative_difficulty=" << get_tip_cumulative_difficulty() << " bid=" << get_tip_bid()
	                     << std::endl;
	/*	RawBlock rb;
	    Block bb;
	    invariant(read_block(common::pfh<Hash>("ec140124695fbe90929a3f49dbe4d2b88fa0ad5ae271aedf0ebcd9f55b6bd3d7"),
	   &rb), "");
	    invariant(bb.from_raw_block(rb), "");
	    Hash ha1 = get_auxiliary_block_header_hash(bb.header);
	    Hash ha2 = get_block_hash(bb.header);
	    auto ba3 = currency.get_block_long_hashing_data(bb.header);
	    auto bbh = seria::to_binary(bb.header);
	    std::cout << common::to_hex(rb.block.data(), rb.block.size()) << std::endl;
	    std::cout << common::to_hex(bbh.data(), bbh.size()) << std::endl;
	    invariant(bbh == rb.block, "");*/
	/*	size_t templates_size = 0;
	    size_t true_headers_size = 0;
	    Height start = 400000;
	    Height ha = start;
	    for(; ha < start + 10000; ++ha ){
	        Hash bid;
	        if(!read_chain(ha, &bid))
	            break;
	        RawBlock rb;
	        Block bb;
	        invariant(read_block(bid, &rb), "");
	        invariant(bb.from_raw_block(rb), "");
	        BinaryArray tba = seria::to_binary(static_cast<BlockHeader &>(bb.header));
	        BinaryArray tba2 = seria::to_binary(get_body_proxy_from_template(bb.header));
	        templates_size += rb.block.size();
	        true_headers_size += tba.size() + tba2.size();
	    }
	    std::cout << "from height " << start << " to " << ha << " block templates size=" << templates_size << " true
	   headers + body proxies size=" << true_headers_size << std::endl;*/
	/*BlockHeader tr;
	tr.major_version = 104;
	tr.cm_merkle_branch.push_back(crypto::rand<Hash>());
	tr.cm_merkle_branch.push_back(crypto::rand<Hash>());
	tr.cm_merkle_branch.push_back(Hash{});
	tr.cm_merkle_branch.push_back(Hash{});
	tr.cm_merkle_branch.push_back(Hash{});
	tr.cm_merkle_branch.push_back(crypto::rand<Hash>());
	tr.cm_merkle_branch.push_back(Hash{});
	tr.cm_merkle_branch.push_back(Hash{});
	tr.cm_merkle_branch.push_back(Hash{});
	tr.cm_merkle_branch.push_back(crypto::rand<Hash>());
	BinaryArray ba = seria::to_binary(tr);
	std::cout << seria::to_json_value(tr).to_string() << std::endl;
	BlockHeader tr2;
	seria::from_binary(tr2, ba);
	invariant(tr.cm_merkle_branch == tr2.cm_merkle_branch, "");*/
	build_blods();
}

std::string BlockChainState::check_standalone_consensus(
    const PreparedBlock &pb, api::BlockHeader *info, const api::BlockHeader &prev_info, bool check_pow) const {
	const auto &block = pb.block;
	if (block.transactions.size() != block.header.transaction_hashes.size() ||
	    block.transactions.size() != pb.raw_block.transactions.size())
		return "WRONG_TRANSACTIONS_COUNT";
	info->size_median      = m_next_median_size;
	info->timestamp_median = m_next_median_timestamp;
	//	info->timestamp_unlock = m_next_unlock_timestamp;

	if (get_tip_bid() != prev_info.hash)  // Optimization for most common case
		calculate_consensus_values(prev_info, &info->size_median, &info->timestamp_median);

	auto next_minimum_size_median = m_currency.get_minimum_size_median(block.header.major_version);
	info->effective_size_median   = std::max(info->size_median, next_minimum_size_median);

	size_t cumulative_size = 0;
	for (size_t i = 0; i != pb.raw_block.transactions.size(); ++i) {
		if (pb.raw_block.transactions.at(i).size() >
		    m_currency.max_transaction_allowed_size(info->effective_size_median)) {
			//            log(Logging::INFO) << "Raw transaction size " <<
			//            binary_transaction.size() << " is too big.";
			return "RAW_TRANSACTION_SIZE_TOO_BIG";
		}
		cumulative_size += pb.raw_block.transactions.at(i).size();
		Hash tid = get_transaction_hash(pb.block.transactions.at(i));
		if (tid != pb.block.header.transaction_hashes.at(i))
			return "TRANSACTION_ABSENT_IN_POOL";
	}
	info->block_size               = static_cast<uint32_t>(pb.coinbase_tx_size + cumulative_size);
	auto max_block_cumulative_size = m_currency.max_block_cumulative_size(info->height);
	if (info->block_size > max_block_cumulative_size)
		return "CUMULATIVE_BLOCK_SIZE_TOO_BIG";

	uint8_t should_be_major = 0, might_be_minor = 0;
	if (!fill_next_block_versions(prev_info, false, &should_be_major, &might_be_minor))
		return "DOES_NOT_PASS_THROUGH_LAST_SW_CHECKPOINT";
	if (block.header.major_version != should_be_major)
		return "WRONG_VERSION";

	if (block.header.is_merge_mined()) {
		if (block.header.major_version == 2 && block.header.parent_block.major_version > 1)
			return "PARENT_BLOCK_WRONG_VERSION";
		size_t pasi = pb.parent_block_size;
		if (pasi > 2048)
			return "PARENT_BLOCK_SIZE_TOO_BIG";
	}
	auto now = platform::now_unix_timestamp();  // It would be better to pass now through Node
	if (block.header.timestamp > now + m_currency.block_future_time_limit)
		return "TIMESTAMP_TOO_FAR_IN_FUTURE";
	if (block.header.timestamp < info->timestamp_median)
		return "TIMESTAMP_TOO_FAR_IN_PAST";

	if (block.header.base_transaction.inputs.size() != 1)
		return "INPUT_WRONG_COUNT";

	if (block.header.base_transaction.inputs[0].type() != typeid(CoinbaseInput))
		return "INPUT_UNEXPECTED_TYPE";

	if (boost::get<CoinbaseInput>(block.header.base_transaction.inputs[0]).height != info->height)
		return "BASE_INPUT_WRONG_BLOCK_INDEX";

	if (block.header.base_transaction.unlock_block_or_timestamp != info->height + m_currency.mined_money_unlock_window)
		return "WRONG_TRANSACTION_UNLOCK_TIME";

	const bool check_keys = m_config.paranoid_checks || !m_currency.is_in_sw_checkpoint_zone(info->height);
	uint64_t miner_reward = 0;
	for (const auto &output : block.header.base_transaction.outputs) {  // TODO - call validate_semantic
		if (output.amount == 0)
			return "OUTPUT_ZERO_AMOUNT";
		if (output.target.type() == typeid(KeyOutput)) {
			if (check_keys && !key_isvalid(boost::get<KeyOutput>(output.target).public_key))
				return "OUTPUT_INVALID_KEY";
		} else
			return "OUTPUT_UNKNOWN_TYPE";

		if (std::numeric_limits<uint64_t>::max() - output.amount < miner_reward)
			return "OUTPUTS_AMOUNT_OVERFLOW";
		miner_reward += output.amount;
	}
	{
		std::vector<Timestamp> timestamps;
		std::vector<CumulativeDifficulty> difficulties;
		Height blocks_count    = std::min(prev_info.height, m_currency.difficulty_blocks_count());
		auto timestamps_window = get_tip_segment(prev_info, blocks_count, false);  // TODO - excess min
		size_t actual_count    = timestamps_window.size();
		timestamps.resize(actual_count);
		difficulties.resize(actual_count);
		size_t pos = 0;
		for (auto it = timestamps_window.begin(); it != timestamps_window.end(); ++it, ++pos) {
			timestamps.at(pos)   = it->timestamp;
			difficulties.at(pos) = it->cumulative_difficulty;
		}
		info->difficulty = m_currency.next_effective_difficulty(block.header.major_version, timestamps, difficulties);
		info->cumulative_difficulty = prev_info.cumulative_difficulty + info->difficulty;
	}

	//	if (info->difficulty == 0)
	//		return "DIFFICULTY_OVERHEAD";

	Amount transactions_fee = 0;
	for (const auto &tx : block.transactions) {
		Amount fee = 0;
		if (!get_tx_fee(tx, &fee))
			return "WRONG_AMOUNT";
		transactions_fee += fee;
	}

	int64_t emission_change      = 0;
	auto already_generated_coins = prev_info.already_generated_coins;

	if (info->block_size > info->effective_size_median * 2)
		return "CUMULATIVE_BLOCK_SIZE_TOO_BIG";

	m_currency.get_block_reward(block.header.major_version, info->effective_size_median, 0, already_generated_coins, 0,
	    &info->base_reward, &emission_change);

	m_currency.get_block_reward(block.header.major_version, info->effective_size_median, info->block_size,
	    already_generated_coins, transactions_fee, &info->reward, &emission_change);

	if (miner_reward != info->reward) {
		//        log(Logging::WARNING) << "Block reward mismatch for block " <<
		//        hash <<  ". Expected reward: " << reward << ", got reward: " <<
		//        miner_reward;
		return "BLOCK_REWARD_MISMATCH";
	}
	info->already_generated_coins        = prev_info.already_generated_coins + emission_change;
	info->already_generated_transactions = prev_info.already_generated_transactions + block.transactions.size() + 1;
	info->transactions_fee               = transactions_fee;
	info->transactions_size              = static_cast<uint32_t>(cumulative_size);
	for (auto &&tx : pb.block.transactions) {
		Amount tx_fee         = 0;
		std::string tx_result = validate_semantic(false, tx, &tx_fee, m_config.paranoid_checks || check_keys);
		if (!tx_result.empty())
			return tx_result;
	}
	if (m_currency.is_in_sw_checkpoint_zone(info->height)) {
		bool is_checkpoint;
		if (!m_currency.check_sw_checkpoint(info->height, info->hash, is_checkpoint))
			return "CHECKPOINT_BLOCK_HASH_MISMATCH";
	} else {
		if (!check_pow && !m_config.paranoid_checks)
			return std::string();
		Hash long_hash = pb.long_block_hash;
		if (long_hash == Hash{}) {
			auto body_proxy = get_body_proxy_from_template(block.header);
			auto ba         = m_currency.get_block_long_hashing_data(block.header, body_proxy);
			long_hash       = m_hash_crypto_context.cn_slow_hash(ba.data(), ba.size());
		}
		if (!check_hash(long_hash, info->difficulty))
			return "PROOF_OF_WORK_TOO_WEAK";
	}
	return std::string();
}
void BlockChainState::fill_statistics(api::bytecoind::GetStatistics::Response &res) const {
	BlockChain::fill_statistics(res);
	res.transaction_pool_size     = m_memory_state_total_size;
	res.transaction_pool_max_size = MAX_POOL_SIZE;
	Hash minimal_tid;
	res.transaction_pool_lowest_fee_per_byte = minimum_pool_fee_per_byte(&minimal_tid);
}

void BlockChainState::calculate_consensus_values(
    const api::BlockHeader &prev_info, uint32_t *next_median_size, Timestamp *next_median_timestamp) const {
	std::vector<uint32_t> last_blocks_sizes;
	auto window = get_tip_segment(prev_info, m_currency.reward_blocks_window, true);
	last_blocks_sizes.reserve(m_currency.reward_blocks_window);
	for (auto it = window.begin(); it != window.end(); ++it)
		last_blocks_sizes.push_back(it->block_size);
	*next_median_size = common::median_value(&last_blocks_sizes);

	window = get_tip_segment(prev_info, m_currency.timestamp_check_window, false);
	if (window.size() >= m_currency.timestamp_check_window) {
		std::vector<Timestamp> timestamps;
		timestamps.reserve(m_currency.timestamp_check_window);
		for (auto it = window.begin(); it != window.end(); ++it)
			timestamps.push_back(it->timestamp);
		*next_median_timestamp = common::median_value(&timestamps);  // sorts timestamps
		//*next_unlock_timestamp = timestamps[timestamps.size() / 2];
		// unlike median_value, here we select lesser of 2 middle values for
		// even-sized array, so
		// that m_next_unlock_timestamp will never decrease with block number
		// if (*next_unlock_timestamp < m_currency.block_future_time_limit)
		//	*next_unlock_timestamp = 0;
		// else
		//	*next_unlock_timestamp -= m_currency.block_future_time_limit;
	} else {
		*next_median_timestamp = 0;
		//*next_unlock_timestamp = 0;
	}
}

void BlockChainState::tip_changed() {
	calculate_consensus_values(get_tip(), &m_next_median_size, &m_next_median_timestamp);
}

void BlockChainState::create_mining_block_template(const AccountPublicAddress &adr, const BinaryArray &extra_nonce,
    BlockTemplate *b, Difficulty *difficulty, Height *height) const {
	create_mining_block_template(adr, extra_nonce, b, difficulty, height, get_tip_bid());
}

void BlockChainState::create_mining_block_template(const AccountPublicAddress &adr, const BinaryArray &extra_nonce,
    BlockTemplate *b, Difficulty *difficulty, Height *height, Hash parent_bid) const {
	api::BlockHeader parent_info;
	if (!read_header(parent_bid, &parent_info))
		throw std::runtime_error("Attempt to mine from block we do not have");
	*height = parent_info.height + 1;
	*b      = BlockTemplate{};
	if (!fill_next_block_versions(parent_info, false, &b->major_version, &b->minor_version))
		throw std::runtime_error(
		    "Mining of block in chain not passing through last SW checkpoint is not possible (will not be accepted by network anyway)");

	uint32_t next_median_size       = 0;
	Timestamp next_median_timestamp = 0;
	calculate_consensus_values(parent_info, &next_median_size, &next_median_timestamp);
	clear_mining_transactions();  // ????
	{
		std::vector<Timestamp> timestamps;
		std::vector<CumulativeDifficulty> difficulties;
		Height blocks_count = std::min(parent_info.height, m_currency.difficulty_blocks_count());
		timestamps.reserve(blocks_count);
		difficulties.reserve(blocks_count);
		auto timestamps_window = get_tip_segment(parent_info, blocks_count, false);
		for (auto it = timestamps_window.begin(); it != timestamps_window.end(); ++it) {
			timestamps.push_back(it->timestamp);
			difficulties.push_back(it->cumulative_difficulty);
		}
		*difficulty = m_currency.next_effective_difficulty(b->major_version, timestamps, difficulties);
	}
	if (b->is_merge_mined()) {
		b->parent_block.major_version     = 1;
		b->parent_block.minor_version     = 0;
		b->parent_block.transaction_count = 1;

		extra_add_merge_mining_tag(b->parent_block.base_transaction.extra, TransactionExtraMergeMiningTag{});
	}

	b->previous_block_hash    = parent_bid;
	b->parent_block.timestamp = std::max(platform::now_unix_timestamp(), next_median_timestamp);
	b->timestamp              = b->parent_block.timestamp;

	auto next_minimum_size_median  = m_currency.get_minimum_size_median(b->major_version);
	auto effective_size_median     = std::max(next_median_size, next_minimum_size_median);
	Amount already_generated_coins = parent_info.already_generated_coins;

	//	auto max_total_size      = (150 * effective_size_median) / 100;
	const auto max_consensus_block_size =
	    std::min(m_currency.max_block_cumulative_size(*height), 2 * effective_size_median);
	const auto max_txs_size = max_consensus_block_size - m_currency.miner_tx_blob_reserved_size;

	std::vector<Hash> pool_hashes;
	for (auto &&msf : m_memory_state_fee_tx)
		for (auto &&ha : msf.second)
			pool_hashes.push_back(ha);
	size_t txs_size = 0;
	Amount txs_fee  = 0;
	DeltaState memory_state(*height, b->timestamp, this);  // will be get_tip().timestamp_unlock after fork
	// TODO - technically we should give unlock timestamp of next block, but more
	// conservative also works
	Amount base_reward           = 0;
	SignedAmount emission_change = 0;
	m_currency.get_block_reward(
	    b->major_version, effective_size_median, 0, already_generated_coins, 0, &base_reward, &emission_change);

	for (; !pool_hashes.empty(); pool_hashes.pop_back()) {
		auto tit = m_memory_state_tx.find(pool_hashes.back());
		if (tit == m_memory_state_tx.end()) {
			m_log(logging::ERROR) << "Transaction " << pool_hashes.back() << " is in pool index, but not in pool";
			assert(false);
			continue;
		}
		const size_t tx_size = tit->second.binary_tx.size();
		const Amount tx_fee  = tit->second.fee;
		if (txs_size + tx_size > max_txs_size)
			continue;
		BlockGlobalIndices global_indices;
		Height conflict_height = 0;
		const std::string result =
		    redo_transaction_get_error(false, tit->second.tx, &memory_state, &global_indices, &conflict_height, true);
		if (!result.empty()) {
			m_log(logging::ERROR) << "Transaction " << tit->first
			                      << " is in pool, but could not be redone result=" << result
			                      << " Conflict height=" << conflict_height << std::endl;
			continue;
		}
		if (txs_size + tx_size > effective_size_median) {
			Amount reward;
			m_currency.get_block_reward(b->major_version, effective_size_median, txs_size + tx_size,
			    already_generated_coins, txs_fee + tx_fee, &reward, &emission_change);
			if (reward < base_reward)
				continue;
		}
		txs_size += tx_size;
		txs_fee += tx_fee;
		b->transaction_hashes.emplace_back(tit->first);
		m_mining_transactions.erase(tit->first);  // We want ot update height to most recent
		m_mining_transactions.insert(std::make_pair(tit->first, std::make_pair(tit->second.binary_tx, *height)));
		m_log(logging::TRACE) << "Transaction " << tit->first << " included to block template";
	}

	// two-phase miner transaction generation: we don't know exact block size
	// until we prepare block, but we don't know
	// reward until we know
	// block size, so first miner transaction generated with fake amount of money,
	// and with phase we know think we know
	// expected block size
	// make blocks coin-base tx looks close to real coinbase tx to get truthful
	// blob size

	//	bool r = m_currency.construct_miner_tx(b->major_version, *height, effective_size_median,
	// already_generated_coins,
	//	    txs_size, txs_fee, m_config.mineproof_secret, adr, &b->base_transaction, extra_nonce, 11);
	//	if (!r) {
	//		m_log(logging::ERROR) << logging::BrightRed << "Failed to construct miner tx, first chance";
	//		return false;
	//	}

	size_t cumulative_size   = txs_size;
	const size_t TRIES_COUNT = 11;
	for (size_t try_count = 0; try_count < TRIES_COUNT; ++try_count) {
		m_currency.construct_miner_tx(b->major_version, *height, effective_size_median, already_generated_coins,
		    cumulative_size, txs_fee, m_config.mineproof_secret, adr, &b->base_transaction, extra_nonce);
		size_t coinbase_blob_size = seria::binary_size(b->base_transaction);
		if (coinbase_blob_size + txs_size > cumulative_size) {
			cumulative_size = txs_size + coinbase_blob_size;
			continue;
		}
		if (coinbase_blob_size + txs_size < cumulative_size) {
			size_t delta = cumulative_size - (coinbase_blob_size + txs_size);
			common::append(b->base_transaction.extra, delta, 0);
			// here could be 1 byte difference, because of extra field counter is
			// varint, and it can become from
			// 1-byte len to 2-bytes len.
			if (cumulative_size != txs_size + seria::binary_size(b->base_transaction)) {
				invariant(cumulative_size + 1 == txs_size + seria::binary_size(b->base_transaction), "miner_tx case 1");
				b->base_transaction.extra.resize(b->base_transaction.extra.size() - 1);
				if (cumulative_size != txs_size + seria::binary_size(b->base_transaction)) {
					// ooh, not lucky, -1 makes varint-counter size smaller, in that case
					// we continue to grow with cumulative_size
					m_log(logging::TRACE)
					    << logging::BrightRed << "Miner tx creation have no luck with delta_extra size = " << delta
					    << " and " << delta - 1;
					cumulative_size += delta - 1;
					continue;
				}
				m_log(logging::TRACE) << logging::BrightGreen
				                      << "Setting extra for block: " << b->base_transaction.extra.size()
				                      << ", try_count=" << try_count;
			}
		}
		invariant(cumulative_size == txs_size + seria::binary_size(b->base_transaction), "miner_tx case 2");
		return;
	}
	throw std::runtime_error("Failed to create_block_template with " + common::to_string(TRIES_COUNT) + " attempts");
}

uint32_t BlockChainState::get_next_effective_median_size() const {
	uint8_t should_be_major = 0, might_be_minor = 0;
	fill_next_block_versions(get_tip(), false, &should_be_major, &might_be_minor);
	auto next_minimum_size_median = m_currency.get_minimum_size_median(should_be_major);
	return std::max(m_next_median_size, next_minimum_size_median);
}

BroadcastAction BlockChainState::add_mined_block(
    const BinaryArray &raw_block_template, RawBlock *raw_block, api::BlockHeader *info) {
	BlockTemplate block_template;
	seria::from_binary(block_template, raw_block_template);
	raw_block->block = std::move(raw_block_template);

	raw_block->transactions.reserve(block_template.transaction_hashes.size());
	raw_block->transactions.clear();
	for (const auto &tx_hash : block_template.transaction_hashes) {
		auto tit                     = m_memory_state_tx.find(tx_hash);
		const BinaryArray *binary_tx = nullptr;
		if (tit != m_memory_state_tx.end())
			binary_tx = &(tit->second.binary_tx);
		else {
			auto tit2 = m_mining_transactions.find(tx_hash);
			if (tit2 == m_mining_transactions.end()) {
				m_log(logging::WARNING) << "The transaction " << tx_hash
				                        << " is absent in transaction pool on submit mined block";
				return BroadcastAction::NOTHING;
			}
			binary_tx = &(tit2->second.first);
		}
		raw_block->transactions.emplace_back(*binary_tx);
	}
	PreparedBlock pb(std::move(*raw_block), m_currency, nullptr);
	*raw_block = pb.raw_block;
	return add_block(pb, info, "json_rpc");
}

void BlockChainState::clear_mining_transactions() const {
	for (auto tit = m_mining_transactions.begin(); tit != m_mining_transactions.end();)
		if (get_tip_height() > tit->second.second + 10)  // Remember used txs for some number of blocks
			tit = m_mining_transactions.erase(tit);
		else
			++tit;
}

Amount BlockChainState::minimum_pool_fee_per_byte(Hash *minimal_tid) const {
	if (m_memory_state_fee_tx.empty()) {
		*minimal_tid = Hash();
		return 0;
	}
	auto be = m_memory_state_fee_tx.begin();
	invariant(!be->second.empty(), "Invariant dead, memory_state_fee_tx empty set");
	*minimal_tid = *(be->second.begin());
	return be->first;
}

void BlockChainState::on_reorganization(
    const std::map<Hash, std::pair<Transaction, BinaryArray>> &undone_transactions, bool undone_blocks) {
	// TODO - remove/add only those transactions that could have their referenced output keys changed
	Height conflict_height = 0;
	if (undone_blocks) {
		PoolTransMap old_memory_state_tx;
		std::swap(old_memory_state_tx, m_memory_state_tx);
		m_memory_state_ki_tx.clear();
		m_memory_state_fee_tx.clear();
		m_memory_state_total_size = 0;
		for (auto &&msf : old_memory_state_tx) {
			add_transaction(msf.first, msf.second.tx, msf.second.binary_tx, get_tip_height() + 1, get_tip().timestamp,
			    &conflict_height, true, std::string());
		}
	}
	for (auto ud : undone_transactions) {
		add_transaction(ud.first, ud.second.first, ud.second.second, get_tip_height() + 1, get_tip().timestamp,
		    &conflict_height, true, std::string());
	}
	m_tx_pool_version = 2;  // add_transaction will erroneously increase
}

AddTransactionResult BlockChainState::add_transaction(const Hash &tid, const Transaction &tx,
    const BinaryArray &binary_tx, Timestamp now, Height *conflict_height, const std::string &source_address) {
	//	Timestamp g_timestamp = read_first_seen_timestamp(tid);
	//	if (g_timestamp != 0 && now > g_timestamp + m_config.mempool_tx_live_time)
	//		return AddTransactionResult::TOO_OLD;
	return add_transaction(
	    tid, tx, binary_tx, get_tip_height() + 1, get_tip().timestamp, conflict_height, true, source_address);
}

AddTransactionResult BlockChainState::add_transaction(const Hash &tid, const Transaction &tx,
    const BinaryArray &binary_tx, Height unlock_height, Timestamp unlock_timestamp, Height *conflict_height,
    bool check_sigs, const std::string &source_address) {
	if (m_memory_state_tx.count(tid) != 0) {
		m_archive.add(Archive::TRANSACTION, binary_tx, tid, source_address);
		return AddTransactionResult::ALREADY_IN_POOL;
	}
	//	std::cout << "add_transaction " << tid << std::endl;
	const size_t my_size         = binary_tx.size();
	const Amount my_fee          = bytecoin::get_tx_fee(tx);
	const Amount my_fee_per_byte = my_fee / my_size;
	Hash minimal_tid;
	Amount minimal_fee = minimum_pool_fee_per_byte(&minimal_tid);
	// Invariant is if 1 byte of cheapest transaction fits, then all transaction fits
	if (m_memory_state_total_size >= MAX_POOL_SIZE && my_fee_per_byte < minimal_fee)
		return AddTransactionResult::INCREASE_FEE;
	// Deterministic behaviour here and below so tx pools have tendency to stay the same
	if (m_memory_state_total_size >= MAX_POOL_SIZE && my_fee_per_byte == minimal_fee && tid < minimal_tid)
		return AddTransactionResult::INCREASE_FEE;
	for (const auto &input : tx.inputs) {
		if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			auto tit           = m_memory_state_ki_tx.find(in.key_image);
			if (tit == m_memory_state_ki_tx.end())
				continue;
			const PoolTransaction &other_tx = m_memory_state_tx.at(tit->second);
			const Amount other_fee_per_byte = other_tx.fee_per_byte();
			if (my_fee_per_byte < other_fee_per_byte)
				return AddTransactionResult::INCREASE_FEE;
			if (my_fee_per_byte == other_fee_per_byte && tid < tit->second)
				return AddTransactionResult::INCREASE_FEE;
			break;  // Can displace another transaction from the pool, Will have to make heavy-lifting for this tx
		}
	}
	for (const auto &input : tx.inputs) {
		if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			if (read_keyimage(in.key_image, conflict_height)) {
				//				std::cout << tid << " " << in.key_image <<
				// std::endl;
				//				m_log(logging::WARNING) << "OUTPUT_ALREADY_SPENT in transaction " << tid
				//		                      << std::endl; // TODO - remove
				return AddTransactionResult::OUTPUT_ALREADY_SPENT;  // Already spent in main chain
			}
		}
	}
	Amount my_fee3                    = 0;
	const std::string validate_result = validate_semantic(false, tx, &my_fee3, m_config.paranoid_checks || check_sigs);
	if (!validate_result.empty()) {
		m_log(logging::WARNING) << "add_transaction validation failed " << validate_result << " in transaction " << tid
		                        << std::endl;
		return AddTransactionResult::BAN;
	}
	DeltaState memory_state(unlock_height, unlock_timestamp, this);
	BlockGlobalIndices global_indices;
	const std::string redo_result =
	    redo_transaction_get_error(false, tx, &memory_state, &global_indices, conflict_height, check_sigs);
	if (!redo_result.empty()) {
		//		std::cout << "Addding anyway for test " << std::endl;
		m_log(logging::TRACE) << "add_transaction redo failed " << redo_result << " in transaction " << tid
		                      << std::endl;
		return AddTransactionResult::FAILED_TO_REDO;  // Not a ban because reorg can change indices
	}
	if (my_fee != my_fee3)
		m_log(logging::ERROR) << "Inconsistent fees " << my_fee << ", " << my_fee3 << " in transaction " << tid
		                      << std::endl;
	// Only good transactions are recorded in tx_first_seen, because they require
	// space there
	//	update_first_seen_timestamp(tid, unlock_timestamp);
	for (auto &&ki : memory_state.get_keyimages()) {
		auto tit = m_memory_state_ki_tx.find(ki.first);
		if (tit == m_memory_state_ki_tx.end())
			continue;
		const PoolTransaction &other_tx = m_memory_state_tx.at(tit->second);
		const Amount other_fee_per_byte = other_tx.fee_per_byte();
		if (my_fee_per_byte < other_fee_per_byte)
			return AddTransactionResult::INCREASE_FEE;  // Never because checked above
		if (my_fee_per_byte == other_fee_per_byte && tid < tit->second)
			return AddTransactionResult::INCREASE_FEE;  // Never because checked above
		remove_from_pool(tit->second);
	}
	bool all_inserted = true;
	for (auto &&ki : memory_state.get_keyimages()) {
		if (!m_memory_state_ki_tx.insert(std::make_pair(ki.first, tid)).second)
			all_inserted = false;
	}
	if (!m_memory_state_tx.insert(std::make_pair(tid, PoolTransaction(tx, binary_tx, my_fee, 0)))
	         .second)  // TODO set timestamp
		all_inserted = false;
	if (!m_memory_state_fee_tx[my_fee_per_byte].insert(tid).second)
		all_inserted = false;
	// insert all before throw
	invariant(all_inserted, "memory_state_fee_tx empty");
	m_memory_state_total_size += my_size;
	while (m_memory_state_total_size > MAX_POOL_SIZE) {
		invariant(!m_memory_state_fee_tx.empty(), "memory_state_fee_tx empty");
		auto &be = m_memory_state_fee_tx.begin()->second;
		invariant(!be.empty(), "memory_state_fee_tx empty set");
		Hash rhash                        = *(be.begin());
		const PoolTransaction &minimal_tx = m_memory_state_tx.at(rhash);
		if (m_memory_state_total_size < MAX_POOL_SIZE + minimal_tx.binary_tx.size())
			break;  // Removing would diminish pool below max size
		remove_from_pool(rhash);
	}
	auto min_size = m_memory_state_fee_tx.empty() || m_memory_state_fee_tx.begin()->second.empty()
	                    ? 0
	                    : m_memory_state_tx.at(*(m_memory_state_fee_tx.begin()->second.begin())).binary_tx.size();
	auto min_fee_per_byte = m_memory_state_fee_tx.empty() || m_memory_state_fee_tx.begin()->second.empty()
	                            ? 0
	                            : m_memory_state_fee_tx.begin()->first;
	//	if( m_memory_state_total_size-min_size >= MAX_POOL_SIZE)
	//		std::cout << "Aha" << std::endl;
	m_log(logging::INFO) << "Added transaction with hash=" << tid << " size=" << my_size << " fee=" << my_fee
	                     << " fee/byte=" << my_fee_per_byte << " current_pool_size=("
	                     << m_memory_state_total_size - min_size << "+" << min_size << ")=" << m_memory_state_total_size
	                     << " count=" << m_memory_state_tx.size() << " min fee/byte=" << min_fee_per_byte << std::endl;
	m_archive.add(Archive::TRANSACTION, binary_tx, tid, source_address);
	//	for(auto && bb : m_memory_state_fee_tx)
	//		for(auto ff : bb.second){
	//			const PoolTransaction &other_tx = m_memory_state_tx.at(ff);
	//			std::cout << "\t" << other_tx.fee_per_byte() << "\t" << other_tx.binary_tx.size() << "\t" <<
	// common::pod_to_hex(ff) << std::endl;
	//		}
	m_tx_pool_version += 1;
	return AddTransactionResult::BROADCAST_ALL;
}

bool BlockChainState::get_largest_referenced_height(const TransactionPrefix &transaction, Height *block_height) const {
	std::map<Amount, uint32_t> largest_indices;  // Do not check same used amount twice
	size_t input_index = 0;
	for (const auto &input : transaction.inputs) {
		if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			if (in.output_indexes.empty())
				return false;  // semantics invalid
			uint32_t largest_index = in.output_indexes[0];
			for (size_t i = 1; i < in.output_indexes.size(); ++i) {
				largest_index = largest_index + in.output_indexes[i];
			}
			auto &lit = largest_indices[in.amount];
			if (largest_index > lit)
				lit = largest_index;
		}
		input_index++;
	}
	Height max_height = 0;
	for (auto lit : largest_indices) {
		UnlockTimePublickKeyHeightSpent unp;
		if (!read_amount_output(lit.first, lit.second, &unp))
			return false;
		max_height = std::max(max_height, unp.height);
	}
	*block_height = max_height;
	return true;
}

void BlockChainState::remove_from_pool(Hash tid) {
	auto tit = m_memory_state_tx.find(tid);
	if (tit == m_memory_state_tx.end())
		return;
	bool all_erased       = true;
	const Transaction &tx = tit->second.tx;
	for (const auto &input : tx.inputs) {
		if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);
			if (m_memory_state_ki_tx.erase(in.key_image) != 1)
				all_erased = false;
		}
	}
	const size_t my_size         = tit->second.binary_tx.size();
	const Amount my_fee_per_byte = tit->second.fee_per_byte();
	if (m_memory_state_fee_tx[my_fee_per_byte].erase(tid) != 1)
		all_erased = false;
	if (m_memory_state_fee_tx[my_fee_per_byte].empty())
		m_memory_state_fee_tx.erase(my_fee_per_byte);
	m_memory_state_total_size -= my_size;
	m_memory_state_tx.erase(tit);
	invariant(all_erased, "remove_memory_pool failed to erase everything");
	// We do not increment m_tx_pool_version, because removing tx from pool is
	// always followed by reset or increment
	auto min_size = m_memory_state_fee_tx.empty() || m_memory_state_fee_tx.begin()->second.empty()
	                    ? 0
	                    : m_memory_state_tx.at(*(m_memory_state_fee_tx.begin()->second.begin())).binary_tx.size();
	auto min_fee_per_byte = m_memory_state_fee_tx.empty() || m_memory_state_fee_tx.begin()->second.empty()
	                            ? 0
	                            : m_memory_state_fee_tx.begin()->first;
	m_log(logging::INFO) << "Removed transaction with hash=" << tid << " size=" << my_size << " current_pool_size=("
	                     << m_memory_state_total_size - min_size << "+" << min_size << ")=" << m_memory_state_total_size
	                     << " count=" << m_memory_state_tx.size() << " min fee/byte=" << min_fee_per_byte << std::endl;
}

// Called only on transactions which passed validate_semantic()
// if double spend, conflict_height is set to actual conflict height
// if wrong sig, conflict_height is set to newest referenced height found up to the point of wrong sig
// if output not found, conflict height is set to currency max_block_height
// if no error, conflict_height is set to newest referenced height, (for coinbase transaction to 0)

std::string BlockChainState::redo_transaction_get_error(bool generating, const Transaction &transaction,
    DeltaState *delta_state, BlockGlobalIndices *global_indices, Height *conflict_height, bool check_sigs) const {
	const bool check_outputs = check_sigs;
	Hash tx_prefix_hash;
	if (m_config.paranoid_checks || check_sigs)
		tx_prefix_hash = get_transaction_prefix_hash(transaction);
	DeltaState tx_delta(delta_state->get_block_height(), delta_state->get_unlock_timestamp(), delta_state);
	global_indices->resize(global_indices->size() + 1);
	auto &my_indices = global_indices->back();
	my_indices.reserve(transaction.outputs.size());

	*conflict_height   = 0;
	size_t input_index = 0;
	for (const auto &input : transaction.inputs) {
		if (input.type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(input);

			if (m_config.paranoid_checks || check_sigs || check_outputs) {
				Height height = 0;
				if (tx_delta.read_keyimage(in.key_image, &height)) {
					*conflict_height = height;
					return "INPUT_KEYIMAGE_ALREADY_SPENT";
				}
				if (in.output_indexes.empty())
					return "INPUT_UNKNOWN_TYPE";  // Never - checked in validate_semantic
				std::vector<uint32_t> global_indexes(in.output_indexes.size());
				global_indexes[0] = in.output_indexes[0];
				for (size_t i = 1; i < in.output_indexes.size(); ++i) {
					global_indexes[i] = global_indexes[i - 1] + in.output_indexes[i];
				}
				std::vector<PublicKey> output_keys(global_indexes.size());
				for (size_t i = 0; i != global_indexes.size(); ++i) {
					UnlockTimePublickKeyHeightSpent unp;
					if (!tx_delta.read_amount_output(in.amount, global_indexes[i], &unp)) {
						*conflict_height = m_currency.max_block_height;
						return "INPUT_INVALID_GLOBAL_INDEX";
					}
					*conflict_height = std::max(*conflict_height, unp.height);
					if (!m_currency.is_transaction_spend_time_unlocked(unp.unlock_block_or_timestamp,
					        delta_state->get_block_height(), delta_state->get_unlock_timestamp()))
						return "INPUT_SPEND_LOCKED_OUT";
					output_keys[i] = unp.public_key;
				}
				std::vector<const PublicKey *> output_key_pointers;
				output_key_pointers.reserve(output_keys.size());
				std::for_each(output_keys.begin(), output_keys.end(),
				    [&output_key_pointers](const PublicKey &key) { output_key_pointers.push_back(&key); });
				bool key_corrupted = false;
				if ((m_config.paranoid_checks || check_sigs) &&
				    !check_ring_signature(tx_prefix_hash, in.key_image, output_key_pointers.data(),
				        output_key_pointers.size(), transaction.signatures[input_index].data(),
				        delta_state->get_block_height() >= m_currency.key_image_subgroup_checking_height,
				        &key_corrupted)) {
					if (key_corrupted)  // TODO - db corrupted
						return "INPUT_CORRUPTED_SIGNATURES";
					return "INPUT_INVALID_SIGNATURES";
				}
			}
			if (in.output_indexes.size() == 1)
				tx_delta.spend_output(in.amount, in.output_indexes[0]);
			tx_delta.store_keyimage(in.key_image, delta_state->get_block_height());
		}
		input_index++;
	}
	for (const auto &output : transaction.outputs) {
		if (output.target.type() == typeid(KeyOutput)) {
			const KeyOutput &key_output = boost::get<KeyOutput>(output.target);
			auto global_index = tx_delta.push_amount_output(output.amount, transaction.unlock_block_or_timestamp, 0,
			    key_output.public_key);  // DeltaState ignores unlock point
			my_indices.push_back(global_index);
		}
	}
	tx_delta.apply(delta_state);
	// delta_state might be memory pool, we protect it from half-modification
	return std::string();
}

void BlockChainState::undo_transaction(IBlockChainState *delta_state, Height, const Transaction &tx) {
	for (auto oit = tx.outputs.rbegin(); oit != tx.outputs.rend(); ++oit) {
		if (oit->target.type() == typeid(KeyOutput)) {
			delta_state->pop_amount_output(
			    oit->amount, tx.unlock_block_or_timestamp, boost::get<KeyOutput>(oit->target).public_key);
		}
	}
	for (auto iit = tx.inputs.rbegin(); iit != tx.inputs.rend(); ++iit) {
		if (iit->type() == typeid(KeyInput)) {
			const KeyInput &in = boost::get<KeyInput>(*iit);
			delta_state->delete_keyimage(in.key_image);
			if (in.output_indexes.size() == 1)
				spend_output(in.amount, in.output_indexes[0], false);
		}
	}
}

bool BlockChainState::redo_block(const Block &block,
    const api::BlockHeader &info,
    DeltaState *delta_state,
    BlockGlobalIndices *global_indices) const {
	Height conflict_height;
	std::string result = redo_transaction_get_error(
	    true, block.header.base_transaction, delta_state, global_indices, &conflict_height, false);
	if (!result.empty())
		return false;
	for (auto tit = block.transactions.begin(); tit != block.transactions.end(); ++tit) {
		std::string result =
		    redo_transaction_get_error(false, *tit, delta_state, global_indices, &conflict_height, false);
		if (!result.empty())
			return false;
	}
	return true;
}

bool BlockChainState::redo_block(const Hash &bhash, const Block &block, const api::BlockHeader &info) {
	DeltaState delta(info.height, info.timestamp, this);
	BlockGlobalIndices global_indices;
	global_indices.reserve(block.transactions.size() + 1);
	const bool check_sigs = m_config.paranoid_checks || !m_currency.is_in_sw_checkpoint_zone(info.height + 1);
	if (check_sigs &&
	    !ring_checker
	         .start_work_get_error(this, m_currency, block, info.height, info.timestamp,
	             info.height >= m_currency.key_image_subgroup_checking_height)
	         .empty())
		return false;
	if (!redo_block(block, info, &delta, &global_indices))
		return false;
	if (check_sigs && !ring_checker.signatures_valid())
		return false;
	delta.apply(this);  // Will remove from pool by key_image
	m_tx_pool_version = 2;

	auto key =
	    BLOCK_GLOBAL_INDICES_PREFIX + DB::to_binary_key(bhash.data, sizeof(bhash.data)) + BLOCK_GLOBAL_INDICES_SUFFIX;
	BinaryArray ba = seria::to_binary(global_indices);
	m_db.put(key, ba, true);

	//	for (auto th : block.header.transaction_hashes) {
	//		update_first_seen_timestamp(th, 0);
	//	}
	auto now = std::chrono::steady_clock::now();
	if (m_config.net != "main" ||
	    std::chrono::duration_cast<std::chrono::milliseconds>(now - log_redo_block_timestamp).count() > 1000) {
		log_redo_block_timestamp = now;
		m_log(logging::INFO) << "redo_block height=" << info.height << " bid=" << bhash
		                     << " #tx=" << block.transactions.size() << std::endl;
	} else {
		if (m_config.paranoid_checks || check_sigs)  // No point in writing log before checkpoints
			m_log(logging::TRACE) << "redo_block height=" << info.height << " bid=" << bhash
			                      << " #tx=" << block.transactions.size() << std::endl;
	}
	return true;
}

void BlockChainState::undo_block(const Hash &bhash, const Block &block, Height height) {
	//	if (height % 100 == 0)
	//		std::cout << "undo_block height=" << height << " bid=" << bhash
	//		          << " new tip_bid=" << block.header.previous_block_hash << std::endl;
	m_log(logging::INFO) << "undo_block height=" << height << " bid=" << bhash
	                     << " new tip_bid=" << block.header.previous_block_hash << std::endl;
	for (auto tit = block.transactions.rbegin(); tit != block.transactions.rend(); ++tit) {
		undo_transaction(this, height, *tit);
	}
	undo_transaction(this, height, block.header.base_transaction);

	auto key =
	    BLOCK_GLOBAL_INDICES_PREFIX + DB::to_binary_key(bhash.data, sizeof(bhash.data)) + BLOCK_GLOBAL_INDICES_SUFFIX;
	m_db.del(key, true);
}

bool BlockChainState::read_block_output_global_indices(const Hash &bid, BlockGlobalIndices *indices) const {
	BinaryArray rb;
	auto key =
	    BLOCK_GLOBAL_INDICES_PREFIX + DB::to_binary_key(bid.data, sizeof(bid.data)) + BLOCK_GLOBAL_INDICES_SUFFIX;
	if (!m_db.get(key, rb))
		return false;
	seria::from_binary(*indices, rb);
	return true;
}

std::vector<api::Output> BlockChainState::get_random_outputs(
    Amount amount, size_t output_count, Height confirmed_height, Timestamp time) const {
	std::vector<api::Output> result;
	uint32_t total_count = next_global_index_for_amount(amount);
	// We might need better algorithm if we have lots of locked amounts
	if (total_count <= output_count) {
		for (uint32_t i = 0; i != total_count; ++i) {
			api::Output item;
			UnlockTimePublickKeyHeightSpent unp;
			item.amount = amount;
			item.index  = i;
			invariant(read_amount_output(amount, i, &unp), "global amount < total_count not found");
			item.unlock_block_or_timestamp = unp.unlock_block_or_timestamp;
			item.public_key                = unp.public_key;
			item.height                    = unp.height;
			if (unp.spent || unp.height > confirmed_height)
				continue;
			if (!m_currency.is_transaction_spend_time_unlocked(item.unlock_block_or_timestamp, confirmed_height, time))
				continue;
			result.push_back(item);
		}
		return result;
	}
	std::set<uint32_t> tried_or_added;
	crypto::random_engine<uint64_t> generator;
	std::lognormal_distribution<double> distribution(1.9, 1.0);  // Magic params here
	const uint32_t linear_part = 150;                            // Magic params here
	size_t attempts            = 0;
	for (; result.size() < output_count && attempts < output_count * 20; ++attempts) {  // TODO - 20
		uint32_t num = 0;
		if (result.size() % 2 == 0) {  // Half of outputs linear
			if (total_count <= linear_part)
				num = crypto::rand<uint32_t>() % total_count;  // 0 handled above
			else
				num = total_count - 1 - crypto::rand<uint32_t>() % linear_part;
		} else {
			double sample = distribution(generator);
			int d_num     = static_cast<int>(std::floor(total_count * (1 - std::pow(10, -sample / 10))));
			if (d_num < 0 || d_num >= int(total_count))
				continue;
			num = static_cast<uint32_t>(d_num);
		}
		if (!tried_or_added.insert(num).second)
			continue;
		api::Output item;
		UnlockTimePublickKeyHeightSpent unp;
		item.amount = amount;
		item.index  = num;
		invariant(read_amount_output(amount, num, &unp), "num < total_count not found");
		item.unlock_block_or_timestamp = unp.unlock_block_or_timestamp;
		item.public_key                = unp.public_key;
		item.height                    = unp.height;
		if (unp.height > confirmed_height) {
			if (confirmed_height + 128 < get_tip_height())
				total_count = num;
			// heuristic - if confirmed_height is deep, the area under ditribution curve
			// with height < confirmed_height might be very small, so we adjust total_count
			// to get descent results after small number of attempts
			continue;
		}
		if (unp.spent)
			continue;
		if (!m_currency.is_transaction_spend_time_unlocked(item.unlock_block_or_timestamp, confirmed_height, time))
			continue;
		result.push_back(item);
	}
	return result;
}

void BlockChainState::store_keyimage(const KeyImage &key_image, Height height) {
	auto key = KEYIMAGE_PREFIX + DB::to_binary_key(key_image.data, sizeof(key_image.data));
	m_db.put(key, seria::to_binary(height), true);
	auto tit = m_memory_state_ki_tx.find(key_image);
	if (tit == m_memory_state_ki_tx.end())
		return;
	remove_from_pool(tit->second);
}

void BlockChainState::delete_keyimage(const KeyImage &key_image) {
	auto key = KEYIMAGE_PREFIX + DB::to_binary_key(key_image.data, sizeof(key_image.data));
	m_db.del(key, true);
}

bool BlockChainState::read_keyimage(const KeyImage &key_image, Height *height) const {
	auto key = KEYIMAGE_PREFIX + DB::to_binary_key(key_image.data, sizeof(key_image.data));
	BinaryArray rb;
	if (!m_db.get(key, rb))
		return false;
	seria::from_binary(*height, rb);
	return true;
}

uint32_t BlockChainState::push_amount_output(
    Amount amount, BlockOrTimestamp unlock_time, Height block_height, const PublicKey &pk) {
	uint32_t my_gi = next_global_index_for_amount(amount);
	auto key       = AMOUNT_OUTPUT_PREFIX + common::write_varint_sqlite4(amount) + common::write_varint_sqlite4(my_gi);
	BinaryArray ba = seria::to_binary(UnlockTimePublickKeyHeightSpent{unlock_time, pk, block_height});
	m_db.put(key, ba, true);
	m_next_gi_for_amount[amount] += 1;
	return my_gi;
}

void BlockChainState::pop_amount_output(Amount amount, BlockOrTimestamp unlock_time, const PublicKey &pk) {
	uint32_t next_gi = next_global_index_for_amount(amount);
	invariant(next_gi != 0, "BlockChainState::pop_amount_output underflow");
	next_gi -= 1;
	m_next_gi_for_amount[amount] -= 1;
	auto key = AMOUNT_OUTPUT_PREFIX + common::write_varint_sqlite4(amount) + common::write_varint_sqlite4(next_gi);

	UnlockTimePublickKeyHeightSpent unp;
	invariant(read_amount_output(amount, next_gi, &unp), "BlockChainState::pop_amount_output element does not exist");
	// TODO - check also was_height after upgrade to version 4 ?
	invariant(!unp.spent && unp.unlock_block_or_timestamp == unlock_time && unp.public_key == pk,
	    "BlockChainState::pop_amount_output popping wrong element");
	m_db.del(key, true);
}

uint32_t BlockChainState::next_global_index_for_amount(Amount amount) const {
	auto it = m_next_gi_for_amount.find(amount);
	if (it != m_next_gi_for_amount.end())
		return it->second;
	std::string prefix = AMOUNT_OUTPUT_PREFIX + common::write_varint_sqlite4(amount);
	DB::Cursor cur2    = m_db.rbegin(prefix);
	uint32_t alt_in = cur2.end() ? 0 : common::integer_cast<Height>(common::read_varint_sqlite4(cur2.get_suffix())) + 1;
	m_next_gi_for_amount[amount] = alt_in;
	return alt_in;
}

bool BlockChainState::read_amount_output(
    Amount amount, uint32_t global_index, UnlockTimePublickKeyHeightSpent *unp) const {
	auto key = AMOUNT_OUTPUT_PREFIX + common::write_varint_sqlite4(amount) + common::write_varint_sqlite4(global_index);
	BinaryArray rb;
	if (!m_db.get(key, rb))
		return false;
	seria::from_binary(*unp, rb);
	return true;
}

void BlockChainState::spend_output(Amount amount, uint32_t global_index) { spend_output(amount, global_index, true); }
void BlockChainState::spend_output(Amount amount, uint32_t global_index, bool spent) {
	auto key = AMOUNT_OUTPUT_PREFIX + common::write_varint_sqlite4(amount) + common::write_varint_sqlite4(global_index);
	BinaryArray rb;
	if (!m_db.get(key, rb))
		return;
	UnlockTimePublickKeyHeightSpent was;
	seria::from_binary(was, rb);
	was.spent = spent;
	m_db.put(key, seria::to_binary(was), false);
}

void BlockChainState::test_print_outputs() {
	Amount previous_amount     = (Amount)-1;
	uint32_t next_global_index = 0;
	int total_counter          = 0;
	std::map<Amount, uint32_t> coins;
	for (DB::Cursor cur = m_db.begin(AMOUNT_OUTPUT_PREFIX); !cur.end(); cur.next()) {
		const char *be        = cur.get_suffix().data();
		const char *en        = be + cur.get_suffix().size();
		auto amount           = common::read_varint_sqlite4(be, en);
		uint32_t global_index = common::integer_cast<uint32_t>(common::read_varint_sqlite4(be, en));
		if (be != en)
			std::cout << "Excess value bytes for amount=" << amount << " index=" << global_index << std::endl;
		if (amount != previous_amount) {
			if (previous_amount != (Amount)-1) {
				if (!coins.insert(std::make_pair(previous_amount, next_global_index)).second) {
					std::cout << "Duplicate amount for previous_amount=" << previous_amount
					          << " next_global_index=" << next_global_index << std::endl;
				}
			}
			previous_amount   = amount;
			next_global_index = 0;
		}
		if (global_index != next_global_index) {
			std::cout << "Bad output index for amount=" << amount << " index=" << global_index << std::endl;
		}
		next_global_index += 1;
		if (++total_counter % 2000000 == 0)
			std::cout << "Working on amount=" << amount << " index=" << global_index << std::endl;
	}
	total_counter = 0;
	std::cout << "Total coins=" << total_counter << " total stacks=" << coins.size() << std::endl;
	for (auto &&co : coins) {
		auto total_count = next_global_index_for_amount(co.first);
		if (total_count != co.second)
			std::cout << "Wrong next_global_index_for_amount amount=" << co.first << " total_count=" << total_count
			          << " should be " << co.second << std::endl;
		for (uint32_t i = 0; i != total_count; ++i) {
			UnlockTimePublickKeyHeightSpent unp;
			if (!read_amount_output(co.first, i, &unp))
				std::cout << "Failed to read amount=" << co.first << " index=" << i << std::endl;
			if (++total_counter % 1000000 == 0)
				std::cout << "Working on amount=" << co.first << " index=" << i << std::endl;
		}
	}
}
