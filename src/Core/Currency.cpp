// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Currency.hpp"
#include <boost/algorithm/string/erase.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>
#include <cctype>
#include "CryptoNote.hpp"
#include "CryptoNoteConfig.hpp"
#include "CryptoNoteTools.hpp"
#include "Difficulty.hpp"
#include "TransactionBuilder.hpp"
#include "TransactionExtra.hpp"
#include "common/Base58.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "common/string.hpp"
#include "crypto/crypto.hpp"
#include "crypto/int-util.h"
#include "platform/PathTools.hpp"
#include "platform/Time.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace common;
using namespace bytecoin;

const std::vector<Amount> Currency::PRETTY_AMOUNTS = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 30, 40, 50, 60, 70, 80, 90,
    100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000, 20000,
    30000, 40000, 50000, 60000, 70000, 80000, 90000, 100000, 200000, 300000, 400000, 500000, 600000, 700000, 800000,
    900000, 1000000, 2000000, 3000000, 4000000, 5000000, 6000000, 7000000, 8000000, 9000000, 10000000, 20000000,
    30000000, 40000000, 50000000, 60000000, 70000000, 80000000, 90000000, 100000000, 200000000, 300000000, 400000000,
    500000000, 600000000, 700000000, 800000000, 900000000, 1000000000, 2000000000, 3000000000, 4000000000, 5000000000,
    6000000000, 7000000000, 8000000000, 9000000000, 10000000000, 20000000000, 30000000000, 40000000000, 50000000000,
    60000000000, 70000000000, 80000000000, 90000000000, 100000000000, 200000000000, 300000000000, 400000000000,
    500000000000, 600000000000, 700000000000, 800000000000, 900000000000, 1000000000000, 2000000000000, 3000000000000,
    4000000000000, 5000000000000, 6000000000000, 7000000000000, 8000000000000, 9000000000000, 10000000000000,
    20000000000000, 30000000000000, 40000000000000, 50000000000000, 60000000000000, 70000000000000, 80000000000000,
    90000000000000, 100000000000000, 200000000000000, 300000000000000, 400000000000000, 500000000000000,
    600000000000000, 700000000000000, 800000000000000, 900000000000000, 1000000000000000, 2000000000000000,
    3000000000000000, 4000000000000000, 5000000000000000, 6000000000000000, 7000000000000000, 8000000000000000,
    9000000000000000, 10000000000000000, 20000000000000000, 30000000000000000, 40000000000000000, 50000000000000000,
    60000000000000000, 70000000000000000, 80000000000000000, 90000000000000000, 100000000000000000, 200000000000000000,
    300000000000000000, 400000000000000000, 500000000000000000, 600000000000000000, 700000000000000000,
    800000000000000000, 900000000000000000, 1000000000000000000, 2000000000000000000, 3000000000000000000,
    4000000000000000000, 5000000000000000000, 6000000000000000000, 7000000000000000000, 8000000000000000000,
    9000000000000000000, 10000000000000000000ull};

const std::vector<Amount> Currency::DECIMAL_PLACES = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000,
    1000000000, 10000000000, 100000000000, 1000000000000, 10000000000000, 100000000000000, 1000000000000000,
    10000000000000000, 100000000000000000, 1000000000000000000, 10000000000000000000ull};

Currency::Currency(const std::string &net)
    : net(net)
    , max_block_height(parameters::MAX_BLOCK_NUMBER)
    , max_block_blob_size(parameters::MAX_BLOCK_BLOB_SIZE)
    , max_tx_size(parameters::MAX_TX_SIZE)
    , public_address_base58_prefix(parameters::PUBLIC_ADDRESS_BASE58_PREFIX)
    , mined_money_unlock_window(parameters::MINED_MONEY_UNLOCK_WINDOW)
    , timestamp_check_window(parameters::BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW)
    , block_future_time_limit(parameters::BLOCK_FUTURE_TIME_LIMIT)
    , money_supply(parameters::MONEY_SUPPLY)
    , emission_speed_factor(parameters::EMISSION_SPEED_FACTOR)
    , reward_blocks_window(parameters::REWARD_BLOCKS_WINDOW)
    , minimum_size_median(parameters::MINIMUM_SIZE_MEDIAN)
    , miner_tx_blob_reserved_size(parameters::COINBASE_BLOB_RESERVED_SIZE)
    , number_of_decimal_places(parameters::DISPLAY_DECIMAL_POINT)
    , minimum_fee(parameters::MINIMUM_FEE)
    , default_dust_threshold(parameters::DEFAULT_DUST_THRESHOLD)
    , difficulty_target(std::max<Timestamp>(1,
          parameters::DIFFICULTY_TARGET /
              platform::get_time_multiplier_for_tests()))  // multiplier can be != 1 only in testnet
    , minimum_difficulty(net == "test" ? 2 : parameters::MINIMUM_DIFFICULTY)
    , difficulty_window(expected_blocks_per_day())
    , difficulty_lag(parameters::DIFFICULTY_LAG)
    , difficulty_cut(parameters::DIFFICULTY_CUT)
    , max_block_size_initial(net != "main" ? 1024*1024 : parameters::MAX_BLOCK_SIZE_INITIAL)
    , max_block_size_growth_per_year(net != "main" ? 0 : parameters::MAX_BLOCK_SIZE_GROWTH_PER_YEAR)
    , locked_tx_allowed_delta_seconds(parameters::LOCKED_TX_ALLOWED_DELTA_SECONDS(difficulty_target))
    , locked_tx_allowed_delta_blocks(parameters::LOCKED_TX_ALLOWED_DELTA_BLOCKS)
    , upgrade_height_v2(parameters::UPGRADE_HEIGHT_V2)
    , upgrade_height_v3(parameters::UPGRADE_HEIGHT_V3)
    , key_image_subgroup_checking_height(parameters::KEY_IMAGE_SUBGROUP_CHECKING_HEIGHT)
	, upgrade_from_major_version(3)
	, upgrade_indicator_minor_version(3)
	, upgrade_desired_major_version(0)
    , upgrade_voting_window(expected_blocks_per_day())
    , upgrade_votes_required(upgrade_voting_window * 9 / 10)
    , upgrade_blocks_after_voting(expected_blocks_per_day() * 14)
    , current_transaction_version(CURRENT_TRANSACTION_VERSION) {
	if (net != "main") {
		upgrade_height_v2 = 1;
		upgrade_height_v3 = 1;
	}
	// Hard code coinbase tx in genesis block, because through generating tx use
	// random, but genesis should be always
	// the same
	//	std::string genesis_coinbase_tx_hex =
	//	    "010a01ff0001ffffffffffff0f029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f"
	//	    "5142ee494ffbbd08807121013c086a48c15fb637a96991bc6d53caf77068b5ba6eeb3c82357228c49790584a";
	//	BinaryArray miner_tx_blob;
	//	invariant(from_hex(genesis_coinbase_tx_hex, miner_tx_blob), "Currency failed to parse coinbase tx from hard
	// coded blob");
	//	seria::from_binary(genesis_block_template.base_transaction, miner_tx_blob);
	// Demystified genesis block calculations below
	genesis_block_template.major_version = 1;
	genesis_block_template.minor_version = 0;
	genesis_block_template.timestamp     = 0;
	genesis_block_template.nonce         = 70;
	PublicKey genesis_output_key =
	    common::pfh<PublicKey>("9b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd088071");
	PublicKey genesis_tx_public_key =
	    common::pfh<PublicKey>("3c086a48c15fb637a96991bc6d53caf77068b5ba6eeb3c82357228c49790584a");
	genesis_block_template.base_transaction.version                   = 1;
	genesis_block_template.base_transaction.unlock_block_or_timestamp = mined_money_unlock_window;
	genesis_block_template.base_transaction.inputs.push_back(CoinbaseInput{0});
	genesis_block_template.base_transaction.outputs.push_back(
	    TransactionOutput{money_supply >> emission_speed_factor, KeyOutput{genesis_output_key}});
    extra_add_transaction_public_key(genesis_block_template.base_transaction.extra, genesis_tx_public_key);

	if (net == "test")
		genesis_block_template.nonce += 1;
	if (net == "stage")
		genesis_block_template.nonce += 2;
	auto body_proxy    = get_body_proxy_from_template(genesis_block_template);
	genesis_block_hash = get_block_hash(genesis_block_template, body_proxy);
	if (net == "main") {
		checkpoints_begin     = std::begin(CHECKPOINTS);
		checkpoints_end       = std::end(CHECKPOINTS);
		checkpoint_keys_begin = std::begin(CHECKPOINT_PUBLIC_KEYS);
		checkpoint_keys_end   = std::end(CHECKPOINT_PUBLIC_KEYS);
	}
	if (net == "test") {
		checkpoints_begin     = nullptr;
		checkpoints_end       = nullptr;
		checkpoint_keys_begin = std::begin(CHECKPOINT_PUBLIC_KEYS_TESTNET);
		checkpoint_keys_end   = std::end(CHECKPOINT_PUBLIC_KEYS_TESTNET);
	}
	if (net == "stage") {
		checkpoints_begin     = std::begin(CHECKPOINTS_STAGENET);
		checkpoints_end       = std::end(CHECKPOINTS_STAGENET);
		checkpoint_keys_begin = std::begin(CHECKPOINT_PUBLIC_KEYS_STAGENET);
		checkpoint_keys_end   = std::end(CHECKPOINT_PUBLIC_KEYS_STAGENET);
	}
}

uint32_t Currency::expected_blocks_per_day() const {
	return 24 * 60 * 60 / difficulty_target / platform::get_time_multiplier_for_tests();
}
uint32_t Currency::expected_blocks_per_year() const {
	return 365 * 24 * 60 * 60 / difficulty_target / platform::get_time_multiplier_for_tests();
}

bool Currency::is_in_sw_checkpoint_zone(Height height) const { return height <= last_sw_checkpoint().height; }

bool Currency::check_sw_checkpoint(Height height, const Hash &h, bool &is_sw_checkpoint) const {
	if (checkpoints_begin == checkpoints_end) {
		is_sw_checkpoint = (height == 0);
		return height == 0 ? h == genesis_block_hash : true;
	}
	auto it = std::lower_bound(
	    checkpoints_begin, checkpoints_end, height, [](const SWCheckpoint &da, uint32_t ma) { return da.height < ma; });
	is_sw_checkpoint = false;
	if (it == checkpoints_end)
		return true;
	if (it->height != height)
		return true;
	is_sw_checkpoint = true;
	return h == it->hash;
}

SWCheckpoint Currency::last_sw_checkpoint() const {
	if (checkpoints_begin == checkpoints_end)
		return SWCheckpoint{0, genesis_block_hash};
	return *(checkpoints_end - 1);
}

PublicKey Currency::get_checkpoint_public_key(uint32_t key_id) const {
	if (key_id >= checkpoint_keys_end - checkpoint_keys_begin)
		return PublicKey{};
	return checkpoint_keys_begin[key_id];
}

uint8_t Currency::get_block_major_version_for_height(Height height) const {
	if (height < upgrade_height_v2)
		return 1;
	if (height >= upgrade_height_v2 && height < upgrade_height_v3)
		return 2;
	return 3;  // info.height >= currency.upgrade_height_v3
}

Difficulty Currency::get_minimum_difficulty(uint8_t block_major_version) const {
	if (block_major_version == 1)
		return parameters::MINIMUM_DIFFICULTY_V1;
	return minimum_difficulty;
}

uint32_t Currency::get_minimum_size_median(uint8_t block_major_version) const {
	if (block_major_version == 1)
		return parameters::MINIMUM_SIZE_MEDIAN_V1;
	if (block_major_version == 2)
		return parameters::MINIMUM_SIZE_MEDIAN_V2;
	return minimum_size_median;
}

void Currency::get_block_reward(uint8_t block_major_version, size_t effective_median_size, size_t current_block_size,
    Amount already_generated_coins, Amount fee, Amount *reward, SignedAmount *emission_change) const {
	assert(already_generated_coins <= money_supply);
	assert(emission_speed_factor > 0 && emission_speed_factor <= 8 * sizeof(Amount));

	Amount base_reward = (money_supply - already_generated_coins) >> emission_speed_factor;

	Amount penalized_base_reward = get_penalized_amount(base_reward, effective_median_size, current_block_size);
	Amount penalized_fee =
	    block_major_version >= 2 ? get_penalized_amount(fee, effective_median_size, current_block_size) : fee;

	*emission_change = penalized_base_reward - (fee - penalized_fee);
	*reward          = penalized_base_reward + penalized_fee;
}

Height Currency::largest_window() const {
	return std::max(difficulty_blocks_count(), std::max(reward_blocks_window, timestamp_check_window));
}

uint32_t Currency::max_block_cumulative_size(Height height) const {
	if( max_block_size_growth_per_year == 0)
		return max_block_size_initial;
	assert(height <= std::numeric_limits<uint64_t>::max() / max_block_size_growth_per_year);
	uint64_t max_size =
	    max_block_size_initial + (uint64_t(height) * max_block_size_growth_per_year) / expected_blocks_per_year();
	assert(max_size < std::numeric_limits<uint32_t>::max());
	return static_cast<uint32_t>(max_size);
}

uint32_t Currency::max_transaction_allowed_size(uint32_t effective_block_size_median) const {
	assert(effective_block_size_median * 2 > miner_tx_blob_reserved_size);

	return std::min(max_tx_size, effective_block_size_median * 2 - miner_tx_blob_reserved_size);
}

bool Currency::construct_miner_tx(uint8_t block_major_version, Height height, size_t effective_median_size,
    Amount already_generated_coins, size_t current_block_size, Amount fee, Hash mineproof_seed,
    const AccountPublicAddress &miner_address, Transaction *tx, const BinaryArray &extra_nonce, size_t max_outs) const {
	tx->inputs.clear();
	tx->outputs.clear();
	tx->extra.clear();

	tx->inputs.push_back(CoinbaseInput{height});

	KeyPair txkey = mineproof_seed == Hash{} ? crypto::random_keypair()
	                                         : TransactionBuilder::deterministic_keys_from_seed(*tx, mineproof_seed);

	extra_add_transaction_public_key(tx->extra, txkey.public_key);
	if (!extra_nonce.empty())
		extra_add_nonce(tx->extra, extra_nonce);

	Amount block_reward;
	SignedAmount emission_change;
	get_block_reward(block_major_version, effective_median_size, current_block_size, already_generated_coins, fee,
	        &block_reward, &emission_change);

	std::vector<Amount> out_amounts;
	decompose_amount(block_reward, default_dust_threshold, &out_amounts);

	if (max_outs == 0)
		max_outs = 1;  // :)
	while (out_amounts.size() > max_outs) {
		out_amounts[out_amounts.size() - 2] += out_amounts.back();
		out_amounts.pop_back();
	}

	Amount summary_amounts = 0;
	for (size_t no = 0; no < out_amounts.size(); no++) {
		KeyDerivation derivation{};
		PublicKey out_ephemeral_pub_key{};

		if (!crypto::generate_key_derivation(miner_address.view_public_key, txkey.secret_key, derivation)) {
			//      logger(ERROR, BrightRed)
			//        << "while creating outs: failed to generate_key_derivation("
			//        << miner_address.view_public_key << ", " << txkey.secret_key <<
			//        ")";
			return false;
		}

		if (!crypto::derive_public_key(derivation, no, miner_address.spend_public_key, out_ephemeral_pub_key)) {
			//      logger(ERROR, BrightRed)
			//        << "while creating outs: failed to derive_public_key("
			//        << derivation << ", " << no << ", "
			//        << miner_address.spend_public_key << ")";
			return false;
		}

		KeyOutput tk;
		tk.public_key = out_ephemeral_pub_key;

		TransactionOutput out;
		summary_amounts += out.amount = out_amounts[no];
		out.target                    = tk;
		tx->outputs.push_back(out);
	}

	invariant(summary_amounts == block_reward, "");
		//    logger(ERROR, BrightRed) << "Failed to construct miner tx,
		//    summary_amounts = " << summary_amounts << " not
		//    equal block_reward = " << block_reward;

	tx->version = current_transaction_version;
	tx->unlock_block_or_timestamp = height + mined_money_unlock_window;
	return true;
}

uint64_t Currency::get_penalized_amount(uint64_t amount, size_t median_size, size_t current_block_size) {
	static_assert(sizeof(size_t) >= sizeof(uint32_t), "size_t is too small");
	assert(current_block_size <= 2 * median_size);
	assert(median_size <= std::numeric_limits<uint32_t>::max());
	assert(current_block_size <= std::numeric_limits<uint32_t>::max());

	if (amount == 0)
		return 0;
	if (current_block_size <= median_size)
		return amount;

	uint64_t product_hi;
	uint64_t product_lo =
	    mul128(amount, current_block_size * (UINT64_C(2) * median_size - current_block_size), &product_hi);

	uint64_t penalized_amount_hi;
	uint64_t penalized_amount_lo;
	div128_32(product_hi, product_lo, static_cast<uint32_t>(median_size), &penalized_amount_hi, &penalized_amount_lo);
	div128_32(penalized_amount_hi, penalized_amount_lo, static_cast<uint32_t>(median_size), &penalized_amount_hi,
	    &penalized_amount_lo);

	assert(0 == penalized_amount_hi);
	assert(penalized_amount_lo < amount);

	return penalized_amount_lo;
}

std::string Currency::get_account_address_as_str(uint64_t prefix, const AccountPublicAddress &adr) {
	BinaryArray ba = seria::to_binary(adr);
	return common::base58::encode_addr(prefix, ba);
}

bool Currency::parse_account_address_string(uint64_t *prefix, AccountPublicAddress *adr, const std::string &str) {
	BinaryArray data;

	if (!common::base58::decode_addr(str, prefix, &data))
		return false;
	try {
		seria::from_binary(*adr, data);
	} catch (const std::exception &) {
		return false;
	}
	return key_isvalid(adr->spend_public_key) && key_isvalid(adr->view_public_key);
}

std::string Currency::account_address_as_string(const AccountPublicAddress &account_public_address) const {
	return get_account_address_as_str(public_address_base58_prefix, account_public_address);
}

bool Currency::parse_account_address_string(const std::string &str, AccountPublicAddress *addr) const {
	uint64_t prefix;
	if (!parse_account_address_string(&prefix, addr, str)) {
		return false;
	}
	if (prefix != public_address_base58_prefix) {
		//    logger(DEBUGGING) << "Wrong address prefix: " << prefix << ", expected
		//    " << m_publicAddressBase58Prefix;
		return false;
	}
	return true;
}

static std::string ffw(Amount am, size_t digs) {
	std::string result = common::to_string(am);
	if (result.size() < digs)
		result = std::string(digs - result.size(), '0') + result;
	return result;
}

std::string Currency::format_amount(size_t number_of_decimal_places, Amount amount) {
	Amount ia = amount / DECIMAL_PLACES.at(number_of_decimal_places);
	Amount fa = amount - ia * DECIMAL_PLACES.at(number_of_decimal_places);
	std::string result;
	while (ia >= 1000) {
		result = "'" + ffw(ia % 1000, 3) + result;
		ia /= 1000;
	}
	result = std::to_string(ia) + result;
	if (fa != 0) {  // cents
		result += "." + ffw(fa / DECIMAL_PLACES.at(number_of_decimal_places - 2), 2);
		fa %= DECIMAL_PLACES.at(number_of_decimal_places - 2);
	}
	if (fa != 0) {
		result += "'" + ffw(fa / 1000, 3);
		fa %= 1000;
	}
	if (fa != 0)
		result += "'" + ffw(fa, 3);
	return result;
}

std::string Currency::format_amount(size_t number_of_decimal_places, SignedAmount amount) {
	std::string s = Currency::format_amount(number_of_decimal_places, static_cast<Amount>(std::abs(amount)));
	return amount < 0 ? "-" + s : s;
}

bool Currency::parse_amount(size_t number_of_decimal_places, const std::string &str, Amount *amount) {
	std::string str_amount = str;
	boost::algorithm::trim(str_amount);
	boost::algorithm::erase_all(str_amount, "'");

	size_t point_index = str_amount.find_first_of('.');
	size_t fraction_size;
	if (std::string::npos != point_index) {
		fraction_size = str_amount.size() - point_index - 1;
		while (number_of_decimal_places < fraction_size && '0' == str_amount.back()) {
			str_amount.erase(str_amount.size() - 1, 1);
			--fraction_size;
		}
		if (number_of_decimal_places < fraction_size) {
			return false;
		}
		str_amount.erase(point_index, 1);
	} else {
		fraction_size = 0;
	}

	if (str_amount.empty()) {
		return false;
	}

	if (!std::all_of(str_amount.begin(), str_amount.end(), ::isdigit)) {
		return false;
	}

	if (fraction_size < number_of_decimal_places) {
		str_amount.append(number_of_decimal_places - fraction_size, '0');
	}
	std::istringstream stream(str_amount);
	stream >> *amount;
	return !stream.fail();
}

Difficulty Currency::next_difficulty(
    std::vector<Timestamp> *timestamps, std::vector<CumulativeDifficulty> *cumulative_difficulties) const {
	invariant(difficulty_window >= 2, "Bad DIFFICULTY_WINDOW");
	invariant(2 * difficulty_cut <= difficulty_window - 2, "Bad DIFFICULTY_WINDOW or DIFFICULTY_CUT");

	if (timestamps->size() > difficulty_window) {
		timestamps->resize(difficulty_window);
		cumulative_difficulties->resize(difficulty_window);
	}

	size_t length = timestamps->size();
	invariant(length == cumulative_difficulties->size() && length <= difficulty_window, "");
	if (length <= 1)
		return 1;

	std::sort(timestamps->begin(), timestamps->end());

	size_t cut_begin, cut_end;
	if (length <= difficulty_window - 2 * difficulty_cut) {
		cut_begin = 0;
		cut_end   = length;
	} else {
		cut_begin = (length - (difficulty_window - 2 * difficulty_cut) + 1) / 2;
		cut_end   = cut_begin + (difficulty_window - 2 * difficulty_cut);
	}
	invariant(cut_begin + 2 <= cut_end && cut_end <= length, "After difficulty cut at least 2 items should remain");
	Timestamp time_span = timestamps->at(cut_end - 1) - timestamps->at(cut_begin);
	if (time_span == 0) {
		time_span = 1;
	}

	invariant(
	    cumulative_difficulties->at(cut_end - 1) > cumulative_difficulties->at(cut_begin), "Reversed difficulties");
	CumulativeDifficulty total_work = cumulative_difficulties->at(cut_end - 1) - cumulative_difficulties->at(cut_begin);
	invariant(total_work.hi == 0, "Window difficulty difference too large");

	uint64_t low, high;
	low = mul128(total_work.lo, difficulty_target, &high);
	if (high != 0 || std::numeric_limits<uint64_t>::max() - low < (time_span - 1)) {
		return 0;
	}
	return (low + time_span - 1) / time_span;
}

Difficulty Currency::next_effective_difficulty(uint8_t block_major_version, std::vector<Timestamp> timestamps,
    std::vector<CumulativeDifficulty> cumulative_difficulties) const {
	Difficulty difficulty = next_difficulty(&timestamps, &cumulative_difficulties);
	if (difficulty != 0 && difficulty < get_minimum_difficulty(block_major_version))
		difficulty = get_minimum_difficulty(block_major_version);
	return difficulty;
}

BinaryArray Currency::get_block_long_hashing_data(const BlockHeader &bh, const BlockBodyProxy &body_proxy) const {
	common::BinaryArray result;
	common::VectorOutputStream stream(result);
	seria::BinaryOutputStream ba(stream);
	ba.begin_object();
	ser_members(const_cast<BlockHeader &>(bh), ba, BlockSeriaType::LONG_BLOCKHASH, body_proxy);
	ba.end_object();
	//	std::cout << "ba: " << common::to_hex(result.data(), result.size()) << std::endl;
	switch (bh.major_version) {
	case 1:
		return result;
	case 2:
	case 3: {
		TransactionExtraMergeMiningTag mm_tag;
		if (!extra_get_merge_mining_tag(bh.parent_block.base_transaction.extra, mm_tag)) {
			//    logger(ERROR) << "merge mining tag wasn't found in extra of the parent
			//    block miner transaction";
			return BinaryArray{};
		}
		if (mm_tag.depth != bh.parent_block.blockchain_branch.size())
			return BinaryArray{};
		if (bh.parent_block.blockchain_branch.size() > 8 * sizeof(genesis_block_hash))
			return BinaryArray{};
		Hash aux_blocks_merkle_root = crypto::tree_hash_from_branch(bh.parent_block.blockchain_branch.data(),
		    bh.parent_block.blockchain_branch.size(), get_auxiliary_block_header_hash(bh, body_proxy),
		    &genesis_block_hash);

		if (aux_blocks_merkle_root != mm_tag.merkle_root) {
			//    logger(ERROR, BRIGHT_YELLOW) << "Aux block hash wasn't found in merkle
			//    tree";
			return BinaryArray{};
		}
		return result;
	}
#if bytecoin_ALLOW_CM
	case 104: {
		Hash merkle_root_hash = crypto::tree_hash_from_branch(bh.cm_merkle_branch.data(),
		    bh.cm_merkle_branch.size(),
		    get_auxiliary_block_header_hash(bh, body_proxy),
		    genesis_block_hash.data);
		BinaryArray long_hashing_array(sizeof(Hash) + 8);
		memcpy(long_hashing_array.data(), merkle_root_hash.data, sizeof(Hash));
		common::uint_le_to_bytes(long_hashing_array.data() + sizeof(Hash), 8, bh.nonce);
		return long_hashing_array;
	}
#endif
	}
	throw std::runtime_error("Unknown block major version.");
}

bool Currency::is_dust(Amount amount) {
	auto pretty_it = std::lower_bound(std::begin(PRETTY_AMOUNTS), std::end(PRETTY_AMOUNTS), amount);
	return pretty_it == std::end(Currency::PRETTY_AMOUNTS) || *pretty_it != amount ||
	       amount < 1000000;  // After fork, dust definition will change
}

Hash bytecoin::get_transaction_inputs_hash(const TransactionPrefix &tx) {
	BinaryArray ba = seria::to_binary(tx.inputs);
	return crypto::cn_fast_hash(ba.data(), ba.size());
}

Hash bytecoin::get_transaction_prefix_hash(const TransactionPrefix &tx) {
	BinaryArray ba = seria::to_binary(tx);
	return crypto::cn_fast_hash(ba.data(), ba.size());
}

Hash bytecoin::get_transaction_hash(const Transaction &tx) {
	BinaryArray ba = seria::to_binary(tx);
	return crypto::cn_fast_hash(ba.data(), ba.size());
}

Hash bytecoin::get_block_hash(const BlockHeader &bh, const BlockBodyProxy &body_proxy) {
//	common::BinaryArray result;
//	common::VectorOutputStream stream(result);
//	seria::BinaryOutputStream ba(stream);
//	ba.begin_object();
//	ser_members(const_cast<BlockHeader &>(bh), ba, BlockSeriaType::BLOCKHASH, body_proxy);
//	ba.end_object();
	Hash ha2 = get_object_hash(seria::to_binary(bh, BlockSeriaType::BLOCKHASH, body_proxy));
	//	std::cout << "ha: " << ha2 << " ba: " << common::to_hex(result.data(), result.size()) << std::endl;
	return ha2;
}

Hash bytecoin::get_auxiliary_block_header_hash(const BlockHeader &bh, const BlockBodyProxy &body_proxy) {
//	common::BinaryArray result;
//	common::VectorOutputStream stream(result);
//	seria::BinaryOutputStream ba(stream);
//	ba.begin_object();
//	ser(const_cast<BlockHeader &>(bh), ba, BlockSeriaType::PREHASH, body_proxy);
//	ba.end_object();
	Hash ha2 = get_object_hash(seria::to_binary(bh, BlockSeriaType::PREHASH, body_proxy));
	//	std::cout << "ha: " << ha2 << " ba: " << common::to_hex(result.data(), result.size()) << std::endl;
	return ha2;
}
