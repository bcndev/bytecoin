// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Currency.hpp"
#include <boost/algorithm/string/erase.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <cctype>
#include <random>  // for distributions
#include "Config.hpp"
#include "CryptoNote.hpp"
#include "CryptoNoteConfig.hpp"
#include "CryptoNoteTools.hpp"
#include "Difficulty.hpp"
#include "TransactionBuilder.hpp"
#include "TransactionExtra.hpp"
#include "Wallet.hpp"
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
using namespace cn;
using namespace parameters;

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

Currency::Currency(const Config &config)
    : net(config.net)
    , max_block_height(MAX_BLOCK_NUMBER)
    , mined_money_unlock_window(MINED_MONEY_UNLOCK_WINDOW)
    , block_future_time_limit(BLOCK_FUTURE_TIME_LIMIT)
    , money_supply(MONEY_SUPPLY)
    , median_block_size_window(MEIDAN_BLOCK_SIZE_WINDOW)
    , block_capacity_vote_window(BLOCK_CAPACITY_VOTE_WINDOW)
    , max_header_size(MAX_HEADER_SIZE)
    , block_capacity_vote_min(BLOCK_CAPACITY_VOTE_MIN)
    , block_capacity_vote_max(BLOCK_CAPACITY_VOTE_MAX)
    , number_of_decimal_places(DISPLAY_DECIMAL_POINT)
    , min_dust_threshold(MIN_DUST_THRESHOLD)
    , max_dust_threshold(MAX_DUST_THRESHOLD)
    , self_dust_threshold(SELF_DUST_THRESHOLD)
    //, difficulty_target(std::max<Timestamp>(1,
    //      DIFFICULTY_TARGET / platform::get_time_multiplier_for_tests()))  // multiplier can be != 1 only in testnet
    , difficulty_target(DIFFICULTY_TARGET)
    , difficulty_window_lwma(DIFFICULTY_WINDOWS_LWMA)
    , upgrade_heights{UPGRADE_HEIGHT_V2, UPGRADE_HEIGHT_V3, UPGRADE_HEIGHT_V4}
    , key_image_subgroup_checking_height(KEY_IMAGE_SUBGROUP_CHECKING_HEIGHT)
    , amethyst_block_version(BLOCK_VERSION_AMETHYST)
    , amethyst_transaction_version(TRANSACTION_VERSION_AMETHYST)
    , upgrade_vote_minor(9)
    , upgrade_desired_major(4)
    , upgrade_voting_window(UPGRADE_VOTING_WINDOW)
    , upgrade_window(UPGRADE_WINDOW)
    , sendproof_base58_prefix(SENDPROOF_BASE58_PREFIX) {
	// for upgrade_desired_major=4 upgrade_vote_minor=7
	// for upgrade_desired_major=5 upgrade_vote_minor=5
	if (net == "test") {
		upgrade_heights       = {1, 1, 1};  // block 1 is already V4
		upgrade_voting_window = 30;
		upgrade_window        = 10;
	}
	if (net == "stage") {
		upgrade_heights = {1, 1, 64233};
		upgrade_window  = EXPECTED_NUMBER_OF_BLOCKS_PER_DAY;
	}
	{
		BinaryArray miner_tx_blob;
		invariant(from_hex(GENESIS_COINBASE_TX_HEX, &miner_tx_blob),
		    "Currency failed to parse coinbase tx from hard coded blob");
		seria::from_binary(genesis_block_template.base_transaction, miner_tx_blob);
		if (net == "main") {
			// Demystified genesis block calculations below
			PublicKey genesis_tx_public_key =
                common::pfh<PublicKey>("a9fb59d721aa495decac1477605a1e6530e1615c0eace9333e8a7fde90fff908");
			Transaction coinbase_transaction;
			coinbase_transaction.version                   = 1;
			coinbase_transaction.unlock_block_or_timestamp = mined_money_unlock_window;
			coinbase_transaction.inputs.push_back(InputCoinbase{0});
			OutputKey genesis_output;
			genesis_output.amount = money_supply >> EMISSION_SPEED_FACTOR;
			genesis_output.public_key =
                common::pfh<PublicKey>("9b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd088071");
			coinbase_transaction.outputs.push_back(TransactionOutput{genesis_output});
			extra::add_transaction_public_key(coinbase_transaction.extra, genesis_tx_public_key);
			invariant(miner_tx_blob == seria::to_binary(coinbase_transaction),
			    "Demystified transaction does not match original one");
		}
	}
	genesis_block_template.major_version = 1;
	genesis_block_template.minor_version = 0;
	genesis_block_template.timestamp     = 0;
	genesis_block_template.nonce         = BinaryArray{70, 0, 0, 0};

	if (net == "test") {
		genesis_block_template.nonce.at(0) += 1;
		genesis_block_template.timestamp = platform::get_time_multiplier_for_tests() - 1;
	}
	if (net == "stage")
		genesis_block_template.nonce.at(0) += 2;
	auto body_proxy    = get_body_proxy_from_template(genesis_block_template);
	genesis_block_hash = get_block_hash(genesis_block_template, body_proxy);
	if (net == "main") {
		checkpoints_begin     = CHECKPOINTS;
		checkpoints_end       = CHECKPOINTS + sizeof(CHECKPOINTS) / sizeof(*CHECKPOINTS);
		checkpoint_keys_begin = CHECKPOINT_PUBLIC_KEYS;
		checkpoint_keys_end = CHECKPOINT_PUBLIC_KEYS + sizeof(CHECKPOINT_PUBLIC_KEYS) / sizeof(*CHECKPOINT_PUBLIC_KEYS);
	}
	if (net == "test") {
		checkpoint_keys_begin = CHECKPOINT_PUBLIC_KEYS_TESTNET;
		checkpoint_keys_end   = CHECKPOINT_PUBLIC_KEYS_TESTNET +
		                      sizeof(CHECKPOINT_PUBLIC_KEYS_TESTNET) / sizeof(*CHECKPOINT_PUBLIC_KEYS_TESTNET);
	}
	if (net == "stage") {
		checkpoints_begin = CHECKPOINTS_STAGENET;
		checkpoints_end   = CHECKPOINTS_STAGENET + sizeof(CHECKPOINTS_STAGENET) / sizeof(*CHECKPOINTS_STAGENET);
		;
		checkpoint_keys_begin = CHECKPOINT_PUBLIC_KEYS_STAGENET;
		checkpoint_keys_end   = CHECKPOINT_PUBLIC_KEYS_STAGENET +
		                      sizeof(CHECKPOINT_PUBLIC_KEYS_STAGENET) / sizeof(*CHECKPOINT_PUBLIC_KEYS_STAGENET);
	}
	miner_tx_blob_reserved_size =
	    get_maximum_tx_size_amethyst(1, get_max_coinbase_outputs(), 0) + 1 + extra::Nonce::MAX_COUNT;  // ~1k bytes
}

Height Currency::upgrade_votes_required() const { return upgrade_voting_window * UPGRADE_VOTING_PERCENT / 100; }

Height Currency::timestamp_check_window(uint8_t block_major_version) const {
	if (block_major_version >= amethyst_block_version)
		return BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;
	return BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V1_3;
}

bool Currency::is_transaction_unlocked(uint8_t block_major_version, BlockOrTimestamp unlock_time, Height block_height,
    Timestamp block_time, Timestamp block_median_time) const {
	if (block_major_version >= amethyst_block_version) {
		if (unlock_time < max_block_height)  // interpret as block index
			return block_height >= unlock_time;
		return block_median_time + (BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW * difficulty_target) / 2 >= unlock_time;
	}
	if (unlock_time < max_block_height)  // interpret as block index
		return block_height + LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time;
	return block_time + LOCKED_TX_ALLOWED_DELTA_SECONDS(difficulty_target) >= unlock_time;  // interpret as time
}

bool Currency::is_upgrade_vote(uint8_t major, uint8_t minor) const { return minor == upgrade_vote_minor; }

bool Currency::wish_to_upgrade() const { return upgrade_desired_major > 1 + upgrade_heights.size(); }

Height Currency::expected_blocks_per_day() const {
	return 24 * 60 * 60 / difficulty_target / platform::get_time_multiplier_for_tests();
}

Height Currency::expected_blocks_per_year() const {
	return 365 * 24 * 60 * 60 / difficulty_target / platform::get_time_multiplier_for_tests();
}

bool Currency::is_in_hard_checkpoint_zone(Height height) const { return height <= last_hard_checkpoint().height; }

bool Currency::check_hard_checkpoint(Height height, const Hash &h, bool &is_hard_checkpoint) const {
	if (checkpoints_begin == checkpoints_end) {
		is_hard_checkpoint = (height == 0);
		return height == 0 ? h == genesis_block_hash : true;
	}
	auto it = std::lower_bound(
	    checkpoints_begin, checkpoints_end, height, [](const HardCheckpoint &da, Height ma) { return da.height < ma; });
	is_hard_checkpoint = false;
	if (it == checkpoints_end)
		return true;
	if (it->height != height)
		return true;
	is_hard_checkpoint = true;
	return h == it->hash;
}

HardCheckpoint Currency::last_hard_checkpoint() const {
	if (checkpoints_begin == checkpoints_end)
		return HardCheckpoint{0, genesis_block_hash};
	return *(checkpoints_end - 1);
}

PublicKey Currency::get_checkpoint_public_key(size_t key_id) const {
	if (key_id >= get_checkpoint_keys_count())
		return PublicKey{};
	return checkpoint_keys_begin[key_id];
}

uint8_t Currency::get_block_major_version_for_height(Height height) const {
	for (size_t i = 0; i < upgrade_heights.size(); ++i)
		if (height < upgrade_heights[i])
			return static_cast<uint8_t>(i + 1);
	return static_cast<uint8_t>(upgrade_heights.size() + 1);
}

Difficulty Currency::get_minimum_difficulty(uint8_t block_major_version) const {
	if (block_major_version == 1 || net == "test")
		return MINIMUM_DIFFICULTY_V1;
	return MINIMUM_DIFFICULTY;
}

Height Currency::difficulty_windows_plus_lag() const { return DIFFICULTY_WINDOW + DIFFICULTY_LAG; }

Height Currency::difficulty_windows() const {return DIFFICULTY_WINDOWS_LWMA; }

size_t Currency::get_minimum_size_median(uint8_t block_major_version) const {
	if (block_major_version == 1)
		return MINIMUM_SIZE_MEDIAN_V1;
	if (block_major_version == 2)
		return MINIMUM_SIZE_MEDIAN_V2;
	if (block_major_version == 3)
		return MINIMUM_SIZE_MEDIAN_V3;
	return 0;
}

size_t Currency::max_block_transactions_cumulative_size(Height height) const {
	if (net != "main")
		return 1024 * 1024;
	//	if (MAX_BLOCK_SIZE_GROWTH_PER_YEAR == 0)
	//		return MAX_BLOCK_SIZE_INITIAL;
	static_assert(
	    MAX_BLOCK_SIZE_GROWTH_PER_YEAR == 0 ||
	        std::numeric_limits<Height>::max() <= std::numeric_limits<uint64_t>::max() / MAX_BLOCK_SIZE_GROWTH_PER_YEAR,
	    "MAX_BLOCK_SIZE_GROWTH_PER_YEAR too large");
	uint64_t max_size =
	    MAX_BLOCK_SIZE_INITIAL + (uint64_t(height) * MAX_BLOCK_SIZE_GROWTH_PER_YEAR) / expected_blocks_per_year();
	invariant(max_size < std::numeric_limits<size_t>::max(), "");
	return static_cast<size_t>(max_size);
}

size_t Currency::minimum_anonymity(uint8_t block_major_version) const {
	if (block_major_version >= amethyst_block_version)
		return MINIMUM_ANONYMITY_AMETHYST;
	return 0;
}

Amount Currency::get_base_block_reward(
    uint8_t block_major_version, Height height, Amount already_generated_coins) const {
	invariant(already_generated_coins <= money_supply, "");

	return (money_supply - already_generated_coins) >> EMISSION_SPEED_FACTOR;
}

Amount Currency::get_block_reward(uint8_t block_major_version, Height height, size_t effective_median_size,
    size_t current_transactions_size, Amount already_generated_coins, Amount fee, SignedAmount *emission_change) const {
	Amount base_reward = get_base_block_reward(block_major_version, height, already_generated_coins);

	Amount penalized_base_reward = get_penalized_amount(base_reward, effective_median_size, current_transactions_size);
	Amount penalized_fee =
	    block_major_version >= 2 ? get_penalized_amount(fee, effective_median_size, current_transactions_size) : fee;

	if (emission_change)
		*emission_change = penalized_base_reward - (fee - penalized_fee);
	return penalized_base_reward + penalized_fee;
}

Height Currency::largest_window() const {
	return std::max(block_capacity_vote_window,
        //std::max(difficulty_windows_plus_lag(),
          std::max(difficulty_windows(),
	        std::max(median_block_size_window,
	            std::max(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW, BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V1_3))));
}

Transaction Currency::construct_miner_tx(const Hash &miner_secret, uint8_t block_major_version, Height height,
    Amount block_reward, const AccountAddress &miner_address) const {
	Transaction tx;
	const bool is_tx_amethyst = miner_address.type() != typeid(AccountAddressLegacy);
	// If we wish to limit number of outputs, it makes sense to round miner reward to some arbitrary number
	// Though this solution will reduce number of coins to mix

	tx.inputs.push_back(InputCoinbase{height});

	Hash tx_inputs_hash = get_transaction_inputs_hash(tx);
	KeyPair txkey       = miner_secret == Hash{} ? crypto::random_keypair()
	                                       : Wallet::transaction_keys_from_seed(tx_inputs_hash, miner_secret);

	if (!is_tx_amethyst)
		extra::add_transaction_public_key(tx.extra, txkey.public_key);

	std::vector<Amount> out_amounts;
	const size_t max_outs = get_max_coinbase_outputs();
	decompose_amount(block_reward, min_dust_threshold, &out_amounts);

	while (out_amounts.size() > max_outs && out_amounts.size() > 2) {
		out_amounts.at(out_amounts.size() - 2) += out_amounts.back();
		out_amounts.pop_back();
	}

	Amount summary_amounts = 0;
	for (size_t out_index = 0; out_index < out_amounts.size(); out_index++) {
		const Hash output_seed = miner_secret == Hash{}
		                             ? crypto::rand<Hash>()
		                             : Wallet::generate_output_seed(tx_inputs_hash, miner_secret, out_index);
		PublicKey output_shared_secret;
		OutputKey tk = TransactionBuilder::create_output(is_tx_amethyst, miner_address, txkey.secret_key,
		    tx_inputs_hash, out_index, output_seed, &output_shared_secret);
		tk.amount    = out_amounts.at(out_index);
		summary_amounts += tk.amount;
		tx.outputs.push_back(tk);
	}

	invariant(summary_amounts == block_reward, "");

	tx.version = is_tx_amethyst ? amethyst_transaction_version : 1;
	// if mining on old address, we maintain binary compatibility
	if (block_major_version < amethyst_block_version) {
		tx.unlock_block_or_timestamp = height + mined_money_unlock_window;
		if (is_tx_amethyst)
			throw api::ErrorAddress(api::ErrorAddress::ADDRESS_FAILED_TO_PARSE,
			    "You cannot mine to amethyst address before consensus update to amethyst",
			    account_address_as_string(miner_address));
	}
	return tx;
}

Amount Currency::get_penalized_amount(uint64_t amount, size_t median_size, size_t current_block_size) {
	static_assert(sizeof(size_t) >= sizeof(uint32_t), "size_t is too small");
	invariant(current_block_size <= 2 * median_size, "");
	invariant(median_size <= std::numeric_limits<uint32_t>::max(), "");
	invariant(current_block_size <= std::numeric_limits<uint32_t>::max(), "");

	if (amount == 0)
		return 0;
	if (current_block_size <= median_size)
		return amount;

	uint64_t product_hi;
	uint64_t product_lo =
	    mul128(amount, current_block_size * (uint64_t(2) * median_size - current_block_size), &product_hi);

	uint64_t penalized_amount_hi;
	uint64_t penalized_amount_lo;
	div128_32(product_hi, product_lo, static_cast<uint32_t>(median_size), &penalized_amount_hi, &penalized_amount_lo);
	div128_32(penalized_amount_hi, penalized_amount_lo, static_cast<uint32_t>(median_size), &penalized_amount_hi,
	    &penalized_amount_lo);

	invariant(0 == penalized_amount_hi, "");
	invariant(penalized_amount_lo < amount, "");

	return penalized_amount_lo;
}

std::string Currency::account_address_as_string(const AccountAddress &v_addr) const {
	if (auto *addr = boost::get<AccountAddressLegacy>(&v_addr)) {
		BinaryArray ba = seria::to_binary(*addr);
		return common::base58::encode_addr(ADDRESS_BASE58_PREFIX, ba);
	}
	if (auto *addr = boost::get<AccountAddressAmethyst>(&v_addr)) {
		BinaryArray ba = seria::to_binary(*addr);
		return common::base58::encode_addr(ADDRESS_BASE58_PREFIX_AMETHYST, ba);
	}
	throw std::runtime_error("Unknown address type");
}

bool Currency::parse_account_address_string(const std::string &str, AccountAddress *v_addr) const {
	uint64_t tag = 0;
	BinaryArray data;
	if (!common::base58::decode_addr(str, &tag, &data))
		return false;
	if (tag == ADDRESS_BASE58_PREFIX_AMETHYST) {
		AccountAddressAmethyst addr;
		try {
			seria::from_binary(addr, data);
		} catch (const std::exception &) {
			return false;
		}
		if (!key_in_main_subgroup(addr.S) || !key_in_main_subgroup(addr.Sv))
			return false;
		*v_addr = addr;
		return true;
	}
	if (tag == ADDRESS_BASE58_PREFIX) {
		AccountAddressLegacy addr;
		try {
			seria::from_binary(addr, data);
		} catch (const std::exception &) {
			return false;
		}
		if (!key_in_main_subgroup(addr.S) || !key_in_main_subgroup(addr.V))
			return false;
		*v_addr = addr;
		return true;
	}
	return false;
}

// We used C-style here to have same code on Ledger
static void c_ffw(Amount am, size_t digs, char *buf) {
	while (digs-- > 0) {
		Amount d  = am % 10;
		am        = am / 10;
		buf[digs] = static_cast<char>('0' + d);
	}
}

size_t c_format_amount(Amount amount, char *buffer, size_t len) {
	const size_t COIN = 100000000;
	const size_t CENT = COIN / 100;
	Amount ia         = amount / COIN;
	Amount fa         = amount - ia * COIN;
	size_t pos        = 0;
	while (ia >= 1000) {
		pos += 4;
		memmove(buffer + 4, buffer, pos);
		buffer[0] = '\'';
		c_ffw(ia % 1000, 3, buffer + 1);
		ia /= 1000;
	}
	while (true) {
		Amount d = ia % 10;
		ia       = ia / 10;
		pos += 1;
		memmove(buffer + 1, buffer, pos);
		buffer[0] = static_cast<char>('0' + d);
		if (ia == 0)
			break;
	}
	if (fa != 0) {  // cents
		buffer[pos++] = '.';
		c_ffw(fa / CENT, 2, buffer + pos);
		pos += 2;
		fa %= CENT;
	}
	if (fa != 0) {
		//		buffer[pos++] = '\'';
		c_ffw(fa / 1000, 3, buffer + pos);
		pos += 3;
		fa %= 1000;
	}
	if (fa != 0) {
		//		buffer[pos++] = '\'';
		c_ffw(fa, 3, buffer + pos);
		pos += 3;
	}
	return pos;
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
		result += ffw(fa / 1000, 3);
		fa %= 1000;
	}
	if (fa != 0)
		result += ffw(fa, 3);
	//   	char buffer[64]{};
	//   	std::string res2(buffer, c_format_amount(amount, buffer, sizeof(buffer)));
	//   	invariant(res2 == result, "c_format_amount error");
	//   	std::cout << amount << " -> " << result << std::endl;
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
	if (timestamps->size() > DIFFICULTY_WINDOW) {
		timestamps->resize(DIFFICULTY_WINDOW);
		cumulative_difficulties->resize(DIFFICULTY_WINDOW);
	}

	const size_t length = timestamps->size();
	invariant(length == cumulative_difficulties->size() && length <= DIFFICULTY_WINDOW, "");
	if (length <= 1)
		return 1;

	std::sort(timestamps->begin(), timestamps->end());

	size_t cut_begin, cut_end;
	const size_t inner_window = DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT;
	if (length <= inner_window) {
		cut_begin = 0;
		cut_end   = length;
	} else {
		cut_begin = (length - inner_window + 1) / 2;
		cut_end   = cut_begin + inner_window;
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
	if (high != 0 || std::numeric_limits<uint64_t>::max() - low < (time_span - 1))
		throw std::runtime_error("Difficulty overlap");
	return (low + time_span - 1) / time_span;
}

Difficulty Currency::next_effective_difficulty(uint8_t block_major_version, std::vector<Timestamp> timestamps,
    std::vector<CumulativeDifficulty> cumulative_difficulties) const {
    /*
	Difficulty difficulty = next_difficulty(&timestamps, &cumulative_difficulties);
	if (difficulty < get_minimum_difficulty(block_major_version))  // even when it is 0
		difficulty = get_minimum_difficulty(block_major_version);
	return difficulty;
    */
    Difficulty difficulty = next_difficultyLWMA3(block_major_version, timestamps, cumulative_difficulties);
    return difficulty;
}

// LWMA-3 difficulty algorithm
// Copyright (c) 2017-2018 Zawy, MIT License
// https://github.com/zawy12/difficulty-algorithms/issues/3
Difficulty Currency::next_difficultyLWMA3(uint8_t block_major_version, std::vector<Timestamp> timestamps, std::vector<CumulativeDifficulty> cumulative_difficulties) const
{
    uint64_t T = difficulty_target;
    uint64_t N = difficulty_window_lwma - 1;
    uint64_t L(0), ST, sum_3_ST(0), next_D, prev_D, thisTimestamp, previousTimestamp;
    Timestamp difficulty_limit = get_minimum_difficulty(block_major_version);

    if (timestamps.size() <= 10)
        return difficulty_limit;

    /* Don't have the full amount of blocks yet, starting up */
    if (timestamps.size() < N+1)
        N = timestamps.size() - 1;

    previousTimestamp = timestamps[0];

    for (uint64_t i = 1; i <= N; i++)
    {
        if (timestamps[i] > previousTimestamp)
            thisTimestamp = timestamps[i];
        else
            thisTimestamp = previousTimestamp + 1;

        ST = std::min(6*T, thisTimestamp - previousTimestamp);
        previousTimestamp = thisTimestamp;
        L +=  ST * i;

        if (i > N-3)
        {
            sum_3_ST += ST;
        }
    }

    CumulativeDifficulty nD = (cumulative_difficulties[N] - cumulative_difficulties[0]);
    next_D = (nD.lo *T*(N+1)*99 ) / (100*2*L);

    CumulativeDifficulty pD = (cumulative_difficulties[N] - cumulative_difficulties[N-1]);
    prev_D = pD.lo;

    next_D = std::max((prev_D * 67) / 100, std::min(next_D, (prev_D * 150) / 100));

    if(nD.hi!=0 || pD.hi!=0)
        return 0;//DIFFICULTY_OVERHEAD

    if (sum_3_ST < (8 * T) / 10)
    {
        next_D = std::max(next_D, (prev_D * 108) / 100);
    }

    // Minimum limit
    if (next_D < difficulty_limit)
        next_D = difficulty_limit;

    return next_D;
}

BinaryArray Currency::get_block_pow_hashing_data(const BlockHeader &bh, const BlockBodyProxy &body_proxy) const {
	return cn::get_block_pow_hashing_data(bh, body_proxy, genesis_block_hash);
}

size_t Currency::mixin_distribution(Amount am, size_t stack_size) {
	if (stack_size == 0)
		return 0;
	crypto::random_engine<uint64_t> generator;
	std::normal_distribution<double> gaus_distribution{7.03635, 3.274266};  // magic
	std::exponential_distribution<double> exp_distribution(1.13526e-01);    // magic
	std::uniform_real_distribution<double> uniform_distribution(0.0, 1.0);

	while (true) {
		double bound = uniform_distribution(generator);
		double y     = 0.0;
		if (bound > 0.11) {  // 0.11 magic
			y = gaus_distribution(generator);
			y = exp(y);
		} else {
			y = exp_distribution(generator);
		}
		if (y > std::numeric_limits<int>::max() || y < std::numeric_limits<int>::min())
			continue;
		const int tmp = int(y);
		if (tmp > static_cast<int>(stack_size - 1))
			continue;
		const size_t num = (tmp >= 0) ? stack_size - 1 - tmp : stack_size - 1;
		return num;
	}
}

std::vector<size_t> Currency::mixin_distribution(Amount am, size_t stack_size, size_t count) {
	if (count >= stack_size) {
		std::vector<size_t> result;
		for (size_t i = 0; i != stack_size; ++i)
			result.push_back(i);
		return result;
	}
	std::set<size_t> tried_or_added;
	size_t attempts = 0;
	// If we are unlucky, first loop can take a long time, so we limit attempts
	for (; tried_or_added.size() < count && attempts < count * 20; ++attempts)
		tried_or_added.insert(mixin_distribution(am, stack_size));
	for (size_t i = stack_size; tried_or_added.size() < count && i-- > 0;)
		tried_or_added.insert(i);
	return std::vector<size_t>(tried_or_added.begin(), tried_or_added.end());
}
