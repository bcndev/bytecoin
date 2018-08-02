// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "CryptoNote.hpp"
#include "Difficulty.hpp"
#include "crypto/hash.hpp"

namespace bytecoin {

class Currency {  // Consensus calcs depend on those parameters
public:
	static const std::vector<Amount> PRETTY_AMOUNTS;
	static const std::vector<Amount> DECIMAL_PLACES;

	explicit Currency(bool is_testnet);

	bool is_testnet;
	BlockTemplate genesis_block_template{};
	Hash genesis_block_hash{};

	Height max_block_height;
	uint32_t max_block_blob_size;
	uint32_t max_tx_size;
	uint64_t public_address_base58_prefix;
	Height mined_money_unlock_window;

	Height largest_window() const;  // for limit on caching of headers

	Height timestamp_check_window;
	Timestamp block_future_time_limit;

	Amount money_supply;
	unsigned int emission_speed_factor;

	Height reward_blocks_window;
	uint32_t block_granted_full_reward_zone;
	uint32_t miner_tx_blob_reserved_size;

	size_t number_of_decimal_places;
	Amount coin() const { return DECIMAL_PLACES.at(number_of_decimal_places); }

	Amount minimum_fee;
	Amount default_dust_threshold;

	Timestamp difficulty_target;
	Difficulty minimum_difficulty_from_v2;
	Height difficulty_window;
	Height difficulty_lag;
	size_t difficulty_cut;
	Height difficulty_blocks_count() const { return difficulty_window + difficulty_lag; }
	uint32_t expected_blocks_per_day() const { return 24 * 60 * 60 / difficulty_target; }
	uint64_t max_block_size_initial;
	uint64_t max_block_size_growth_speed_numerator;
	uint64_t max_block_size_growth_speed_denominator;

	Timestamp locked_tx_allowed_delta_seconds;
	Height locked_tx_allowed_delta_blocks;

	Height upgrade_height_v2;
	Height upgrade_height_v3;
	uint8_t get_block_major_version_for_height(Height) const;
	uint8_t get_block_minor_version_for_height(Height) const;

	uint8_t current_transaction_version;

	size_t sw_checkpoint_count() const;
	bool is_in_sw_checkpoint_zone(Height index) const;
	bool check_sw_checkpoint(Height index, const crypto::Hash &h, bool &is_sw_checkpoint) const;
	std::pair<Height, crypto::Hash> last_sw_checkpoint() const;
	PublicKey get_checkpoint_public_key(uint32_t key_id) const;
	uint32_t get_checkpoint_keys_count() const;

	uint32_t block_granted_full_reward_zone_by_block_version(uint8_t block_major_version) const;
	bool get_block_reward(uint8_t block_major_version, size_t effective_median_size, size_t current_block_size,
	    Amount already_generated_coins, Amount fee, Amount *reward, SignedAmount *emission_change) const;
	uint32_t max_block_cumulative_size(Height height) const;
	uint32_t max_transaction_allowed_size(uint32_t effective_block_size_median) const;
	bool construct_miner_tx(uint8_t block_major_version, Height height, size_t effective_median_size,
	    Amount already_generated_coins, size_t current_block_size, Amount fee,
	    const AccountPublicAddress &miner_address, Transaction *tx, const BinaryArray &extra_nonce = BinaryArray(),
	    size_t max_outs = 1) const;

	std::string account_address_as_string(const AccountPublicAddress &account_public_address) const;
	bool parse_account_address_string(const std::string &str, AccountPublicAddress *addr) const;

	std::string format_amount(Amount amount) const { return format_amount(number_of_decimal_places, amount); }
	std::string format_amount(SignedAmount amount) const { return format_amount(number_of_decimal_places, amount); }
	bool parse_amount(const std::string &str, Amount *amount) const {
		return parse_amount(number_of_decimal_places, str, amount);
	}

	Difficulty next_difficulty(
	    std::vector<Timestamp> *timestamps, std::vector<CumulativeDifficulty> *cumulative_difficulties) const;
	Difficulty next_effective_difficulty(uint8_t block_major_version, std::vector<Timestamp> timestamps,
	    std::vector<CumulativeDifficulty> cumulative_difficulties) const;

	bool check_proof_of_work_v1(
	    const Hash &long_block_hash, const BlockTemplate &block, Difficulty current_difficulty) const;
	bool check_proof_of_work_v2(
	    const Hash &long_block_hash, const BlockTemplate &block, Difficulty current_difficulty) const;
	bool check_proof_of_work(
	    const Hash &long_block_hash, const BlockTemplate &block, Difficulty current_difficulty) const;

	bool is_transaction_spend_time(UnlockMoment unlock_time) const { return unlock_time >= max_block_height; }
	bool is_transaction_spend_time_block(UnlockMoment unlock_time) const { return unlock_time < max_block_height; }
	bool is_transaction_spend_time_unlocked(UnlockMoment unlock_time, Height block_index, Timestamp block_time) const {
		if (unlock_time < max_block_height) {  // interpret as block index
			return block_index + locked_tx_allowed_delta_blocks >= unlock_time;
		}  // else interpret as time
		return block_time + locked_tx_allowed_delta_seconds >= unlock_time;
	}
	static bool is_dust(Amount am);
	static uint64_t get_penalized_amount(uint64_t amount, size_t median_size, size_t current_block_size);
	static std::string get_account_address_as_str(uint64_t prefix, const AccountPublicAddress &adr);
	static bool parse_account_address_string(uint64_t *prefix, AccountPublicAddress *adr, const std::string &str);
	static std::string format_amount(size_t number_of_decimal_places, Amount);
	static std::string format_amount(size_t number_of_decimal_places, SignedAmount);
	static bool parse_amount(size_t number_of_decimal_places, const std::string &, Amount *);
};

// we should probaly find better place for these global funs
Hash get_transaction_inputs_hash(const TransactionPrefix &);
Hash get_transaction_prefix_hash(const TransactionPrefix &);
Hash get_transaction_hash(const Transaction &);

Hash get_block_hash(const BlockTemplate &);
Hash get_block_long_hash(const BlockTemplate &, crypto::CryptoNightContext &);
Hash get_auxiliary_block_header_hash(const BlockTemplate &);  // Without parent block, for merge mining calculations

}  // namespace bytecoin
