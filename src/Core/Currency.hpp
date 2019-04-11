// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "CryptoNote.hpp"
#include "Difficulty.hpp"
#include "crypto/hash.hpp"

namespace cn {

class Currency {  // Consensus calculations depend on those parameters
public:
	static const std::vector<Amount> PRETTY_AMOUNTS;
	static const std::vector<Amount> DECIMAL_PLACES;

	explicit Currency(const std::string &net);

	std::string net;
	BlockTemplate genesis_block_template{};
	Hash genesis_block_hash{};

	Height max_block_height;
	Height mined_money_unlock_window;

	Height largest_window() const;  // for limit on caching of headers

	Height timestamp_check_window(uint8_t block_major_version) const;
	Timestamp block_future_time_limit;

	Amount money_supply;
	unsigned int emission_speed_factor;

	Height median_block_size_window;
	Height block_capacity_vote_window;
	size_t max_header_size;
	size_t block_capacity_vote_min;
	size_t block_capacity_vote_max;
	size_t miner_tx_blob_reserved_size;
	size_t get_recommended_max_transaction_size() const {
		return block_capacity_vote_min - miner_tx_blob_reserved_size;
	}
	size_t get_minimum_size_median(uint8_t block_major_version) const;

	size_t max_block_transactions_cumulative_size(Height height) const;  // Legacy checks

	size_t minimum_anonymity(uint8_t block_major_version) const;
	size_t number_of_decimal_places;
	Amount coin() const { return DECIMAL_PLACES.at(number_of_decimal_places); }

	size_t get_max_amount_outputs() const { return 15; }  // 2 groups of 3 digits + 13 single digits
	size_t get_max_coinbase_outputs() const { return 10; }
	Amount min_dust_threshold;
	Amount max_dust_threshold;
	Amount self_dust_threshold;

	Timestamp difficulty_target;
	Difficulty get_minimum_difficulty(uint8_t block_major_version) const;
	Height difficulty_windows_plus_lag() const;
	Height expected_blocks_per_day() const;
	Height expected_blocks_per_year() const;

	std::vector<Height> upgrade_heights;  // Height of first V2 bloc, first V3 block, etc
	Height key_image_subgroup_checking_height;
	uint8_t get_block_major_version_for_height(Height) const;
	uint8_t amethyst_block_version;
	uint8_t amethyst_transaction_version;

	// upgrade voting threshold must not be reached before or at last sw checkpoint!
	uint8_t upgrade_from_major_version;
	uint8_t upgrade_indicator_minor_version;
	bool is_upgrade_vote(uint8_t major, uint8_t minor) const;
	uint8_t upgrade_desired_major_version;
	Height upgrade_voting_window;
	Height upgrade_votes_required() const;
	Height upgrade_window;

	uint64_t sendproof_base58_prefix;

	size_t hard_checkpoint_count() const { return checkpoints_end - checkpoints_begin; }
	bool is_in_hard_checkpoint_zone(Height height) const;
	bool check_hard_checkpoint(Height height, const Hash &h, bool &is_hard_checkpoint) const;
	HardCheckpoint last_hard_checkpoint() const;
	PublicKey get_checkpoint_public_key(size_t key_id) const;
	size_t get_checkpoint_keys_count() const { return checkpoint_keys_end - checkpoint_keys_begin; }

	Amount get_base_block_reward(uint8_t block_major_version, Height height, Amount already_generated_coins) const;
	Amount get_block_reward(uint8_t block_major_version, Height height, size_t effective_median_size,
	    size_t current_transactions_size, Amount already_generated_coins, Amount fee,
	    SignedAmount *emission_change = nullptr) const;
	Transaction construct_miner_tx(const Hash &miner_secret, uint8_t block_major_version, Height height,
	    Amount block_reward, const AccountAddress &miner_address) const;

	std::string account_address_as_string(const AccountAddress &account_public_address) const;
	bool parse_account_address_string(const std::string &str, AccountAddress *addr) const;

	std::string format_amount(Amount amount) const { return format_amount(number_of_decimal_places, amount); }
	std::string format_amount(SignedAmount amount) const { return format_amount(number_of_decimal_places, amount); }
	bool parse_amount(const std::string &str, Amount *amount) const {
		return parse_amount(number_of_decimal_places, str, amount);
	}

	Difficulty next_difficulty(
	    std::vector<Timestamp> *timestamps, std::vector<CumulativeDifficulty> *cumulative_difficulties) const;
	Difficulty next_effective_difficulty(uint8_t block_major_version, std::vector<Timestamp> timestamps,
	    std::vector<CumulativeDifficulty> cumulative_difficulties) const;

	BinaryArray get_block_long_hashing_data(const BlockHeader &, const BlockBodyProxy &) const;

	bool is_block_or_timestamp_timestamp(BlockOrTimestamp unlock_time) const { return unlock_time >= max_block_height; }
	bool is_block_or_timestamp_block(BlockOrTimestamp unlock_time) const { return unlock_time < max_block_height; }
	bool is_transaction_unlocked(uint8_t block_major_version, BlockOrTimestamp unlock_time, Height block_height,
	    Timestamp block_time, Timestamp block_median_time) const;

	bool amount_allowed_in_output(uint8_t block_major_version, Amount amount) const;

	static uint64_t get_penalized_amount(uint64_t amount, size_t median_size, size_t current_transactions_size);
	static std::string format_amount(size_t number_of_decimal_places, Amount);
	static std::string format_amount(size_t number_of_decimal_places, SignedAmount);
	static bool parse_amount(size_t number_of_decimal_places, const std::string &, Amount *);

private:
	const PublicKey *checkpoint_keys_begin  = nullptr;
	const PublicKey *checkpoint_keys_end    = nullptr;
	const HardCheckpoint *checkpoints_begin = nullptr;
	const HardCheckpoint *checkpoints_end   = nullptr;
};

}  // namespace cn
