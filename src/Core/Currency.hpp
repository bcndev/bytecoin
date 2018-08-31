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

	explicit Currency(const std::string &net);

	std::string net;
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
	uint32_t minimum_size_median;
	uint32_t get_minimum_size_median(uint8_t block_major_version) const;

	uint32_t miner_tx_blob_reserved_size;

	size_t number_of_decimal_places;
	Amount coin() const { return DECIMAL_PLACES.at(number_of_decimal_places); }

	Amount minimum_fee;
	Amount default_dust_threshold;

	Timestamp difficulty_target;
	Difficulty minimum_difficulty;
	Difficulty get_minimum_difficulty(uint8_t block_major_version) const;
	Height difficulty_window;
	Height difficulty_lag;
	size_t difficulty_cut;
	Height difficulty_blocks_count() const { return difficulty_window + difficulty_lag; }
	uint32_t expected_blocks_per_day() const;
	uint32_t expected_blocks_per_year() const;
	uint32_t max_block_size_initial;
	uint32_t max_block_size_growth_per_year;

	Timestamp locked_tx_allowed_delta_seconds;
	Height locked_tx_allowed_delta_blocks;

	Height upgrade_height_v2;  // height of first v2 block
	Height upgrade_height_v3;  // height of first v3 block
	Height key_image_subgroup_checking_height;
	uint8_t get_block_major_version_for_height(Height) const;

	// upgrade voting threshold must not be reached before or at last sw checkpoint!
	uint8_t upgrade_from_major_version;
	uint8_t upgrade_indicator_minor_version;
	uint8_t upgrade_desired_major_version;
	Height upgrade_voting_window;
	Height upgrade_votes_required;
	Height upgrade_blocks_after_voting;

	uint8_t current_transaction_version;

	size_t sw_checkpoint_count() const { return checkpoints_end - checkpoints_begin; }
	bool is_in_sw_checkpoint_zone(Height height) const;
	bool check_sw_checkpoint(Height height, const Hash &h, bool &is_sw_checkpoint) const;
	SWCheckpoint last_sw_checkpoint() const;
	PublicKey get_checkpoint_public_key(uint32_t key_id) const;
	uint32_t get_checkpoint_keys_count() const {
		return static_cast<uint32_t>(checkpoint_keys_end - checkpoint_keys_begin);
	}

	void get_block_reward(uint8_t block_major_version, size_t effective_median_size, size_t current_block_size,
	    Amount already_generated_coins, Amount fee, Amount *reward, SignedAmount *emission_change) const;
	uint32_t max_block_cumulative_size(Height height) const;
	uint32_t max_transaction_allowed_size(uint32_t effective_block_size_median) const;
	bool construct_miner_tx(uint8_t block_major_version, Height height, size_t effective_median_size,
	    Amount already_generated_coins, size_t current_block_size, Amount fee, Hash mineproof_seed,
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

	BinaryArray get_block_long_hashing_data(const BlockHeader &, const BlockBodyProxy &) const;

	bool is_transaction_spend_time(BlockOrTimestamp unlock_time) const { return unlock_time >= max_block_height; }
	bool is_transaction_spend_time_block(BlockOrTimestamp unlock_time) const { return unlock_time < max_block_height; }
	bool is_transaction_spend_time_unlocked(
	    BlockOrTimestamp unlock_time, Height block_height, Timestamp block_time) const {
		if (unlock_time < max_block_height) {  // interpret as block index
			return block_height + locked_tx_allowed_delta_blocks >= unlock_time;
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

private:
	const PublicKey *checkpoint_keys_begin = nullptr;
	const PublicKey *checkpoint_keys_end   = nullptr;
	const SWCheckpoint *checkpoints_begin  = nullptr;
	const SWCheckpoint *checkpoints_end    = nullptr;
};

// we should probaly find better place for these global funs
Hash get_transaction_inputs_hash(const TransactionPrefix &);
Hash get_transaction_prefix_hash(const TransactionPrefix &);
Hash get_transaction_hash(const Transaction &);

Hash get_block_hash(const BlockHeader &, const BlockBodyProxy &);
Hash get_auxiliary_block_header_hash(const BlockHeader &, const BlockBodyProxy &);
// Auxilary hash, or prehash - inserted into MM or CM tree

}  // namespace bytecoin
