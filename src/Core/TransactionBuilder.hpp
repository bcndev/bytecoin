// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <unordered_map>
#include "CryptoNote.hpp"
#include "TransactionExtra.hpp"
#include "Wallet.hpp"
#include "crypto/chacha8.h"
#include "rpc_api.hpp"

namespace bytecoin {

class Wallet;
class Currency;

class TransactionBuilder {
	Transaction m_transaction;
	struct InputDesc {
		std::vector<api::Output> outputs;
		size_t real_output_index = 0;
		KeyPair eph_keys;
		KeyInput input;
		static bool less_amount(const InputDesc &a, const InputDesc &b) { return a.input.amount < b.input.amount; }
	};
	std::vector<InputDesc> m_input_descs;
	struct OutputDesc {
		Amount amount;
		AccountPublicAddress addr;
		static bool less_amount(const OutputDesc &a, const OutputDesc &b) { return a.amount < b.amount; }
	};
	std::vector<OutputDesc> m_output_descs;
	TransactionExtra m_extra;
	Amount m_outputs_amount = 0;
	Amount m_inputs_amount  = 0;

public:
	explicit TransactionBuilder(const Currency &, UnlockMoment);

	void set_payment_id(const Hash &);
	void set_extra_nonce(const BinaryArray &);

	// before calling, make sure mix_outputs do not contain real_output...
	size_t add_input(
	    const AccountKeys &sender_keys, api::Output real_output, const std::vector<api::Output> &mix_outputs);
	size_t add_output(uint64_t amount, const AccountPublicAddress &to);

	Amount get_outputs_amount() const { return m_outputs_amount; }
	Amount get_inputs_amount() const { return m_inputs_amount; }

	Transaction sign(const Hash &tx_derivation_seed);

	BinaryArray generate_history(const crypto::chacha8_key &history_key) const;

	static crypto::KeyPair deterministic_keys_from_seed(const Hash &tx_inputs_hash, const Hash &tx_derivation_seed);
	static crypto::KeyPair deterministic_keys_from_seed(const TransactionPrefix &tx, const Hash &tx_derivation_seed);
	static bool generate_key_image_helper(const AccountKeys &ack, const crypto::PublicKey &tx_public_key,
	    size_t real_output_index, KeyPair &in_ephemeral, crypto::KeyImage &ki);
	static bool derive_public_key(
	    const AccountPublicAddress &to, const SecretKey &tx_key, size_t output_index, PublicKey &ephemeral_key);
	static std::vector<uint32_t> absolute_output_offsets_to_relative(const std::vector<uint32_t> &off);
};

class UnspentSelector {
	logging::LoggerRef m_log;
	const Currency &m_currency;
	typedef std::vector<api::Output> Unspents;
	typedef std::map<size_t, std::map<size_t, std::vector<api::Output>>> HaveCoins;
	typedef std::map<Amount, std::vector<api::Output>> DustCoins;
	Unspents m_unspents;
	Unspents m_used_unspents;
	Unspents m_optimization_unspents;
	void create_have_coins(Height block_height, Timestamp block_time, Height confirmed_height, HaveCoins *have_coins,
	    DustCoins *dust_coins, size_t *max_digit);
	void unoptimize_amounts(HaveCoins *have_coins, DustCoins *dust_coins);
	void optimize_amounts(HaveCoins *have_coins, size_t max_digit, Amount total_amount);
	void combine_optimized_unspents();

	Amount m_used_total   = 0;
	size_t m_inputs_count = 0;
	std::vector<Amount> m_ra_amounts;
	bool select_optimal_outputs(HaveCoins *have_coins, DustCoins *dust_coins, size_t max_digit, Amount amount,
	    size_t anonymity, size_t optimization_count);

public:
	explicit UnspentSelector(logging::ILogger &logger, const Currency &currency, Unspents &&unspents);
	void reset(Unspents &&unspents);
	void add_mixed_inputs(const SecretKey &view_secret_key,
	    const std::unordered_map<PublicKey, WalletRecord> &wallet_records, TransactionBuilder *builder,
	    uint32_t anonymity, api::bytecoind::GetRandomOutputs::Response &&ra_response);

	std::string select_optimal_outputs(Height block_height, Timestamp block_time, Height confirmed_height,
	    size_t effective_median_size, size_t anonymity, Amount total_amount, size_t total_outputs, Amount fee_per_byte,
	    std::string optimization_level, Amount *change);
	Amount get_used_total() const { return m_used_total; }
	const std::vector<Amount> &get_ra_amounts() const { return m_ra_amounts; }
};

}  // namespace bytecoin
