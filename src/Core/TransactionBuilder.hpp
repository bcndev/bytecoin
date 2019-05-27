// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "CryptoNote.hpp"
#include "TransactionExtra.hpp"
#include "Wallet.hpp"
#include "logging/LoggerMessage.hpp"
#include "rpc_api.hpp"

namespace cn {

class Currency;
class WalletStateBasic;

class TransactionBuilder {
public:
	Transaction m_transaction;
	struct InputDesc {
		std::vector<api::Output> outputs;
		size_t real_output_index = 0;
		//		KeyPair eph_keys;
		//		InputKey input;
		static bool less_amount(const InputDesc &a, const InputDesc &b) {
			return a.outputs.at(a.real_output_index).amount < b.outputs.at(b.real_output_index).amount;
		}
	};
	std::vector<InputDesc> m_input_descs;
	struct OutputDesc {
		Amount amount;
		AccountAddress addr;
		std::string message;
		static bool less_amount(const OutputDesc &a, const OutputDesc &b) { return a.amount < b.amount; }
	};
	std::vector<OutputDesc> m_output_descs;

	// before calling, make sure mix_outputs do not contain real_output...
	void add_input(const std::vector<api::Output> &mix_outputs, size_t real_output_index);
	void add_output(uint64_t amount, const AccountAddress &to, const std::string &message);

	Transaction sign(
	    const WalletStateBasic &wallet_state, Wallet *wallet, const std::set<AccountAddress> *only_records);

	static KeyPair transaction_keys_from_seed(const Hash &tx_inputs_hash, const Hash &view_seed);
	static Hash generate_output_seed(const Hash &tx_inputs_hash, const Hash &view_seed, const size_t &out_index);
	static void generate_output_secrets(const Hash &output_seed, crypto::SecretKey *output_secret_scalar,
	    crypto::PublicKey *output_secret_point, uint8_t *output_secret_address_type);
	static OutputKey create_output(bool tx_amethyst, const AccountAddress &to, const SecretKey &tx_secret_key,
	    const Hash &tx_inputs_hash, size_t output_index, const Hash &output_seed, PublicKey *output_shared_secret);
	static bool detect_not_our_output(const Wallet *wallet, bool tx_amethyst, const Hash &tid,
	    const Hash &tx_inputs_hash, boost::optional<Wallet::History> *, KeyPair *tx_keys, size_t out_index,
	    const OutputKey &, AccountAddress *, PublicKey *output_shared_secret);
	static bool detect_not_our_output_amethyst(const Hash &tx_inputs_hash, const Hash &output_seed, size_t out_index,
	    const OutputKey &, AccountAddress *, PublicKey *output_shared_secret);

	static BinaryArray encrypt_message_chunk(const std::string &message, const PublicKey &output_shared_secret,
	    const Hash &tx_inputs_hash, const size_t &out_index, size_t mid);
	static bool decrypt_message_chunk(std::string *message, const BinaryArray &encrypted_message,
	    const PublicKey &output_shared_secret, const Hash &tx_inputs_hash, const size_t &out_index, size_t mid);
	static std::string decrypt_message(const std::vector<extra::EncryptedMessage> &encrypted_messages,
	    const PublicKey &output_shared_secret, const Hash &tx_inputs_hash, const size_t &out_index);
};

class UnspentSelector {
	logging::LoggerRef m_log;
	const Currency &m_currency;
	typedef std::vector<api::Output> Unspents;
	typedef std::map<size_t, std::map<size_t, std::vector<api::Output>>> PrettyCoins;
	typedef std::map<Amount, std::vector<api::Output>> NonPrettyCoins;
	Unspents m_unspents;
	Unspents m_used_unspents;
	Unspents m_optimization_unspents;
	void create_coin_index(
	    PrettyCoins *pretty_coins, NonPrettyCoins *non_pretty_coins, NonPrettyCoins *dust_coins, size_t *max_digit);
	void return_coins_to_index(PrettyCoins *pretty_coins, NonPrettyCoins *non_pretty_coins, NonPrettyCoins *dust_coins);
	void optimize_amounts(PrettyCoins *pretty_coins, size_t max_digit, Amount total_amount);
	void combine_optimized_unspents();

	Amount m_used_total   = 0;
	size_t m_inputs_count = 0;
	std::vector<Amount> m_ra_amounts;
	bool select_optimal_outputs(PrettyCoins *pretty_coins, NonPrettyCoins *non_pretty_coins, NonPrettyCoins *dust_coins,
	    size_t max_digit, Amount amount, size_t anonymity, size_t optimization_count, bool small_optimizations);
	void select_max_outputs(PrettyCoins *pretty_coins, NonPrettyCoins *non_pretty_coins, NonPrettyCoins *dust_coins,
	    Amount total_amount, size_t anonymity, size_t max_inputs_count);

public:
	explicit UnspentSelector(logging::ILogger &logger, const Currency &currency, Unspents &&unspents);
	void reset(Unspents &&unspents);
	size_t add_mixed_inputs(
	    TransactionBuilder *builder, size_t anonymity, api::cnd::GetRandomOutputs::Response &&ra_response);

	// if receiver_fee == nullptr, fee will be subtracted from change
	void select_optimal_outputs(size_t max_transaction_size, size_t anonymity, size_t min_anonymity,
	    Amount total_amount, size_t total_outputs, Amount fee_per_byte, std::string optimization_level, Amount *change,
	    Amount *receiver_fee);
	Amount get_used_total() const { return m_used_total; }
	const std::vector<Amount> &get_ra_amounts() const { return m_ra_amounts; }
};

}  // namespace cn
