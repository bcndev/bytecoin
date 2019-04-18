// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "TransactionBuilder.hpp"
#include <iostream>
#include "BlockChain.hpp"
#include "CryptoNoteTools.hpp"
#include "Currency.hpp"
#include "TransactionExtra.hpp"
#include "Wallet.hpp"
#include "WalletStateBasic.hpp"
#include "common/Varint.hpp"
#include "common/string.hpp"
#include "crypto/crypto.hpp"
#include "crypto/crypto_helpers.hpp"
#include "http/JsonRpc.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace cn;
using namespace common;

OutputKey TransactionBuilder::create_output(bool tx_amethyst, const AccountAddress &to, const SecretKey &tx_secret_key,
    const Hash &tx_inputs_hash, size_t output_index, const Hash &output_seed) {
	OutputKey out_key;

	SecretKey output_secret_scalar;
	PublicKey output_secret_point;
	uint8_t output_secret_address_type = 0;
	TransactionBuilder::generate_output_secrets(
	    output_seed, &output_secret_scalar, &output_secret_point, &output_secret_address_type);
	//	std::cout << "generate_output_secrets=" << output_secret_scalar << " " << output_secret_point << " "
	//	          << output_secret_address_type << std::endl;

	if (!tx_amethyst) {
		if (to.type() == typeid(AccountAddressLegacy)) {
			auto &addr                     = boost::get<AccountAddressLegacy>(to);
			const KeyDerivation derivation = crypto::generate_key_derivation(addr.V, tx_secret_key);
			out_key.public_key             = crypto::derive_output_public_key(derivation, output_index, addr.S);
			return out_key;
		}
		throw std::runtime_error(
		    "TransactionBuilder::create_output output type forbidden for transaction version, wait for amethyst upgrade");
	}
	if (to.type() == typeid(AccountAddressLegacy)) {
		auto &addr         = boost::get<AccountAddressLegacy>(to);
		out_key.public_key = crypto::linkable_derive_output_public_key(
		    output_secret_scalar, tx_inputs_hash, output_index, addr.S, addr.V, &out_key.encrypted_secret);
		out_key.encrypted_address_type = AccountAddressLegacy::type_tag ^ output_secret_address_type;
		//		std::cout << "AccountAddressLegacy=" << addr.S << " " << addr.V << " " << out_key.public_key << " "
		//		          << out_key.encrypted_secret << std::endl;
		return out_key;
	}
	if (to.type() == typeid(AccountAddressAmethyst)) {
		auto &addr         = boost::get<AccountAddressAmethyst>(to);
		out_key.public_key = crypto::unlinkable_derive_output_public_key(
		    output_secret_point, tx_inputs_hash, output_index, addr.S, addr.Sv, &out_key.encrypted_secret);
		out_key.encrypted_address_type = AccountAddressAmethyst::type_tag ^ output_secret_address_type;
		//		std::cout << "AccountAddressAmethyst=" << addr.S << " " << addr.Sv << " " << out_key.public_key << " "
		//		          << out_key.encrypted_secret << std::endl;
		return out_key;
	}
	throw std::runtime_error("TransactionBuilder::create_output unknown address type");
}

bool TransactionBuilder::detect_not_our_output(const Wallet *wallet, bool tx_amethyst, const Hash &tid,
    const Hash &tx_inputs_hash, boost::optional<Wallet::History> *history, KeyPair *tx_keys, size_t out_index,
    const OutputKey &key_output, AccountAddress *address) {
	if (!tx_amethyst) {
		if (!*history)
			*history = wallet->load_history(tid);
		if (!history->get().empty()) {
			if (tx_keys->secret_key == SecretKey{})
				*tx_keys = transaction_keys_from_seed(tx_inputs_hash, wallet->get_view_seed());
			for (const auto &addr : history->get()) {
				const KeyDerivation derivation = generate_key_derivation(addr.V, tx_keys->secret_key);
				const PublicKey guess_key      = crypto::derive_output_public_key(derivation, out_index, addr.S);
				if (guess_key == key_output.public_key) {
					*address = addr;
					return true;
				}
			}
		}
		return false;
	}
	// In amethyst, we should always detect out outputs if we know view_seed
	Hash output_seed;
	if (wallet->get_hw()) {
		output_seed = wallet->get_hw()->generate_output_seed(tx_inputs_hash, out_index);
	} else {
		output_seed = TransactionBuilder::generate_output_seed(tx_inputs_hash, wallet->get_view_seed(), out_index);
	}
	return detect_not_our_output_amethyst(tx_inputs_hash, output_seed, out_index, key_output, address);
}

bool TransactionBuilder::detect_not_our_output_amethyst(const Hash &tx_inputs_hash, const Hash &output_seed,
    size_t out_index, const OutputKey &key_output, AccountAddress *address) {
	SecretKey output_secret_scalar;
	PublicKey output_secret_point;
	uint8_t output_secret_address_type = 0;
	TransactionBuilder::generate_output_secrets(
	    output_seed, &output_secret_scalar, &output_secret_point, &output_secret_address_type);

	const uint8_t address_type = key_output.encrypted_address_type ^ output_secret_address_type;
	if (address_type == AccountAddressLegacy::type_tag) {
		AccountAddressLegacy addr;
		crypto::linkable_underive_address(output_secret_scalar, tx_inputs_hash, out_index, key_output.public_key,
		    key_output.encrypted_secret, &addr.S, &addr.V);
		*address = addr;
		return true;
	}
	if (address_type == AccountAddressAmethyst::type_tag) {
		AccountAddressAmethyst u_address;
		crypto::unlinkable_underive_address(&u_address.S, &u_address.Sv, output_secret_point, tx_inputs_hash, out_index,
		    key_output.public_key, key_output.encrypted_secret);
		*address = u_address;
		return true;
	}
	return false;
}

void TransactionBuilder::add_output(uint64_t amount, const AccountAddress &to) {
	m_output_descs.push_back(OutputDesc{amount, to});
}

static bool APIOutputLessGlobalIndex(const api::Output &a, const api::Output &b) {
	return a.stack_index < b.stack_index;
}
static bool APIOutputEqualGlobalIndex(const api::Output &a, const api::Output &b) {
	return a.stack_index == b.stack_index;
}

void TransactionBuilder::add_input(const std::vector<api::Output> &mix_outputs, size_t real_output_index) {
	m_input_descs.push_back(InputDesc{mix_outputs, real_output_index});
}

KeyPair TransactionBuilder::transaction_keys_from_seed(const Hash &tx_inputs_hash, const Hash &view_seed) {
	BinaryArray ba;
	common::append(ba, std::begin(tx_inputs_hash.data), std::end(tx_inputs_hash.data));
	common::append(ba, std::begin(view_seed.data), std::end(view_seed.data));

	KeyPair tx_keys{};
	tx_keys.secret_key = crypto::hash_to_scalar(ba.data(), ba.size());
	crypto::secret_key_to_public_key(tx_keys.secret_key, &tx_keys.public_key);
	return tx_keys;
}

Hash TransactionBuilder::generate_output_seed(
    const Hash &tx_inputs_hash, const Hash &view_seed, const size_t &out_index) {
	auto add = common::get_varint_data(out_index);
	BinaryArray ba;
	common::append(ba, std::begin(view_seed.data), std::end(view_seed.data));
	common::append(ba, std::begin(tx_inputs_hash.data), std::end(tx_inputs_hash.data));
	common::append(ba, add);

	return crypto::cn_fast_hash(ba);
}

void TransactionBuilder::generate_output_secrets(const Hash &output_seed, SecretKey *output_secret_scalar,
    PublicKey *output_secret_point, uint8_t *output_secret_address_type) {
	*output_secret_scalar                = crypto::bytes_to_scalar(output_seed);
	*output_secret_point                 = crypto::bytes_to_good_point(output_seed);
	Hash output_secret_address_type_hash = crypto::cn_fast_hash(output_seed.data, sizeof(output_seed.data));
	*output_secret_address_type          = output_secret_address_type_hash.data[0];
}

Transaction TransactionBuilder::sign(
    const WalletStateBasic &wallet_state, Wallet *wallet, const std::set<AccountAddress> *only_records) {
	std::shuffle(m_output_descs.begin(), m_output_descs.end(), crypto::random_engine<size_t>{});
	std::shuffle(m_input_descs.begin(), m_input_descs.end(), crypto::random_engine<size_t>{});
	std::stable_sort(m_output_descs.begin(), m_output_descs.end(), OutputDesc::less_amount);
	std::stable_sort(m_input_descs.begin(), m_input_descs.end(), InputDesc::less_amount);
	std::cout << "TransactionBuilder::sign" << std::endl << std::endl;
	const bool is_tx_amethyst = m_transaction.version >= wallet_state.get_currency().amethyst_transaction_version;
	// First we create inputs, because we need tx_inputs_hash
	m_transaction.inputs.reserve(m_input_descs.size());

	std::vector<SecretKey> all_secret_keys_s;  // empty if hw
	std::vector<SecretKey> all_secret_keys_a;  // empty if hw
	std::vector<size_t> all_sec_indexes;
	std::vector<KeyImage> all_keyimages;
	std::vector<std::vector<PublicKey>> all_output_keys;
	std::vector<BinaryArray> output_secret_hash_args;  // for hw
	std::vector<size_t> address_indexes;
	for (size_t i = 0; i != m_input_descs.size(); ++i) {
		const InputDesc &desc         = m_input_descs[i];
		const api::Output &our_output = desc.outputs.at(desc.real_output_index);
		std::vector<PublicKey> output_keys;
		for (const auto &o : desc.outputs)
			output_keys.push_back(o.public_key);
		InputKey input_key;
		input_key.key_image = our_output.key_image;
		input_key.amount    = our_output.amount;
		for (const auto &o : desc.outputs)
			input_key.output_indexes.push_back(o.stack_index);
		input_key.output_indexes = absolute_output_offsets_to_relative(input_key.output_indexes);

		TransactionPrefix ptx;
		api::Transaction atx;
		invariant(wallet_state.get_transaction(our_output.transaction_hash, &ptx, &atx) &&
		              our_output.index_in_transaction < ptx.outputs.size(),
		    "Originating transaction for output not found");
		const auto &key_output = boost::get<OutputKey>(ptx.outputs.at(our_output.index_in_transaction));
		Hash other_inputs_hash = get_transaction_inputs_hash(ptx);
		KeyDerivation other_kd = crypto::generate_key_derivation(atx.public_key, wallet->get_view_secret_key());

		AccountAddress address;
		if (!wallet_state.get_currency().parse_account_address_string(our_output.address, &address))
			throw json_rpc::Error(json_rpc::INTERNAL_ERROR, "Could not parse address " + our_output.address);
		invariant(!only_records || only_records->count(address) != 0, "Output with wrong address selected by selector");
		all_keyimages.push_back(our_output.key_image);
		all_output_keys.push_back(output_keys);
		all_sec_indexes.push_back(desc.real_output_index);

		size_t record_index = 0;
		SecretKey output_secret_key_s;
		SecretKey output_secret_key_a;
		BinaryArray output_secret_hash_arg;
		if (!wallet->prepare_input_for_spend(ptx.version, other_kd, other_inputs_hash, our_output.index_in_transaction,
		        key_output, &output_secret_hash_arg, &output_secret_key_s, &output_secret_key_a, &record_index)) {
			throw json_rpc::Error(json_rpc::INTERNAL_ERROR, "No keys in wallet for address " + our_output.address);
		}
		output_secret_hash_args.push_back(output_secret_hash_arg);
		all_secret_keys_s.push_back(output_secret_key_s);
		all_secret_keys_a.push_back(output_secret_key_a);
		address_indexes.push_back(record_index);

		m_transaction.inputs.push_back(input_key);
	}
	if (wallet->get_hw()) {
		wallet->get_hw()->sign_start(m_transaction.version, m_transaction.unlock_block_or_timestamp,
		    m_input_descs.size(), m_output_descs.size(), m_transaction.extra.size());
		for (size_t i = 0; i != m_input_descs.size(); ++i) {
			const InputKey &input_key = boost::get<InputKey>(m_transaction.inputs.at(i));
			wallet->get_hw()->sign_add_input(
			    input_key.amount, input_key.output_indexes, output_secret_hash_args.at(i), address_indexes.at(i));
		}
	}
	// Deterministic generation of tx private key.
	const Hash tx_inputs_hash = get_transaction_inputs_hash(m_transaction);
	//	std::cout << "tx_inputs_hash=" << tx_inputs_hash << std::endl;
	const KeyPair tx_keys = transaction_keys_from_seed(tx_inputs_hash, wallet->get_view_seed());

	if (!is_tx_amethyst)  // Never in case of hw, because we set extra size beforehand
		extra_add_transaction_public_key(m_transaction.extra, tx_keys.public_key);
	// Now when we set tx keys we can derive output keys
	m_transaction.outputs.resize(m_output_descs.size());
	for (size_t out_index = 0; out_index != m_output_descs.size(); ++out_index) {
		OutputKey out_key;
		Amount amount            = m_output_descs.at(out_index).amount;
		const AccountAddress &to = m_output_descs.at(out_index).addr;
		if (wallet->get_hw()) {
			size_t record_index = 0;
			WalletRecord record;
			if (wallet->get_record(to, &record_index, &record)) {
				wallet->get_hw()->sign_add_output(true, amount, record_index, 0, PublicKey{}, PublicKey{},
				    &out_key.public_key, &out_key.encrypted_secret, &out_key.encrypted_address_type);
			} else {
				if (to.type() == typeid(AccountAddressLegacy)) {
					auto &addr = boost::get<AccountAddressLegacy>(to);
					wallet->get_hw()->sign_add_output(false, amount, 0, AccountAddressLegacy::type_tag, addr.S, addr.V,
					    &out_key.public_key, &out_key.encrypted_secret, &out_key.encrypted_address_type);
				} else if (to.type() == typeid(AccountAddressAmethyst)) {
					auto &addr = boost::get<AccountAddressAmethyst>(to);
					wallet->get_hw()->sign_add_output(false, amount, 0, AccountAddressAmethyst::type_tag, addr.S,
					    addr.Sv, &out_key.public_key, &out_key.encrypted_secret, &out_key.encrypted_address_type);
				} else
					throw std::runtime_error("TransactionBuilder::sign unknown address type");
			}
		} else {
			Hash output_seed = generate_output_seed(tx_inputs_hash, wallet->get_view_seed(), out_index);
			out_key          = TransactionBuilder::create_output(is_tx_amethyst, m_output_descs.at(out_index).addr,
                tx_keys.secret_key, tx_inputs_hash, out_index, output_seed);
		}
		out_key.amount                      = amount;
		m_transaction.outputs.at(out_index) = out_key;
	}
	if (wallet->get_hw()) {
		wallet->get_hw()->sign_add_extra(m_transaction.extra);
	}
	/*	for (size_t i = 0; i != m_input_descs.size(); ++i) {
	        if (i < all_secret_keys_s.size())
	            std::cout << "all_secret_keys_s[" << i << "]=" << all_secret_keys_s.at(i) << std::endl;
	        if (i < all_secret_keys_a.size())
	            std::cout << "all_secret_keys_a[" << i << "]=" << all_secret_keys_a.at(i) << std::endl;
	        std::cout << "all_keyimages[" << i << "]=" << all_keyimages.at(i) << std::endl;
	        std::cout << "output_secret_hashes[" << i << "]=" << output_secret_hashes.at(i) << std::endl;
	        std::cout << "address_indexes[" << i << "]=" << address_indexes.at(i) << std::endl;
	    }*/
	const Hash tx_prefix_hash = get_transaction_prefix_hash(m_transaction);
	//	std::cout << "tx_prefix_hash=" << tx_prefix_hash << std::endl;
	if (wallet->get_hw()) {
		auto rsa = wallet->get_hw()->generate_ring_signature_amethyst(
		    tx_prefix_hash, output_secret_hash_args, address_indexes, all_keyimages, all_output_keys, all_sec_indexes);
		invariant(crypto::check_ring_signature_amethyst(tx_prefix_hash, all_keyimages, all_output_keys, rsa), "");
		m_transaction.signatures = std::move(rsa);
	} else if (is_tx_amethyst) {
		const RingSignatureAmethyst rsa = generate_ring_signature_amethyst(
		    tx_prefix_hash, all_keyimages, all_output_keys, all_secret_keys_s, all_secret_keys_a, all_sec_indexes);
		invariant(crypto::check_ring_signature_amethyst(tx_prefix_hash, all_keyimages, all_output_keys, rsa), "");
		m_transaction.signatures = std::move(rsa);
	} else {
		RingSignatures ring_signatures;
		for (size_t i = 0; i != m_input_descs.size(); ++i) {
			const RingSignature signature =
			    generate_ring_signature(tx_prefix_hash, all_keyimages.at(i), all_output_keys.at(i).data(),
			        all_output_keys.at(i).size(), all_secret_keys_a.at(i), all_sec_indexes.at(i));
			ring_signatures.signatures.push_back(signature);
		}
		m_transaction.signatures = std::move(ring_signatures);
	}
	return m_transaction;
}

UnspentSelector::UnspentSelector(logging::ILogger &logger, const Currency &currency, Unspents &&unspents)
    : m_log(logger, "UnspentSelector"), m_currency(currency), m_unspents(std::move(unspents)) {}

void UnspentSelector::reset(Unspents &&unspents) {
	m_unspents = std::move(unspents);
	m_used_unspents.clear();
	m_optimization_unspents.clear();
	m_used_total   = 0;
	m_inputs_count = 0;
	m_ra_amounts.clear();
}

size_t UnspentSelector::add_mixed_inputs(
    TransactionBuilder *builder, size_t anonymity, api::cnd::GetRandomOutputs::Response &&ra_response) {
	size_t actual_anonymity = anonymity;
	for (const auto &uu : m_used_unspents) {
		std::vector<api::Output> mix_outputs;
		auto &our_ra_outputs = ra_response.outputs[uu.amount];
		while (mix_outputs.size() < anonymity + 1 && !our_ra_outputs.empty()) {
			if (uu.amount != our_ra_outputs.back().amount)
				throw std::runtime_error("Got outputs with wrong amounts from GetRandomOutputs call");
			mix_outputs.push_back(std::move(our_ra_outputs.back()));
			our_ra_outputs.pop_back();
		}
		std::sort(mix_outputs.begin(), mix_outputs.end(), APIOutputLessGlobalIndex);
		mix_outputs.erase(
		    std::unique(mix_outputs.begin(), mix_outputs.end(), APIOutputEqualGlobalIndex), mix_outputs.end());
		int best_distance = 0;
		size_t best_index = mix_outputs.size();
		for (size_t i = 0; i != mix_outputs.size(); ++i) {
			int distance = abs(int(uu.stack_index) - int(mix_outputs[i].stack_index));
			if (best_index == mix_outputs.size() || distance < best_distance) {
				best_index    = i;
				best_distance = distance;
			}
		}
		if (best_index != mix_outputs.size())  // mix_outputs not empty
			mix_outputs.erase(mix_outputs.begin() + best_index);
		actual_anonymity = std::min(actual_anonymity, mix_outputs.size());
		mix_outputs.insert(mix_outputs.begin() + best_index, uu);
		invariant(std::is_sorted(mix_outputs.begin(), mix_outputs.end(), APIOutputLessGlobalIndex), "");
		builder->add_input(mix_outputs, best_index);
	}
	return actual_anonymity;
}

const bool detailed_output  = false;
constexpr Amount fake_large = 10000000000000000000ULL;
// optimize negative amounts by adding this large number to them
constexpr size_t OPTIMIZATIONS_PER_TX            = 50;
constexpr size_t OPTIMIZATIONS_PER_TX_AGGRESSIVE = 200;
constexpr size_t MEDIAN_PERCENT                  = 25;  // make tx up to X% of block
constexpr size_t MEDIAN_PERCENT_AGGRESSIVE       = 50;  // make tx up to X% of block
constexpr size_t STACK_OPTIMIZATION_THRESHOLD    = 20;  // If any coin stack is larger, we will spend 10 coins.
constexpr size_t TWO_THRESHOLD                   = 10;
// if any of 2 coin stacks is larger, we will use 2 coins to cover single digit (e.g. 7 + 9 for 6)

void UnspentSelector::select_optimal_outputs(size_t max_transaction_size, size_t anonymity, size_t min_anonymity,
    Amount total_amount, size_t total_outputs, Amount fee_per_byte, std::string optimization_level, Amount *change,
    Amount *receiver_fee) {
	PrettyCoins pretty_coins;
	size_t max_digits;
	NonPrettyCoins non_pretty_coins;
	NonPrettyCoins dust_coins;
	create_coin_index(&pretty_coins, &non_pretty_coins, &dust_coins, &max_digits);
	Amount fee           = 0;
	size_t optimizations = (optimization_level == "aggressive")
	                           ? OPTIMIZATIONS_PER_TX_AGGRESSIVE
	                           : (optimization_level == "minimal") ? 9 : OPTIMIZATIONS_PER_TX;
	bool small_optimizations = true;
	// 9 allows some dust optimization, but never "stack of coins" optimization.
	// "Minimal" optimization does not mean no optimization
	const size_t optimization_median_percent =
	    (optimization_level == "aggressive") ? MEDIAN_PERCENT_AGGRESSIVE : MEDIAN_PERCENT;
	const size_t optimization_median = max_transaction_size * optimization_median_percent / 100;
	const Amount dust_threshold      = m_currency.self_dust_threshold;
	while (true) {
		if (!select_optimal_outputs(&pretty_coins, &non_pretty_coins, &dust_coins, max_digits,
		        total_amount + (receiver_fee ? 0 : fee), anonymity, optimizations, small_optimizations))
			throw json_rpc::Error(api::walletd::CreateTransaction::NOT_ENOUGH_FUNDS, "Not enough spendable funds");
		Amount change_dust_fee = (m_used_total - total_amount - (receiver_fee ? 0 : fee)) % dust_threshold;
		size_t tx_size = get_maximum_tx_size(m_inputs_count, total_outputs + m_currency.get_max_amount_outputs(),
		    anonymity);  // Expected max change outputs
		if (tx_size > optimization_median && (optimizations > 0 || small_optimizations)) {
			return_coins_to_index(&pretty_coins, &non_pretty_coins, &dust_coins);
			if (optimizations == 0)
				small_optimizations = false;
			optimizations /= 2;
			if (optimizations < 10)
				optimizations = 0;  // no point trying so many times for so few optimizations
			continue;
		}
		if (fee_per_byte >
		    std::numeric_limits<Amount>::max() / tx_size / 2)  // *2 to take into account + dust_threshold :)
			throw json_rpc::Error(json_rpc::INVALID_PARAMS,
			    "'fee_per_byte' is too large for transaction of size " + common::to_string(tx_size));
		Amount size_fee = fee_per_byte * tx_size;
		if (tx_size > max_transaction_size) {
			fee = ((size_fee + dust_threshold - 1) / dust_threshold) * dust_threshold;
			return_coins_to_index(&pretty_coins, &non_pretty_coins, &dust_coins);
			auto ets = get_maximum_tx_size(0, total_outputs + 2 * m_currency.get_max_amount_outputs(), anonymity);
			auto max_inputs_count = (max_transaction_size - ets) / get_maximum_tx_input_size(anonymity);
			select_max_outputs(&pretty_coins, &non_pretty_coins, &dust_coins, std::numeric_limits<Amount>::max(),
			    anonymity, max_inputs_count);
			auto total_anon = m_used_total - fee;
			return_coins_to_index(&pretty_coins, &non_pretty_coins, &dust_coins);
			max_inputs_count = (max_transaction_size - ets) / get_maximum_tx_input_size(min_anonymity);
			select_max_outputs(
			    &pretty_coins, &non_pretty_coins, &dust_coins, std::numeric_limits<Amount>::max(), 0, max_inputs_count);
			auto total_zero_anon = m_used_total - fee;
			std::string msg =
			    "Transaction with desired amount is too big (cannot fit in block). Max amount you can send with requested anonymity is " +
			    m_currency.format_amount(total_anon) + " (" + m_currency.format_amount(total_zero_anon) +
			    " with anonymity " + common::to_string(min_anonymity) + ")";
			throw api::walletd::CreateTransaction::ErrorTransactionTooBig(msg, total_anon, total_zero_anon);
		}
		if (fee + change_dust_fee >= size_fee) {
			if (receiver_fee) {
				*receiver_fee = fee;
				*change       = m_used_total - total_amount - change_dust_fee;
			} else
				*change = m_used_total - total_amount - fee - change_dust_fee;
			combine_optimized_unspents();
			std::string final_coins;
			for (const auto &uu : m_used_unspents)
				final_coins += " " + common::to_string(uu.amount);
			m_log(logging::INFO) << "Selected used_total=" << m_used_total << " for total_amount=" << total_amount
			                     << ", final coins" << final_coins << std::endl;
			return;
		}
		fee = ((size_fee - change_dust_fee + dust_threshold - 1) / dust_threshold) * dust_threshold;
		return_coins_to_index(&pretty_coins, &non_pretty_coins, &dust_coins);
	}
}

void UnspentSelector::create_coin_index(
    PrettyCoins *pretty_coins, NonPrettyCoins *non_pretty_coins, NonPrettyCoins *dust_coins, size_t *max_digit) {
	*max_digit = 0;
	// We wish our coin index reversed, because we use pop_back to get coins from there
	for (auto uit = m_unspents.rbegin(); uit != m_unspents.rend(); ++uit) {
		api::Output &un = *uit;
		//		if (m_currency.is_dust(un.amount)) {
		//			(*dust_coins)[un.amount].push_back(un);
		//			continue;
		//		}
		Amount am    = un.amount;
		size_t digit = 0;
		while (am % 10 == 0) {
			digit += 1;
			am /= 10;
		}
		if (am <= 9) {
			*max_digit = std::max(*max_digit, digit);
			(*pretty_coins)[digit][static_cast<size_t>(am)].push_back(un);
		} else
			(*non_pretty_coins)[un.amount].push_back(un);
	}
}

void UnspentSelector::combine_optimized_unspents() {
	for (auto &&un : m_optimization_unspents) {
		m_ra_amounts.push_back(un.amount);
	}
	m_used_unspents.insert(m_used_unspents.end(), m_optimization_unspents.begin(), m_optimization_unspents.end());
	m_optimization_unspents.clear();
}

void UnspentSelector::return_coins_to_index(
    PrettyCoins *pretty_coins, NonPrettyCoins *non_pretty_coins, NonPrettyCoins *dust_coins) {
	// First remove all optimized coins.
	for (auto &&un : m_optimization_unspents) {
		m_used_total -= un.amount;
		m_inputs_count -= 1;
		Amount am    = un.amount;
		size_t digit = 0;
		while (am % 10 == 0) {
			digit += 1;
			am /= 10;
		}
		if (am <= 9)
			(*pretty_coins)[digit][static_cast<size_t>(am)].push_back(std::move(un));
		else
			(*non_pretty_coins)[un.amount].push_back(std::move(un));
	}
	m_optimization_unspents.clear();
}

void UnspentSelector::optimize_amounts(PrettyCoins *pretty_coins, size_t max_digit, Amount total_amount) {
	if (detailed_output)
		m_log(logging::INFO) << "Sub optimizing amount=" << fake_large + total_amount - m_used_total
		                     << " total_amount=" << total_amount << " used_total=" << m_used_total << std::endl;
	Amount digit_amount = 1;
	for (size_t digit = 0; digit != max_digit + 1; ++digit, digit_amount *= 10) {
		if (m_used_total >= total_amount && digit_amount > m_used_total)  // No optimization far beyond requested sum
			break;
		Amount am = 10 - ((fake_large + total_amount + digit_amount - 1 - m_used_total) / digit_amount) % 10;
		if (am == 10)
			continue;
		auto dit = pretty_coins->find(digit);
		if (dit == pretty_coins->end())  // No coins for digit
			continue;
		size_t best_two_counts[2] = {};
		size_t best_weight        = 0;
		for (const auto &ait : dit->second)
			for (const auto &bit : dit->second) {
				if ((ait.first + bit.first + am) % 10 == 0 &&
				    (ait.second.size() >= TWO_THRESHOLD || bit.second.size() >= TWO_THRESHOLD) &&
				    (ait.second.size() + bit.second.size()) > best_weight) {
					best_weight        = ait.second.size() + bit.second.size();
					best_two_counts[0] = ait.first;
					best_two_counts[1] = bit.first;
				}
			}
		if (best_weight != 0) {
			if (detailed_output)
				m_log(logging::INFO) << "Found pair for digit=" << digit << " am=" << 10 - am << " coins=("
				                     << best_two_counts[0] << ", " << best_two_counts[1]
				                     << ") sum weight=" << best_weight << std::endl;
			for (size_t i = 0; i != 2; ++i) {
				auto &uns = dit->second[best_two_counts[i]];
				auto &un  = uns.back();
				m_used_total += un.amount;
				m_inputs_count += 1;
				m_optimization_unspents.push_back(std::move(un));
				uns.pop_back();
				if (uns.empty())
					dit->second.erase(best_two_counts[i]);
				if (dit->second.empty())
					pretty_coins->erase(dit);
			}
			continue;
		}
		size_t best_single = 0;
		best_weight        = 0;
		for (const auto &ait : dit->second)
			if ((ait.first + am) % 10 == 0) {
				best_single = ait.first;
				break;
			} else if (ait.first > 10 - am && ait.second.size() > best_weight) {
				best_weight = ait.second.size();
				best_single = ait.first;
			}
		if (best_single != 0) {
			if (detailed_output)
				m_log(logging::INFO) << "Found single for digit=" << digit << " am=" << 10 - am
				                     << " coin=" << best_single << " weight=" << best_weight << std::endl;
			auto &uns = dit->second[best_single];
			auto &un  = uns.back();
			m_used_total += un.amount;
			m_inputs_count += 1;
			m_optimization_unspents.push_back(std::move(un));
			uns.pop_back();
			if (uns.empty())
				dit->second.erase(best_single);
			if (dit->second.empty())
				pretty_coins->erase(dit);
			continue;
		}
		if (detailed_output)
			m_log(logging::INFO) << "Found nothing for digit=" << digit << std::endl;
	}
	if (detailed_output)
		m_log(logging::INFO) << "Sub optimized used_total=" << m_used_total << " for total=" << total_amount
		                     << std::endl;
}

bool UnspentSelector::select_optimal_outputs(PrettyCoins *pretty_coins, NonPrettyCoins *non_pretty_coins,
    NonPrettyCoins *dust_coins, size_t max_digit, Amount total_amount, size_t anonymity, size_t optimization_count,
    bool small_optimizations) {
	// Optimize for roundness of used_total - total_amount;
	//    [digit:size:outputs]
	if (detailed_output)
		m_log(logging::INFO) << "Optimizing amount=" << fake_large + total_amount - m_used_total
		                     << " total_amount=" << total_amount << " used_total=" << m_used_total << std::endl;
	if (anonymity == 0) {
		if (m_used_total < total_amount) {
			// Find smallest dust coin >= total_amount - used_total, it can be very
			// large
			auto duit = dust_coins->lower_bound(total_amount - m_used_total);
			if (duit != dust_coins->end()) {
				auto &un = duit->second.back();
				if (detailed_output)
					m_log(logging::INFO) << "Found single large dust coin=" << un.amount << std::endl;
				m_used_total += un.amount;
				m_inputs_count += 1;
				m_optimization_unspents.push_back(std::move(un));
				duit->second.pop_back();
				if (duit->second.empty())
					dust_coins->erase(duit);
			}
		}
		// Fill with dust coins, but no more than K coins.
		while (m_used_total < total_amount && !dust_coins->empty() && optimization_count >= 1) {
			auto duit = --dust_coins->end();
			auto &un  = duit->second.back();
			if (detailed_output)
				m_log(logging::INFO) << "Found optimization dust coin=" << un.amount << std::endl;
			m_used_total += un.amount;
			m_inputs_count += 1;
			optimization_count -= 1;
			m_optimization_unspents.push_back(std::move(un));
			duit->second.pop_back();
			if (duit->second.empty())
				dust_coins->erase(duit);
		}
	}
	// Fill with non-pretty coins, but no more than K coins.
	while (m_used_total < total_amount && !non_pretty_coins->empty() && optimization_count >= 1) {
		auto duit = --non_pretty_coins->end();
		auto &un  = duit->second.back();
		if (detailed_output)
			m_log(logging::INFO) << "Found optimization non-pretty coin=" << un.amount << std::endl;
		m_used_total += un.amount;
		m_inputs_count += 1;
		optimization_count -= 1;
		m_optimization_unspents.push_back(std::move(un));
		duit->second.pop_back();
		if (duit->second.empty())
			non_pretty_coins->erase(duit);
	}
	// Add coins from large stacks, up to optimization_count
	while (optimization_count >= 10) {
		size_t best_weight                   = STACK_OPTIMIZATION_THRESHOLD;
		std::vector<api::Output> *best_stack = nullptr;
		for (auto &hit : *pretty_coins)
			for (auto &ait : hit.second)
				if (ait.second.size() > best_weight) {
					best_weight = ait.second.size();
					best_stack  = &ait.second;
				}
		if (!best_stack)
			break;
		for (int i = 0; i != 10; ++i) {
			auto &un = best_stack->back();
			if (detailed_output)
				m_log(logging::INFO) << "Found optimization stack for coin=" << un.amount << std::endl;
			m_used_total += un.amount;
			m_inputs_count += 1;
			optimization_count -= 1;
			m_optimization_unspents.push_back(std::move(un));
			best_stack->pop_back();  // Will never become empty because of threshold
		}
	}
	optimize_amounts(pretty_coins, max_digit, total_amount);
	if (m_used_total >= total_amount)
		return true;
	// Find smallest coin >= total_amount - used_total
	bool found          = false;
	Amount digit_amount = 1;
	for (size_t digit = 0; !found && digit != max_digit + 1; ++digit, digit_amount *= 10) {
		auto dit = pretty_coins->find(digit);
		if (dit == pretty_coins->end())  // No coins for digit
			continue;
		for (auto ait = dit->second.begin(); ait != dit->second.end(); ++ait)
			if (!ait->second.empty() && ait->first * digit_amount >= total_amount - m_used_total) {
				if (detailed_output)
					m_log(logging::INFO) << "Found single large coin for digit=" << digit << " coin=" << ait->first
					                     << std::endl;
				auto &uns = dit->second[ait->first];
				auto &un  = uns.back();
				m_used_total += un.amount;
				m_inputs_count += 1;
				m_optimization_unspents.push_back(std::move(un));
				uns.pop_back();
				if (uns.empty())
					dit->second.erase(ait);
				if (dit->second.empty())
					pretty_coins->erase(dit);
				found = true;
				break;
			}
	}
	if (m_used_total >= total_amount)
		return true;
	// Use largest coins (including dust if anonymity == 0) until amount satisfied
	return_coins_to_index(pretty_coins, non_pretty_coins, dust_coins);
	select_max_outputs(
	    pretty_coins, non_pretty_coins, dust_coins, total_amount, anonymity, std::numeric_limits<size_t>::max());
	if (small_optimizations)
		optimize_amounts(pretty_coins, max_digit, total_amount);
	return m_used_total >= total_amount;
}

void UnspentSelector::select_max_outputs(PrettyCoins *pretty_coins, NonPrettyCoins *non_pretty_coins,
    NonPrettyCoins *dust_coins, Amount total_amount, size_t anonymity, size_t max_inputs_count) {
	while (m_used_total < total_amount && m_inputs_count < max_inputs_count) {
		if (pretty_coins->empty() && non_pretty_coins->empty() && (anonymity != 0 || dust_coins->empty()))
			return;
		Amount ha_amount = 0;
		Amount np_amount = 0;
		Amount du_amount = 0;
		if (!pretty_coins->empty()) {
			auto dit  = --pretty_coins->end();
			auto ait  = --dit->second.end();
			ha_amount = ait->second.back().amount;
		}
		if (!non_pretty_coins->empty()) {
			auto duit = --non_pretty_coins->end();
			np_amount = duit->second.back().amount;
		}
		if (anonymity == 0 && !dust_coins->empty()) {
			auto duit = --dust_coins->end();
			du_amount = duit->second.back().amount;
		}
		if (ha_amount > np_amount && ha_amount > du_amount) {
			auto dit  = --pretty_coins->end();
			auto ait  = --dit->second.end();
			auto &uns = ait->second;
			auto &un  = uns.back();
			if (detailed_output)
				m_log(logging::INFO) << "Found filler coin=" << un.amount << std::endl;
			m_used_total += un.amount;
			m_inputs_count += 1;
			m_optimization_unspents.push_back(std::move(un));
			uns.pop_back();
			if (uns.empty())
				dit->second.erase(ait);
			if (dit->second.empty())
				pretty_coins->erase(dit);
			continue;
		}
		if (np_amount > ha_amount && np_amount > du_amount) {
			auto duit = --non_pretty_coins->end();
			auto &un  = duit->second.back();
			if (detailed_output)
				m_log(logging::INFO) << "Found filler non-pretty coin=" << un.amount << std::endl;
			m_used_total += un.amount;
			m_inputs_count += 1;
			m_optimization_unspents.push_back(std::move(un));
			duit->second.pop_back();
			if (duit->second.empty())
				non_pretty_coins->erase(duit);
			continue;
		}
		auto duit = --dust_coins->end();
		auto &un  = duit->second.back();
		if (detailed_output)
			m_log(logging::INFO) << "Found filler dust coin=" << un.amount << std::endl;
		m_used_total += un.amount;
		m_inputs_count += 1;
		m_optimization_unspents.push_back(std::move(un));
		duit->second.pop_back();
		if (duit->second.empty())
			dust_coins->erase(duit);
	}
}
