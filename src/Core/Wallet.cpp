// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "WalletSerializationV1.hpp"
#include "WalletState.hpp"
#include "common/BIPs.hpp"
#include "common/Math.hpp"
#include "common/MemoryStreams.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "common/Words.hpp"
#include "crypto/crypto.hpp"
#include "crypto/crypto_helpers.hpp"
#include "http/JsonRpc.hpp"
#include "platform/Files.hpp"
#include "platform/PathTools.hpp"
#include "platform/Time.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace cn;
using namespace common;
using namespace crypto;

std::string Wallet::net_append(const std::string &net) { return net == "main" ? std::string{} : "_" + net + "net"; }

Wallet::Wallet(const Currency &currency, logging::ILogger &log) : m_currency(currency), m_log(log, "Wallet") {}

AccountAddress Wallet::get_first_address() const { return record_to_address(0); }

std::string Wallet::get_cache_name() const {
	Hash h           = cn_fast_hash(m_view_public_key.data, sizeof(m_view_public_key.data));
	std::string name = common::pod_to_hex(h);
	if (is_view_only()) {
		if (can_view_outgoing_addresses())
			name += "-view-only-voa";
		else
			name += "-view-only";
	}
	return name;
}

bool Wallet::get_look_ahead_record(
    const PublicKey &address_S, size_t *index, WalletRecord *record, AccountAddress *address) {
	auto rit = m_records_map.find(address_S);
	if (rit == m_records_map.end())
		return false;
	invariant(m_wallet_records.at(rit->second).spend_public_key == address_S, "");
	*index   = rit->second;
	*record  = m_wallet_records.at(rit->second);
	*address = record_to_address(*index);
	create_look_ahead_records(rit->second + 1);
	return true;
}

bool Wallet::get_record(size_t index, WalletRecord *record, AccountAddress *address) const {
	if (index >= get_actual_records_count())
		return false;
	*record = m_wallet_records.at(index);
	if (address)
		*address = record_to_address(index);
	return true;
}

bool Wallet::is_our_address(const AccountAddress &v_addr) const {
	size_t index = 0;
	WalletRecord wr;
	return get_record(v_addr, &index, &wr);
}

bool Wallet::prepare_input_for_spend(uint8_t tx_version, const KeyDerivation &kd, const Hash &tx_inputs_hash,
    size_t out_index, const OutputKey &key_output, PublicKey *output_shared_secret, SecretKey *output_secret_key_s,
    SecretKey *output_secret_key_a, size_t *record_index) {
	PublicKey address_S;
	get_output_handler()(tx_version, kd, tx_inputs_hash, out_index, key_output, &address_S, output_shared_secret);
	Amount amount = 0;
	AccountAddress other_address;
	KeyImage key_image;
	return detect_our_output(tx_version, tx_inputs_hash, kd, out_index, address_S, *output_shared_secret, key_output,
	    &amount, output_secret_key_s, output_secret_key_a, &other_address, record_index, &key_image);
}

Hash Wallet::generate_output_seed(const Hash &tx_inputs_hash, const size_t &out_index) const {
	return generate_output_seed(tx_inputs_hash, get_view_seed(), out_index);
}

Hash Wallet::generate_output_seed(const Hash &tx_inputs_hash, const Hash &view_seed, const size_t &out_index) {
	auto add = common::get_varint_data(out_index);
	BinaryArray ba;
	common::append(ba, std::begin(view_seed.data), std::end(view_seed.data));
	common::append(ba, std::begin(tx_inputs_hash.data), std::end(tx_inputs_hash.data));
	common::append(ba, add);

	return crypto::cn_fast_hash(ba);
}

KeyPair Wallet::transaction_keys_from_seed(const Hash &tx_inputs_hash, const Hash &view_seed) {
	BinaryArray ba;
	common::append(ba, std::begin(tx_inputs_hash.data), std::end(tx_inputs_hash.data));
	common::append(ba, std::begin(view_seed.data), std::end(view_seed.data));

	KeyPair tx_keys{};
	tx_keys.secret_key = crypto::hash_to_scalar(ba.data(), ba.size());
	crypto::secret_key_to_public_key(tx_keys.secret_key, &tx_keys.public_key);
	return tx_keys;
}

void Wallet::generate_output_secrets(const Hash &output_seed, SecretKey *output_secret_scalar,
    PublicKey *output_secret_point, uint8_t *output_secret_address_type) {
	*output_secret_scalar                = crypto::bytes_to_scalar(output_seed);
	*output_secret_point                 = crypto::bytes_to_good_point(output_seed);
	Hash output_secret_address_type_hash = crypto::cn_fast_hash(output_seed.data, sizeof(output_seed.data));
	*output_secret_address_type          = output_secret_address_type_hash.data[0];
}
