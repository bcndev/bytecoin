// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletHD.hpp"
#include <boost/algorithm/string.hpp>
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "common/BIPs.hpp"
#include "common/Math.hpp"
#include "common/MemoryStreams.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "crypto/crypto.hpp"
#include "crypto/crypto_helpers.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

#ifndef __EMSCRIPTEN__
#include <thread>
#endif

using namespace cn;
using namespace common;
using namespace crypto;

static const std::string current_version = "CryptoNoteWallet1";
#ifdef __EMSCRIPTEN__
static const size_t GENERATE_AHEAD = 2000;  // TODO - move to better place
#else
static const size_t GENERATE_AHEAD = 20000;  // TODO - move to better place
#endif
/*std::string WalletHD::generate_mnemonic(size_t bits, uint32_t version) {
    //	using common::BITS_PER_WORD;
    //	using common::crc32_reverse_step_zero;
    //	using common::crc32_step_zero;
    //	using common::word_crc32_adj;
    //	using common::word_ptrs;
    //	using common::words_bylen;
    //	using common::WORDS_COUNT;
    //	using common::WORDS_MAX_LEN;
    //	using common::WORDS_MIN_LEN;
    std::unordered_map<uint32_t, size_t> last_word(WORDS_COUNT);
    for (size_t i = 0; i != WORDS_COUNT; i++) {
        uint32_t crc32_suffix = version ^ word_crc32_adj[i];
        for (auto p = word_ptrs[i]; p != word_ptrs[i + 1]; p++) {
            crc32_suffix = crc32_reverse_step_zero(crc32_suffix);
        }
        last_word[crc32_suffix] = i;
    }
    size_t words_in_prefix = (bits - 1) / BITS_PER_WORD + 1;
    size_t words_total     = words_in_prefix + 3;
    std::unique_ptr<size_t[]> word_ids(new size_t[words_total]);
    while (true) {
        uint32_t crc32_prefix = 0;
        for (size_t i = 0; i != words_in_prefix; i++) {
            size_t j    = crypto::rand<size_t>() % WORDS_COUNT;
            word_ids[i] = j;
            for (auto p = word_ptrs[j]; p != word_ptrs[j + 1]; p++) {
                crc32_prefix = crc32_step_zero(crc32_prefix);
            }
            crc32_prefix ^= word_crc32_adj[j];
        }
        for (size_t i = 0; i < WORDS_MIN_LEN; i++) {
            crc32_prefix = crc32_step_zero(crc32_prefix);
        }
        const uint32_t *adj1 = word_crc32_adj;
        for (size_t l1 = 0;; l1++) {
            for (; adj1 != words_bylen[l1]; adj1++) {
                uint32_t crc32_prefix2 = crc32_prefix ^ *adj1;
                for (size_t i = 0; i < WORDS_MIN_LEN; i++) {
                    crc32_prefix2 = crc32_step_zero(crc32_prefix2);
                }
                const uint32_t *adj2 = word_crc32_adj;
                for (size_t l2 = 0;; l2++) {
                    for (; adj2 != words_bylen[l2]; adj2++) {
                        auto it = last_word.find(crc32_prefix2 ^ *adj2);
                        if (it != last_word.end()) {
                            word_ids[words_in_prefix]     = adj1 - word_crc32_adj;
                            word_ids[words_in_prefix + 1] = adj2 - word_crc32_adj;
                            word_ids[words_in_prefix + 2] = it->second;
                            size_t word0                  = word_ids[0];
                            std::string result(word_ptrs[word0], word_ptrs[word0 + 1]);
                            for (size_t i = 1; i != words_total; i++) {
                                result.push_back(' ');
                                size_t word = word_ids[i];
                                result.append(word_ptrs[word], word_ptrs[word + 1]);
                            }
                            return result;
                        }
                    }
                    if (l2 == WORDS_MAX_LEN - WORDS_MIN_LEN) {
                        break;
                    }
                    crc32_prefix2 = crc32_step_zero(crc32_prefix2);
                }
            }
            if (l1 == WORDS_MAX_LEN - WORDS_MIN_LEN) {
                break;
            }
            crc32_prefix = crc32_step_zero(crc32_prefix);
        }
    }
}*/

static const std::string ADDRESS_COUNT_PREFIX      = "total_address_count";
static const std::string CREATION_TIMESTAMP_PREFIX = "creation_timestamp";

void WalletHDBase::derive_secrets(std::string mnemonic, const std::string &mnemonic_password) {
	if (!mnemonic.empty()) {
		mnemonic                    = cn::Bip32Key::check_bip39_mnemonic(mnemonic);
		cn::Bip32Key master_key     = cn::Bip32Key::create_master_key(mnemonic, mnemonic_password);
		cn::Bip32Key k0             = master_key.derive_key(0x8000002c);
		cn::Bip32Key k1             = k0.derive_key(0x800000cc);
		cn::Bip32Key k2             = k1.derive_key(0x80000001);
		cn::Bip32Key k3             = k2.derive_key(0);
		cn::Bip32Key k4             = k3.derive_key(0);
		m_seed                      = cn_fast_hash(k4.get_priv_key());
		const BinaryArray tx_data   = m_seed.as_binary_array() | as_binary_array("view_seed");
		m_view_seed                 = cn_fast_hash(tx_data);
		const BinaryArray vk_data   = m_view_seed.as_binary_array() | as_binary_array("view_key");
		m_view_secret_key           = hash_to_scalar(vk_data.data(), vk_data.size());
		const BinaryArray ak_data   = m_view_seed.as_binary_array() | as_binary_array("view_key_audit");
		m_audit_key_base.secret_key = hash_to_scalar(ak_data.data(), ak_data.size());
		const BinaryArray sk_data   = m_seed.as_binary_array() | as_binary_array("spend_key");
		m_spend_secret_key          = hash_to_scalar(sk_data.data(), sk_data.size());
		m_sH                        = to_bytes(crypto::H * m_spend_secret_key);
	} else {  // View only
		// only if we have output_secret_derivation_seed, view-only wallet will be able to see outgoing addresses
		if (m_view_seed != Hash{}) {
			const BinaryArray vk_data   = m_view_seed.as_binary_array() | as_binary_array("view_key");
			m_view_secret_key           = hash_to_scalar(vk_data.data(), vk_data.size());
			const BinaryArray ak_data   = m_view_seed.as_binary_array() | as_binary_array("view_key_audit");
			m_audit_key_base.secret_key = hash_to_scalar(ak_data.data(), ak_data.size());
		}
		invariant(key_in_main_subgroup(m_sH), "Wallet Corrupted - s*H is invalid");
		// We check that sH is product of some known s0 by H, this is required by audit
		if (!check_proof_H(m_sH, m_view_secrets_signature))
			throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Wallet view secrets are corrupted");
	}
	invariant(secret_key_to_public_key(m_view_secret_key, &m_view_public_key), "");
	invariant(secret_key_to_public_key(m_audit_key_base.secret_key, &m_audit_key_base.public_key), "");
	m_A_plus_sH       = to_bytes(P3(m_audit_key_base.public_key) + P3(m_sH));
	m_v_mul_A_plus_sH = to_bytes(P3(m_A_plus_sH) * m_view_secret_key);  // for hw debug only
}

bool WalletHDBase::get_record(const AccountAddress &v_addr, size_t *index, WalletRecord *record) const {
	if (v_addr.type() != typeid(AccountAddressAmethyst))
		return false;
	auto &addr = boost::get<AccountAddressAmethyst>(v_addr);
	auto rit   = m_records_map.find(addr.S);
	if (rit == m_records_map.end() || rit->second >= get_actual_records_count())
		return false;
	// TODO - do not call record_to_address
	auto addr2 = record_to_address(rit->second);
	if (v_addr != addr2)
		return false;
	//	invariant (m_wallet_records.at(rit->second).spend_public_key == addr.spend_public_key, "");
	*index  = rit->second;
	*record = m_wallet_records.at(rit->second);
	return true;
}

void WalletHDBase::generate_ahead1(size_t counter, std::vector<WalletRecord> &result) const {
	std::vector<KeyPair> key_result;
	key_result.resize(result.size());
	generate_hd_spendkeys(m_audit_key_base.secret_key, m_A_plus_sH, counter, &key_result);
	for (size_t i = 0; i != result.size(); ++i) {
		WalletRecord &record    = result[i];
		record.spend_secret_key = key_result.at(i).secret_key;
		record.spend_public_key = key_result.at(i).public_key;
		record.creation_timestamp =
		    std::numeric_limits<Timestamp>::max();  // TODO - adding an address will never rescan, which is wrong
	}
}

void WalletHDBase::generate_ahead() {
	if (m_wallet_records.size() >= m_used_address_count + GENERATE_AHEAD)
		return;
	size_t delta = m_used_address_count + GENERATE_AHEAD - m_wallet_records.size();
	std::vector<std::vector<WalletRecord>> results;
#ifndef __EMSCRIPTEN__
	if (delta < 1000) {  // TODO - arbitrary constant when single-threaded generation is faster
#endif
		results.resize(1);
		results[0].resize(delta);
		generate_ahead1(m_wallet_records.size(), results[0]);
#ifndef __EMSCRIPTEN__
	} else {
		const size_t thc = std::thread::hardware_concurrency();
		results.resize(thc);
		std::vector<std::thread> workers;
		for (size_t i = 0; i != thc; i++) {
			size_t start = delta * i / thc;
			results[i].resize(delta * (i + 1) / thc - start);
			workers.push_back(std::thread(std::bind(
			    &WalletHDBase::generate_ahead1, this, m_wallet_records.size() + start, std::ref(results[i]))));
		}
		std::for_each(workers.begin(), workers.end(), [](std::thread &t) { t.join(); });
	}
#endif
	m_wallet_records.reserve(m_used_address_count + GENERATE_AHEAD);
	for (const auto &result : results)
		for (const auto &record : result) {
			m_records_map.insert(std::make_pair(record.spend_public_key, m_wallet_records.size()));
			m_wallet_records.push_back(record);
		}
}

AccountAddress WalletHDBase::record_to_address(size_t index) const {
	const WalletRecord &record = m_wallet_records.at(index);
	Hash view_seed;
	memcpy(view_seed.data, m_audit_key_base.public_key.data, sizeof(m_audit_key_base.public_key.data));
	PublicKey sv2 = generate_hd_spendkey(m_v_mul_A_plus_sH, m_A_plus_sH, m_view_public_key, index);
	if (m_view_secret_key != SecretKey{}) {
		PublicKey sv = to_bytes(P3(record.spend_public_key) * m_view_secret_key);
		invariant(sv == sv2, "");
	}
	// TODO - do multiplication only once
	return AccountAddressAmethyst{record.spend_public_key, sv2};
}

std::vector<WalletRecord> WalletHDBase::generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct,
    Timestamp now, std::vector<AccountAddress> *addresses, bool *rescan_from_ct) {
	for (const auto &sk : sks)
		if (sk != SecretKey{})
			throw std::runtime_error("Generating non-deterministic addreses not supported by HD wallet");
	std::vector<WalletRecord> result;
	addresses->clear();
	if (sks.empty())
		return result;
	auto was_used_address_count = m_used_address_count;
	m_used_address_count += sks.size();
	generate_ahead();
	for (size_t i = 0; i != sks.size(); ++i) {
		result.push_back(m_wallet_records.at(was_used_address_count + i));
		addresses->push_back(record_to_address(was_used_address_count + i));
	}
	return result;
}

Timestamp WalletHDBase::get_oldest_timestamp() const {
	auto it      = m_oldest_timestamp.find(m_currency.net);
	Timestamp ts = (it == m_oldest_timestamp.end()) ? 0 : it->second;
	return std::max<Timestamp>(ts, 1551341000);
}

bool WalletHDBase::on_first_output_found(Timestamp ts) {
	auto it = m_oldest_timestamp.find(m_currency.net);
	if (it != m_oldest_timestamp.end() || ts == 0)
		return false;
	m_oldest_timestamp[m_currency.net] = ts;
	return true;
}

bool WalletHDBase::create_look_ahead_records(size_t count) {
	if (count <= m_used_address_count)
		return false;
	m_log(logging::INFO) << "Wallet address created because found in block chain, now total_address_count=" << count
	                     << std::endl;
	m_used_address_count = count;
	generate_ahead();
	return true;
}

std::vector<BinaryArray> WalletHDBase::payment_queue_get() const {
	std::vector<BinaryArray> result;
	auto nit = m_payment_queue.find(m_currency.net);
	if (nit == m_payment_queue.end())
		return result;
	for (const auto &el : nit->second)
		result.push_back(el.second);
	return result;
}

void WalletHDBase::payment_queue_add(const Hash &tid, const BinaryArray &binary_transaction) {
	m_payment_queue[m_currency.net][tid] = binary_transaction;
}

void WalletHDBase::payment_queue_remove(const Hash &tid) {
	auto nit = m_payment_queue.find(m_currency.net);
	if (nit == m_payment_queue.end())
		return;
	nit->second.erase(tid);
	if (!nit->second.empty())
		return;
	m_payment_queue.erase(nit);
}

void WalletHDBase::set_label(const std::string &address, const std::string &label) {
	if (label.empty())
		m_labels.erase(address);
	else
		m_labels[address] = label;
}

std::string WalletHDBase::get_label(const std::string &address) const {
	auto lit = m_labels.find(address);
	if (lit == m_labels.end())
		return std::string();
	return lit->second;
}

Wallet::OutputHandler WalletHDBase::get_output_handler() const {
	SecretKey vsk_copy = m_view_secret_key;
	return [vsk_copy](uint8_t tx_version, const KeyDerivation &kd, const Hash &tx_inputs_hash, size_t output_index,
	           const OutputKey &key_output, PublicKey *address_S, PublicKey *output_shared_secret) {
		*address_S = unlinkable_underive_address_S(vsk_copy, tx_inputs_hash, output_index, key_output.public_key,
		    key_output.encrypted_secret, output_shared_secret);
	};
}

bool WalletHDBase::detect_our_output(uint8_t tx_version, const Hash &tx_inputs_hash, const KeyDerivation &kd,
    size_t out_index, const PublicKey &address_S, const PublicKey &output_shared_secret, const OutputKey &key_output,
    Amount *amount, SecretKey *output_secret_key_s, SecretKey *output_secret_key_a, AccountAddress *address,
    size_t *record_index, KeyImage *keyimage) {
	WalletRecord record;
	AccountAddress addr;
	if (!get_look_ahead_record(address_S, record_index, &record, &addr))
		return false;
	auto output_secret_hash_arg  = crypto::get_output_secret_hash_arg(output_shared_secret, tx_inputs_hash, out_index);
	SecretKey output_secret_hash = hash_to_scalar(output_secret_hash_arg.data(), output_secret_hash_arg.size());
	*output_secret_key_a         = unlinkable_derive_output_secret_key(record.spend_secret_key, output_secret_hash);
	if (m_spend_secret_key != SecretKey{}) {
		*output_secret_key_s        = unlinkable_derive_output_secret_key(m_spend_secret_key, output_secret_hash);
		PublicKey output_public_key = secret_keys_to_public_key(*output_secret_key_a, *output_secret_key_s);
		if (output_public_key != key_output.public_key)
			return false;
	}
	*keyimage = generate_key_image(key_output.public_key, *output_secret_key_a);
	*address  = addr;
	// std::cout << "My unlinkable output! out_index=" << out_index <<
	// "amount=" << key_output.amount << std::endl;
	*amount = key_output.amount;
	return true;
}

WalletHDJson::WalletHDJson(const Currency &currency, logging::ILogger &log, const std::string &json_data)
    : WalletHDBase(currency, log) {
	try {
		seria::from_json_value(*this, common::JsonValue::from_string(json_data));
		derive_secrets(m_mnemonic, m_mnemonic_password);
		generate_ahead();
	} catch (const Bip32Key::Exception &) {
		std::throw_with_nested(Exception{api::WALLETD_MNEMONIC_CRC, "Wrong mnemonic"});
	} catch (const std::exception &) {
		std::throw_with_nested(Exception{api::WALLET_FILE_DECRYPT_ERROR, "Wallet file invalid or wrong password"});
	}
}

WalletHDJson::WalletHDJson(const Currency &currency, logging::ILogger &log, const std::string &mnemonic,
    Timestamp creation_timestamp, const std::string &mnemonic_password)
    : WalletHDBase(currency, log)
    , m_mnemonic(cn::Bip32Key::check_bip39_mnemonic(mnemonic))
    , m_mnemonic_password(mnemonic_password) {
	on_first_output_found(creation_timestamp);
	derive_secrets(m_mnemonic, m_mnemonic_password);
	generate_ahead();
}

void WalletHDJson::ser_members(seria::ISeria &s) {
	std::string version  = current_version;
	std::string coinname = CRYPTONOTE_NAME;
	seria_kv("version", version, s);
	if (version != current_version)
		throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Wallet version unknown, please update walletd - " + version);
	seria_kv("coinname", coinname, s);
	if (coinname != CRYPTONOTE_NAME)
		throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Wallet is for different coin - " + coinname);
	seria_kv("mnemonic", m_mnemonic, s);
	seria_kv("mnemonic-password", m_mnemonic_password, s);
	if (m_mnemonic.empty()) {
		seria_kv("view_seed", m_view_seed, s);
		if (m_view_seed == Hash{}) {
			seria_kv("view_key", m_view_secret_key, s);
			seria_kv("view_key_audit", m_audit_key_base.secret_key, s);
		}
		seria_kv("sH", m_sH, s);
		seria_kv("view_secrets_signature", m_view_secrets_signature, s);
	}
	seria_kv("total_address_count", m_used_address_count, s);
	seria_kv("creation_timestamp", m_oldest_timestamp, s);
	seria_kv("labels", m_labels, s);
	seria_kv("payment_queue", m_payment_queue, s);
}

std::string WalletHDJson::save_json_data() const { return seria::to_json_value(*this).to_string(); }
