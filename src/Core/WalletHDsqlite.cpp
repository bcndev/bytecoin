// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletHDsqlite.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "common/BIPs.hpp"
#include "common/Math.hpp"
#include "common/MemoryStreams.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "common/Words.hpp"
#include "crypto/crypto.hpp"
#include "crypto/crypto_helpers.hpp"
//#include "http/JsonRpc.hpp"
//#include "platform/PathTools.hpp"
#include "platform/Time.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace cn;
using namespace common;
using namespace crypto;

static Hash derive_from_key(const chacha_key &key, const std::string &append) {
	BinaryArray seed_data = key.as_binary_array() | as_binary_array(append);
	return cn_fast_hash(seed_data);
}

static const std::string current_version = "CryptoNoteWallet1";

static const std::string ADDRESS_COUNT_PREFIX      = "total_address_count";
static const std::string CREATION_TIMESTAMP_PREFIX = "creation_timestamp";

using namespace platform;

bool WalletHDsqlite::is_sqlite(const std::string &full_path) {
	bool created = false;
	sqlite::Dbi db_dbi;
	try {
		db_dbi.open_check_create(platform::O_READ_EXISTING, full_path, &created);
		return true;
	} catch (const std::exception &) {
	}
	return false;
}

WalletHDsqlite::WalletHDsqlite(const Currency &currency, logging::ILogger &log, const std::string &path,
    const std::string &password, bool readonly)
    : WalletHDBase(currency, log), m_path(path) {
	bool created = false;
	ewrap(m_db_dbi.open_check_create(readonly ? platform::O_READ_EXISTING : platform::O_OPEN_EXISTING, path, &created),
	    Exception(api::WALLET_FILE_READ_ERROR, "Cannot open wallet file"));

	if (get_is_hardware()) {
		auto connected = hardware::HardwareWallet::get_connected();
		for (auto &&c : connected) {
			try {
				m_wallet_key = chacha_key{c->get_wallet_key()};
				std::string version;
				if (get("version", version)) {
					m_hw = std::make_unique<hardware::Proxy>(std::move(c));
					break;
				}
			} catch (const std::exception &) {
				// ignore, probably disconnected while we were trying
			}
		}
		if (!m_hw)
			throw Exception(api::WALLET_FILE_HARDWARE_DECRYPT_ERROR,
			    "Hardware-backed wallet file failed to decrypt using keys stored in " +
			        common::to_string(connected.size()) + " hardware wallet(s)");
	} else {
		BinaryArray salt_data = get_salt() | as_binary_array(password);
		CryptoNightContext cn_ctx;
		m_wallet_key = generate_chacha8_key(cn_ctx, salt_data.data(), salt_data.size());
	}
	try {
		load();
	} catch (const Bip32Key::Exception &) {
		std::throw_with_nested(Exception{api::WALLETD_MNEMONIC_CRC, "Wrong mnemonic"});
	} catch (const std::exception &) {
		std::throw_with_nested(Exception{api::WALLET_FILE_DECRYPT_ERROR, "Wallet file invalid or wrong password"});
	}
}

WalletHDsqlite::WalletHDsqlite(const Currency &currency, logging::ILogger &log, const std::string &path,
    const std::string &password, const std::string &mnemonic, Timestamp creation_timestamp,
    const std::string &mnemonic_password, bool hardware_wallet)
    : WalletHDBase(currency, log), m_path(path) {
	if (hardware_wallet) {
		if (!password.empty())
			throw Exception(api::WALLET_FILE_HARDWARE_DECRYPT_ERROR,
			    "Wallet password should be empty when backed by hardware, wallet file will be encrypted using key stored in hardware wallet");
		auto connected = hardware::HardwareWallet::get_connected();
		if (connected.empty())
			throw Exception(api::WALLET_FILE_HARDWARE_DECRYPT_ERROR,
			    "No hardware wallets connected, please connect one and try again.");
		if (connected.size() > 1)
			throw Exception(api::WALLET_FILE_HARDWARE_DECRYPT_ERROR,
			    "More than 1 hardware wallet connected, please disconnect all but one you wish to use to create wallet file.");
		m_hw = std::make_unique<hardware::Proxy>(std::move(connected.back()));
	}
	bool created = false;
	try {
		m_db_dbi.open_check_create(platform::O_CREATE_NEW, path, &created);
	} catch (const platform::sqlite::ErrorDBExists &) {
		std::throw_with_nested(Exception(
		    api::WALLET_FILE_EXISTS, "Will not overwrite existing wallet - delete it first or specify another file"));
	} catch (const platform::sqlite::Error &) {
		std::throw_with_nested(
		    Exception(api::WALLET_FILE_READ_ERROR, "Error creating wallet - check that you have permissions"));
	}

	m_db_dbi.exec(
	    "CREATE TABLE unencrypted(key BLOB PRIMARY KEY COLLATE BINARY NOT NULL, value BLOB NOT NULL) WITHOUT ROWID");
	m_db_dbi.exec(
	    "CREATE TABLE parameters(key_hash BLOB PRIMARY KEY COLLATE BINARY NOT NULL, key BLOB NOT NULL, value BLOB NOT NULL) WITHOUT ROWID");
	m_db_dbi.exec(
	    "CREATE TABLE labels(address_hash BLOB PRIMARY KEY NOT NULL, address BLOB NOT NULL, label BLOB NOT NULL) WITHOUT ROWID");
	m_db_dbi.exec(
	    "CREATE TABLE payment_queue(tid_hash BLOB COLLATE BINARY NOT NULL, net_hash BLOB COLLATE BINARY NOT NULL, tid BLOB NOT NULL, net BLOB NOT NULL, binary_transaction BLOB NOT NULL, PRIMARY KEY (tid_hash, net_hash)) WITHOUT ROWID");
	BinaryArray salt(sizeof(Hash));
	generate_random_bytes(salt.data(), salt.size());
	put_salt(salt);  // The only unencrypted field
	if (m_hw) {
		m_wallet_key = chacha_key{m_hw->get_wallet_key()};
		put_is_hardware(true);
	} else {
		salt |= as_binary_array(password);
		CryptoNightContext cn_ctx;
		m_wallet_key = generate_chacha8_key(cn_ctx, salt.data(), salt.size());
	}
	if (mnemonic.empty() && !m_hw)
		return;
	put("version", current_version, true);
	put("coinname", CRYPTONOTE_NAME, true);
	if (!m_hw) {
		put("mnemonic", cn::Bip32Key::check_bip39_mnemonic(mnemonic), true);
		put("mnemonic-password", mnemonic_password, true);  // write always to keep row count the same
	}
	put(ADDRESS_COUNT_PREFIX, seria::to_binary(1U), true);

	on_first_output_found(creation_timestamp);

	try {
		load();
	} catch (const Bip32Key::Exception &) {
		std::throw_with_nested(Exception{api::WALLETD_MNEMONIC_CRC, "Wrong mnemonic"});
	} catch (const std::exception &) {
		std::throw_with_nested(Exception{api::WALLET_FILE_DECRYPT_ERROR, "Wallet file invalid or wrong password"});
	}
	commit();
}

void WalletHDsqlite::load() {
	std::string version;
	if (!get("version", version)) {
		throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Wallet password incorrect");
	}
	if (version != current_version)
		throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Wallet version unknown, please update walletd - " + version);
	std::string coinname;
	if (!get("coinname", coinname) || coinname != CRYPTONOTE_NAME)
		throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Wallet is for different coin - " + coinname);
	if (m_hw) {
		m_A_plus_sH       = m_hw->get_A_plus_SH();
		m_v_mul_A_plus_sH = m_hw->get_v_mul_A_plus_SH();
		m_view_public_key = m_hw->get_public_view_key();
		invariant(key_in_main_subgroup(m_A_plus_sH), "Hardware wallet error - spend key base is invalid");
		invariant(key_in_main_subgroup(m_v_mul_A_plus_sH), "Hardware wallet error - view key base is invalid");
		invariant(key_in_main_subgroup(m_view_public_key), "Hardware wallet error - view public key is invalid");
		BinaryArray ba;
		if (get("view_key", ba)) {  // hardware wallet with a view key
			seria::from_binary(m_view_secret_key, ba);
			invariant(keys_match(m_view_secret_key, m_view_public_key), "Hardware-backed wallet corrupted");
		}
	} else {
		std::string mnemonic;
		std::string mnemonic_password;
		if (get("mnemonic", mnemonic)) {
			invariant(get("mnemonic-password", mnemonic_password), "Wallet corrupted - no mnemonic password");
		} else {  // View only
			// only if we have output_secret_derivation_seed, view-only wallet will be able to see outgoing addresses
			BinaryArray ba;
			if (get("view_seed", ba)) {
				seria::from_binary(m_view_seed, ba);
			} else {
				invariant(get("view_key", ba), "Wallet corrupted - no view key");
				seria::from_binary(m_view_secret_key, ba);
				invariant(get("view_key_audit", ba), "Wallet corrupted - no audit key base");
				seria::from_binary(m_audit_key_base.secret_key, ba);
			}
			invariant(get("sH", ba), "Wallet corrupted - no sH key");
			seria::from_binary(m_sH, ba);
			invariant(get("view_secrets_signature", ba), "Wallet audit secrets are corrupted");
			seria::from_binary(m_view_secrets_signature, ba);
		}
		derive_secrets(mnemonic, mnemonic_password);
	}
	{
		BinaryArray ba;
		if (get(ADDRESS_COUNT_PREFIX, ba))
			seria::from_binary(m_used_address_count, ba);
		// We do not read for all nets for simplicity. TODO - read
		if (get(CREATION_TIMESTAMP_PREFIX + net_append(m_currency.net), ba)) {
			Timestamp ts = 0;
			seria::from_binary(ts, ba);
			m_oldest_timestamp[m_currency.net] = ts;
		}
	}
	generate_ahead();

	auto pq2 = payment_queue_get2();
	for (const auto &el : pq2)
		m_payment_queue[std::get<1>(el)][std::get<0>(el)] = std::get<2>(el);

	sqlite::Stmt stmt_get;
	stmt_get.prepare(m_db_dbi, "SELECT address, label FROM labels");
	while (stmt_get.step()) {
		auto address_size = stmt_get.column_bytes(0);
		auto address_data = stmt_get.column_blob(0);
		auto label_size   = stmt_get.column_bytes(1);
		auto label_data   = stmt_get.column_blob(1);
		BinaryArray ka    = decrypt_data(m_wallet_key, address_data, address_size);
		BinaryArray ba    = decrypt_data(m_wallet_key, label_data, label_size);

		m_labels[std::string{ka.begin(), ka.end()}] = std::string{ba.begin(), ba.end()};
	}
}

BinaryArray WalletHDsqlite::encrypt_data(const chacha_key &wallet_key, const BinaryArray &data) {
	const size_t MIN_SIZE   = 256;
	const size_t EXTRA_SIZE = sizeof(Hash) + 4;  // iv, actual size in le
	size_t actual_size      = 1;
	while (actual_size < data.size() + EXTRA_SIZE || actual_size < MIN_SIZE)
		actual_size *= 2;
	BinaryArray large_data(actual_size - sizeof(Hash));
	uint_le_to_bytes(large_data.data(), 4, data.size());
	memcpy(large_data.data() + 4, data.data(), data.size());
	BinaryArray enc_data(sizeof(Hash) + large_data.size());
	Hash iv = crypto::rand<Hash>();
	memcpy(enc_data.data(), iv.data, sizeof(iv));
	const BinaryArray key_data = wallet_key.as_binary_array() | iv.as_binary_array();
	chacha_key key{cn_fast_hash(key_data)};
	chacha(20, large_data.data(), large_data.size(), key, chacha_iv{}, enc_data.data() + sizeof(Hash));
	return enc_data;
}

BinaryArray WalletHDsqlite::decrypt_data(const chacha_key &wallet_key, const uint8_t *value_data, size_t value_size) {
	Hash iv;
	invariant(value_size >= 4 + sizeof(Hash), "");
	memcpy(iv.data, value_data, sizeof(Hash));
	BinaryArray result(value_size - sizeof(Hash));
	BinaryArray key_data = wallet_key.as_binary_array() | iv.as_binary_array();
	chacha_key key{cn_fast_hash(key_data)};
	chacha(20, value_data + sizeof(Hash), result.size(), key, chacha_iv{}, result.data());
	auto real_size = uint_le_from_bytes<size_t>(result.data(), 4);
	invariant(real_size <= result.size() - 4, "");
	return BinaryArray{result.data() + 4, result.data() + 4 + real_size};
}

void WalletHDsqlite::put_salt(const BinaryArray &salt) {
	sqlite::Stmt stmt_update;
	stmt_update.prepare(m_db_dbi, "REPLACE INTO unencrypted (key, value) VALUES ('salt', ?)");
	stmt_update.bind_blob(1, salt.data(), salt.size());
	invariant(!stmt_update.step(), "");
}

BinaryArray WalletHDsqlite::get_salt() const {
	sqlite::Stmt stmt_get;
	stmt_get.prepare(m_db_dbi, "SELECT value FROM unencrypted WHERE key = 'salt'");
	invariant(stmt_get.step(), "");
	auto salt_size = stmt_get.column_bytes(0);
	auto salt_data = stmt_get.column_blob(0);
	return BinaryArray{salt_data, salt_data + salt_size};
}

void WalletHDsqlite::put_is_hardware(bool ha) {
	sqlite::Stmt stmt_update;
	if (ha)
		stmt_update.prepare(m_db_dbi, "REPLACE INTO unencrypted (key, value) VALUES ('is_hardware', 1)");
	else
		stmt_update.prepare(m_db_dbi, "DELETE FROM unencrypted WHERE key = 'is_hardware'");
	invariant(!stmt_update.step(), "");
}

bool WalletHDsqlite::get_is_hardware() const {
	sqlite::Stmt stmt_get;
	stmt_get.prepare(m_db_dbi, "SELECT value FROM unencrypted WHERE key = 'is_hardware'");
	return stmt_get.step();
}

void WalletHDsqlite::put(const std::string &key, const BinaryArray &value, bool nooverwrite) {
	Hash key_hash         = derive_from_key(m_wallet_key, "db_parameters" + key);
	BinaryArray enc_key   = encrypt_data(m_wallet_key, as_binary_array(key));
	BinaryArray enc_value = encrypt_data(m_wallet_key, value);
	sqlite::Stmt stmt_update;
	stmt_update.prepare(m_db_dbi,
	    nooverwrite ? "INSERT INTO parameters (key_hash, key, value) VALUES (?, ?, ?)"
	                : "REPLACE INTO parameters (key_hash, key, value) VALUES (?, ?, ?)");
	stmt_update.bind_blob(1, key_hash.data, sizeof(key_hash.data));
	stmt_update.bind_blob(2, enc_key.data(), enc_key.size());
	stmt_update.bind_blob(3, enc_value.data(), enc_value.size());
	invariant(!stmt_update.step(), "");
}

bool WalletHDsqlite::get(const std::string &key, BinaryArray &value) const {
	Hash key_hash = derive_from_key(m_wallet_key, "db_parameters" + key);

	sqlite::Stmt stmt_get;
	stmt_get.prepare(m_db_dbi, "SELECT value FROM parameters WHERE key_hash = ?");
	stmt_get.bind_blob(1, key_hash.data, sizeof(key_hash.data));
	if (!stmt_get.step())
		return false;
	auto label_size = stmt_get.column_bytes(0);
	auto label_data = stmt_get.column_blob(0);
	value           = decrypt_data(m_wallet_key, label_data, label_size);
	return true;
}

void WalletHDsqlite::put(const std::string &key, const std::string &value, bool nooverwrite) {
	return put(key, as_binary_array(value), nooverwrite);
}

bool WalletHDsqlite::get(const std::string &key, std::string &value) const {
	BinaryArray ba;
	if (!get(key, ba))
		return false;
	value = common::as_string(ba);
	return true;
}

std::vector<WalletRecord> WalletHDsqlite::generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct,
    Timestamp now, std::vector<AccountAddress> *addresses, bool *rescan_from_ct) {
	auto result = WalletHDBase::generate_new_addresses(sks, ct, now, addresses, rescan_from_ct);
	if (result.empty())
		return result;
	put(ADDRESS_COUNT_PREFIX, seria::to_binary(m_used_address_count), false);
	commit();
	return result;
}

void WalletHDsqlite::set_password(const std::string &password) {
	if (m_hw)
		throw std::runtime_error(
		    "Cannot set password on this wallet created from hardware wallet. It is encrypted with keys stored in hardware wallet");
	auto parameters = parameters_get();
	auto pq2        = payment_queue_get2();

	m_db_dbi.exec("DELETE FROM payment_queue");
	m_db_dbi.exec("DELETE FROM parameters");
	m_db_dbi.exec("DELETE FROM labels");

	BinaryArray salt(sizeof(Hash));
	generate_random_bytes(salt.data(), salt.size());
	put_salt(salt);
	salt |= as_binary_array(password);
	CryptoNightContext cn_ctx;
	m_wallet_key = generate_chacha8_key(cn_ctx, salt.data(), salt.size());

	for (const auto &p : parameters)
		put(p.first, p.second, true);
	for (const auto &l : m_labels)
		set_label(l.first, l.second);
	for (const auto &el : pq2)
		payment_queue_add(std::get<0>(el), std::get<1>(el), std::get<2>(el));
	commit();
}

void WalletHDsqlite::export_wallet(const std::string &export_path, const std::string &new_password, bool view_only,
    bool view_outgoing_addresses) const {
	if (m_hw && !view_only)
		throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Exporting hardware-backed wallet is not possible");

	WalletHDsqlite other(
	    m_currency, m_log.get_logger(), export_path, new_password, std::string{}, 0, std::string{}, false);

	if (!is_view_only() && view_only) {
		if (m_hw) {
			SecretKey audit_key_base_secret_key;
			PublicKey A;
			SecretKey view_secret_key;
			Hash view_seed;
			Signature view_secrets_signature;
			m_hw->export_view_only(&audit_key_base_secret_key, &view_secret_key, &view_seed, &view_secrets_signature);
			invariant(secret_key_to_public_key(audit_key_base_secret_key, &A), "");
			PublicKey sH = to_bytes(P3(m_A_plus_sH) - P3(A));
			if (view_seed != Hash{}) {
				other.put("view_seed", view_seed.as_binary_array(), true);
			} else {
				other.put("view_key", view_secret_key.as_binary_array(), true);
				other.put("view_key_audit", audit_key_base_secret_key.as_binary_array(), true);
			}
			other.put("sH", sH.as_binary_array(), true);
			other.put("view_secrets_signature", seria::to_binary(view_secrets_signature), true);
			invariant(check_proof_H(sH, view_secrets_signature), "");
		} else {
			if (view_outgoing_addresses) {  // always have m_view_seed here
				other.put("view_seed", m_view_seed.as_binary_array(), true);
			} else {
				other.put("view_key", m_view_secret_key.as_binary_array(), true);
				other.put("view_key_audit", m_audit_key_base.secret_key.as_binary_array(), true);
			}
			auto sH = to_bytes(crypto::H * m_spend_secret_key);
			other.put("sH", sH.as_binary_array(), true);
			other.put("view_secrets_signature", seria::to_binary(m_view_secrets_signature), true);
			invariant(check_proof_H(sH, m_view_secrets_signature), "");
		}
		other.put("version", current_version, true);
		other.put("coinname", CRYPTONOTE_NAME, true);
		other.put(ADDRESS_COUNT_PREFIX, seria::to_binary(m_used_address_count), true);
	} else if (is_view_only() && view_only) {
		if (view_outgoing_addresses && m_view_seed != Hash{}) {
			other.put("view_seed", m_view_seed.as_binary_array(), true);
		} else {
			other.put("view_key", m_view_secret_key.as_binary_array(), true);
			other.put("view_key_audit", m_audit_key_base.secret_key.as_binary_array(), true);
		}
		other.put("sH", m_sH.as_binary_array(), true);
		other.put("view_secrets_signature", seria::to_binary(m_view_secrets_signature), true);
		other.put("version", current_version, true);
		other.put("coinname", CRYPTONOTE_NAME, true);
		other.put(ADDRESS_COUNT_PREFIX, seria::to_binary(m_used_address_count), true);
	} else {
		for (const auto &p : parameters_get())
			other.put(p.first, p.second, true);
		for (const auto &el : payment_queue_get2())
			other.payment_queue_add(std::get<0>(el), std::get<1>(el), std::get<2>(el));
	}
	for (const auto &l : m_labels)
		other.set_label(l.first, l.second);
	other.commit();
}

void WalletHDsqlite::import_view_key() {
	if (!m_hw || m_view_secret_key != SecretKey{})
		return;
	SecretKey audit_key_base_secret_key;
	Hash view_seed;
	Signature view_secrets_signature;
	m_hw->export_view_only(&audit_key_base_secret_key, &m_view_secret_key, &view_seed, &view_secrets_signature);
	// We do not store other secrets and will continue using hardware wallet for them
	invariant(secret_key_to_public_key(m_view_secret_key, &m_view_public_key), "");

	put("view_key", m_view_secret_key.as_binary_array(), true);
	commit();
}

std::string WalletHDsqlite::export_keys() const {
	std::string mnemonic;
	if (!get("mnemonic", mnemonic))
		throw std::runtime_error("Exporting mnemonic not supported by view-only or hardware-backed wallet");
	return mnemonic;
}

bool WalletHDsqlite::on_first_output_found(Timestamp ts) {
	if (!WalletHDBase::on_first_output_found(ts))
		return false;
	put(CREATION_TIMESTAMP_PREFIX + net_append(m_currency.net), seria::to_binary(ts), false);
	commit();
	return true;
}

bool WalletHDsqlite::create_look_ahead_records(size_t count) {
	if (!WalletHDBase::create_look_ahead_records(count))
		return false;
	put(ADDRESS_COUNT_PREFIX, seria::to_binary(m_used_address_count), false);
	commit();
	return true;
}

void WalletHDsqlite::backup(const std::string &dst_name, const std::string &pass) const {
	export_wallet(dst_name, pass, false, false);
}

std::vector<std::tuple<Hash, std::string, BinaryArray>> WalletHDsqlite::payment_queue_get2() const {
	std::vector<std::tuple<Hash, std::string, BinaryArray>> result;
	sqlite::Stmt stmt_get;
	stmt_get.prepare(m_db_dbi, "SELECT tid, net, binary_transaction FROM payment_queue");
	while (stmt_get.step()) {
		auto tid_size = stmt_get.column_bytes(0);
		auto tid_data = stmt_get.column_blob(0);
		auto net_size = stmt_get.column_bytes(1);
		auto net_data = stmt_get.column_blob(1);
		auto btx_size = stmt_get.column_bytes(2);
		auto btx_data = stmt_get.column_blob(2);

		BinaryArray key = decrypt_data(m_wallet_key, tid_data, tid_size);
		invariant(key.size() == sizeof(Hash), "");
		Hash tid;
		memcpy(tid.data, key.data(), sizeof(Hash));
		BinaryArray net = decrypt_data(m_wallet_key, net_data, net_size);
		BinaryArray ba  = decrypt_data(m_wallet_key, btx_data, btx_size);
		result.push_back(std::make_tuple(tid, std::string(net.begin(), net.end()), ba));
	}
	return result;
}

void WalletHDsqlite::payment_queue_add(const Hash &tid, const std::string &net, const BinaryArray &binary_transaction) {
	m_payment_queue[net][tid] = binary_transaction;
	Hash tid_hash =
	    derive_from_key(m_wallet_key, "db_payment_queue_tid" + std::string(std::begin(tid.data), std::end(tid.data)));
	Hash net_hash         = derive_from_key(m_wallet_key, "db_payment_queue_net" + net);
	BinaryArray enc_tid   = encrypt_data(m_wallet_key, tid.as_binary_array());
	BinaryArray enc_net   = encrypt_data(m_wallet_key, as_binary_array(net));
	BinaryArray enc_value = encrypt_data(m_wallet_key, binary_transaction);
	sqlite::Stmt stmt_update;
	stmt_update.prepare(m_db_dbi,
	    "REPLACE INTO payment_queue (tid_hash, net_hash, tid, net, binary_transaction) VALUES (?, ?, ?, ?, ?)");
	stmt_update.bind_blob(1, tid_hash.data, sizeof(tid_hash.data));
	stmt_update.bind_blob(2, net_hash.data, sizeof(net_hash.data));
	stmt_update.bind_blob(3, enc_tid.data(), enc_tid.size());
	stmt_update.bind_blob(4, enc_net.data(), enc_net.size());
	stmt_update.bind_blob(5, enc_value.data(), enc_value.size());
	invariant(!stmt_update.step(), "");
}

std::vector<std::pair<std::string, BinaryArray>> WalletHDsqlite::parameters_get() const {
	std::vector<std::pair<std::string, BinaryArray>> result;
	sqlite::Stmt stmt_get;
	stmt_get.prepare(m_db_dbi, "SELECT key, value FROM parameters");
	while (stmt_get.step()) {
		auto key_size   = stmt_get.column_bytes(0);
		auto key_data   = stmt_get.column_blob(0);
		auto value_size = stmt_get.column_bytes(1);
		auto value_data = stmt_get.column_blob(1);

		BinaryArray ka  = decrypt_data(m_wallet_key, key_data, key_size);
		BinaryArray ba  = decrypt_data(m_wallet_key, value_data, value_size);
		std::string key = std::string(ka.begin(), ka.end());
		result.push_back(std::make_pair(key, ba));
	}
	return result;
}

void WalletHDsqlite::payment_queue_add(const Hash &tid, const BinaryArray &binary_transaction) {
	WalletHDBase::payment_queue_add(tid, binary_transaction);
	payment_queue_add(tid, m_currency.net, binary_transaction);
	commit();
}

void WalletHDsqlite::commit() {
	m_db_dbi.commit_txn();
	m_db_dbi.begin_txn();
}

void WalletHDsqlite::payment_queue_remove(const Hash &tid) {
	Hash tid_hash =
	    derive_from_key(m_wallet_key, "db_payment_queue_tid" + std::string(std::begin(tid.data), std::end(tid.data)));
	Hash net_hash = derive_from_key(m_wallet_key, "db_payment_queue_net" + m_currency.net);

	sqlite::Stmt stmt_del;
	stmt_del.prepare(m_db_dbi, "DELETE FROM payment_queue WHERE net_hash = ? AND tid_hash = ?");
	stmt_del.bind_blob(1, net_hash.data, sizeof(net_hash.data));
	stmt_del.bind_blob(2, tid_hash.data, sizeof(tid_hash.data));
	invariant(!stmt_del.step(), "");

	if (tid.data[0] == 'x')  // committing here is not so critical, improve speed here
		commit();
}

void WalletHDsqlite::set_label(const std::string &address, const std::string &label) {
	WalletHDBase::set_label(address, label);
	Hash address_hash       = derive_from_key(m_wallet_key, "db_labels" + address);
	BinaryArray enc_address = encrypt_data(m_wallet_key, as_binary_array(address));
	BinaryArray enc_label   = encrypt_data(m_wallet_key, as_binary_array(label));

	if (label.empty()) {
		sqlite::Stmt stmt_del;
		stmt_del.prepare(m_db_dbi, "DELETE FROM labels WHERE address_hash = ?");
		stmt_del.bind_blob(1, address_hash.data, sizeof(address_hash.data));
		invariant(!stmt_del.step(), "");
	} else {
		sqlite::Stmt stmt_update;
		stmt_update.prepare(m_db_dbi, "REPLACE INTO labels (address_hash, address, label) VALUES (?, ?, ?)");
		stmt_update.bind_blob(1, address_hash.data, sizeof(address_hash.data));
		stmt_update.bind_blob(2, enc_address.data(), enc_address.size());
		stmt_update.bind_blob(3, enc_label.data(), enc_label.size());
		invariant(!stmt_update.step(), "");
	}
	commit();
}

Wallet::OutputHandler WalletHDsqlite::get_output_handler() const {
	SecretKey vsk_copy                = m_view_secret_key;
	hardware::HardwareWallet *hw_copy = m_view_secret_key == SecretKey{} ? m_hw.get() : nullptr;
	// When we have imported view key, we can scan as usual
	return
	    [vsk_copy, hw_copy](uint8_t tx_version, const KeyDerivation &kd, const Hash &tx_inputs_hash,
	        size_t output_index, const OutputKey &key_output, PublicKey *address_S, PublicKey *output_shared_secret) {
		    // multicore preparator should be never used with hardware wallet, otherwise crash
		    // we will remake architecture later
		    if (hw_copy) {
			    auto Pv    = hw_copy->scan_outputs({key_output.public_key}).at(0);
			    *address_S = unlinkable_underive_address_S_step2(Pv, tx_inputs_hash, output_index,
			        key_output.public_key, key_output.encrypted_secret, output_shared_secret);
		    } else {
			    *address_S = unlinkable_underive_address_S(vsk_copy, tx_inputs_hash, output_index,
			        key_output.public_key, key_output.encrypted_secret, output_shared_secret);
		    }
	    };
}

bool WalletHDsqlite::detect_our_output(uint8_t tx_version, const Hash &tx_inputs_hash, const KeyDerivation &kd,
    size_t out_index, const PublicKey &address_S, const PublicKey &output_shared_secret, const OutputKey &key_output,
    Amount *amount, SecretKey *output_secret_key_s, SecretKey *output_secret_key_a, AccountAddress *address,
    size_t *record_index, KeyImage *keyimage) {
	WalletRecord record;
	AccountAddress addr;
	if (!get_look_ahead_record(address_S, record_index, &record, &addr))
		return false;
	auto output_secret_hash_arg = crypto::get_output_secret_hash_arg(output_shared_secret, tx_inputs_hash, out_index);
	if (m_hw) {
		*keyimage = m_hw->generate_keyimage(output_secret_hash_arg, *record_index);
	} else {
		SecretKey output_secret_hash = hash_to_scalar(output_secret_hash_arg.data(), output_secret_hash_arg.size());
		*output_secret_key_a         = unlinkable_derive_output_secret_key(record.spend_secret_key, output_secret_hash);
		if (m_spend_secret_key != SecretKey{}) {
			*output_secret_key_s        = unlinkable_derive_output_secret_key(m_spend_secret_key, output_secret_hash);
			PublicKey output_public_key = secret_keys_to_public_key(*output_secret_key_a, *output_secret_key_s);
			if (output_public_key != key_output.public_key)
				return false;
		}
		*keyimage = generate_key_image(key_output.public_key, *output_secret_key_a);
	}
	*address = addr;
	// std::cout << "My unlinkable output! out_index=" << out_index <<
	// "amount=" << key_output.amount << std::endl;
	*amount = key_output.amount;
	return true;
}

Hash WalletHDsqlite::generate_output_seed(const Hash &tx_inputs_hash, const size_t &out_index) const {
	if (m_hw)
		return m_hw->generate_output_seed(tx_inputs_hash, out_index);
	return WalletHDBase::generate_output_seed(tx_inputs_hash, out_index);
}
