// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletLegacy.hpp"
#include <boost/algorithm/string.hpp>
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

static Hash derive_from_seed_legacy(const Hash &seed, const std::string &append) {
	BinaryArray seed_data = as_binary_array(append) | seed.as_binary_array();
	return cn_fast_hash(seed_data);
}

static const uint8_t SERIALIZATION_VERSION_V2 = 6;

static const size_t CHECK_KEYS_COUNT = 128;  // >8 KB checked at start and end of file
#pragma pack(push, 1)
struct EncryptedWalletRecord {
	chacha_iv iv;
	// Secret key, public key and creation timestamp
	uint8_t data[sizeof(PublicKey) + sizeof(SecretKey) + sizeof(uint64_t)]{};
};
struct ContainerStoragePrefix {
	// We moved uint8_t version out of this struct, because with it other fields become unaligned
	chacha_iv next_iv;
	EncryptedWalletRecord encrypted_view_keys;
};
// struct ContainerStorageWalletRecord {
//	PublicKey pk{};
//	SecretKey sk{};
//	uint64_t ct = 0;
//};
#pragma pack(pop)

static void decrypt_key_pair(
    const EncryptedWalletRecord &r, PublicKey &pk, SecretKey &sk, Timestamp &ct, const chacha_key &key) {
	//	ContainerStorageWalletRecord rec;
	unsigned char rec_data[sizeof(r.data)]{};
	chacha8(r.data, sizeof(r.data), key, r.iv, rec_data);
	memcpy(pk.data, rec_data, sizeof(PublicKey));
	memcpy(sk.data, rec_data + sizeof(PublicKey), sizeof(SecretKey));
	ct = static_cast<Timestamp>(
	    uint_le_from_bytes<uint64_t>(rec_data + sizeof(PublicKey) + sizeof(SecretKey), sizeof(uint64_t)));
}

static void encrypt_key_pair(
    EncryptedWalletRecord &r, PublicKey pk, SecretKey sk, Timestamp ct, const chacha_key &key) {
	unsigned char rec_data[sizeof(r.data)]{};
	memcpy(rec_data, pk.data, sizeof(PublicKey));
	memcpy(rec_data + sizeof(PublicKey), sk.data, sizeof(SecretKey));
	uint_le_to_bytes<uint64_t>(rec_data + sizeof(PublicKey) + sizeof(SecretKey), sizeof(uint64_t), ct);
	r.iv = crypto::rand<chacha_iv>();
	chacha8(&rec_data, sizeof(r.data), key, r.iv, r.data);
}

size_t WalletLegacy::wallet_file_size(size_t records) {
	return 1 + sizeof(ContainerStoragePrefix) + sizeof(uint64_t) * 2 + sizeof(EncryptedWalletRecord) * records;
}

void WalletLegacy::load_container_storage() {
	uint8_t version = 0;
	ContainerStoragePrefix prefix{};
	unsigned char count_capacity_data[2 * sizeof(uint64_t)]{};
	m_file->read(&version, 1);
	m_file->read(&prefix, sizeof(prefix));
	m_file->read(count_capacity_data, 2 * sizeof(uint64_t));
	uint64_t f_item_capacity = uint_le_from_bytes<uint64_t>(count_capacity_data, sizeof(uint64_t));
	uint64_t f_item_count    = uint_le_from_bytes<uint64_t>(count_capacity_data + sizeof(uint64_t), sizeof(uint64_t));

	if (version < SERIALIZATION_VERSION_V2)
		throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Wallet version too old");

	Timestamp creation_timestamp = 0;  // We ignore view keys timestamp on load
	decrypt_key_pair(
	    prefix.encrypted_view_keys, m_view_public_key, m_view_secret_key, creation_timestamp, m_wallet_key);
	if (!keys_match(m_view_secret_key, m_view_public_key))
		throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Restored view public key doesn't correspond to secret key");

	const size_t item_count =
	    integer_cast<size_t>(std::min(f_item_count, f_item_capacity));  // Protection against write shredding
	if (item_count > std::numeric_limits<size_t>::max() / sizeof(EncryptedWalletRecord))
		throw Exception(
		    api::WALLET_FILE_DECRYPT_ERROR, "Restored item count is too big " + common::to_string(item_count));
	std::vector<EncryptedWalletRecord> all_encrypted(item_count);
	m_file->read(reinterpret_cast<char *>(all_encrypted.data()), sizeof(EncryptedWalletRecord) * item_count);
	bool tracking_mode = false;
	m_wallet_records.reserve(item_count);
	for (size_t i = 0; i != item_count; ++i) {
		WalletRecord wallet_record;
		decrypt_key_pair(all_encrypted[i], wallet_record.spend_public_key, wallet_record.spend_secret_key,
		    wallet_record.creation_timestamp, m_wallet_key);

		if (i == 0) {
			tracking_mode = wallet_record.spend_secret_key == SecretKey{};
		} else if ((tracking_mode && wallet_record.spend_secret_key != SecretKey{}) ||
		           (!tracking_mode && wallet_record.spend_secret_key == SecretKey{})) {
			throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "All addresses must be either tracking or not");
		}

		if (i < CHECK_KEYS_COUNT || i >= item_count - CHECK_KEYS_COUNT) {  // check only first and last spend keys
			if (wallet_record.spend_secret_key != SecretKey{}) {
				if (!keys_match(wallet_record.spend_secret_key, wallet_record.spend_public_key))
					throw Exception(
					    api::WALLET_FILE_DECRYPT_ERROR, "Restored spend public key doesn't correspond to secret key");
			} else {
				if (!key_in_main_subgroup(wallet_record.spend_public_key)) {
					throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Public spend key is incorrect");
				}
			}
		}
		m_oldest_timestamp = std::min(m_oldest_timestamp, wallet_record.creation_timestamp);
		m_records_map.insert(std::make_pair(wallet_record.spend_public_key, m_wallet_records.size()));
		m_wallet_records.push_back(wallet_record);
	}
	auto file_size           = m_file->seek(0, SEEK_END);
	auto should_be_file_size = wallet_file_size(item_count);
	if (file_size > should_be_file_size) {  // We truncate legacy wallet cache
		try {
			m_file->truncate(should_be_file_size);
			m_log(logging::WARNING) << "Truncated wallet cache legacy wallet file to size=" << should_be_file_size;
		} catch (const std::exception &) {  // probably read only, ignore
		}
	}
}

void WalletLegacy::load_legacy_wallet_file() {
	//	m_wallet_records.clear();
	//	std::vector<WalletRecord> wallets_container;

	WalletSerializerV1 s(m_view_public_key, m_view_secret_key, m_wallet_records);

	s.load(m_wallet_key, *m_file.get());

	//	m_wallet_records.reserve()
	//	m_first_record = wallets_container.at(0);
	for (size_t i = 0; i != m_wallet_records.size(); ++i) {
		m_oldest_timestamp = std::min(m_oldest_timestamp, m_wallet_records[i].creation_timestamp);
		m_records_map.insert(std::make_pair(m_wallet_records[i].spend_public_key, i));
	}
}

WalletLegacy::WalletLegacy(
    const Currency &currency, logging::ILogger &log, const std::string &path, const chacha_key &wallet_key)
    : Wallet(currency, log), m_path(path) {
	m_wallet_key = wallet_key;
	load();
}

WalletLegacy::WalletLegacy(const Currency &currency, logging::ILogger &log, const std::string &path,
    const std::string &password, const std::string &import_keys, Timestamp creation_timestamp)
    : Wallet(currency, log), m_path(path) {
	CryptoNightContext cn_ctx;
	m_wallet_key = generate_chacha8_key(cn_ctx, password.data(), password.size());
	try {
		m_file = std::make_unique<platform::FileStream>(path, platform::O_CREATE_NEW);
	} catch (const StreamErrorFileExists &) {
		std::throw_with_nested(Exception(
		    api::WALLET_FILE_EXISTS, "Will not overwrite existing wallet - delete it first or specify another file"));
	} catch (const StreamError &) {
		std::throw_with_nested(
		    Exception(api::WALLET_FILE_READ_ERROR, "Error creating wallet - check that you have permissions"));
	}

	if (import_keys.empty()) {
		m_oldest_timestamp = platform::now_unix_timestamp();  // ignore creation_timestamp
		random_keypair(m_view_public_key, m_view_secret_key);
		m_wallet_records.push_back(WalletRecord{});
		m_wallet_records.at(0).creation_timestamp = m_oldest_timestamp;
		random_keypair(m_wallet_records.at(0).spend_public_key, m_wallet_records.at(0).spend_secret_key);
	} else {
		if (import_keys.size() != 256)
			throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Imported keys should be exactly 128 hex bytes");
		WalletRecord record{};
		record.creation_timestamp = creation_timestamp;
		if (!pod_from_hex(import_keys.substr(0, 64), &record.spend_public_key) ||
		    !pod_from_hex(import_keys.substr(64, 64), &m_view_public_key) ||
		    !pod_from_hex(import_keys.substr(128, 64), &record.spend_secret_key) ||
		    !pod_from_hex(import_keys.substr(192, 64), &m_view_secret_key))
			throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Imported keys should contain only hex bytes");
		if (!keys_match(m_view_secret_key, m_view_public_key))
			throw Exception(
			    api::WALLET_FILE_DECRYPT_ERROR, "Imported secret view key does not match corresponding public key");
		if (record.spend_secret_key != SecretKey{} && !keys_match(record.spend_secret_key, record.spend_public_key))
			throw Exception(
			    api::WALLET_FILE_DECRYPT_ERROR, "Imported secret spend key does not match corresponding public key");
		m_wallet_records.push_back(record);
		m_oldest_timestamp = 0;  // Alas, will scan entire blockchain
	}
	m_records_map.insert(std::make_pair(m_wallet_records.at(0).spend_public_key, 0));
	save_and_check();  // TODO - better swap in save_and_check
	m_wallet_records.clear();
	m_records_map.clear();
	load();
}

WalletLegacy::WalletLegacy(
    const Currency &currency, logging::ILogger &log, const std::string &path, const std::string &password)
    : Wallet(currency, log), m_path(path) {
	CryptoNightContext cn_ctx;
	m_wallet_key = generate_chacha8_key(cn_ctx, password.data(), password.size());
	load();
}

void WalletLegacy::load() {
	try {
		m_file = std::make_unique<platform::FileStream>(m_path, platform::O_OPEN_EXISTING);
	} catch (const StreamError &) {  // Read-only media?
		m_file = std::make_unique<platform::FileStream>(m_path, platform::O_READ_EXISTING);
	}
	uint8_t version = 0;
	m_file->read(&version, 1);
	if (version > SERIALIZATION_VERSION_V2)
		throw Exception(api::WALLET_FILE_UNKNOWN_VERSION, "Unknown version");
	m_file->seek(0, SEEK_SET);
	if (version < SERIALIZATION_VERSION_V2) {
		try {
			load_legacy_wallet_file();
		} catch (const StreamError &ex) {
			std::throw_with_nested(
			    Exception(api::WALLET_FILE_READ_ERROR, std::string("Error reading wallet file ") + common::what(ex)));
		} catch (const std::exception &ex) {
			std::throw_with_nested(Exception(
			    api::WALLET_FILE_DECRYPT_ERROR, std::string("Error decrypting wallet file ") + common::what(ex)));
		}
		m_file.reset();  // Indicates legacy format
		try {
			save_and_check();  // We try to overwrite legacy format with new format
			m_log(logging::WARNING) << "Overwritten legacy wallet file with new data format";
		} catch (const std::exception &) {  // probably read only, ignore
		}
	} else {
		load_container_storage();
	}
	if (m_wallet_records.empty())
		throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Error reading wallet file");

	m_inv_view_secret_key = sc_invert(m_view_secret_key);
	if (!is_view_only()) {
		BinaryArray seed_data = m_view_secret_key.as_binary_array();
		seed_data |= m_wallet_records.at(0).spend_secret_key.as_binary_array();
		m_seed                  = cn_fast_hash(seed_data);
		m_view_seed             = derive_from_seed_legacy(m_seed, "tx_derivation");
		m_history_filename_seed = derive_from_seed_legacy(m_seed, "history_filename");
		m_history_key           = chacha_key{derive_from_seed_legacy(m_seed, "history")};
	}
}

void WalletLegacy::save(
    const std::string &export_path, const chacha_key &wallet_key, bool view_only, platform::OpenMode open_mode) const {
	platform::FileStream f(export_path, open_mode);

	uint8_t version = SERIALIZATION_VERSION_V2;
	ContainerStoragePrefix prefix{};
	encrypt_key_pair(prefix.encrypted_view_keys, m_view_public_key, m_view_secret_key, m_oldest_timestamp, wallet_key);
	unsigned char count_capacity_data[sizeof(uint64_t)]{};
	uint_le_to_bytes<uint64_t>(count_capacity_data, sizeof(uint64_t), m_wallet_records.size());
	f.write(&version, 1);
	f.write(&prefix, sizeof(prefix));

	f.write(count_capacity_data, sizeof(uint64_t));  // we set capacity to item_count
	f.write(count_capacity_data, sizeof(uint64_t));

	EncryptedWalletRecord record;
	for (const auto &rec : m_wallet_records) {
		encrypt_key_pair(record, rec.spend_public_key, view_only ? SecretKey{} : rec.spend_secret_key,
		    rec.creation_timestamp, wallet_key);
		f.write(&record, sizeof(record));
	}
	f.fsync();
}

std::string WalletLegacy::export_keys() const {
	BinaryArray result = m_wallet_records.at(0).spend_public_key.as_binary_array();
	result |= m_view_public_key.as_binary_array();
	result |= m_wallet_records.at(0).spend_secret_key.as_binary_array();
	result |= m_view_secret_key.as_binary_array();
	return common::to_hex(result);
}

void WalletLegacy::save_and_check() {
	const std::string tmp_path = m_path + ".tmp";

	save(tmp_path, m_wallet_key, false, platform::O_CREATE_ALWAYS);

	WalletLegacy other(m_currency, m_log.get_logger(), tmp_path, m_wallet_key);
	if (*this != other)
		throw Exception(api::WALLET_FILE_WRITE_ERROR, "Error writing wallet file - records do not match");
	m_file.reset();
	if (!platform::atomic_replace_file(tmp_path, m_path))
		throw Exception(api::WALLET_FILE_WRITE_ERROR, "Error replacing wallet file");
	std::swap(m_file, other.m_file);
}

void WalletLegacy::set_password(const std::string &password) {
	CryptoNightContext cn_ctx;
	m_wallet_key = generate_chacha8_key(cn_ctx, password.data(), password.size());
	save_and_check();
}

void WalletLegacy::export_wallet(const std::string &export_path, const std::string &new_password, bool view_only,
    bool view_outgoing_addresses) const {
	std::unique_ptr<platform::FileStream> export_file;
	for (const auto &rec : m_wallet_records) {
		if (rec.spend_secret_key != SecretKey{}) {
			if (!keys_match(rec.spend_secret_key, rec.spend_public_key))
				throw Exception(api::WALLET_FILE_DECRYPT_ERROR,
				    "Spend public key doesn't correspond to secret key (corrupted wallet?)");
		} else {
			if (!key_in_main_subgroup(rec.spend_public_key)) {
				throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Public spend key is incorrect (corrupted wallet?)");
			}
		}
	}
	CryptoNightContext cn_ctx;
	auto new_wallet_key = generate_chacha8_key(cn_ctx, new_password.data(), new_password.size());
	save(export_path, new_wallet_key, view_only, platform::O_CREATE_NEW);
}

bool WalletLegacy::operator==(const WalletLegacy &other) const {
	return m_view_public_key == other.m_view_public_key && m_view_secret_key == other.m_view_secret_key &&
	       m_oldest_timestamp == other.m_oldest_timestamp && m_wallet_records == other.m_wallet_records;
}

std::vector<WalletRecord> WalletLegacy::generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct,
    Timestamp now, std::vector<AccountAddress> *addresses, bool *rescan_from_ct) {
	std::vector<AccountAddress> result_addresses;
	std::vector<WalletRecord> result;
	if (is_view_only())
		throw Exception(101, "Generate new addresses impossible for view-only wallet");
	if (!m_file.get()) {  // Legacy format, now overwrite
		m_log(logging::WARNING) << "Creation of new addresses forces overwrite of legacy format wallet";
		save_and_check();
	}
	*rescan_from_ct   = false;
	size_t append_pos = wallet_file_size(m_wallet_records.size());
	m_file->seek(append_pos, SEEK_SET);
	for (auto &&sk : sks) {
		WalletRecord record{};
		if (sk == SecretKey{}) {
			record.creation_timestamp = now;
			do {
				random_keypair(record.spend_public_key, record.spend_secret_key);
			} while (m_records_map.count(record.spend_public_key) != 0);
			m_oldest_timestamp = std::min(m_oldest_timestamp, record.creation_timestamp);
		} else {
			record.creation_timestamp = ct;
			record.spend_secret_key   = sk;
			if (!secret_key_to_public_key(sk, &record.spend_public_key))
				throw Exception(101, "Imported keypair is invalid - sk=" + common::pod_to_hex(sk));
		}
		auto rit = m_records_map.find(record.spend_public_key);
		if (rit != m_records_map.end()) {
			if (m_wallet_records.at(rit->second).creation_timestamp > record.creation_timestamp) {
				m_wallet_records.at(rit->second).creation_timestamp = record.creation_timestamp;
				m_oldest_timestamp = std::min(m_oldest_timestamp, record.creation_timestamp);
				*rescan_from_ct    = true;
			}
			result.push_back(m_wallet_records.at(rit->second));
			result_addresses.push_back(record_to_address(rit->second));
			continue;
		}
		m_records_map.insert(std::make_pair(record.spend_public_key, m_wallet_records.size()));
		m_wallet_records.push_back(record);
		EncryptedWalletRecord enc_record;
		encrypt_key_pair(
		    enc_record, record.spend_public_key, record.spend_secret_key, record.creation_timestamp, m_wallet_key);
		m_file->write(&enc_record, sizeof(enc_record));
		result.push_back(record);
		result_addresses.push_back(record_to_address(m_wallet_records.size() - 1));
	}
	m_file->fsync();
	m_file->seek(1 + sizeof(ContainerStoragePrefix), SEEK_SET);

	unsigned char count_capacity_data[sizeof(uint64_t)]{};
	uint_le_to_bytes<uint64_t>(count_capacity_data, sizeof(uint64_t), m_wallet_records.size());

	m_file->write(count_capacity_data, sizeof(uint64_t));
	m_file->write(count_capacity_data, sizeof(uint64_t));

	m_file->fsync();
	if (*rescan_from_ct) {  // We never write to the middle of the file
		m_log(logging::WARNING) << "Updating creation timestamp of existing addresses to " << ct
		                        << " in a wallet file (might take minutes for large wallets)...";
		save_and_check();
	}
	*addresses = result_addresses;
	return result;
}

AccountAddress WalletLegacy::record_to_address(size_t index) const {
	const WalletRecord &record = m_wallet_records.at(index);
	return AccountAddressLegacy{record.spend_public_key, m_view_public_key};
}

bool WalletLegacy::get_record(const AccountAddress &v_addr, size_t *index, WalletRecord *record) const {
	if (v_addr.type() != typeid(AccountAddressLegacy))
		return false;
	auto &addr = boost::get<AccountAddressLegacy>(v_addr);
	auto rit   = m_records_map.find(addr.S);
	if (m_view_public_key != addr.V || rit == m_records_map.end())
		return false;
	if (rit->second >= get_actual_records_count())
		return false;
	invariant(m_wallet_records.at(rit->second).spend_public_key == addr.S, "");
	*index  = rit->second;
	*record = m_wallet_records.at(rit->second);
	return true;
}

bool WalletLegacy::on_first_output_found(Timestamp ts) {
	if (m_currency.net != "main")
		return false;  // Legacy format has not place for other nets
	if (ts == 0 || m_oldest_timestamp != 0)
		return false;
	m_oldest_timestamp = ts;
	for (auto &&rec : m_wallet_records)
		if (rec.creation_timestamp == 0)
			rec.creation_timestamp = ts;
	m_log(logging::WARNING) << "Updating creation timestamp to " << ts
	                        << " in a wallet file (might take minutes for large wallets)...";
	save_and_check();
	return true;
}

void WalletLegacy::backup(const std::string &dst_name, const std::string &pass) const {
	const std::string dst_history_name  = dst_name + ".history";
	const std::string dst_payments_name = dst_name + ".payments";
	if (!platform::create_folder_if_necessary(dst_payments_name))
		throw std::runtime_error("Could not create folder for backup " + dst_payments_name);
	if (!platform::create_folder_if_necessary(dst_history_name))
		throw std::runtime_error("Could not create folder for backup " + dst_history_name);
	export_wallet(dst_name, pass, false, false);
	for (const auto &file : platform::get_filenames_in_folder(get_payment_queue_folder())) {
		platform::copy_file(get_payment_queue_folder() + "/" + file, dst_payments_name + "/" + file);
	}
	for (const auto &file : platform::get_filenames_in_folder(get_history_folder())) {
		platform::copy_file(get_history_folder() + "/" + file, dst_history_name + "/" + file);
	}
}

std::string WalletLegacy::get_history_folder() const { return m_path + ".history" + net_append(m_currency.net); }

std::string WalletLegacy::get_payment_queue_folder() const { return m_path + ".payments" + net_append(m_currency.net); }

bool WalletLegacy::save_history(const Hash &tid, const History &used_addresses) {
	std::string history_folder = get_history_folder();
	if (!platform::create_folders_if_necessary(history_folder))
		return false;
	if (used_addresses.empty())
		return true;  // saved empty history :)
	chacha_iv iv = crypto::rand<chacha_iv>();
	BinaryArray data;

	for (auto &&addr : used_addresses) {
		data |= addr.V.as_binary_array();
		data |= addr.S.as_binary_array();
	}
	BinaryArray encrypted_data;
	encrypted_data.resize(data.size(), 0);
	chacha8(data.data(), data.size(), m_history_key, iv, encrypted_data.data());
	encrypted_data.insert(encrypted_data.begin(), std::begin(iv.data), std::end(iv.data));

	const BinaryArray filename_data = tid.as_binary_array() | m_history_filename_seed.as_binary_array();
	const Hash filename_hash        = cn_fast_hash(filename_data);

	const auto tmp_path = history_folder + "/_tmp.txh";
	return platform::atomic_save_file(history_folder + "/" + common::pod_to_hex(filename_hash) + ".txh",
	    encrypted_data.data(), encrypted_data.size(), tmp_path);
}

Wallet::History WalletLegacy::load_history(const Hash &tid) const {
	Wallet::History used_addresses;
	std::string history_folder      = get_history_folder();
	const BinaryArray filename_data = tid.as_binary_array() | m_history_filename_seed.as_binary_array();
	const Hash filename_hash        = cn_fast_hash(filename_data);

	BinaryArray hist;
	if (!platform::load_file(history_folder + "/" + common::pod_to_hex(filename_hash) + ".txh", hist) ||
	    hist.size() < sizeof(chacha_iv) || (hist.size() - sizeof(chacha_iv)) % (2 * sizeof(PublicKey)) != 0)
		return used_addresses;
	const chacha_iv *iv = (const chacha_iv *)hist.data();
	BinaryArray dec(hist.size() - sizeof(chacha_iv), 0);
	chacha8(hist.data() + sizeof(chacha_iv), hist.size() - sizeof(chacha_iv), m_history_key, *iv, dec.data());
	for (size_t i = 0; i != dec.size() / (2 * sizeof(PublicKey)); ++i) {
		AccountAddressLegacy ad;
		memcpy(ad.V.data, dec.data() + i * 2 * sizeof(PublicKey), sizeof(PublicKey));
		memcpy(ad.S.data, dec.data() + i * 2 * sizeof(PublicKey) + sizeof(PublicKey), sizeof(PublicKey));
		used_addresses.insert(ad);
	}
	return used_addresses;
}

std::vector<BinaryArray> WalletLegacy::payment_queue_get() const {
	std::vector<BinaryArray> result;
	platform::remove_file(get_payment_queue_folder() + "/tmp.tx");
	for (const auto &file : platform::get_filenames_in_folder(get_payment_queue_folder())) {
		BinaryArray body;
		if (!platform::load_file(get_payment_queue_folder() + "/" + file, body))
			continue;
		result.push_back(std::move(body));
	}
	return result;
}

void WalletLegacy::payment_queue_add(const Hash &tid, const BinaryArray &binary_transaction) {
	const std::string file = get_payment_queue_folder() + "/" + common::pod_to_hex(tid) + ".tx";
	platform::create_folder_if_necessary(get_payment_queue_folder());
	if (!platform::atomic_save_file(
	        file, binary_transaction.data(), binary_transaction.size(), get_payment_queue_folder() + "/tmp.tx"))
		m_log(logging::WARNING) << "Failed to save transaction " << tid << " to file " << file;
	else
		m_log(logging::INFO) << "Saved transaction " << tid << " to file " << file;
}

void WalletLegacy::payment_queue_remove(const Hash &tid) {
	const std::string file = get_payment_queue_folder() + "/" + common::pod_to_hex(tid) + ".tx";
	if (!platform::remove_file(file))
		m_log(logging::WARNING) << "Failed to remove PQ transaction " << tid << " from file " << file;
	else
		m_log(logging::INFO) << "Removed PQ transaction " << tid << " from file " << file;
	platform::remove_file(get_payment_queue_folder());  // When it becomes empty
}

void WalletLegacy::set_label(const std::string &address, const std::string &label) {
	throw std::runtime_error("Legacy wallet file cannot store labels");
}

Wallet::OutputHandler WalletLegacy::get_output_handler() const {
	SecretKey vsk_copy                   = m_view_secret_key;
	SecretKey inv_vsk_copy               = m_inv_view_secret_key;
	uint8_t amethyst_transaction_version = m_currency.amethyst_transaction_version;
	return [vsk_copy, inv_vsk_copy, amethyst_transaction_version](uint8_t tx_version, const KeyDerivation &kd,
	           const Hash &tx_inputs_hash, size_t output_index, const OutputKey &key_output, PublicKey *address_S,
	           PublicKey *output_shared_secret) {
		if (tx_version >= amethyst_transaction_version) {
			*address_S = linkable_underive_address_S(inv_vsk_copy, tx_inputs_hash, output_index, key_output.public_key,
			    key_output.encrypted_secret, output_shared_secret);
			return;
		}
		if (kd == KeyDerivation{})
			*address_S = PublicKey{};
		else
			*address_S = underive_address_S(kd, output_index, key_output.public_key);
	};
}

bool WalletLegacy::detect_our_output(uint8_t tx_version, const Hash &tx_inputs_hash, const KeyDerivation &kd,
    size_t out_index, const PublicKey &address_S, const PublicKey &output_shared_secret, const OutputKey &key_output,
    Amount *amount, SecretKey *output_secret_key_s, SecretKey *output_secret_key_a, AccountAddress *address,
    size_t *record_index, KeyImage *keyimage) {
	WalletRecord record;
	AccountAddress addr;
	if (!get_look_ahead_record(address_S, record_index, &record, &addr))
		return false;
	if (record.spend_secret_key != SecretKey{}) {
		auto output_secret_hash_arg =
		    crypto::get_output_secret_hash_arg(output_shared_secret, tx_inputs_hash, out_index);
		const bool is_tx_amethyst = tx_version >= m_currency.amethyst_transaction_version;
		if (is_tx_amethyst) {
			SecretKey output_secret_hash = hash_to_scalar(output_secret_hash_arg.data(), output_secret_hash_arg.size());
			*output_secret_key_a = linkable_derive_output_secret_key(record.spend_secret_key, output_secret_hash);
		} else {
			if (kd == KeyDerivation{})  // tx_public_key was invalid
				return false;
			// We do some calcs twice here, but only for our outputs (which are usually very small %)
			PublicKey output_public_key2 = derive_output_public_key(kd, out_index, address_S);
			*output_secret_key_a         = derive_output_secret_key(kd, out_index, record.spend_secret_key);
			if (output_public_key2 != key_output.public_key)
				return false;
		}
		*output_secret_key_s        = SecretKey{};
		PublicKey output_public_key = secret_keys_to_public_key(*output_secret_key_a, *output_secret_key_s);
		if (output_public_key != key_output.public_key)
			return false;
		*keyimage = generate_key_image(key_output.public_key, *output_secret_key_a);
	}
	*address = addr;
	*amount  = key_output.amount;
	return true;
}
