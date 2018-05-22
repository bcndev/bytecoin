// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <http/JsonRpc.h>
#include "CryptoNoteTools.hpp"
#include "WalletSerializationV1.h"
#include "WalletState.hpp"
#include "common/MemoryStreams.hpp"
#include "common/StringTools.hpp"
#include "crypto/crypto.hpp"
#include "platform/Files.hpp"
#include "platform/PathTools.hpp"

using namespace bytecoin;

static const uint8_t SERIALIZATION_VERSION_V2 = 6;

static const size_t CHECK_KEYS_COUNT = 100;
#pragma pack(push, 1)
struct EncryptedWalletRecord {
	crypto::chacha8_iv iv;
	// Secret key, public key and creation timestamp
	uint8_t data[sizeof(crypto::PublicKey) + sizeof(crypto::SecretKey) + sizeof(uint64_t)]{};
};
struct ContainerStoragePrefix {
	// We moved uint8_t version out of this struct, because with it other fields become unaligned
	crypto::chacha8_iv next_iv;
	EncryptedWalletRecord encrypted_view_keys;
};
struct ContainerStorageWalletRecord {
	crypto::PublicKey pk{};
	crypto::SecretKey sk{};
	uint64_t ct = 0;
};
#pragma pack(pop)

static void decrypt_key_pair(
    const EncryptedWalletRecord &r, PublicKey &pk, SecretKey &sk, Timestamp &ct, const WalletKey &key) {
	ContainerStorageWalletRecord rec;
	chacha8(r.data, sizeof(r.data), key, r.iv, &rec);
	pk = rec.pk;
	sk = rec.sk;
	ct = static_cast<Timestamp>(rec.ct);
}

static void encrypt_key_pair(EncryptedWalletRecord &r, PublicKey pk, SecretKey sk, Timestamp ct, const WalletKey &key) {
	ContainerStorageWalletRecord rec;
	rec.pk = pk;
	rec.sk = sk;
	rec.ct = ct;
	r.iv   = crypto::rand<crypto::chacha8_iv>();
	chacha8(&rec, sizeof(r.data), key, r.iv, r.data);
}

size_t Wallet::wallet_file_size(size_t records) {
	return 1 + sizeof(ContainerStoragePrefix) + sizeof(uint64_t) * 2 + sizeof(EncryptedWalletRecord) * records;
}

void Wallet::load_container_storage() {
	uint8_t version = 0;
	ContainerStoragePrefix prefix{};
	uint64_t f_item_capacity = 0;
	uint64_t f_item_count    = 0;
	file->read(&version, 1);
	file->read(reinterpret_cast<char *>(&prefix), sizeof(prefix));
	file->read(reinterpret_cast<char *>(&f_item_capacity), sizeof(f_item_capacity));
	file->read(reinterpret_cast<char *>(&f_item_count), sizeof(f_item_count));

	if (version < SERIALIZATION_VERSION_V2)
		throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Wallet version too old");

	Timestamp creation_timestamp = 0;  // We ignore view keys timestamp on load
	decrypt_key_pair(
	    prefix.encrypted_view_keys, m_view_public_key, m_view_secret_key, creation_timestamp, m_wallet_key);
	if (!keys_match(m_view_secret_key, m_view_public_key))
		throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Restored view public key doesn't correspond to secret key");

	const size_t item_count =
	    boost::lexical_cast<size_t>(std::min(f_item_count, f_item_capacity));  // Protection against write shredding
	std::vector<EncryptedWalletRecord> all_encrypted(item_count);
	file->read(reinterpret_cast<char *>(all_encrypted.data()), sizeof(EncryptedWalletRecord) * item_count);
	bool tracking_mode = false;
	for (size_t i = 0; i != item_count; ++i) {
		WalletRecord wallet_record;
		decrypt_key_pair(all_encrypted[i], wallet_record.spend_public_key, wallet_record.spend_secret_key,
		    wallet_record.creation_timestamp, m_wallet_key);

		if (i == 0) {
			tracking_mode = wallet_record.spend_secret_key == SecretKey{};
			first_record  = wallet_record;
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
				if (!key_isvalid(wallet_record.spend_public_key)) {
					throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Public spend key is incorrect");
				}
			}
		}
		m_oldest_timestamp = std::min(m_oldest_timestamp, wallet_record.creation_timestamp);
		m_wallet_records.insert(std::make_pair(wallet_record.spend_public_key, wallet_record));
	}
	auto file_size           = file->seek(0, SEEK_END);
	auto should_be_file_size = wallet_file_size(item_count);
	if (file_size > should_be_file_size) {  // We truncate legacy wallet cache
		try {
			file->truncate(should_be_file_size);
			std::cout << "Truncated wallet cache legacy wallet file to size=" << should_be_file_size << std::endl;
		} catch (const std::exception &) {  // probably read only, ignore
		}
	}
}

void Wallet::load_legacy_wallet_file() {
	std::vector<WalletRecord> wallets_container;

	WalletSerializerV1 s(m_view_public_key, m_view_secret_key, wallets_container);

	s.load(m_wallet_key, *file.get());

	first_record = wallets_container.at(0);
	for (auto &&w : wallets_container) {
		m_oldest_timestamp = std::min(m_oldest_timestamp, w.creation_timestamp);
		m_wallet_records.insert(std::make_pair(w.spend_public_key, w));
	}
}

Wallet::Wallet(const std::string &path, const std::string &password, bool create, const std::string &import_keys)
    : m_path(path), m_password(password) {
	crypto::CryptoNightContext cn_ctx;
	m_wallet_key = generate_chacha8_key(cn_ctx, password);
	if (create) {
		try {
			file.reset(new platform::FileStream(path, platform::FileStream::READ_EXISTING));
		} catch (const common::StreamError &) {
			// file does not exist
		}
		if (file.get())  // opened ok
			throw Exception(api::WALLET_FILE_EXISTS,
			    "Will not overwrite existing wallet - delete it first or specify another file " + path);

		if (import_keys.empty()) {
			m_oldest_timestamp = static_cast<Timestamp>(std::time(nullptr));
			crypto::random_keypair(m_view_public_key, m_view_secret_key);
			generate_new_address(SecretKey{}, m_oldest_timestamp);
			first_record = m_wallet_records.begin()->second;
		} else {
			if (import_keys.size() != 256)
				throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Imported keys should be exactly 128 hex bytes");
			WalletRecord record{};
			if (!common::pod_from_hex(import_keys.substr(0, 64), record.spend_public_key) ||
			    !common::pod_from_hex(import_keys.substr(64, 64), m_view_public_key) ||
			    !common::pod_from_hex(import_keys.substr(128, 64), record.spend_secret_key) ||
			    !common::pod_from_hex(import_keys.substr(192, 64), m_view_secret_key))
				throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Imported keys should contain only hex bytes");
			if (!keys_match(m_view_secret_key, m_view_public_key))
				throw Exception(
				    api::WALLET_FILE_DECRYPT_ERROR, "Imported secret view key does not match corresponding public key");
			if (record.spend_secret_key != SecretKey{} && !keys_match(record.spend_secret_key, record.spend_public_key))
				throw Exception(api::WALLET_FILE_DECRYPT_ERROR,
				    "Imported secret spend key does not match corresponding public key");
			m_wallet_records.insert(std::make_pair(record.spend_public_key, record));
			first_record       = m_wallet_records.begin()->second;
			m_oldest_timestamp = 0;  // Alas, will scan entire blockchain
		}
		save_and_check();
	}
	try {
		file.reset(new platform::FileStream(path, platform::FileStream::READ_WRITE_EXISTING));
	} catch (const common::StreamError &) {  // Read-only media?
		file.reset(new platform::FileStream(path, platform::FileStream::READ_EXISTING));
	}
	uint8_t version = 0;
	file->read(&version, 1);
	if (version > SERIALIZATION_VERSION_V2)
		throw Exception(api::WALLET_FILE_UNKNOWN_VERSION, "Unknown version");
	file->seek(0, SEEK_SET);
	if (version < SERIALIZATION_VERSION_V2) {
		try {
			load_legacy_wallet_file();
		} catch (const common::StreamError &ex) {
			throw Exception(api::WALLET_FILE_READ_ERROR, std::string("Error reading wallet file ") + ex.what());
		} catch (const std::exception &ex) {
			throw Exception(api::WALLET_FILE_DECRYPT_ERROR, std::string("Error decrypting wallet file ") + ex.what());
		}
		file.reset();  // Indicates legacy format
		try {
			save_and_check();  // We try to overwrite legacy format with new format
			std::cout << "Overwritten legacy wallet file with new data format" << std::endl;
		} catch (const std::exception &) {  // probably read only, ignore
		}
	} else {
		load_container_storage();
	}
	if (m_wallet_records.empty())
		throw Exception(api::WALLET_FILE_DECRYPT_ERROR, "Error reading wallet file");

	if (!is_view_only()) {
		BinaryArray seed_data;
		seed_data.assign(std::begin(m_view_secret_key.data), std::end(m_view_secret_key.data));
		common::append(
		    seed_data, std::begin(first_record.spend_secret_key.data), std::end(first_record.spend_secret_key.data));
		m_seed = crypto::cn_fast_hash(seed_data.data(), seed_data.size());

		const unsigned char derivation_prefix[] = "tx_derivation";
		seed_data.assign(derivation_prefix, derivation_prefix + sizeof(derivation_prefix) - 1);
		common::append(seed_data, std::begin(m_seed.data), std::end(m_seed.data));
		m_tx_derivation_seed = crypto::cn_fast_hash(seed_data.data(), seed_data.size());

		const unsigned char history_filename_prefix[] = "history_filename";
		seed_data.assign(history_filename_prefix, history_filename_prefix + sizeof(history_filename_prefix) - 1);
		common::append(seed_data, std::begin(m_seed.data), std::end(m_seed.data));
		m_history_filename_seed = crypto::cn_fast_hash(seed_data.data(), seed_data.size());

		const unsigned char history_prefix[] = "history";
		seed_data.assign(history_prefix, history_prefix + sizeof(history_prefix) - 1);
		common::append(seed_data, std::begin(m_seed.data), std::end(m_seed.data));
		m_history_key = crypto::chacha8_key{crypto::cn_fast_hash(seed_data.data(), seed_data.size())};
	}
}

void Wallet::save(const std::string &export_path, bool view_only) {
	platform::FileStream f(export_path, platform::FileStream::TRUNCATE_READ_WRITE);

	uint8_t version = SERIALIZATION_VERSION_V2;
	ContainerStoragePrefix prefix{};
	encrypt_key_pair(
	    prefix.encrypted_view_keys, m_view_public_key, m_view_secret_key, m_oldest_timestamp, m_wallet_key);
	uint64_t item_count = m_wallet_records.size();
	f.write(&version, 1);
	f.write(&prefix, sizeof(prefix));
	f.write(&item_count, sizeof(item_count));  // we set capacity to item_count
	f.write(&item_count, sizeof(item_count));

	EncryptedWalletRecord record;
	encrypt_key_pair(record, first_record.spend_public_key, view_only ? SecretKey{} : first_record.spend_secret_key,
	    first_record.creation_timestamp, m_wallet_key);
	f.write(&record, sizeof(record));
	for (auto &&r : m_wallet_records) {
		if (r.second.spend_public_key == first_record.spend_public_key)
			continue;
		encrypt_key_pair(record, r.second.spend_public_key, view_only ? SecretKey{} : r.second.spend_secret_key,
		    r.second.creation_timestamp, m_wallet_key);

		f.write(&record, sizeof(record));
	}
	f.fdatasync();
}

BinaryArray Wallet::export_keys() const {
	BinaryArray result;
	if (m_wallet_records.size() != 1)
		throw Exception(
		    api::WALLETD_EXPORTKEYS_MORETHANONE, "You can only export keys from a wallet containing 1 address");
	common::append(
	    result, std::begin(first_record.spend_public_key.data), std::end(first_record.spend_public_key.data));
	common::append(result, std::begin(m_view_public_key.data), std::end(m_view_public_key.data));
	common::append(
	    result, std::begin(first_record.spend_secret_key.data), std::end(first_record.spend_secret_key.data));
	common::append(result, std::begin(m_view_secret_key.data), std::end(m_view_secret_key.data));
	return result;
}

void Wallet::save_and_check() {
	const std::string tmp_path = m_path + ".tmp";

	save(tmp_path, false);

	Wallet other(tmp_path, m_password);
	if (*this != other)
		throw Exception(api::WALLET_FILE_WRITE_ERROR, "Error writing wallet file - records do not match");
	file.reset();
	if (!platform::atomic_replace_file(tmp_path, m_path))
		throw Exception(api::WALLET_FILE_WRITE_ERROR, "Error replacing wallet file");
	std::swap(file, other.file);
}

void Wallet::set_password(const std::string &password) {
	m_password = password;
	crypto::CryptoNightContext cn_ctx;
	m_wallet_key = generate_chacha8_key(cn_ctx, m_password);
	save_and_check();
}

void Wallet::export_view_only(const std::string &export_path) {
	std::unique_ptr<platform::FileStream> export_file;
	try {
		export_file.reset(new platform::FileStream(export_path, platform::FileStream::READ_EXISTING));
	} catch (const common::StreamError &) {
		// file does not exist
	}
	if (export_file.get())  // opened ok
		throw Exception(api::WALLET_FILE_EXISTS,
		    "Will not overwrite existing "
		    "wallet - delete it first or "
		    "specify another file " +
		        export_path);
	save(export_path, true);
}

bool Wallet::operator==(const Wallet &other) const {
	return m_view_public_key == other.m_view_public_key && m_view_secret_key == other.m_view_secret_key &&
	       m_oldest_timestamp == other.m_oldest_timestamp && m_wallet_records == other.m_wallet_records;
}

std::pair<WalletRecord, bool> Wallet::generate_new_address(const SecretKey &sk, Timestamp ct) {
	WalletRecord record{};
	record.creation_timestamp = ct;
	if (sk == SecretKey{})
		crypto::random_keypair(record.spend_public_key, record.spend_secret_key);
	else {
		record.spend_secret_key = sk;
		if (!secret_key_to_public_key(sk, record.spend_public_key))
			throw Exception(101, "Imported keypair is invalid - sk=" + common::pod_to_hex(sk));
	}
	m_oldest_timestamp = std::min(m_oldest_timestamp, record.creation_timestamp);
	auto ins           = m_wallet_records.insert(std::make_pair(record.spend_public_key, record));
	return std::make_pair(ins.first->second, ins.second);
}

AccountPublicAddress Wallet::get_first_address() const {
	return AccountPublicAddress{first_record.spend_public_key, m_view_public_key};
}

std::vector<WalletRecord> Wallet::generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct) {
	std::vector<WalletRecord> result;
	if (is_view_only())
		return result;
	if (!file.get()) {  // Legacy format, now overwrite
		save_and_check();
	}
	size_t append_pos = wallet_file_size(m_wallet_records.size());
	file->seek(append_pos, SEEK_SET);
	for (auto &&sk : sks) {
		auto new_rit = generate_new_address(sk, ct);
		if (!new_rit.second) {
			result.push_back(new_rit.first);
			continue;  // Existed before, do not append
		}
		EncryptedWalletRecord record;
		encrypt_key_pair(record, new_rit.first.spend_public_key, new_rit.first.spend_secret_key,
		    new_rit.first.creation_timestamp, m_wallet_key);
		file->write(&record, sizeof(record));
		result.push_back(new_rit.first);
	}
	file->fdatasync();
	file->seek(1 + sizeof(ContainerStoragePrefix), SEEK_SET);
	uint64_t item_count = m_wallet_records.size();
	file->write(&item_count, sizeof(item_count));
	file->write(&item_count, sizeof(item_count));
	file->fdatasync();
	return result;
}

void Wallet::on_first_output_found(Timestamp ts) {
	if (ts == 0 || m_oldest_timestamp != 0)
		return;
	m_oldest_timestamp              = ts;
	first_record.creation_timestamp = ts;
	for (auto &&rec : m_wallet_records)
		rec.second.creation_timestamp = ts;
	std::cout << "Updating creation timestamp in a wallet file imported from keys..." << std::endl;
	save_and_check();
}

std::string Wallet::get_cache_name() const {
	Hash h = crypto::cn_fast_hash(m_view_public_key.data, sizeof(m_view_public_key.data));
	return common::pod_to_hex(h);
}

bool Wallet::spend_keys_for_address(const AccountPublicAddress &addr, AccountKeys &keys) const {
	auto sec = m_wallet_records.find(addr.spend_public_key);
	if (m_view_public_key != addr.view_public_key || sec == m_wallet_records.end() ||
	    sec->second.spend_public_key != addr.spend_public_key || sec->second.spend_secret_key == SecretKey{})
		return false;
	keys.address          = addr;
	keys.spend_secret_key = sec->second.spend_secret_key;
	keys.view_secret_key  = m_view_secret_key;
	return true;
}

bool Wallet::get_only_record(
    std::unordered_map<PublicKey, WalletRecord> &records, const AccountPublicAddress &addr) const {
	auto rit = m_wallet_records.find(addr.spend_public_key);
	if (rit == m_wallet_records.end() || rit->second.spend_public_key != addr.spend_public_key ||
	    m_view_public_key != addr.view_public_key)
		return false;
	records.insert(*rit);
	return true;
}

bool Wallet::save_history(const Hash &bid, const History &used_addresses) const {
	std::string history_folder = get_history_folder();
	if (!platform::create_directories_if_necessary(history_folder))
		return false;
	crypto::chacha8_iv iv = crypto::rand<crypto::chacha8_iv>();
	BinaryArray data;

	for (auto &&to : used_addresses) {
		common::append(data, std::begin(to.view_public_key.data), std::end(to.view_public_key.data));
		common::append(data, std::begin(to.spend_public_key.data), std::end(to.spend_public_key.data));
	}
	BinaryArray encrypted_data;
	encrypted_data.resize(data.size(), 0);
	crypto::chacha8(data.data(), data.size(), m_history_key, iv, encrypted_data.data());
	encrypted_data.insert(encrypted_data.begin(), std::begin(iv.data), std::end(iv.data));

	BinaryArray filename_data(std::begin(bid.data), std::end(bid.data));
	common::append(filename_data, std::begin(m_history_filename_seed.data), std::end(m_history_filename_seed.data));
	Hash filename_hash = crypto::cn_fast_hash(filename_data.data(), filename_data.size());

	const auto tmp_path = history_folder + "/_tmp.txh";
	if( !common::save_file(tmp_path, encrypted_data.data(), encrypted_data.size()) )
		return false;
	return platform::atomic_replace_file(tmp_path, history_folder + "/" + common::pod_to_hex(filename_hash) + ".txh");
}

Wallet::History Wallet::load_history(const Hash &bid) const {
	Wallet::History used_addresses;
	std::string history_folder = get_history_folder();
	BinaryArray filename_data(std::begin(bid.data), std::end(bid.data));
	common::append(filename_data, std::begin(m_history_filename_seed.data), std::end(m_history_filename_seed.data));
	Hash filename_hash = crypto::cn_fast_hash(filename_data.data(), filename_data.size());

	BinaryArray hist;
	if (!common::load_file(history_folder + "/" + common::pod_to_hex(filename_hash) + ".txh", hist) ||
	    hist.size() < sizeof(crypto::chacha8_iv) ||
	    (hist.size() - sizeof(crypto::chacha8_iv)) % (2 * sizeof(PublicKey)) != 0)
		return used_addresses;
	const crypto::chacha8_iv *iv = (const crypto::chacha8_iv *)hist.data();
	BinaryArray dec(hist.size() - sizeof(crypto::chacha8_iv), 0);
	crypto::chacha8(hist.data() + sizeof(crypto::chacha8_iv), hist.size() - sizeof(crypto::chacha8_iv), m_history_key,
	    *iv, dec.data());
	for (size_t i = 0; i != dec.size() / (2 * sizeof(PublicKey)); ++i) {
		AccountPublicAddress ad;
		memcpy(ad.view_public_key.data, dec.data() + i * 2 * sizeof(PublicKey), sizeof(PublicKey));
		memcpy(ad.spend_public_key.data, dec.data() + i * 2 * sizeof(PublicKey) + sizeof(PublicKey), sizeof(PublicKey));
		used_addresses.insert(ad);
	}
	return used_addresses;
}
