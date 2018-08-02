// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <set>
#include <unordered_map>
#include "CryptoNote.hpp"
#include "Currency.hpp"
#include "crypto/chacha8.h"
#include "logging/LoggerMessage.hpp"
#include "platform/Files.hpp"

namespace bytecoin {

using WalletKey  = crypto::chacha8_key;
using HistoryKey = crypto::chacha8_key;

struct WalletRecord {
	crypto::PublicKey spend_public_key{};
	crypto::SecretKey spend_secret_key{};
	Timestamp creation_timestamp = 0;
};

inline bool operator==(const WalletRecord &lhs, const WalletRecord &rhs) {
	return lhs.spend_public_key == rhs.spend_public_key && lhs.spend_secret_key == rhs.spend_secret_key &&
	       lhs.creation_timestamp == rhs.creation_timestamp;
}
inline bool operator!=(const WalletRecord &lhs, const WalletRecord &rhs) { return !(lhs == rhs); }

// stores at most 1 view secret key. 1 or more spend secret keys
// We do not allow deleting first spend key. It is used in seed calculations
// All file formats are opened as is, and saved to V2 when changing something
class Wallet {
	logging::LoggerRef m_log;
	std::unique_ptr<platform::FileStream> file;
	std::string m_path;
	std::string m_password;
	WalletKey m_wallet_key;  // very slow to generate, save

	PublicKey m_view_public_key;
	SecretKey m_view_secret_key;
	WalletRecord first_record;
	std::unordered_map<PublicKey, WalletRecord> m_wallet_records;
	//	Timestamp m_creation_timestamp = 0;
	Timestamp m_oldest_timestamp = std::numeric_limits<Timestamp>::max();

	Hash m_seed;                   // Main seed, never used directly
	Hash m_tx_derivation_seed;     // Hashed from seed
	HistoryKey m_history_key;      // Hashed from seed
	Hash m_history_filename_seed;  // Hashed from seed

	void load_container_storage();
	void load_legacy_wallet_file();
	bool operator==(const Wallet &) const;
	bool operator!=(const Wallet &other) const { return !(*this == other); }

	void save(const std::string &export_path, bool view_only);
	void save_and_check();

public:
	class Exception : public std::runtime_error {
	public:
		const int return_code;
		explicit Exception(int rc, const std::string &what) : std::runtime_error(what), return_code(rc) {}
	};
	Wallet(logging::ILogger &log, const std::string &path, const std::string &password, bool create = false,
	    const std::string &import_keys = std::string());
	std::vector<WalletRecord> generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct, Timestamp now,
	    bool *rescan_from_ct);  // set secret_key to SecretKey{} to generate
	void set_password(const std::string &password);
	void export_wallet(const std::string &export_path, bool view_only);
	bool is_view_only() const { return first_record.spend_secret_key == SecretKey{}; }
	BinaryArray export_keys() const;
	const PublicKey &get_view_public_key() const { return m_view_public_key; }
	const SecretKey &get_view_secret_key() const { return m_view_secret_key; }
	const std::unordered_map<PublicKey, WalletRecord> &get_records() const { return m_wallet_records; }
	bool get_only_record(std::unordered_map<PublicKey, WalletRecord> &records, const AccountPublicAddress &) const;

	bool spend_keys_for_address(const AccountPublicAddress &, AccountKeys &) const;
	AccountPublicAddress get_first_address() const;

	static size_t wallet_file_size(size_t records);

	std::string get_cache_name() const;

	const Hash &get_tx_derivation_seed() const { return m_tx_derivation_seed; }
	const HistoryKey &get_history_key() const { return m_history_key; }
	const Hash &get_history_filename_seed() const { return m_history_filename_seed; }
	std::string get_history_folder() const { return m_path + ".history"; }
	std::string get_payment_queue_folder() const { return m_path + ".payments"; }

	Timestamp get_oldest_timestamp() const { return m_oldest_timestamp; }
	void on_first_output_found(Timestamp ts);  // called by WalletState, updates creation timestamp for imported wallet

	typedef std::set<AccountPublicAddress> History;
	bool save_history(const Hash &bid, const History &used_addresses) const;
	History load_history(const Hash &bid) const;
};

}  // namespace bytecoin
