// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <set>
#include <unordered_map>
#include "CryptoNote.hpp"
#include "Currency.hpp"
//#include "Multicore.hpp"
#include <boost/optional.hpp>
#include "crypto/chacha.hpp"
#include "logging/LoggerMessage.hpp"
#include "platform/DBsqlite3.hpp"
#include "platform/Files.hpp"

namespace cn {

struct WalletRecord {
	PublicKey spend_public_key{};
	SecretKey spend_secret_key{};
	Timestamp creation_timestamp = 0;
};

inline bool operator==(const WalletRecord &lhs, const WalletRecord &rhs) {
	return lhs.spend_public_key == rhs.spend_public_key && lhs.spend_secret_key == rhs.spend_secret_key &&
	       lhs.creation_timestamp == rhs.creation_timestamp;
}
inline bool operator!=(const WalletRecord &lhs, const WalletRecord &rhs) { return !(lhs == rhs); }

// stores at most 1 view secret key. 1 or more spend secret keys
// We do not allow deleting first spend key. It is used in seed calculations
// File formats are opened as is, and saved to V2 when changing something
class Wallet {
protected:
	const Currency &m_currency;
	logging::LoggerRef m_log;
	std::string m_path;
	crypto::chacha_key m_wallet_key;  // very slow to generate, save

	PublicKey m_view_public_key;
	SecretKey m_view_secret_key;
	std::vector<WalletRecord> m_wallet_records;
	std::unordered_map<PublicKey, size_t> m_records_map;  // index into vector
	//	Timestamp m_creation_timestamp = 0;
	Timestamp m_oldest_timestamp = std::numeric_limits<Timestamp>::max();

	Hash m_seed;                // Main seed, never used directly
	Hash m_tx_derivation_seed;  // Hashed from seed
public:
	class Exception : public std::runtime_error {
	public:
		const int return_code;
		explicit Exception(int rc, const std::string &what) : std::runtime_error(what), return_code(rc) {}
	};
	Wallet(const Currency &currency, logging::ILogger &log, const std::string &path);
	virtual ~Wallet()                                      = default;
	virtual void set_password(const std::string &password) = 0;
	virtual void export_wallet(const std::string &export_path, const std::string &new_password, bool view_only,
	    bool view_outgoing_addresses) const                = 0;
	virtual bool is_view_only() const { return m_wallet_records.at(0).spend_secret_key == SecretKey{}; }
	bool can_view_outgoing_addresses() const { return m_tx_derivation_seed != Hash{}; }
	virtual bool is_deterministic() const { return false; }
	virtual bool is_unlinkable() const { return false; }
	virtual bool is_auditable() const { return false; }
	bool is_det_viewonly() const { return is_view_only() && is_deterministic(); }
	virtual std::string export_keys() const = 0;
	const PublicKey &get_view_public_key() const { return m_view_public_key; }
	const SecretKey &get_view_secret_key() const { return m_view_secret_key; }
	const std::vector<WalletRecord> &get_records() const { return m_wallet_records; }
	virtual size_t get_actual_records_count() const { return m_wallet_records.size(); }
	virtual bool get_record(WalletRecord *record, const AccountAddress &) const = 0;
	virtual void create_look_ahead_records(size_t count) {}
	bool get_look_ahead_record(WalletRecord &record, const PublicKey &);

	bool is_our_address(const AccountAddress &) const;
	AccountAddress get_first_address() const;
	virtual AccountAddress record_to_address(const WalletRecord &record) const = 0;

	virtual std::vector<WalletRecord> generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct,
	    Timestamp now,
	    bool *rescan_from_ct) = 0;  // set secret_key to SecretKey{} to generate

	std::string get_cache_name() const;

	virtual Timestamp get_oldest_timestamp() const { return m_oldest_timestamp; }
	virtual void on_first_output_found(Timestamp ts) = 0;
	// called by WalletState, updates creation timestamp for imported wallet

	const Hash &get_tx_derivation_seed() const { return m_tx_derivation_seed; }

	virtual void backup(const std::string &dst_name, const std::string &pass) const = 0;

	typedef std::set<AccountAddressSimple> History;
	virtual bool save_history(const Hash &tid, const History &used_addresses) { return true; }
	virtual History load_history(const Hash &tid) const = 0;

	virtual std::vector<BinaryArray> payment_queue_get() const                             = 0;
	virtual void payment_queue_add(const Hash &tid, const BinaryArray &binary_transaction) = 0;
	virtual void payment_queue_remove(const Hash &tid)                                     = 0;

	virtual void set_label(const std::string &address, const std::string &label) = 0;
	virtual std::string get_label(const std::string &address) const              = 0;

	typedef std::function<void(const PublicKey &tx_public_key, boost::optional<KeyDerivation> *,
	    const Hash &tx_inputs_hash, size_t out_index, const OutputKey &, PublicKey *, SecretKey *)>
	    OutputHandler;
	// Self-contain functor with all info copied to be called from other threads
	virtual OutputHandler get_output_handler() const                                                            = 0;
	virtual bool detect_our_output(const Hash &tid, const Hash &tx_inputs_hash,
	    const boost::optional<KeyDerivation> &kd, size_t out_index, const PublicKey &spend_public_key,
	    const SecretKey &secret_scalar, const OutputKey &, Amount *, KeyPair *output_keypair, AccountAddress *) = 0;
};

// stores at most 1 view secret key. 1 or more spend secret keys
// We do not allow deleting first spend key. It is used in seed calculations
// File formats are opened as is, and saved to V2 when changing something
class WalletContainerStorage : public Wallet {
	std::unique_ptr<platform::FileStream> m_file;

	crypto::chacha_key m_history_key;  // Hashed from seed
	Hash m_history_filename_seed;      // Hashed from seed

	void load_container_storage();
	void load_legacy_wallet_file();
	bool operator==(const WalletContainerStorage &) const;
	bool operator!=(const WalletContainerStorage &other) const { return !(*this == other); }

	void load();
	void save(const std::string &export_path, const crypto::chacha_key &wallet_key, bool view_only,
	    platform::OpenMode open_mode) const;
	void save_and_check();

	std::string get_history_folder() const;
	std::string get_payment_queue_folder() const;

	WalletContainerStorage(
	    const Currency &currency, logging::ILogger &log, const std::string &path, const crypto::chacha_key &wallet_key);

public:
	WalletContainerStorage(
	    const Currency &currency, logging::ILogger &log, const std::string &path, const std::string &password);
	WalletContainerStorage(const Currency &currency, logging::ILogger &log, const std::string &path,
	    const std::string &password, const std::string &import_keys, Timestamp creation_timestamp);
	std::vector<WalletRecord> generate_new_addresses(
	    const std::vector<SecretKey> &sks, Timestamp ct, Timestamp now, bool *rescan_from_ct) override;
	AccountAddress record_to_address(const WalletRecord &record) const override;
	bool get_record(WalletRecord *record, const AccountAddress &) const override;
	void set_password(const std::string &password) override;
	void export_wallet(const std::string &export_path, const std::string &new_password, bool view_only,
	    bool view_outgoing_addresses) const override;
	std::string export_keys() const override;

	static size_t wallet_file_size(size_t records);

	void on_first_output_found(Timestamp ts) override;

	void backup(const std::string &dst_name, const std::string &pass) const override;

	bool save_history(const Hash &tid, const History &used_addresses) override;
	History load_history(const Hash &tid) const override;

	std::vector<BinaryArray> payment_queue_get() const override;
	void payment_queue_add(const Hash &tid, const BinaryArray &binary_transaction) override;
	void payment_queue_remove(const Hash &tid) override;

	void set_label(const std::string &address, const std::string &label) override;
	std::string get_label(const std::string &address) const override { return std::string(); }

	OutputHandler get_output_handler() const override;
	bool detect_our_output(const Hash &tid, const Hash &tx_inputs_hash, const boost::optional<KeyDerivation> &kd,
	    size_t out_index, const PublicKey &spend_public_key, const SecretKey &secret_scalar, const OutputKey &,
	    Amount *, KeyPair *output_keypair, AccountAddress *) override;
};

// stores either mnemonic or some seeds if view-only
// stores number of used addresses, (per net) creation timestamp, (per net) payment queue
class WalletHD : public Wallet {
	platform::sqlite::Dbi m_db_dbi;
	uint8_t m_address_type = 0;
	KeyPair m_spend_key_base;
	size_t m_used_address_count = 1;
	std::map<std::string, std::string> m_labels;

	static BinaryArray encrypt_data(const crypto::chacha_key &wallet_key, const BinaryArray &data);
	static BinaryArray decrypt_data(const crypto::chacha_key &wallet_key, const uint8_t *value_data, size_t value_size);
	void put_salt(const BinaryArray &salt);
	BinaryArray get_salt() const;
	void commit();

	void put(const std::string &key, const common::BinaryArray &value, bool nooverwrite);
	bool get(const std::string &key, common::BinaryArray &value) const;
	void put(const std::string &key, const std::string &value, bool nooverwrite);
	bool get(const std::string &key, std::string &value) const;

	void generate_ahead();
	void generate_ahead1(size_t counter, std::vector<WalletRecord> &result) const;
	void load();

	std::vector<std::pair<std::string, BinaryArray>> parameters_get() const;
	std::vector<std::tuple<Hash, std::string, BinaryArray>> payment_queue_get2() const;
	void payment_queue_add(const Hash &tid, const std::string &net, const BinaryArray &binary_transaction);

public:
	static std::string generate_mnemonic(size_t bits, uint32_t version);
	static bool is_sqlite(const std::string &full_path);
	// In contrast with WalletContainerStorage, we must know read_only flag, because otherwise
	// inability to save address count will lead to wallet losing track of funds due to skipping outputs
	WalletHD(const Currency &currency, logging::ILogger &log, const std::string &path, const std::string &password,
	    bool readonly);
	WalletHD(const Currency &currency, logging::ILogger &log, const std::string &path, const std::string &password,
	    const std::string &mnemonic, uint8_t address_type, Timestamp creation_timestamp,
	    const std::string &mnemonic_password);
	bool is_view_only() const override { return m_spend_key_base.secret_key == SecretKey{}; }
	bool is_deterministic() const override { return true; }
	bool is_unlinkable() const override { return true; }
	bool is_auditable() const override { return m_address_type == AccountAddressUnlinkable::type_tag_auditable; }
	size_t get_actual_records_count() const override { return m_used_address_count; }
	std::vector<WalletRecord> generate_new_addresses(
	    const std::vector<SecretKey> &sks, Timestamp ct, Timestamp now, bool *rescan_from_ct) override;
	AccountAddress record_to_address(const WalletRecord &record) const override;
	bool get_record(WalletRecord *record, const AccountAddress &) const override;
	void set_password(const std::string &password) override;
	void export_wallet(const std::string &export_path, const std::string &new_password, bool view_only,
	    bool view_outgoing_addresses) const override;
	std::string export_keys() const override;

	// Date first unlinkable addresses appeared in stagenet blockchain
	Timestamp get_oldest_timestamp() const override { return std::max<Timestamp>(m_oldest_timestamp, 1540489975); }
	void on_first_output_found(Timestamp ts) override;
	void create_look_ahead_records(size_t count) override;

	void backup(const std::string &dst_name, const std::string &pass) const override;

	History load_history(const Hash &tid) const override;

	std::vector<BinaryArray> payment_queue_get() const override;
	void payment_queue_add(const Hash &tid, const BinaryArray &binary_transaction) override;
	void payment_queue_remove(const Hash &tid) override;

	void set_label(const std::string &address, const std::string &label) override;
	std::string get_label(const std::string &address) const override;

	OutputHandler get_output_handler() const override;
	bool detect_our_output(const Hash &tid, const Hash &tx_inputs_hash, const boost::optional<KeyDerivation> &kd,
	    size_t out_index, const PublicKey &spend_public_key, const SecretKey &secret_scalar, const OutputKey &,
	    Amount *, KeyPair *output_keypair, AccountAddress *) override;
};

}  // namespace cn
