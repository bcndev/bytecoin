// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <set>
#include <unordered_map>
#include "CryptoNote.hpp"
#include "Currency.hpp"
#include "crypto/chacha.hpp"
#include "logging/LoggerMessage.hpp"

namespace cn {

namespace hardware {
class Proxy;
}

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
	crypto::chacha_key m_wallet_key;  // very slow to generate, save

	PublicKey m_view_public_key;
	SecretKey m_view_secret_key;
	std::vector<WalletRecord> m_wallet_records;
	std::unordered_map<PublicKey, size_t> m_records_map;  // index into vector

	Hash m_seed;       // Main seed, never used directly
	Hash m_view_seed;  // Hashed from seed

	virtual AccountAddress record_to_address(size_t index) const = 0;

	static std::string net_append(const std::string &net);

public:
	class Exception : public std::runtime_error {
	public:
		const int return_code;
		explicit Exception(int rc, const std::string &what) : std::runtime_error(what), return_code(rc) {}
	};
	Wallet(const Currency &currency, logging::ILogger &log);
	virtual ~Wallet() = default;
	virtual hardware::Proxy *get_hw() const { return nullptr; }
	bool scan_outputs_via_hw() const { return get_hw() && m_view_secret_key == SecretKey{}; }
	virtual void import_view_key() {}
	virtual void set_password(const std::string &password) = 0;
	virtual void export_wallet(const std::string &export_path, const std::string &new_password, bool view_only,
	    bool view_outgoing_addresses) const                = 0;
	virtual bool is_view_only() const { return m_wallet_records.at(0).spend_secret_key == SecretKey{}; }
	virtual bool can_view_outgoing_addresses() const { return m_view_seed != Hash{}; }
	virtual bool is_amethyst() const { return false; }
	virtual std::string get_hardware_type() const { return std::string(); }
	virtual std::string export_keys() const = 0;
	const PublicKey &get_view_public_key() const { return m_view_public_key; }
	const SecretKey &get_view_secret_key() const { return m_view_secret_key; }
	const std::vector<WalletRecord> &test_get_records() const { return m_wallet_records; }
	virtual size_t get_actual_records_count() const { return m_wallet_records.size(); }
	virtual bool get_record(const AccountAddress &, size_t *index, WalletRecord *record) const = 0;
	virtual bool create_look_ahead_records(size_t count) { return false; }
	bool get_record(size_t index, WalletRecord *record, AccountAddress *) const;  // address can be null if not needed
	bool get_look_ahead_record(const PublicKey &, size_t *index, WalletRecord *record, AccountAddress *);

	bool is_our_address(const AccountAddress &) const;
	AccountAddress get_first_address() const;

	virtual std::vector<WalletRecord> generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct,
	    Timestamp now, std::vector<AccountAddress> *addresses,
	    bool *rescan_from_ct) = 0;  // set secret_key to SecretKey{} to generate

	std::string get_cache_name() const;

	virtual Timestamp get_oldest_timestamp() const   = 0;
	virtual bool on_first_output_found(Timestamp ts) = 0;
	// called by WalletState, updates creation timestamp for imported wallet

	const Hash &get_view_seed() const { return m_view_seed; }

	virtual void backup(const std::string &dst_name, const std::string &pass) const = 0;

	typedef std::set<AccountAddressLegacy> History;
	virtual bool save_history(const Hash &tid, const History &used_addresses) { return true; }
	virtual History load_history(const Hash &tid) const = 0;

	virtual std::vector<BinaryArray> payment_queue_get() const                             = 0;
	virtual void payment_queue_add(const Hash &tid, const BinaryArray &binary_transaction) = 0;
	virtual void payment_queue_remove(const Hash &tid)                                     = 0;

	virtual void set_label(const std::string &address, const std::string &label) = 0;
	virtual std::string get_label(const std::string &address) const              = 0;

	typedef std::function<void(uint8_t tx_version, const KeyDerivation &, const Hash &tx_inputs_hash, size_t out_index,
	    const OutputKey &, PublicKey *, PublicKey *)>
	    OutputHandler;
	// Self-contain functor with all info copied to be called from other threads
	virtual OutputHandler get_output_handler() const = 0;
	virtual bool detect_our_output(uint8_t tx_version, const Hash &tx_inputs_hash, const KeyDerivation &kd,
	    size_t out_index, const PublicKey &address_S, const PublicKey &output_shared_secret, const OutputKey &,
	    Amount *, SecretKey *output_secret_key_s, SecretKey *output_secret_key_a, AccountAddress *,
	    size_t *record_index, KeyImage *keyimage)    = 0;

	bool prepare_input_for_spend(uint8_t tx_version, const KeyDerivation &kd, const Hash &tx_inputs_hash,
	    size_t out_index, const OutputKey &, PublicKey *output_shared_secret, SecretKey *output_secret_key_s,
	    SecretKey *output_secret_key_a, size_t *record_index);

	virtual Hash generate_output_seed(const Hash &tx_inputs_hash, const size_t &out_index) const;
	static Hash generate_output_seed(const Hash &tx_inputs_hash, const Hash &view_seed, const size_t &out_index);
	static KeyPair transaction_keys_from_seed(const Hash &tx_inputs_hash, const Hash &view_seed);
	static void generate_output_secrets(const Hash &output_seed, SecretKey *output_secret_scalar,
	    PublicKey *output_secret_point, uint8_t *output_secret_address_type);
};

}  // namespace cn
