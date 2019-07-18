// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "Wallet.hpp"
#include "platform/Files.hpp"

namespace cn {

// stores at most 1 view secret key. 1 or more spend secret keys
// We do not allow deleting first spend key. It is used in seed calculations
// File formats are opened as is, and saved to V2 when changing something
class WalletLegacy : public Wallet {
	Timestamp m_oldest_timestamp = std::numeric_limits<Timestamp>::max();
	std::string m_path;
	std::unique_ptr<platform::FileStream> m_file;
	SecretKey m_inv_view_secret_key;  // for new linkable crypto

	crypto::chacha_key m_history_key;  // Hashed from seed
	Hash m_history_filename_seed;      // Hashed from seed

	void load_container_storage();
	void load_legacy_wallet_file();
	bool operator==(const WalletLegacy &) const;
	bool operator!=(const WalletLegacy &other) const { return !(*this == other); }

	void load();
	void save(const std::string &export_path, const crypto::chacha_key &wallet_key, bool view_only,
	    platform::OpenMode open_mode) const;
	void save_and_check();

	std::string get_history_folder() const;
	std::string get_payment_queue_folder() const;

	WalletLegacy(
	    const Currency &currency, logging::ILogger &log, const std::string &path, const crypto::chacha_key &wallet_key);

protected:
	AccountAddress record_to_address(size_t index) const override;

public:
	WalletLegacy(const Currency &currency, logging::ILogger &log, const std::string &path, const std::string &password);
	WalletLegacy(const Currency &currency, logging::ILogger &log, const std::string &path, const std::string &password,
	    const std::string &import_keys, Timestamp creation_timestamp);
	std::vector<WalletRecord> generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct, Timestamp now,
	    std::vector<AccountAddress> *addresses, bool *rescan_from_ct) override;
	bool get_record(const AccountAddress &, size_t *index, WalletRecord *record) const override;
	void set_password(const std::string &password) override;
	void export_wallet(const std::string &export_path, const std::string &new_password, bool view_only,
	    bool view_outgoing_addresses) const override;
	std::string export_viewonly_wallet_string(
	    const std::string &new_password, bool view_outgoing_addresses) const override;
	std::string export_keys() const override;

	static size_t wallet_file_size(size_t records);

	Timestamp get_oldest_timestamp() const override { return m_oldest_timestamp; }
	bool on_first_output_found(Timestamp ts) override;

	void backup(const std::string &dst_name, const std::string &pass) const override;

	bool save_history(const Hash &tid, const History &used_addresses) override;
	History load_history(const Hash &tid) const override;

	std::vector<BinaryArray> payment_queue_get() const override;
	void payment_queue_add(const Hash &tid, const BinaryArray &binary_transaction) override;
	void payment_queue_remove(const Hash &tid) override;

	void set_label(const std::string &address, const std::string &label) override;
	std::string get_label(const std::string &address) const override { return std::string{}; }

	OutputHandler get_output_handler() const override;
	bool detect_our_output(uint8_t tx_version, const Hash &tx_inputs_hash, const KeyDerivation &kd, size_t out_index,
	    const PublicKey &address_S, const PublicKey &output_shared_secret, const OutputKey &, Amount *,
	    SecretKey *output_secret_key_s, SecretKey *output_secret_key_a, AccountAddress *, size_t *record_index,
	    KeyImage *keyimage) override;
};

}  // namespace cn
