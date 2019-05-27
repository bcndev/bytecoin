// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "WalletHD.hpp"
#include "hardware/Proxy.hpp"
#include "platform/DBsqlite3.hpp"

namespace cn {

class WalletHDsqlite : public WalletHDBase {
	std::string m_path;
	platform::sqlite::Dbi m_db_dbi;
	std::unique_ptr<hardware::Proxy> m_hw;  // quick prototyping, will refactor later

	static BinaryArray encrypt_data(const crypto::chacha_key &wallet_key, const BinaryArray &data);
	static BinaryArray decrypt_data(const crypto::chacha_key &wallet_key, const uint8_t *value_data, size_t value_size);
	void put_salt(const BinaryArray &salt);
	BinaryArray get_salt() const;
	void put_is_hardware(bool ha);
	bool get_is_hardware() const;
	void commit();

	void put(const std::string &key, const common::BinaryArray &value, bool nooverwrite);
	bool get(const std::string &key, common::BinaryArray &value) const;
	void put(const std::string &key, const std::string &value, bool nooverwrite);
	bool get(const std::string &key, std::string &value) const;

	void load();

	std::vector<std::pair<std::string, BinaryArray>> parameters_get() const;
	std::vector<std::tuple<Hash, std::string, BinaryArray>> payment_queue_get2() const;
	void payment_queue_add(const Hash &tid, const std::string &net, const BinaryArray &binary_transaction);

public:
	//	static std::string generate_mnemonic(size_t bits, uint32_t version);
	static bool is_sqlite(const std::string &full_path);
	// In contrast with WalletLegacy, we must know read_only flag, because otherwise
	// inability to save address count will lead to wallet losing track of funds due to skipping outputs
	WalletHDsqlite(const Currency &currency, logging::ILogger &log, const std::string &path,
	    const std::string &password, bool readonly);
	WalletHDsqlite(const Currency &currency, logging::ILogger &log, const std::string &path,
	    const std::string &password, const std::string &mnemonic, Timestamp creation_timestamp,
	    const std::string &mnemonic_password, bool hardware_wallet);
	hardware::Proxy *get_hw() const override { return m_hw.get(); }
	void import_view_key() override;
	bool is_view_only() const override { return m_hw ? false : WalletHDBase::is_view_only(); }
	bool can_view_outgoing_addresses() const override {
		return m_hw ? true : WalletHDBase::can_view_outgoing_addresses();
	}
	std::string get_hardware_type() const override { return m_hw ? m_hw->get_hardware_type() : std::string(); }
	std::vector<WalletRecord> generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct, Timestamp now,
	    std::vector<AccountAddress> *addresses, bool *rescan_from_ct) override;
	void set_password(const std::string &password) override;
	void export_wallet(const std::string &export_path, const std::string &new_password, bool view_only,
	    bool view_outgoing_addresses) const override;
	std::string export_keys() const override;

	bool on_first_output_found(Timestamp ts) override;
	bool create_look_ahead_records(size_t count) override;

	void backup(const std::string &dst_name, const std::string &pass) const override;

	void payment_queue_add(const Hash &tid, const BinaryArray &binary_transaction) override;
	void payment_queue_remove(const Hash &tid) override;

	void set_label(const std::string &address, const std::string &label) override;
	OutputHandler get_output_handler() const override;
	bool detect_our_output(uint8_t tx_version, const Hash &tx_inputs_haash, const KeyDerivation &kd, size_t out_index,
	    const PublicKey &address_S, const PublicKey &output_shared_secret, const OutputKey &, Amount *,
	    SecretKey *output_secret_key_s, SecretKey *output_secret_key_a, AccountAddress *, size_t *record_index,
	    KeyImage *keyimage) override;
};

}  // namespace cn
