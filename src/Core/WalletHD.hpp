// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "Wallet.hpp"
#include "common/JsonValue.hpp"

namespace cn {

// stores either mnemonic or some seeds if view-only
// stores number of used addresses, (per net) creation timestamp, (per net) payment queue
class WalletHDBase : public Wallet {
protected:
	SecretKey m_spend_secret_key;
	KeyPair m_audit_key_base;
	PublicKey m_A_plus_sH;
	PublicKey m_v_mul_A_plus_sH;
	PublicKey m_sH;
	Signature m_view_secrets_signature;
	size_t m_used_address_count = 1;
	std::map<std::string, Timestamp> m_oldest_timestamp;
	std::map<std::string, std::string> m_labels;
	std::map<std::string, std::map<Hash, common::BinaryArray>> m_payment_queue;

	void derive_secrets(std::string mnemonic, const std::string &mnemonic_password);

	void generate_ahead();
	void generate_ahead1(size_t counter, std::vector<WalletRecord> &result) const;

	AccountAddress record_to_address(size_t index) const override;

	WalletHDBase(const Currency &currency, logging::ILogger &log) : Wallet(currency, log) {}

public:
	void set_password(const std::string &password) override {}  // TODO, later

	bool is_view_only() const override { return m_spend_secret_key == SecretKey{}; }
	bool is_amethyst() const override { return true; }
	bool can_view_outgoing_addresses() const override { return m_view_seed != Hash{}; }
	size_t get_actual_records_count() const override { return m_used_address_count; }
	History load_history(const Hash &tid) const override { return Wallet::History{}; }
	std::vector<WalletRecord> generate_new_addresses(const std::vector<SecretKey> &sks, Timestamp ct, Timestamp now,
	    std::vector<AccountAddress> *addresses, bool *rescan_from_ct) override;
	bool get_record(const AccountAddress &, size_t *index, WalletRecord *record) const override;
	void export_wallet(const std::string &export_path, const std::string &new_password, bool view_only,
	    bool view_outgoing_addresses) const override {}                 // TODO
	std::string export_keys() const override { return std::string{}; }  // TODO
	// Date first amethyst addresses appeared in stagenet blockchain - 02/28/2019 @ 8:03am (UTC)
	Timestamp get_oldest_timestamp() const override;
	bool on_first_output_found(Timestamp ts) override;
	bool create_look_ahead_records(size_t count) override;

	void backup(const std::string &dst_name, const std::string &pass) const override {}  // TODO

	std::vector<BinaryArray> payment_queue_get() const override;

	void payment_queue_add(const Hash &tid, const BinaryArray &binary_transaction) override;
	void payment_queue_remove(const Hash &tid) override;

	void set_label(const std::string &address, const std::string &label) override;
	std::string get_label(const std::string &address) const override;

	OutputHandler get_output_handler() const override;
	bool detect_our_output(uint8_t tx_version, const Hash &tx_inputs_haash, const KeyDerivation &kd, size_t out_index,
	    const PublicKey &address_S, const PublicKey &output_shared_secret, const OutputKey &, Amount *,
	    SecretKey *output_secret_key_s, SecretKey *output_secret_key_a, AccountAddress *, size_t *record_index,
	    KeyImage *keyimage) override;
};

class WalletHDJson : public WalletHDBase {
	std::string m_mnemonic, m_mnemonic_password;
	//	void load(const common::JsonValue & root);
	//	common::JsonValue save()const;
public:
	WalletHDJson(const Currency &currency, logging::ILogger &log, const std::string &json_data);
	WalletHDJson(const Currency &currency, logging::ILogger &log, const std::string &mnemonic,
	    Timestamp creation_timestamp, const std::string &mnemonic_password);
	void ser_members(seria::ISeria &s);
	std::string save_json_data() const;
};

}  // namespace cn

namespace seria {

inline void ser_members(cn::WalletHDJson &v, ISeria &s) { v.ser_members(s); }
}  // namespace seria
