// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include "HardwareWallet.hpp"

namespace cn { namespace hardware {

class Proxy : public HardwareWallet {
	Hash m_wallet_key;  // wallet encryption key, derived from secret

	mutable std::mutex mu;

	std::unique_ptr<HardwareWallet> m_proxy;
	std::unique_ptr<HardwareWallet> m_proxy_b;  // if set, will compare result between 2 proxies

	void check_proxy() const;

public:
	// proxy must respond to get_wallet_key() in constructor
	explicit Proxy(std::unique_ptr<HardwareWallet> &&proxy);
	~Proxy() override;
	bool is_connected() const { return m_proxy.get(); }
	bool reconnect();

	std::string get_hardware_type() const override;
	Hash get_wallet_key() const override { return m_wallet_key; }
	PublicKey get_A_plus_SH() const override;
	PublicKey get_v_mul_A_plus_SH() const override;
	PublicKey get_public_view_key() const override;

	// 3 scanning methods below will be called from thread other than main, disconnect on failure
	size_t get_scan_outputs_max_batch() const override;
	std::vector<PublicKey> scan_outputs(const std::vector<PublicKey> &output_public_keys) override;
	KeyImage generate_keyimage(const common::BinaryArray &output_secret_hash_arg, size_t address_index) override;
	Hash generate_output_seed(const Hash &tx_inputs_hash, size_t out_index) override;

	void sign_start(size_t version, uint64_t ut, size_t inputs_size, size_t outputs_size, size_t extra_size) override;
	void sign_add_input(uint64_t amount, const std::vector<size_t> &output_indexes,
	    const common::BinaryArray &output_secret_hash_arg, size_t address_index) override;
	void sign_add_output(bool change, uint64_t amount, size_t change_address_index, uint8_t dst_address_tag,
	    PublicKey dst_address_s, PublicKey dst_address_s_v, PublicKey *public_key, PublicKey *encrypted_secret,
	    uint8_t *encrypted_address_type) override;
	void sign_add_extra(const common::BinaryArray &extra) override;
	void sign_step_a(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
	    crypto::EllipticCurvePoint *sig_p, crypto::EllipticCurvePoint *y, crypto::EllipticCurvePoint *z) override;
	void sign_step_a_more_data(const common::BinaryArray &data) override;
	crypto::EllipticCurveScalar sign_get_c0() override;
	void sign_step_b(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
	    crypto::EllipticCurveScalar my_c, Hash *sig_my_rr, Hash *sig_rs, Hash *sig_ra, Hash *e_key) override;
	void export_view_only(SecretKey *audit_key_base_secret_key, SecretKey *view_secret_key, Hash *view_seed,
	    Signature *view_secrets_signature) override;

	void proof_start(const common::BinaryArray &data) override;

	static void debug_set_mnemonic(const std::string &mnemonic);
};

}}  // namespace cn::hardware
