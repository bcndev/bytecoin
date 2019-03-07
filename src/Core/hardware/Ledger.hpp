// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <memory>
#include "HardwareWallet.hpp"

#if cn_WITH_LEDGER

struct libusb_device_handle;
typedef struct libusb_device_handle libusb_device_handle;

namespace cn { namespace hardware {

struct USBDevice {
	libusb_device_handle *handle = nullptr;
	explicit USBDevice(libusb_device_handle *dev_handle) : handle(dev_handle) {}
	~USBDevice();
};

class Ledger : public HardwareWallet {
	Hash m_wallet_key;
	PublicKey m_A_plus_sH;
	PublicKey m_v_mul_A_plus_sH;
	PublicKey m_view_public_key;

	const size_t m_address_type = 1;

	USBDevice m_device;

public:
	static void add_connected(std::vector<std::unique_ptr<HardwareWallet>> *result);

	explicit Ledger(libusb_device_handle *dev_handle);
	~Ledger() override;
	std::string get_hardware_type() const override;
	Hash get_wallet_key() const override { return m_wallet_key; }
	PublicKey get_A_plus_SH() const override { return m_A_plus_sH; }
	PublicKey get_v_mul_A_plus_SH() const override { return m_v_mul_A_plus_sH; }
	PublicKey get_public_view_key() const override { return m_view_public_key; }

	std::vector<PublicKey> scan_outputs(const std::vector<PublicKey> &output_public_keys) override;
	KeyImage generate_keyimage(const common::BinaryArray &output_secret_hash_arg, size_t address_index) override;
	void generate_output_seed(const Hash &tx_inputs_hash, size_t out_index, Hash *output_seed) override;
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
};

}}  // namespace cn::hardware

#endif  // cn_WITH_LEDGER
