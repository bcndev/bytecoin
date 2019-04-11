// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <common/MemoryStreams.hpp>
#include <cstdint>
#include <memory>
#include "HardwareWallet.hpp"

#if cn_WITH_LEDGER

struct libusb_device_handle;
typedef struct libusb_device_handle libusb_device_handle;

namespace cn { namespace hardware {

struct USBLib {
	USBLib();
	~USBLib();
};

struct USBDevice {
	libusb_device_handle *handle = nullptr;
	bool attached_kernel_driver  = true;
	explicit USBDevice(libusb_device_handle *dev_handle) : handle(dev_handle) {}
	void attach_kernel_driver(bool attach);
	~USBDevice();
};

class Ledger : public HardwareWallet {
	struct LedgerAppInfo {
		std::string app_name;
		std::string app_version;
		std::string app_spec_version;
		uint8_t major_version;
		uint8_t minor_version;
		uint8_t patch_version;
	};

	LedgerAppInfo m_app_info;
	Hash m_wallet_key;
	PublicKey m_A_plus_sH;
	PublicKey m_v_mul_A_plus_sH;
	PublicKey m_view_public_key;

	USBLib usb_lib;
	USBDevice m_device;
	const std::string m_path;

	int sendApdu(const uint8_t *data, size_t len, uint8_t *out, size_t out_len, unsigned *sw);
	BinaryArray sendApdu(uint8_t cmd, const BinaryArray &body);

	void get_wallet_keys();
	void get_app_info();
	void sign_add_input_start(uint64_t amount, size_t output_indexes_count);
	void sign_add_input_indexes(const std::vector<size_t> &output_indexes_chunk);
	void sign_add_input_finish(const common::BinaryArray &output_secret_hash_arg, size_t address_index);

public:
	static void add_connected(std::vector<std::unique_ptr<HardwareWallet>> *result);

	explicit Ledger(libusb_device_handle *dev_handle, const std::string &path);
	~Ledger() override;
	std::string get_hardware_type() const override;
	Hash get_wallet_key() const override { return m_wallet_key; }
	PublicKey get_A_plus_SH() const override { return m_A_plus_sH; }
	PublicKey get_v_mul_A_plus_SH() const override { return m_v_mul_A_plus_sH; }
	PublicKey get_public_view_key() const override { return m_view_public_key; }

	size_t get_scan_outputs_max_batch() const override { return 4; }
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
};

}}  // namespace cn::hardware

#endif  // cn_WITH_LEDGER
