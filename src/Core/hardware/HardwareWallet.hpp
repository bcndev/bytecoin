// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <memory>
#include "CryptoNote.hpp"

namespace cn { namespace hardware {

// Prototype - max simplified synchronous calls

// All funs including constructor throw std::runtime_error when connection to hardware wallet lost before end of fun.
// All funs must quickly try reestablishing connection at the start if it was lost during previous call
// Calls might be from different threads, but will be externally synchronized

class HardwareWallet {
public:
	virtual ~HardwareWallet()                     = default;
	virtual std::string get_hardware_type() const = 0;

	// In constructor read those secrets from device at once
	virtual Hash get_wallet_key() const           = 0;
	virtual PublicKey get_A_plus_SH() const       = 0;
	virtual PublicKey get_v_mul_A_plus_SH() const = 0;
	virtual PublicKey get_public_view_key() const = 0;

	// We multiply in batches, because we have lots of them (for all outputs)
	// Hardware is expected to divide into chunks of size that fit
	virtual std::vector<PublicKey> scan_outputs(const std::vector<PublicKey> &output_public_keys) = 0;
	// We generate key images by one because we have a few of them (only for 'our' outputs)
	// output_secret_hash_arg - max 32+32+10 bytes
	virtual KeyImage generate_keyimage(const common::BinaryArray &output_secret_hash_arg, size_t address_index) = 0;
	virtual void generate_output_seed(const Hash &tx_inputs_hash, size_t out_index, Hash *output_seed)          = 0;
	virtual void sign_start(
	    size_t version, uint64_t ut, size_t inputs_size, size_t outputs_size, size_t extra_size) = 0;
	virtual void sign_add_input(uint64_t amount, const std::vector<size_t> &output_indexes,
	    const common::BinaryArray &output_secret_hash_arg, size_t address_index)                 = 0;
	virtual void sign_add_output(bool change, uint64_t amount, size_t change_address_index, uint8_t dst_address_tag,
	    PublicKey dst_address_s, PublicKey dst_address_s_v, PublicKey *public_key, PublicKey *encrypted_secret,
	    uint8_t *encrypted_address_type)                                                         = 0;
	// sign_add_extra called even when empty, to simplify state machine
	virtual void sign_add_extra(const common::BinaryArray &extra) = 0;
	// add_sig_a1, then add_sig_a2 is called for each input
	virtual void sign_step_a(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
	    crypto::EllipticCurvePoint *sig_p, crypto::EllipticCurvePoint *y, crypto::EllipticCurvePoint *z) = 0;
	virtual void sign_step_a_more_data(const common::BinaryArray &data)                                  = 0;
	virtual crypto::EllipticCurveScalar sign_get_c0()                                                    = 0;
	virtual void sign_step_b(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
	    crypto::EllipticCurveScalar my_c, Hash *sig_my_rr, Hash *sig_rs, Hash *sig_ra, Hash *e_key)      = 0;
	virtual void export_view_only(SecretKey *audit_key_base_secret_key, SecretKey *view_secret_key, Hash *view_seed,
	    Signature *view_secrets_signature)                                                               = 0;
	virtual void proof_start(const common::BinaryArray &data)                                            = 0;

	virtual void precache_scan_outputs(const std::vector<PublicKey> &output_public_keys) {
		// this method is optional, will be used for future latency optimization - TBD
	}

	static void debug_set_mnemonic(const std::string &mnemonic);

	void test_all_methods();

	static std::vector<std::unique_ptr<HardwareWallet>> get_connected();

	// Common helper algos
	static Hash encrypt_scalar(
	    const Hash &encryption_key, const crypto::EllipticCurveScalar &scalar, size_t i, const char scalar_name[2]);
	static SecretKey decrypt_scalar(
	    const Hash &encryption_key, const Hash &escalar, size_t i, const char scalar_name[2]);

	RingSignatureAmethyst generate_ring_signature_amethyst(const Hash &tx_prefix_hash,
	    const std::vector<BinaryArray> &output_secret_hash_args, const std::vector<size_t> &address_indexes,
	    const std::vector<KeyImage> &images, const std::vector<std::vector<PublicKey>> &pubs,
	    const std::vector<size_t> &sec_indexes);
};

}}  // namespace cn::hardware
