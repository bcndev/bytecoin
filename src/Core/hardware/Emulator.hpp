// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <memory>
#include "HardwareWallet.hpp"

namespace cn { namespace hardware {

class Emulator : public HardwareWallet {
	Hash m_wallet_key;  // wallet encryption key, derived from secret
	PublicKey m_A_plus_sH;
	PublicKey m_v_mul_A_plus_sH;
	PublicKey m_view_public_key;

	const size_t m_address_type = 1;

	// following vars reside inside hw wallet
	std::string m_mnemonics;
	SecretKey m_view_secret_key;
	SecretKey m_spend_secret_key;
	SecretKey m_audit_key_base_secret_key;
	Hash m_view_seed;
	PublicKey m_sH;

	mutable size_t last_address_index = std::numeric_limits<size_t>::max();
	mutable SecretKey last_address_audit_secret_key;
	void prepare_address(size_t address_index) const;
	void prepare_address(size_t address_index, PublicKey *address_S, PublicKey *address_Sv) const;
	struct KeccakStream {  // Naive implemenatation, real hardware will use fixed 200+4 bytes rep
		common::BinaryArray ba;

		void append(const unsigned char *data, size_t size);
		void append(uint64_t a);
		void append_byte(uint8_t b);
		Hash cn_fast_hash() const;
		SecretKey hash_to_scalar() const;
		SecretKey hash_to_scalar64() const;
		PublicKey hash_to_good_point() const;
	};
	struct SigningState {
		// FINISHED is default state.
		// sign_start can be called in any state to restart signing
		// other sign methods require specific state, and
		// move system into subsequent state until moved to FINISHED
		enum State {
			FINISHED,
			EXPECT_ADD_INPUT_START,
			EXPECT_ADD_INPUT_INDEXES,
			EXPECT_ADD_INPUT_FINISH,  // inputs_counter as a substate for (EXPECT_ADD_INPUT_* states)
			EXPECT_ADD_OUTPUT,        // outputs_counter as a substate
			EXPECT_ADD_EXTRA_CHUNK,   // extra_counter as a substate
			EXPECT_STEP_A,            // inputs_counter as a substate for (EXPECT_STEP_A, EXPECT_STEP_A_MORE_DATA)
			EXPECT_STEP_A_MORE_DATA,
			EXPECT_STEP_B  // inputs_counter as a substate
		};
		// Fields required during whole sign operation
		KeccakStream tx_inputs_stream;  // we reuse it during sig_a, sig_b for c0 = Hash(...
		KeccakStream tx_prefix_stream;  // we reuse it during sig_a, sig_b for H(step input)

		State state           = FINISHED;
		size_t inputs_size    = 0;
		size_t inputs_counter = 0;

		// Fields required before sign_step_a (can be union with fields declared after next comment)
		size_t outputs_size    = 0;
		size_t outputs_counter = 0;
		size_t extra_counter   = 0;
		size_t extra_size      = 0;

		Hash tx_inputs_hash;
		PublicKey dst_address_s;
		PublicKey dst_address_s_v;
		uint64_t inputs_amount  = 0;
		uint64_t dst_amount     = 0;
		uint64_t change_amount  = 0;
		bool dst_address_set    = false;
		uint8_t dst_address_tag = 0;

		// Fields required during and after sign_step_a
		crypto::EllipticCurveScalar c0;
		Hash random_seed;  // single seed for the whole transaction
		crypto::Hash encryption_key;
		crypto::Hash step_args_hash;

		// Fields required during add_input only
		size_t mixin_counter = 0;
		size_t mixin_size    = 0;
	};
	mutable SigningState sign;
	void add_output_or_change(uint64_t amount, uint8_t dst_address_tag, PublicKey dst_address_s,
	    PublicKey dst_address_s_v, PublicKey *public_key, PublicKey *encrypted_secret,
	    uint8_t *encrypted_address_type) const;
	SecretKey generate_sign_secret(size_t i, const char secret_name[2]) const;

	std::unique_ptr<HardwareWallet> m_proxy;

	void sign_add_input_start(uint64_t amount, size_t output_indexes_count);
	void sign_add_input_indexes(const std::vector<size_t> &output_indexes_chunk);
	void sign_add_input_finish(const common::BinaryArray &output_secret_hash_arg, size_t address_index);

public:
	explicit Emulator(const std::string &mnemonic, std::unique_ptr<HardwareWallet> &&proxy);
	~Emulator() override;
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
