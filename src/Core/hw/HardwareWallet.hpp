// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <memory>
#include "CryptoNote.hpp"
#include "crypto/chacha.hpp"

namespace cn { namespace hw {

// Prototype - max simplified synchronous calls

// All funs including constructor throw std::runtime_error when connection to hardware wallet lost before end of fun.
// All funs must quickly try reestablishing connection at the start if it was lost during previous call
// Calls might be from different threads, but will be externally synchronized

class HardwareWallet {
public:
	virtual ~HardwareWallet()                     = default;
	virtual std::string get_hardware_type() const = 0;

	// In constructor read those secrets from device at once
	virtual crypto::chacha_key get_wallet_key() const = 0;
	virtual PublicKey get_A_plus_SH() const           = 0;
	virtual PublicKey get_v_mul_A_plus_SH() const     = 0;
	virtual PublicKey get_public_view_key() const     = 0;

	// We multiply in batches, because we have lots of them (for all outputs)
	// Hardware is expected to divide into chunks of size that fit
	virtual std::vector<PublicKey> mul_by_view_secret_key(const std::vector<PublicKey> &output_public_keys) const = 0;
	// We generate key images by one because we have a few of them (only for 'our' outputs)
	virtual KeyImage generate_keyimage(
	    const PublicKey &output_public_key, const SecretKey &inv_spend_scalar, size_t address_index) const = 0;
	virtual void generate_output_secret(
	    const Hash &tx_inputs_hash, size_t out_index, PublicKey *output_secret_Q) const = 0;
	virtual void sign_start(size_t version, size_t ut, size_t inputs_size, size_t outputs_size, size_t extra_size,
	    size_t change_address_index, uint8_t dst_address_tag, PublicKey dst_address_s,
	    PublicKey dst_address_s_v) const                                                = 0;
	virtual void add_input(uint64_t amount, const std::vector<size_t> &output_indexes, SecretKey inv_spend_scalar,
	    size_t address_index) const                                                     = 0;
	virtual void add_output(bool change, uint64_t amount, PublicKey *public_key, PublicKey *encrypted_secret,
	    uint8_t *encrypted_address_type) const                                          = 0;
	// add_extra called even when empty, to simplify state machine
	virtual void add_extra(const common::BinaryArray &extra) const = 0;
	// add_sig_a1, then add_sig_a2 is called for each input
	virtual void add_sig_a(SecretKey inv_spend_scalar, size_t address_index, crypto::EllipticCurvePoint *sig_p,
	    crypto::EllipticCurvePoint *x, crypto::EllipticCurvePoint *y) const                                     = 0;
	virtual void add_sig_a_more_data(const common::BinaryArray &data, crypto::EllipticCurveScalar *c0) const    = 0;
	virtual void add_sig_b(SecretKey inv_spend_scalar, size_t address_index, crypto::EllipticCurveScalar my_c,
	    crypto::EllipticCurveScalar *sig_my_ra, crypto::EllipticCurveScalar *sig_rb,
	    crypto::EllipticCurveScalar *sig_rc) const                                                              = 0;
	virtual void generate_sendproof(const Hash &tx_inputs_hash, size_t out_index, const Hash &transaction_hash,
	    const Hash &message_hash, const std::string &address, size_t outputs_count, Signature *signature) const = 0;
	virtual void export_view_only(SecretKey *audit_key_base_secret_key, SecretKey *view_secret_key,
	    Hash *tx_derivation_seed, Signature *view_secrets_signature) const                                      = 0;

	void test_all_methods();

	static std::vector<std::unique_ptr<HardwareWallet>> get_connected();
};

class Emulator : public HardwareWallet {
	crypto::chacha_key m_wallet_key;  // wallet encryption key, derived from secret
	PublicKey m_A_plus_SH;
	PublicKey m_v_mul_A_plus_SH;
	PublicKey m_view_public_key;

	const size_t m_address_type = 1;

	// following vars reside inside hw wallet
	std::string m_mnemonics;
	SecretKey m_view_secret_key;
	SecretKey m_spend_secret_key;
	SecretKey m_audit_key_base_secret_key;
	Hash m_tx_derivation_seed;
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
			EXPECT_INPUT,             // inputs_counter as a substate
			EXPECT_OUTPUT,            // outputs_counter as a substate
			EXPECT_EXTRA_CHUNK,       // extra_counter as a substate
			EXPECT_SIGN_A,            // inputs_counter as a substate
			EXPECT_SIGN_A_MORE_DATA,  // inputs_counter as a substate
			EXPECT_SIGN_B             // inputs_counter as a substate
		};
		State state             = FINISHED;
		size_t version          = 0;
		size_t ut               = 0;
		size_t inputs_size      = 0;
		size_t outputs_size     = 0;
		size_t extra_size       = 0;
		uint8_t dst_address_tag = 0;
		PublicKey dst_address_s;
		PublicKey dst_address_s_v;
		PublicKey change_address_s;
		PublicKey change_address_s_v;

		size_t inputs_counter  = 0;
		size_t outputs_counter = 0;
		size_t extra_counter   = 0;
		Hash random_seed;               // single seed for the whole transaction
		KeccakStream tx_inputs_stream;  // we reuse it during sig_a, sig_b for c0 = Hash(...
		Hash tx_inputs_hash;
		KeccakStream tx_prefix_stream;
		Hash tx_prefix_hash;
		uint64_t inputs_amount = 0;
		uint64_t dst_amount    = 0;
		uint64_t change_amount = 0;
		crypto::EllipticCurveScalar c0;
	};
	mutable SigningState sign;
	void add_output_or_change(uint64_t amount, uint8_t dst_address_tag, PublicKey dst_address_s,
	    PublicKey dst_address_s_v, PublicKey *public_key, PublicKey *encrypted_secret,
	    uint8_t *encrypted_address_type) const;
	SecretKey generate_sign_secret(size_t i, const char secret_name[2]) const;

	std::unique_ptr<HardwareWallet> m_proxy;

public:
	static void debug_set_mnemonic(const std::string &mnemonic);

	explicit Emulator(std::unique_ptr<HardwareWallet> &&proxy);
	~Emulator() override;
	std::string get_hardware_type() const override;
	crypto::chacha_key get_wallet_key() const override { return m_wallet_key; }
	PublicKey get_A_plus_SH() const override { return m_A_plus_SH; }
	PublicKey get_v_mul_A_plus_SH() const override { return m_v_mul_A_plus_SH; }
	PublicKey get_public_view_key() const override { return m_view_public_key; }

	std::vector<PublicKey> mul_by_view_secret_key(const std::vector<PublicKey> &output_public_keys) const override;
	KeyImage generate_keyimage(
	    const PublicKey &output_public_key, const SecretKey &inv_spend_scalar, size_t address_index) const override;
	void generate_output_secret(
	    const Hash &tx_inputs_hash, size_t out_index, PublicKey *output_secret_Q) const override;
	void sign_start(size_t version, size_t ut, size_t inputs_size, size_t outputs_size, size_t extra_size,
	    size_t change_address_index, uint8_t dst_address_tag, PublicKey dst_address_s,
	    PublicKey dst_address_s_v) const override;
	void add_input(uint64_t amount, const std::vector<size_t> &output_indexes, SecretKey inv_spend_scalar,
	    size_t address_index) const override;
	void add_output(bool change, uint64_t amount, PublicKey *public_key, PublicKey *encrypted_secret,
	    uint8_t *encrypted_address_type) const override;
	void add_extra(const common::BinaryArray &extra) const override;
	void add_sig_a(SecretKey inv_spend_scalar, size_t address_index, crypto::EllipticCurvePoint *sig_p,
	    crypto::EllipticCurvePoint *x, crypto::EllipticCurvePoint *y) const override;
	void add_sig_a_more_data(const common::BinaryArray &data, crypto::EllipticCurveScalar *c0) const override;
	void add_sig_b(SecretKey inv_spend_scalar, size_t address_index, crypto::EllipticCurveScalar my_c,
	    crypto::EllipticCurveScalar *sig_my_ra, crypto::EllipticCurveScalar *sig_rb,
	    crypto::EllipticCurveScalar *sig_rc) const override;
	void generate_sendproof(const Hash &tx_inputs_hash, size_t out_index, const Hash &transaction_hash,
	    const Hash &message_hash, const std::string &address, size_t outputs_count,
	    Signature *signature) const override;
	void export_view_only(SecretKey *audit_key_base_secret_key, SecretKey *view_secret_key, Hash *tx_derivation_seed,
	    Signature *view_secrets_signature) const override;
};

}}  // namespace cn::hw
