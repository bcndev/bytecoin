// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Proxy.hpp"
#include <iostream>
#include "Emulator.hpp"
#include "common/exception.hpp"

using namespace crypto;
using namespace cn::hardware;

static std::string debug_mnemonic;

void Proxy::debug_set_mnemonic(const std::string &mnemonic) { debug_mnemonic = mnemonic; }

Proxy::Proxy(std::unique_ptr<HardwareWallet> &&proxy) : m_proxy(std::move(proxy)) {
	m_wallet_key = m_proxy->get_wallet_key();
	// Now we create emulator
	try {
		if (!debug_mnemonic.empty()) {
			auto em = std::make_unique<Emulator>(debug_mnemonic);
			if (em->get_wallet_key() == m_wallet_key) {
				m_proxy_b = std::move(em);
				test_all_methods();
			}
		}
	} catch (const std::exception &ex) {
		std::cout << "Failed to create hardware wallet emulator, reason=" << common::what(ex) << std::endl;
	}
}

Proxy::~Proxy() {}

void Proxy::check_proxy() const {
	if (!m_proxy)
		throw HardwareWallet::Exception("Wallet disconnected, please connect");
}

bool Proxy::reconnect() {
	std::unique_lock<std::mutex> lock(mu);
	if (m_proxy)
		return false;  // not just reconnected
	auto connected = hardware::HardwareWallet::get_connected();
	for (auto &&c : connected) {
		try {
			if (c->get_wallet_key() == m_wallet_key) {
				m_proxy = std::move(c);
				break;
			}
		} catch (const std::exception &) {
			// ignore, probably disconnected while we were trying
		}
	}
	return m_proxy.get();  // just reconnected
}

std::string Proxy::get_hardware_type() const {
	std::unique_lock<std::mutex> lock(mu);
	std::string result = "Proxy";
	if (m_proxy)
		result += " connected to " + m_proxy->get_hardware_type();
	else
		result += " (disconnected)";
	if (m_proxy_b)
		result += " validating with " + m_proxy_b->get_hardware_type();
	return result;
}

PublicKey Proxy::get_A_plus_SH() const {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	auto result = m_proxy->get_A_plus_SH();
	if (m_proxy_b)
		invariant(m_proxy_b->get_A_plus_SH() == result, "");
	return result;
}

PublicKey Proxy::get_v_mul_A_plus_SH() const {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	auto result = m_proxy->get_v_mul_A_plus_SH();
	if (m_proxy_b)
		invariant(m_proxy_b->get_v_mul_A_plus_SH() == result, "");
	return result;
}

PublicKey Proxy::get_public_view_key() const {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	auto result = m_proxy->get_public_view_key();
	if (m_proxy_b)
		invariant(m_proxy_b->get_public_view_key() == result, "");
	return result;
}

size_t Proxy::get_scan_outputs_max_batch() const {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	return m_proxy->get_scan_outputs_max_batch();  // not expected to throw
}

std::vector<PublicKey> Proxy::scan_outputs(const std::vector<PublicKey> &output_public_keys) {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	std::vector<PublicKey> result;
	try {
		result = m_proxy->scan_outputs(output_public_keys);
	} catch (const std::runtime_error &) {
		m_proxy.reset();
		std::throw_with_nested(HardwareWallet::Exception("Hardware wallet just disconnected"));
	}
	if (m_proxy_b)
		invariant(m_proxy_b->scan_outputs(output_public_keys) == result, "");
	return result;
}

KeyImage Proxy::generate_keyimage(const common::BinaryArray &output_secret_hash_arg, size_t address_index) {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	KeyImage result;

	try {
		result = m_proxy->generate_keyimage(output_secret_hash_arg, address_index);
	} catch (const std::runtime_error &) {
		m_proxy.reset();
		std::throw_with_nested(HardwareWallet::Exception("Hardware wallet just disconnected"));
	}
	if (m_proxy_b)
		invariant(m_proxy_b->generate_keyimage(output_secret_hash_arg, address_index) == result, "");
	return result;
}

Hash Proxy::generate_output_seed(const Hash &tx_inputs_hash, size_t out_index) {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	Hash result;
	try {
		result = m_proxy->generate_output_seed(tx_inputs_hash, out_index);
	} catch (const std::runtime_error &) {
		m_proxy.reset();
		std::throw_with_nested(HardwareWallet::Exception("Hardware wallet just disconnected"));
	}
	if (m_proxy_b) {
		Hash output_seed2 = m_proxy_b->generate_output_seed(tx_inputs_hash, out_index);
		invariant(output_seed2 == result, "");
	}
	return result;
}

void Proxy::sign_start(size_t version, uint64_t ut, size_t inputs_size, size_t outputs_size, size_t extra_size) {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	m_proxy->sign_start(version, ut, inputs_size, outputs_size, extra_size);
	if (m_proxy_b)
		m_proxy_b->sign_start(version, ut, inputs_size, outputs_size, extra_size);
}

void Proxy::sign_add_input(uint64_t amount, const std::vector<size_t> &output_indexes,
    const common::BinaryArray &output_secret_hash_arg, size_t address_index) {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	m_proxy->sign_add_input(amount, output_indexes, output_secret_hash_arg, address_index);
	if (m_proxy_b)
		m_proxy_b->sign_add_input(amount, output_indexes, output_secret_hash_arg, address_index);
}

void Proxy::sign_add_output(bool change, uint64_t amount, size_t change_address_index, uint8_t dst_address_tag,
    PublicKey dst_address_s, PublicKey dst_address_s_v, PublicKey *public_key, PublicKey *encrypted_secret,
    uint8_t *encrypted_address_type) {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();

	m_proxy->sign_add_output(change, amount, change_address_index, dst_address_tag, dst_address_s, dst_address_s_v,
	    public_key, encrypted_secret, encrypted_address_type);
	if (m_proxy_b) {
		PublicKey encrypted_secret2;
		PublicKey public_key2;
		uint8_t encrypted_address_type2 = 0;
		m_proxy_b->sign_add_output(change, amount, change_address_index, dst_address_tag, dst_address_s,
		    dst_address_s_v, &public_key2, &encrypted_secret2, &encrypted_address_type2);
		invariant(*public_key == public_key2 && *encrypted_secret == encrypted_secret2 &&
		              *encrypted_address_type == encrypted_address_type2,
		    "");
	}
}

void Proxy::sign_add_extra(const BinaryArray &chunk) {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	m_proxy->sign_add_extra(chunk);
	if (m_proxy_b)
		m_proxy_b->sign_add_extra(chunk);
}

void Proxy::sign_step_a(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
    EllipticCurvePoint *sig_p, EllipticCurvePoint *y, EllipticCurvePoint *z) {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	m_proxy->sign_step_a(output_secret_hash_arg, address_index, sig_p, y, z);
	if (m_proxy_b) {
		EllipticCurvePoint sigp2;
		EllipticCurvePoint y2, z2;

		m_proxy_b->sign_step_a(output_secret_hash_arg, address_index, &sigp2, &y2, &z2);
		invariant(*sig_p == sigp2 && *y == y2 && *z == z2, "");
	}
}

void Proxy::sign_step_a_more_data(const BinaryArray &data) {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	m_proxy->sign_step_a_more_data(data);
	if (m_proxy_b)
		m_proxy_b->sign_step_a_more_data(data);
}

EllipticCurveScalar Proxy::sign_get_c0() {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	auto result = m_proxy->sign_get_c0();
	if (m_proxy_b) {
		invariant(result == m_proxy_b->sign_get_c0(), "");
	}
	return result;
}

void Proxy::sign_step_b(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
    EllipticCurveScalar my_c, Hash *sig_my_rr, Hash *sig_rs, Hash *sig_ra, Hash *e_key) {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	m_proxy->sign_step_b(output_secret_hash_arg, address_index, my_c, sig_my_rr, sig_rs, sig_ra, e_key);
	if (m_proxy_b) {
		Hash sig_my_rr2, rs2, ra2, ek2;
		m_proxy_b->sign_step_b(output_secret_hash_arg, address_index, my_c, &sig_my_rr2, &rs2, &ra2, &ek2);
		invariant(*sig_my_rr == sig_my_rr2 && *sig_rs == rs2 && *sig_ra == ra2 && *e_key == ek2, "");
	}
}

void Proxy::proof_start(const common::BinaryArray &data) {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	m_proxy->proof_start(data);
	if (m_proxy_b)
		m_proxy_b->proof_start(data);
}

void Proxy::export_view_only(SecretKey *audit_key_base_secret_key, SecretKey *view_secret_key, Hash *view_seed,
    Signature *view_secrets_signature) {
	std::unique_lock<std::mutex> lock(mu);
	check_proxy();
	m_proxy->export_view_only(audit_key_base_secret_key, view_secret_key, view_seed, view_secrets_signature);

	if (m_proxy_b) {
		SecretKey audit_key_base_secret_key2, view_secret_key2;
		Hash tx_derivation_seed2;
		Signature view_secrets_signature2;
		m_proxy_b->export_view_only(
		    &audit_key_base_secret_key2, &view_secret_key2, &tx_derivation_seed2, &view_secrets_signature2);
		invariant(*audit_key_base_secret_key == audit_key_base_secret_key2 && *view_secret_key == view_secret_key2 &&
		              *view_seed == tx_derivation_seed2,
		    "");
		// Cannot compare signatures - they include random component
	}
}
