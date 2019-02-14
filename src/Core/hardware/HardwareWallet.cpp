// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "HardwareWallet.hpp"
#include <ctime>
#include <iostream>
#include "CryptoNote.hpp"
#include "Emulator.hpp"
#include "Ledger.hpp"
#include "Trezor.hpp"
#include "common/Invariant.hpp"
#include "common/exception.hpp"
#include "crypto/bernstein/crypto-ops.h"
#include "crypto/crypto_helpers.hpp"

using namespace cn::hardware;
using namespace crypto;
using namespace common;

static std::string debug_mnemonic;

void HardwareWallet::debug_set_mnemonic(const std::string &mnemonic) { debug_mnemonic = mnemonic; }

std::vector<std::unique_ptr<HardwareWallet>> HardwareWallet::get_connected() {
	std::vector<std::unique_ptr<HardwareWallet>> result;

#if cn_WITH_TREZOR
	Trezor::add_connected(&result);
#endif
#if cn_WITH_LEDGER
	Ledger::add_connected(&result);
#endif
	// Now we create emulator and if hardware wallet found with the same mnemonic, we connect it through emulator
	std::unique_ptr<HardwareWallet> em;
	try {
		if (!debug_mnemonic.empty())
			em = std::make_unique<Emulator>(debug_mnemonic, std::unique_ptr<HardwareWallet>());
	} catch (const std::exception &ex) {
		std::cout << "Failed to create hardware wallet emulator, reason=" << common::what(ex) << std::endl;
	}
	for (auto &&r : result) {
		if (em && r->get_wallet_key() == em->get_wallet_key()) {
			em = std::unique_ptr<HardwareWallet>();
			r  = std::make_unique<Emulator>(debug_mnemonic, std::move(r));
		}
	}
	if (em)
		result.push_back(std::move(em));
	if (!result.empty())
		std::cout << "Connected hardware wallets" << std::endl;
	for (auto &&r : result) {
		std::cout << "\t" << r->get_hardware_type() << std::endl;
	}
	return result;
}

RingSignatureAmethyst HardwareWallet::generate_ring_signature_auditable(const Hash &tx_prefix_hash,
    const std::vector<SecretKey> &output_secret_hashes, const std::vector<size_t> &address_indexes,
    const std::vector<KeyImage> &images, const std::vector<std::vector<PublicKey>> &pubs,
    const std::vector<size_t> &sec_indexes) {
	RingSignatureAmethyst rsa;
	rsa.p.resize(output_secret_hashes.size());
	rsa.ra.resize(output_secret_hashes.size());
	rsa.rb.resize(output_secret_hashes.size());
	rsa.rc.resize(output_secret_hashes.size());

	for (size_t i = 0; i != output_secret_hashes.size(); ++i) {
		PublicKey x;
		PublicKey y;
		sign_step_a(crypto::sc_invert(output_secret_hashes.at(i)), address_indexes.at(i), &rsa.p.at(i), &x, &y);

		const crypto::P3 b_coin_p3(hash_to_good_point_p3(images.at(i)));
		const crypto::P3 p_p3(rsa.p.at(i));
		const crypto::P3 G_plus_B_p3 = crypto::P3(crypto::G) + b_coin_p3;
		const crypto::P3 image_p3(images.at(i));

		crypto::generate_ring_signature_auditable_loop1(
		    i, tx_prefix_hash, image_p3, p_p3, G_plus_B_p3, sec_indexes.at(i), pubs.at(i), &rsa.ra.at(i), &x, &y);
		BinaryArray ba = x.as_binary_array() | y.as_binary_array();
		for (const auto &pk : pubs.at(i))
			ba |= pk.as_binary_array();
		sign_step_a_more_data(ba);
	}
	rsa.c0 = sign_get_c0();
	for (size_t i = 0; i != output_secret_hashes.size(); ++i) {
		const crypto::P3 b_coin_p3(hash_to_good_point_p3(images.at(i)));
		const crypto::P3 p_p3(rsa.p.at(i));
		const crypto::P3 G_plus_B_p3 = crypto::P3(crypto::G) + b_coin_p3;
		const crypto::P3 image_p3(images.at(i));

		crypto::EllipticCurveScalar next_c = rsa.c0;
		crypto::generate_ring_signature_auditable_loop2(
		    i, tx_prefix_hash, image_p3, p_p3, G_plus_B_p3, sec_indexes.at(i), pubs.at(i), &rsa.ra.at(i), &next_c);
		sign_step_b(crypto::sc_invert(output_secret_hashes.at(i)), address_indexes.at(i), next_c,
		    &rsa.ra.at(i).at(sec_indexes.at(i)), &rsa.rb.at(i), &rsa.rc.at(i));
	}
	return rsa;
}

void HardwareWallet::test_all_methods() {
	const PublicKey pk          = get_public_view_key();
	const PublicKey test_point1 = crypto::hash_to_good_point(pk.data, sizeof(pk.data));
	std::cout << "---- testing hashes for m_spend_key_base_public_key =" << pk << std::endl;
	{
		std::cout << "hash_to_bad_point = " << crypto::hash_to_bad_point(pk.data, sizeof(pk.data)) << std::endl;
		std::cout << "hash_to_good_point = " << test_point1 << std::endl;
		Hash h  = cn_fast_hash(pk.data, sizeof(pk.data));
		Hash h2 = cn_fast_hash(h.data, sizeof(h.data));
		std::cout << "hash32 = " << h << std::endl;
		std::cout << "hash64 = " << h << h2 << std::endl;
		std::cout << "hash_to_scalar64 = " << crypto::hash_to_scalar64(pk.data, sizeof(pk.data)) << std::endl;
	}
	const SecretKey test_scalar1    = crypto::hash_to_scalar(test_point1.data, sizeof(test_point1.data));
	const Hash test_hash1           = crypto::cn_fast_hash(test_scalar1.data, sizeof(test_scalar1.data));
	const PublicKey test_address1_s = crypto::hash_to_good_point(test_hash1.data, sizeof(test_hash1.data));
	const PublicKey test_address1_v = crypto::hash_to_good_point(test_address1_s.data, sizeof(test_address1_s.data));
	const PublicKey test_point2     = crypto::hash_to_good_point(test_address1_v.data, sizeof(test_address1_v.data));
	const PublicKey test_point3     = crypto::hash_to_good_point(test_point2.data, sizeof(test_point2.data));
	const SecretKey test_scalar2    = crypto::hash_to_scalar(test_point3.data, sizeof(test_point3.data));

	std::cout << "---- mul_by_view_secret_key" << std::endl;
	std::cout << mul_by_view_secret_key({test_point1}).at(0) << std::endl;
	std::cout << "---- generate_keyimage" << std::endl;
	std::cout << generate_keyimage(test_point1, test_scalar1, 0) << std::endl;
	std::cout << "---- generate_output_seed" << std::endl;
	PublicKey result_point1, result_point2, result_point3;
	generate_output_seed(test_hash1, 0, &result_point1);
	std::cout << result_point1 << std::endl;
	std::vector<uint8_t> extra{1, 2, 3, 4, 5};
	const size_t my_address = 0;
	std::cout << "---- sign_start" << std::endl;
	sign_start(4, 5, 1, 2, extra.size());
	std::cout << "---- sign_add_input" << std::endl;
	uint8_t result_byte = 0;
	sign_add_input(1000, {0, 1, 2}, test_scalar1, my_address);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << "---- sign_add_output" << std::endl;
	sign_add_output(false, 400, my_address, cn::AccountAddressSimple::type_tag, test_address1_s, test_address1_v,
	    &result_point1, &result_point2, &result_byte);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << int(result_byte) << std::endl;
	std::cout << "---- sign_add_output" << std::endl;
	sign_add_output(true, 500, my_address, cn::AccountAddressSimple::type_tag, test_address1_s, test_address1_v,
	    &result_point1, &result_point2, &result_byte);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << int(result_byte) << std::endl;
	std::cout << "---- add_extra_chunk" << std::endl;
	sign_add_extra(extra);
	std::cout << "---- sign_step_a" << std::endl;
	sign_step_a(test_scalar1, my_address, &result_point1, &result_point2, &result_point3);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << result_point3 << std::endl;
	std::cout << "---- sign_step_a" << std::endl;
	SecretKey result_scalar1, result_scalar2, result_scalar3;
	sign_step_a_more_data(test_point1.as_binary_array() | test_point2.as_binary_array());
	std::cout << "---- sign_get_c0" << std::endl;
	std::cout << sign_get_c0() << std::endl;
	std::cout << "---- sign_step_b" << std::endl;
	sign_step_b(test_scalar1, my_address, test_scalar1, &result_scalar1, &result_scalar2, &result_scalar3);
	std::cout << result_scalar1 << std::endl;
	std::cout << result_scalar2 << std::endl;
	std::cout << result_scalar3 << std::endl;

	// repeat first steps to check output generation to unlinkable address
	std::cout << "---- sign_start" << std::endl;
	sign_start(4, 0, 1, 2, extra.size());
	std::cout << "---- sign_add_input" << std::endl;
	sign_add_input(1000, {0, 1, 2}, test_scalar1, my_address);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << "---- sign_add_output" << std::endl;
	sign_add_output(false, 400, my_address, cn::AccountAddressUnlinkable::type_tag, test_address1_s, test_address1_v,
	    &result_point1, &result_point2, &result_byte);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << int(result_byte) << std::endl;

	Signature result_sig0;
	//	std::cout << "---- generate_sendproof" << std::endl;
	//	generate_sendproof(test_hash1, 1, test_hash1, test_hash1, "mega address", 5, &result_sig0);
	std::cout << result_sig0.c << result_sig0.r << std::endl;
	std::cout << "---- export_view_only" << std::endl;
	Hash result_hash1;
	export_view_only(&result_scalar1, &result_scalar2, &result_hash1, &result_sig0);
	std::cout << result_scalar1 << std::endl;
	std::cout << result_scalar2 << std::endl;
	std::cout << result_hash1 << std::endl;
	std::cout << result_sig0.c << result_sig0.r << std::endl;
	std::cout << "---- tests finished" << std::endl;
}
