// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "HardwareWallet.hpp"
#include <ctime>
#include <iostream>
#include "CryptoNote.hpp"
#include "common/Invariant.hpp"
#include "common/exception.hpp"
#include "crypto/bernstein/crypto-ops.h"
#include "crypto/crypto_helpers.hpp"

#if !defined(__EMSCRIPTEN__)
#include "Emulator.hpp"
#include "Ledger.hpp"
#if !platform_USE_QT
#include "Trezor.hpp"
#endif
#endif

using namespace cn::hardware;
using namespace crypto;
using namespace common;

std::vector<std::unique_ptr<HardwareWallet>> HardwareWallet::get_connected() {
	std::vector<std::unique_ptr<HardwareWallet>> result;

#if !defined(__EMSCRIPTEN__)
#if !platform_USE_QT
	Trezor::add_connected(&result);
#endif
	Ledger::add_connected(&result);
	if (!result.empty())
		std::cout << "Connected hardware wallets" << std::endl;
	for (auto &&r : result) {
		std::cout << "\t" << r->get_hardware_type() << std::endl;
	}
#endif
	return result;
}

RingSignatureAmethyst HardwareWallet::generate_ring_signature_amethyst(const Hash &tx_prefix_hash,
    const std::vector<BinaryArray> &output_secret_hash_args, const std::vector<size_t> &address_indexes,
    const std::vector<KeyImage> &images, const std::vector<std::vector<PublicKey>> &pubs,
    const std::vector<size_t> &sec_indexes) {
	RingSignatureAmethyst rsa;
	rsa.pp.resize(output_secret_hash_args.size());
	rsa.rr.resize(output_secret_hash_args.size());
	rsa.rs.resize(output_secret_hash_args.size());
	rsa.ra.resize(output_secret_hash_args.size());

	for (size_t i = 0; i != output_secret_hash_args.size(); ++i) {
		PublicKey y;
		PublicKey z;
		sign_step_a(output_secret_hash_args.at(i), address_indexes.at(i), &rsa.pp.at(i), &y, &z);

		const crypto::P3 b_coin_p3(hash_to_good_point_p3(images.at(i)));
		const crypto::P3 p_p3(rsa.pp.at(i));
		const crypto::P3 G_plus_B_p3 = crypto::P3(crypto::G) + b_coin_p3;
		const crypto::P3 image_p3(images.at(i));

		crypto::generate_ring_signature_amethyst_loop1(
		    i, image_p3, p_p3, G_plus_B_p3, sec_indexes.at(i), pubs.at(i), &rsa.rr.at(i), &y, &z);
		BinaryArray ba = y.as_binary_array() | z.as_binary_array();
		for (const auto &pk : pubs.at(i))
			ba |= pk.as_binary_array();
		sign_step_a_more_data(ba);
	}
	rsa.c0 = sign_get_c0();
	Hash e_key;
	std::vector<Hash> err(output_secret_hash_args.size());
	std::vector<Hash> ers(output_secret_hash_args.size());
	std::vector<Hash> era(output_secret_hash_args.size());
	for (size_t i = 0; i != output_secret_hash_args.size(); ++i) {
		const crypto::P3 b_coin_p3(hash_to_good_point_p3(images.at(i)));
		const crypto::P3 p_p3(rsa.pp.at(i));
		const crypto::P3 G_plus_B_p3 = crypto::P3(crypto::G) + b_coin_p3;
		const crypto::P3 image_p3(images.at(i));

		crypto::EllipticCurveScalar next_c = rsa.c0;
		crypto::generate_ring_signature_amethyst_loop2(
		    i, image_p3, p_p3, G_plus_B_p3, sec_indexes.at(i), pubs.at(i), &rsa.rr.at(i), &next_c);
		sign_step_b(
		    output_secret_hash_args.at(i), address_indexes.at(i), next_c, &err.at(i), &ers.at(i), &era.at(i), &e_key);
	}
	//	if(e_key == Hash{})
	//		throw std::runtime_error("Hardware protocol violated - empty encryption_key after step B");
	for (size_t i = 0; i != output_secret_hash_args.size(); ++i) {
		rsa.rr.at(i).at(sec_indexes.at(i)) = decrypt_scalar(e_key, err.at(i), i, "rr");
		rsa.rs.at(i)                       = decrypt_scalar(e_key, ers.at(i), i, "rs");
		rsa.ra.at(i)                       = decrypt_scalar(e_key, era.at(i), i, "ra");
	}
	return rsa;
}

static_assert(
    sizeof(crypto::EllipticCurveScalar::data) <= sizeof(Hash::data), "Encryption value_key size is not enough");

Hash HardwareWallet::encrypt_scalar(const Hash &encryption_key, const crypto::EllipticCurveScalar &scalar,
    size_t input_index, const char scalar_name[2]) {
	KeccakStream ks{};
	ks.append(encryption_key.data, 32);
	ks.append_byte(scalar_name[0]);
	ks.append_byte(scalar_name[1]);
	ks.append(input_index);
	Hash value_key = ks.cn_fast_hash();
	for (size_t i = 0; i != sizeof(scalar.data); ++i)
		value_key.data[i] ^= scalar.data[i];
	return value_key;
}

SecretKey HardwareWallet::decrypt_scalar(
    const Hash &encryption_key, const Hash &escalar, size_t input_index, const char scalar_name[2]) {
	KeccakStream ks{};
	ks.append(encryption_key.data, 32);
	ks.append_byte(scalar_name[0]);
	ks.append_byte(scalar_name[1]);
	ks.append(input_index);
	Hash value_key = ks.cn_fast_hash();
	SecretKey result;
	for (size_t i = 0; i != sizeof(escalar.data); ++i)
		result.data[i] = value_key.data[i] ^ escalar.data[i];
	return result;
}

void HardwareWallet::test_all_methods() {
	const PublicKey pk          = get_public_view_key();
	const PublicKey test_point1 = crypto::hash_to_good_point(pk.data, sizeof(pk.data));
	std::cout << "---- testing hashes for m_spend_key_base_public_key =" << pk << std::endl;
	{
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

	std::cout << "---- scan_outputs" << std::endl;
	std::cout << scan_outputs({test_point1}).at(0) << std::endl;
	std::cout << "---- generate_keyimage" << std::endl;
	std::cout << generate_keyimage(test_point1.as_binary_array(), 0) << std::endl;
	std::cout << "---- generate_output_seed" << std::endl;
	Hash result_hash1, result_hash2, result_hash3, result_hash4;
	PublicKey result_point1, result_point2, result_point3;
	result_hash1 = generate_output_seed(test_hash1, 0);
	std::cout << result_point1 << std::endl;
	std::vector<uint8_t> extra{1, 2, 3, 4, 5};
	const size_t my_address = 0;
	std::cout << "---- sign_start" << std::endl;
	sign_start(4, 5, 1, 2, extra.size());
	std::cout << "---- sign_add_input" << std::endl;
	uint8_t result_byte = 0;
	sign_add_input(1000, {0, 1, 2}, test_scalar1.as_binary_array(), my_address);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << "---- sign_add_output" << std::endl;
	sign_add_output(false, 400, my_address, cn::AccountAddressLegacy::type_tag, test_address1_s, test_address1_v,
	    &result_point1, &result_point2, &result_byte);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << int(result_byte) << std::endl;
	std::cout << "---- sign_add_output" << std::endl;
	sign_add_output(true, 500, my_address, cn::AccountAddressLegacy::type_tag, test_address1_s, test_address1_v,
	    &result_point1, &result_point2, &result_byte);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << int(result_byte) << std::endl;
	std::cout << "---- add_extra_chunk" << std::endl;
	sign_add_extra(extra);
	std::cout << "---- sign_step_a" << std::endl;
	sign_step_a(test_scalar1.as_binary_array(), my_address, &result_point1, &result_point2, &result_point3);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << result_point3 << std::endl;
	std::cout << "---- sign_step_a" << std::endl;
	SecretKey result_scalar1, result_scalar2, result_scalar3;
	sign_step_a_more_data(test_point1.as_binary_array() | test_point2.as_binary_array());
	std::cout << "---- sign_get_c0" << std::endl;
	std::cout << sign_get_c0() << std::endl;
	std::cout << "---- sign_step_b" << std::endl;
	sign_step_b(test_scalar1.as_binary_array(), my_address, test_scalar1, &result_hash1, &result_hash2, &result_hash3,
	    &result_hash4);
	std::cout << result_hash1 << std::endl;
	std::cout << result_hash2 << std::endl;
	std::cout << result_hash3 << std::endl;
	std::cout << result_hash4 << std::endl;

	// repeat first steps to check output generation to unlinkable address
	std::cout << "---- sign_start" << std::endl;
	sign_start(4, 0, 1, 2, extra.size());
	std::cout << "---- sign_add_input" << std::endl;
	sign_add_input(1000, {0, 1, 2}, test_scalar1.as_binary_array(), my_address);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << "---- sign_add_output" << std::endl;
	sign_add_output(false, 400, my_address, cn::AccountAddressAmethyst::type_tag, test_address1_s, test_address1_v,
	    &result_point1, &result_point2, &result_byte);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << int(result_byte) << std::endl;

	Signature result_sig0;
	//	std::cout << "---- generate_sendproof" << std::endl;
	//	generate_sendproof(test_hash1, 1, test_hash1, test_hash1, "mega address", 5, &result_sig0);
	std::cout << result_sig0.c << result_sig0.r << std::endl;
	std::cout << "---- export_view_only" << std::endl;
	export_view_only(&result_scalar1, &result_scalar2, &result_hash1, &result_sig0);
	std::cout << result_scalar1 << std::endl;
	std::cout << result_scalar2 << std::endl;
	std::cout << result_hash1 << std::endl;
	std::cout << result_sig0.c << result_sig0.r << std::endl;
	std::cout << "---- tests finished" << std::endl;
}
