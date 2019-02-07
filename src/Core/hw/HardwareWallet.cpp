// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "HardwareWallet.hpp"
#include <ctime>
#include <iostream>
#include "Core/TransactionBuilder.hpp"
#include "CryptoNote.hpp"
#include "common/BIPs.hpp"
#include "common/Invariant.hpp"
#include "common/MemoryStreams.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "crypto/bernstein/crypto-ops.h"
#include "crypto/crypto_helpers.hpp"

static const bool debug_print = true;

using namespace cn::hw;
using namespace crypto;
using namespace common;

std::vector<std::unique_ptr<HardwareWallet>> HardwareWallet::get_connected() {
	std::vector<std::unique_ptr<HardwareWallet>> result;
	// TODO - add all real connected wallets here

	// Now we create emulator and if hardware wallet found with the same mnemonic, we connect it through emulator
	std::unique_ptr<HardwareWallet> em;
	try {
		em = std::make_unique<Emulator>(std::unique_ptr<HardwareWallet>());
	} catch (const std::exception &) {
		// no debug mnemonics set - no problem
	}
	for (auto &&r : result) {
		if (em && r->get_public_view_key() == em->get_public_view_key()) {
			em = std::unique_ptr<HardwareWallet>();
			r  = std::make_unique<Emulator>(std::move(r));
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
	std::cout << "---- generate_output_secret" << std::endl;
	PublicKey result_point1, result_point2, result_point3;
	generate_output_secret(test_hash1, 0, &result_point1);
	std::cout << result_point1 << std::endl;
	std::vector<uint8_t> extra{1, 2, 3, 4, 5};
	const size_t my_address = 1;
	std::cout << "---- sign_start" << std::endl;
	sign_start(
	    4, 5, 1, 2, extra.size(), my_address, cn::AccountAddressSimple::type_tag, test_address1_s, test_address1_v);
	std::cout << "---- add_input" << std::endl;
	uint8_t result_byte = 0;
	add_input(1000, {0, 1, 2}, test_scalar1, my_address);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << "---- add_output" << std::endl;
	add_output(false, 400, &result_point1, &result_point2, &result_byte);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << int(result_byte) << std::endl;
	std::cout << "---- add_output" << std::endl;
	add_output(true, 500, &result_point1, &result_point2, &result_byte);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << int(result_byte) << std::endl;
	std::cout << "---- add_extra_chunk" << std::endl;
	add_extra(extra);
	std::cout << "---- add_sig_get_xy" << std::endl;
	add_sig_a(test_scalar1, my_address, &result_point1, &result_point2, &result_point3);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << result_point3 << std::endl;
	std::cout << "---- add_sig_a" << std::endl;
	SecretKey result_scalar1, result_scalar2, result_scalar3;
	add_sig_a_more_data(test_point1.as_binary_array() | test_point2.as_binary_array(), &result_scalar1);
	std::cout << "---- add_sig_c0" << std::endl;
	std::cout << result_scalar1 << std::endl;
	std::cout << "---- add_sig_b" << std::endl;
	add_sig_b(test_scalar1, my_address, test_scalar1, &result_scalar1, &result_scalar2, &result_scalar3);
	std::cout << result_scalar1 << std::endl;
	std::cout << result_scalar2 << std::endl;
	std::cout << result_scalar3 << std::endl;

	// repeat first steps to check output generation to unlinkable address
	std::cout << "---- sign_start" << std::endl;
	sign_start(
	    4, 0, 1, 2, extra.size(), my_address, cn::AccountAddressUnlinkable::type_tag, test_address1_s, test_address1_v);
	std::cout << "---- add_input" << std::endl;
	add_input(1000, {0, 1, 2}, test_scalar1, my_address);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << "---- add_output" << std::endl;
	add_output(false, 400, &result_point1, &result_point2, &result_byte);
	std::cout << result_point1 << std::endl;
	std::cout << result_point2 << std::endl;
	std::cout << int(result_byte) << std::endl;

	Signature result_sig0;
	std::cout << "---- generate_sendproof" << std::endl;
	generate_sendproof(test_hash1, 1, test_hash1, test_hash1, "mega address", 5, &result_sig0);
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

static Hash derive_from_seed(const Hash &seed, const std::string &append) {
	BinaryArray seed_data = seed.as_binary_array() | as_binary_array(append);
	return crypto::cn_fast_hash(seed_data.data(), seed_data.size());
}

void Emulator::KeccakStream::append(const unsigned char *data, size_t size) { common::append(ba, data, data + size); }
void Emulator::KeccakStream::append(uint64_t a) { common::append(ba, common::get_varint_data(a)); }
void Emulator::KeccakStream::append_byte(uint8_t b) { ba.push_back(b); }
Hash Emulator::KeccakStream::cn_fast_hash() const {
	Hash result = crypto::cn_fast_hash(ba.data(), ba.size());
	if (debug_print)
		std::cout << "KeccakStream hash( " << common::to_hex(ba) << " )= " << result << std::endl;
	return result;
}
SecretKey Emulator::KeccakStream::hash_to_scalar() const { return crypto::hash_to_scalar(ba.data(), ba.size()); }
SecretKey Emulator::KeccakStream::hash_to_scalar64() const { return crypto::hash_to_scalar(ba.data(), ba.size()); }
PublicKey Emulator::KeccakStream::hash_to_good_point() const {
	return crypto::hash_to_good_point(ba.data(), ba.size());
}

inline bool add_amount(uint64_t &sum, uint64_t amount) {
	if (std::numeric_limits<uint64_t>::max() - amount < sum)
		return false;
	sum += amount;
	return true;
}

std::string debug_mnemonic;

void Emulator::debug_set_mnemonic(const std::string &mnemonic) { debug_mnemonic = mnemonic; }

Emulator::Emulator(std::unique_ptr<HardwareWallet> &&proxy) : m_proxy(std::move(proxy)) {
	// read m_wallet_key, m_spend_key_base_public_key from device

	m_mnemonics                   = cn::Bip32Key::check_bip39_mnemonic(debug_mnemonic);
	const cn::Bip32Key master_key = cn::Bip32Key::create_master_key(m_mnemonics, std::string());

	const cn::Bip32Key k0 = master_key.derive_key(0x8000002c);
	const cn::Bip32Key k1 = k0.derive_key(0x800000cc);
	const cn::Bip32Key k2 = k1.derive_key(0x80000000 + uint32_t(m_address_type));
	const cn::Bip32Key k3 = k2.derive_key(0);
	const cn::Bip32Key k4 = k3.derive_key(0);
	const Hash m_seed     = crypto::cn_fast_hash(k4.get_priv_key().data(), k4.get_priv_key().size());

	m_tx_derivation_seed        = derive_from_seed(m_seed, "tx_derivation");
	BinaryArray vk_data         = m_seed.as_binary_array() | as_binary_array("view_key");
	m_view_secret_key           = crypto::hash_to_scalar(vk_data.data(), vk_data.size());
	BinaryArray ak_data         = m_seed.as_binary_array() | as_binary_array("audit_key_base");
	m_audit_key_base_secret_key = crypto::hash_to_scalar(ak_data.data(), ak_data.size());
	BinaryArray sk_data         = m_seed.as_binary_array() | as_binary_array("spend_key");
	m_spend_secret_key          = crypto::hash_to_scalar(sk_data.data(), sk_data.size());

	m_sH = crypto::A_mul_b(crypto::get_H(), m_spend_secret_key);

	invariant(crypto::secret_key_to_public_key(m_view_secret_key, &m_view_public_key), "");
	PublicKey A;
	invariant(crypto::secret_key_to_public_key(m_audit_key_base_secret_key, &A), "");
	m_A_plus_SH       = crypto::A_plus_B(A, m_sH);
	m_v_mul_A_plus_SH = A_mul_b(m_A_plus_SH, m_view_secret_key);  // for hw debug only

	const Hash wallet_key_hash = derive_from_seed(m_seed, "wallet_key");
	m_wallet_key               = chacha_key{wallet_key_hash};

	if (debug_print) {
		std::cout << "bip44 child private key " << common::to_hex(k4.get_priv_key()) << std::endl;
		std::cout << "m_seed " << m_seed << std::endl;
		std::cout << "m_tx_derivation_seed " << m_tx_derivation_seed << std::endl;
		std::cout << "m_audit_key_base_secret_key " << m_audit_key_base_secret_key << std::endl;
		std::cout << "A " << A << std::endl;
		std::cout << "m_view_secret_key " << m_view_secret_key << std::endl;
		std::cout << "m_view_public_key " << m_view_public_key << std::endl;
		std::cout << "m_spend_secret_key " << m_spend_secret_key << std::endl;
		std::cout << "m_sH " << m_sH << std::endl;
		std::cout << "m_wallet_key " << wallet_key_hash << std::endl;
	}
	if (m_proxy) {
		invariant(get_A_plus_SH() == m_proxy->get_A_plus_SH(), "");
		invariant(get_v_mul_A_plus_SH() == m_proxy->get_v_mul_A_plus_SH(), "");
		invariant(get_public_view_key() == m_proxy->get_public_view_key(), "");
		// TODO - compare chacha keys
	}
	test_all_methods();
}

Emulator::~Emulator() {}

std::string Emulator::get_hardware_type() const {
	std::string result = "Emulator";
	if (m_proxy)
		result += " connected to " + m_proxy->get_hardware_type();
	return result + ", mnemonic=" + m_mnemonics;
}

// When we need only secrets
void Emulator::prepare_address(size_t address_index) const {
	if (address_index != last_address_index) {
		last_address_index = address_index;
		last_address_audit_secret_key =
		    crypto::generate_hd_secretkey(m_audit_key_base_secret_key, m_A_plus_SH, address_index);
		std::cout << "HW::prepare_address[" << address_index << "]=" << last_address_audit_secret_key << std::endl;
	}
}

// When we need also public address part
void Emulator::prepare_address(size_t address_index, PublicKey *address_S, PublicKey *address_Sv) const {
	prepare_address(address_index);
	PublicKey last_address_audit_public_key;
	invariant(crypto::secret_key_to_public_key(last_address_audit_secret_key, &last_address_audit_public_key), "");
	*address_S  = crypto::A_plus_B(last_address_audit_public_key, m_sH);
	*address_Sv = crypto::A_mul_b(*address_S, m_view_secret_key);
}

std::vector<PublicKey> Emulator::mul_by_view_secret_key(const std::vector<PublicKey> &output_public_keys) const {
	// multiply by m_view_secret_key on device, throw if PublicKey detected to be invalid by device
	std::vector<PublicKey> result(output_public_keys.size());
	for (size_t i = 0; i != result.size(); ++i)
		result.at(i) = crypto::unlinkable_underive_address_S_step1(m_view_secret_key, output_public_keys.at(i));
	if (m_proxy)
		invariant(m_proxy->mul_by_view_secret_key(output_public_keys) == result, "");
	return result;
}

KeyImage Emulator::generate_keyimage(
    const PublicKey &output_public_key, const SecretKey &inv_spend_scalar, size_t address_index) const {
	prepare_address(address_index);
	SecretKey output_secret_key_a = crypto::sc_mul(last_address_audit_secret_key, inv_spend_scalar);
	auto result                   = crypto::generate_key_image(output_public_key, output_secret_key_a);
	if (m_proxy)
		invariant(m_proxy->generate_keyimage(output_public_key, inv_spend_scalar, address_index) == result, "");
	return result;
}

void Emulator::generate_output_secret(const Hash &tx_inputs_hash, size_t out_index, PublicKey *output_secret_Q) const {
	*output_secret_Q = cn::TransactionBuilder::deterministic_keys_from_seed(
	    tx_inputs_hash, m_tx_derivation_seed, common::get_varint_data(out_index))
	                       .public_key;
	if (m_proxy) {
		PublicKey p_output_secret_Q;
		m_proxy->generate_output_secret(tx_inputs_hash, out_index, &p_output_secret_Q);
		invariant(*output_secret_Q == p_output_secret_Q, "");
	}
}

// TODO - check sig methods for resuls with proxy

void Emulator::sign_start(size_t version, size_t ut, size_t inputs_size, size_t outputs_size, size_t extra_size,
    size_t change_address_index, uint8_t dst_address_tag, PublicKey dst_address_s, PublicKey dst_address_s_v) const {
	invariant(inputs_size != 0, "");   // 0 inputs not allowed in consensus
	invariant(outputs_size != 0, "");  // 0 outputs allowed in consensus, we prohibit it to simplify our state machine
	sign                 = SigningState{};
	sign.version         = version;
	sign.ut              = ut;
	sign.inputs_size     = inputs_size;
	sign.outputs_size    = outputs_size;
	sign.extra_size      = extra_size;
	sign.dst_address_tag = dst_address_tag;
	sign.dst_address_s   = dst_address_s;
	sign.dst_address_s_v = dst_address_s_v;
	sign.state           = SigningState::EXPECT_INPUT;

	prepare_address(change_address_index, &sign.change_address_s, &sign.change_address_s_v);

	sign.tx_prefix_stream.append(version);
	sign.tx_prefix_stream.append(ut);
	sign.tx_prefix_stream.append(inputs_size);
	sign.tx_inputs_stream.append(inputs_size);

	sign.random_seed = Hash{};  // = crypto::rand<Hash>(); - uncomment in final code for full security
}

SecretKey Emulator::generate_sign_secret(size_t i, const char secret_name[2]) const {
	KeccakStream ks{};
	ks.append(sign.random_seed.data, 32);
	ks.append(m_spend_secret_key.data, 32);
	ks.append_byte(secret_name[0]);
	ks.append_byte(secret_name[1]);
	ks.append(i);
	SecretKey b = ks.hash_to_scalar64();
	if (debug_print)
		std::cout << secret_name[0] << secret_name[1] << "[" << i << "]=" << b << std::endl;
	return b;
}

void Emulator::add_input(uint64_t amount, const std::vector<size_t> &output_indexes, SecretKey inv_spend_scalar,
    size_t address_index) const {
	invariant(sign.state == SigningState::EXPECT_INPUT && sign.inputs_counter < sign.inputs_size, "");
	const uint8_t tag = cn::InputKey::type_tag;
	sign.tx_prefix_stream.append_byte(tag);
	sign.tx_inputs_stream.append_byte(tag);
	sign.tx_prefix_stream.append(amount);
	sign.tx_inputs_stream.append(amount);
	invariant(add_amount(sign.inputs_amount, amount), "");
	sign.tx_prefix_stream.append(output_indexes.size());
	sign.tx_inputs_stream.append(output_indexes.size());
	for (size_t j = 0; j != output_indexes.size(); ++j) {
		sign.tx_prefix_stream.append(output_indexes[j]);
		sign.tx_inputs_stream.append(output_indexes[j]);
	}
	prepare_address(address_index);
	SecretKey output_secret_key_a = crypto::sc_mul(last_address_audit_secret_key, inv_spend_scalar);
	SecretKey output_secret_key_s = crypto::sc_mul(m_spend_secret_key, inv_spend_scalar);
	PublicKey output_public_key   = crypto::secret_keys_to_public_key(output_secret_key_a, output_secret_key_s);
	KeyImage key_image            = crypto::generate_key_image(output_public_key, output_secret_key_a);

	sign.tx_prefix_stream.append(key_image.data, 32);
	sign.tx_inputs_stream.append(key_image.data, 32);

	if (++sign.inputs_counter < sign.inputs_size)
		return;
	sign.state          = SigningState::EXPECT_OUTPUT;
	sign.tx_inputs_hash = sign.tx_inputs_stream.cn_fast_hash();
	sign.tx_prefix_stream.append_byte(sign.outputs_size);
}

void Emulator::add_output_or_change(uint64_t amount, uint8_t dst_address_tag, PublicKey dst_address_s,
    PublicKey dst_address_s_v, PublicKey *public_key, PublicKey *encrypted_secret,
    uint8_t *encrypted_address_type) const {
	KeyPair output_det_keys = cn::TransactionBuilder::deterministic_keys_from_seed(
	    sign.tx_inputs_hash, m_tx_derivation_seed, common::get_varint_data(sign.outputs_counter));
	SecretKey output_secret_scalar;
	PublicKey output_secret_point;
	Hash output_secret_address_type;
	cn::TransactionBuilder::generate_output_secrets(
	    output_det_keys.public_key, &output_secret_scalar, &output_secret_point, &output_secret_address_type);

	uint8_t output_tag = cn::OutputKey::type_tag;

	*encrypted_address_type = dst_address_tag ^ output_secret_address_type.data[0];
	if (dst_address_tag == cn::AccountAddressSimple::type_tag) {
		*public_key = crypto::linkable_derive_output_public_key(output_secret_scalar, sign.tx_inputs_hash,
		    sign.outputs_counter, dst_address_s, dst_address_s_v, encrypted_secret);
	} else {
		*public_key = crypto::unlinkable_derive_output_public_key(output_secret_point, sign.tx_inputs_hash,
		    sign.outputs_counter, dst_address_s, dst_address_s_v, encrypted_secret);
	}

	sign.tx_prefix_stream.append_byte(output_tag);
	sign.tx_prefix_stream.append(amount);
	sign.tx_prefix_stream.append(public_key->data, 32);
	sign.tx_prefix_stream.append(encrypted_secret->data, 32);
	sign.tx_prefix_stream.append_byte(*encrypted_address_type);
}

void Emulator::add_output(bool change, uint64_t amount, PublicKey *public_key, PublicKey *encrypted_secret,
    uint8_t *encrypted_address_type) const {
	invariant(sign.state == SigningState::EXPECT_OUTPUT && sign.outputs_counter < sign.outputs_size, "");
	if (change) {
		invariant(add_amount(sign.change_amount, amount), "");
		add_output_or_change(amount, cn::AccountAddressUnlinkable::type_tag, sign.change_address_s,
		    sign.change_address_s_v, public_key, encrypted_secret, encrypted_address_type);
	} else {
		invariant(add_amount(sign.dst_amount, amount), "");
		add_output_or_change(amount, sign.dst_address_tag, sign.dst_address_s, sign.dst_address_s_v, public_key,
		    encrypted_secret, encrypted_address_type);
	}
	if (++sign.outputs_counter < sign.outputs_size)
		return;
	uint64_t outputs_amount = sign.dst_amount;
	invariant(add_amount(outputs_amount, sign.change_amount), "");
	invariant(sign.inputs_amount >= outputs_amount, "");
	uint64_t fee = sign.inputs_amount - outputs_amount;
	std::cout << "fee=" << fee << std::endl;
	// Here, show user 2 dialogs
	// 1. Do you wish to send 'dst_amount' to 'dst_address'?
	// 2. Fee will be 'fee'
	// If both answered yes, continue to signing. Otherwise cancel
	sign.state = SigningState::EXPECT_EXTRA_CHUNK;
	sign.tx_prefix_stream.append(sign.extra_size);
}

void Emulator::add_extra(const BinaryArray &chunk) const {
	invariant(sign.state == SigningState::EXPECT_EXTRA_CHUNK, "");
	invariant(sign.extra_counter + chunk.size() <= sign.extra_size, "");  // <= because we call it also for empty extra
	sign.tx_prefix_stream.append(chunk.data(), chunk.size());
	sign.extra_counter += chunk.size();
	if (sign.extra_counter < sign.extra_size)
		return;
	sign.state            = SigningState::EXPECT_SIGN_A;
	sign.tx_prefix_hash   = sign.tx_prefix_stream.cn_fast_hash();
	sign.inputs_counter   = 0;
	sign.tx_inputs_stream = KeccakStream{};
	sign.tx_inputs_stream.append(sign.tx_prefix_hash.data, 32);
}

void Emulator::add_sig_a(SecretKey inv_spend_scalar, size_t address_index, EllipticCurvePoint *sig_p,
    EllipticCurvePoint *x, EllipticCurvePoint *y) const {
	invariant(sign.state == SigningState::EXPECT_SIGN_A && sign.inputs_counter < sign.inputs_size, "");

	prepare_address(address_index);
	SecretKey output_secret_key_a = crypto::sc_mul(last_address_audit_secret_key, inv_spend_scalar);
	SecretKey output_secret_key_s = crypto::sc_mul(m_spend_secret_key, inv_spend_scalar);
	PublicKey output_public_key   = crypto::secret_keys_to_public_key(output_secret_key_a, output_secret_key_s);
	KeyImage key_image            = crypto::generate_key_image(output_public_key, output_secret_key_a);

	const P3 b_coin_p3(hash_to_good_point_p3(key_image));
	const PublicKey b_coin = to_bytes(b_coin_p3);
	const P3 hash_pubs_sec_p3(hash_to_good_point_p3(output_public_key));
	if (debug_print)
		std::cout << "b_coin[" << sign.inputs_counter << "]=" << b_coin << std::endl;
	const P3 p_p3 = H * output_secret_key_s - b_coin_p3 * output_secret_key_a;
	*sig_p        = to_bytes(p_p3);
	if (debug_print)
		std::cout << "p[" << sign.inputs_counter << "]=" << *sig_p << std::endl;
	sign.tx_inputs_stream.append(sig_p->data, 32);

	const SecretKey ka = generate_sign_secret(sign.inputs_counter, "ka");
	const SecretKey kb = generate_sign_secret(sign.inputs_counter, "kb");
	const SecretKey kc = generate_sign_secret(sign.inputs_counter, "kc");

	const PublicKey z = to_bytes(kb * H + kc * b_coin_p3);
	sign.tx_inputs_stream.append(z.data, 32);

	const P3 G_plus_B_p3 = P3(G) + b_coin_p3;
	if (debug_print)
		std::cout << "pk[" << sign.inputs_counter << ", "
		          << "my"
		          << "]=" << output_public_key << std::endl;
	*x = to_bytes(ka * G_plus_B_p3);
	if (debug_print)
		std::cout << "x[" << sign.inputs_counter << ", "
		          << "my"
		          << "]=" << *x << std::endl;
	*y = to_bytes(ka * hash_pubs_sec_p3);
	if (debug_print)
		std::cout << "y[" << sign.inputs_counter << ", "
		          << "my"
		          << "]=" << *y << std::endl;

	sign.state = SigningState::EXPECT_SIGN_A_MORE_DATA;
}

void Emulator::add_sig_a_more_data(const BinaryArray &data, EllipticCurveScalar *c0) const {
	invariant(sign.state == SigningState::EXPECT_SIGN_A_MORE_DATA, "");

	sign.tx_inputs_stream.append(data.data(), data.size());

	if (++sign.inputs_counter < sign.inputs_size) {
		*c0        = EllipticCurveScalar{};
		sign.state = SigningState::EXPECT_SIGN_A;
		return;
	}
	sign.c0 = sign.tx_inputs_stream.hash_to_scalar();
	*c0     = sign.c0;
	if (debug_print)
		std::cout << "c0=" << sign.c0 << std::endl;
	sign.state          = SigningState::EXPECT_SIGN_B;
	sign.inputs_counter = 0;
}

void Emulator::add_sig_b(SecretKey inv_spend_scalar, size_t address_index, EllipticCurveScalar my_c,
    EllipticCurveScalar *sig_my_ra, EllipticCurveScalar *sig_rb, EllipticCurveScalar *sig_rc) const {
	invariant(sign.state == SigningState::EXPECT_SIGN_B, "");

	prepare_address(address_index);
	SecretKey output_secret_key_a = crypto::sc_mul(last_address_audit_secret_key, inv_spend_scalar);
	SecretKey output_secret_key_s = crypto::sc_mul(m_spend_secret_key, inv_spend_scalar);

	const SecretKey ka = generate_sign_secret(sign.inputs_counter, "ka");
	const SecretKey kb = generate_sign_secret(sign.inputs_counter, "kb");
	const SecretKey kc = generate_sign_secret(sign.inputs_counter, "kc");

	*sig_rb    = kb - sign.c0 * output_secret_key_s;
	*sig_rc    = kc + sign.c0 * output_secret_key_a;
	*sig_my_ra = ka - my_c * output_secret_key_a;

	if (debug_print)
		std::cout << "ra[" << sign.inputs_counter << ", my]=" << *sig_my_ra << std::endl;
	if (debug_print)
		std::cout << "rb[" << sign.inputs_counter << "]=" << *sig_rb << std::endl;
	if (debug_print)
		std::cout << "rc[" << sign.inputs_counter << "]=" << *sig_rc << std::endl;

	if (++sign.inputs_counter < sign.inputs_size)
		return;
	sign.state = SigningState::FINISHED;
}

void Emulator::generate_sendproof(const Hash &tx_inputs_hash, size_t out_index, const Hash &transaction_hash,
    const Hash &message_hash, const std::string &address, size_t outputs_count, Signature *signature) const {
	//	KeyPair output_det_keys = cn::TransactionBuilder::deterministic_keys_from_seed(
	//	    tx_inputs_hash, m_tx_derivation_seed, common::get_varint_data(out_index));
	//	*signature =
	//	    crypto::amethyst_generate_sendproof(output_det_keys, transaction_hash, message_hash, address,
	// outputs_count);
}

void Emulator::export_view_only(SecretKey *audit_key_base_secret_key, SecretKey *view_secret_key,
    Hash *tx_derivation_seed, Signature *view_secrets_signature) const {
	*view_secret_key           = m_view_secret_key;
	*audit_key_base_secret_key = m_audit_key_base_secret_key;
	// Ask user if he wants view wallet to view outgoing addresses
	bool view_outgoing_addresses = true;
	if (view_outgoing_addresses)
		*tx_derivation_seed = m_tx_derivation_seed;
	KeccakStream ks;
	ks.append(audit_key_base_secret_key->data, 32);
	ks.append(m_view_secret_key.data, 32);
	Hash view_secrets_hash = ks.cn_fast_hash();

	*view_secrets_signature = crypto::generate_signature_H(view_secrets_hash, m_sH, m_spend_secret_key);
	if (debug_print) {
		std::cout << "audit_key_base_secret_key=" << *audit_key_base_secret_key << std::endl;
		std::cout << "view_secret_key=" << view_secret_key << std::endl;
		std::cout << "m_sH=" << m_sH << std::endl;
		std::cout << "view_secrets_hash=" << view_secrets_hash << std::endl;
		std::cout << "view_secrets_signature=" << view_secrets_signature->c << view_secrets_signature->r << std::endl;
	}
}
