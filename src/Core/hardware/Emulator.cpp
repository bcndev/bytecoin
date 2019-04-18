// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Emulator.hpp"
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
#include "crypto/crypto.hpp"
#include "crypto/crypto_helpers.hpp"

static const bool debug_print = true;
static const bool debug_seed  = true;  // set to true to debug new hardware

using namespace cn::hardware;
using namespace crypto;
using namespace common;

static Hash derive_from_seed(const Hash &seed, const std::string &append) {
	BinaryArray seed_data = seed.as_binary_array() | as_binary_array(append);
	return cn_fast_hash(seed_data.data(), seed_data.size());
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

static const cryptoEllipticCurveScalar sc_2_256{
    {0x1d, 0x95, 0x98, 0x8d, 0x74, 0x31, 0xec, 0xd6, 0x70, 0xcf, 0x7d, 0x73, 0xf4, 0x5b, 0xef, 0xc6, 0xfe, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f}};

SecretKey Emulator::KeccakStream::hash_to_scalar64() const {
	SecretKey must_be = crypto::hash_to_scalar64(ba.data(), ba.size());

	Hash left_hash  = crypto::cn_fast_hash(ba.data(), ba.size());
	Hash right_hash = crypto::cn_fast_hash(left_hash.data, sizeof(left_hash.data));

	SecretKey left;
	sc_reduce32(&left, left_hash.data);
	SecretKey right;
	sc_reduce32(&right, right_hash.data);

	SecretKey mu;
	sc_mul(&mu, &right, &sc_2_256);
	sc_add(&mu, &mu, &left);
	invariant(mu == must_be, "");
	return mu;
}

PublicKey Emulator::KeccakStream::hash_to_good_point() const {
	return crypto::hash_to_good_point(ba.data(), ba.size());
}

inline bool add_amount(uint64_t &sum, uint64_t amount) {
	if (std::numeric_limits<uint64_t>::max() - amount < sum)
		return false;
	sum += amount;
	return true;
}

Emulator::Emulator(const std::string &mnemonic) {
	// read m_wallet_key, m_spend_key_base_public_key from device

	m_mnemonics                   = cn::Bip32Key::check_bip39_mnemonic(mnemonic);
	const cn::Bip32Key master_key = cn::Bip32Key::create_master_key(m_mnemonics, std::string());

	const cn::Bip32Key k0 = master_key.derive_key(0x8000002c);
	const cn::Bip32Key k1 = k0.derive_key(0x800000cc);
	const cn::Bip32Key k2 = k1.derive_key(0x80000000 + uint32_t(m_address_type));
	const cn::Bip32Key k3 = k2.derive_key(0);
	const cn::Bip32Key k4 = k3.derive_key(0);
	const Hash m_seed     = cn_fast_hash(k4.get_priv_key().data(), k4.get_priv_key().size());

	m_view_seed                 = derive_from_seed(m_seed, "view_seed");
	BinaryArray vk_data         = m_view_seed.as_binary_array() | as_binary_array("view_key");
	m_view_secret_key           = hash_to_scalar(vk_data.data(), vk_data.size());
	BinaryArray ak_data         = m_view_seed.as_binary_array() | as_binary_array("view_key_audit");
	m_audit_key_base_secret_key = hash_to_scalar(ak_data.data(), ak_data.size());
	BinaryArray sk_data         = m_seed.as_binary_array() | as_binary_array("spend_key");
	m_spend_secret_key          = hash_to_scalar(sk_data.data(), sk_data.size());

	m_sH = to_bytes(crypto::H * m_spend_secret_key);

	invariant(secret_key_to_public_key(m_view_secret_key, &m_view_public_key), "");
	PublicKey A;
	invariant(secret_key_to_public_key(m_audit_key_base_secret_key, &A), "");
	m_A_plus_sH       = to_bytes(P3(A) + P3(m_sH));
	m_v_mul_A_plus_sH = to_bytes(P3(m_A_plus_sH) * m_view_secret_key);  // for hw debug only

	m_wallet_key = derive_from_seed(m_seed, "wallet_key");

	if (debug_print) {
		std::cout << "bip44 child private key " << common::to_hex(k4.get_priv_key()) << std::endl;
		std::cout << "m_seed " << m_seed << std::endl;
		std::cout << "m_view_seed " << m_view_seed << std::endl;
		std::cout << "m_audit_key_base_secret_key " << m_audit_key_base_secret_key << std::endl;
		std::cout << "A " << A << std::endl;
		std::cout << "m_view_secret_key " << m_view_secret_key << std::endl;
		std::cout << "m_view_public_key " << m_view_public_key << std::endl;
		std::cout << "m_spend_secret_key " << m_spend_secret_key << std::endl;
		std::cout << "m_sH " << m_sH << std::endl;
		std::cout << "m_wallet_key " << m_wallet_key << std::endl;
	}

	SecretKey sc2;
	sc2.data[0] = 2;
	auto poi1   = crypto::G * sc2;
	auto poi2   = crypto::H * sc2;
	std::cout << "poi1=" << to_bytes(poi1) << std::endl;
	std::cout << "poi2=" << to_bytes(poi2) << std::endl;
	std::cout << "poi3=" << to_bytes(poi1 * sc2) << std::endl;
	std::cout << "poi4=" << to_bytes(poi1 + poi2) << std::endl;
	std::cout << "poi5=" << to_bytes(poi1 - poi2) << std::endl;

	const char bcn[] = "bcn";

	std::cout << cn_fast_hash(bcn, 3) << std::endl;
	std::cout << hash_to_scalar(bcn, 3) << std::endl;
	std::cout << hash_to_scalar64(bcn, 3) << std::endl;
	std::cout << hash_to_good_point(bcn, 3) << std::endl;
}

Emulator::~Emulator() {}

std::string Emulator::get_hardware_type() const { return "Emulator, mnemonic=" + m_mnemonics; }

// When we need only secrets
void Emulator::prepare_address(size_t address_index) const {
	if (address_index != last_address_index) {
		last_address_index            = address_index;
		last_address_audit_secret_key = generate_hd_secretkey(m_audit_key_base_secret_key, m_A_plus_sH, address_index);
		std::cout << "HW::prepare_address[" << address_index << "]=" << last_address_audit_secret_key << std::endl;
	}
}

// When we need also public address part
void Emulator::prepare_address(size_t address_index, PublicKey *address_S, PublicKey *address_Sv) const {
	prepare_address(address_index);
	PublicKey last_address_audit_public_key;
	invariant(secret_key_to_public_key(last_address_audit_secret_key, &last_address_audit_public_key), "");
	*address_S  = to_bytes(P3(last_address_audit_public_key) + P3(m_sH));
	*address_Sv = to_bytes(P3(*address_S) * m_view_secret_key);
}

std::vector<PublicKey> Emulator::scan_outputs(const std::vector<PublicKey> &output_public_keys) {
	// multiply by m_view_secret_key on device, throw if PublicKey detected to be invalid by device
	std::vector<PublicKey> result(output_public_keys.size());
	for (size_t i = 0; i != result.size(); ++i)
		result.at(i) = unlinkable_underive_address_S_step1(m_view_secret_key, output_public_keys.at(i));
	return result;
}

KeyImage Emulator::generate_keyimage(const common::BinaryArray &output_secret_hash_arg, size_t address_index) {
	SecretKey inv_output_secret_hash =
	    sc_invert(hash_to_scalar(output_secret_hash_arg.data(), output_secret_hash_arg.size()));
	prepare_address(address_index);
	SecretKey output_secret_key_a = last_address_audit_secret_key * inv_output_secret_hash;
	SecretKey output_secret_key_s = m_spend_secret_key * inv_output_secret_hash;
	PublicKey output_public_key   = secret_keys_to_public_key(output_secret_key_a, output_secret_key_s);
	auto result                   = generate_key_image(output_public_key, output_secret_key_a);

	return result;
}

Hash Emulator::generate_output_seed(const Hash &tx_inputs_hash, size_t out_index) {
	return cn::TransactionBuilder::generate_output_seed(tx_inputs_hash, m_view_seed, out_index);
}

void Emulator::sign_start(size_t version, uint64_t ut, size_t inputs_size, size_t outputs_size, size_t extra_size) {
	invariant(inputs_size != 0, "");   // 0 inputs not allowed in consensus
	invariant(outputs_size != 0, "");  // 0 outputs allowed in consensus, we prohibit it to simplify our state machine
	invariant(version != 0, "Wrong transaction version ");
	sign              = SigningState{};
	sign.inputs_size  = inputs_size;
	sign.outputs_size = outputs_size;
	sign.extra_size   = extra_size;
	sign.state        = SigningState::EXPECT_ADD_INPUT_START;

	sign.tx_prefix_stream.append(version);
	sign.tx_prefix_stream.append(ut);
	sign.tx_prefix_stream.append(inputs_size);
	sign.tx_inputs_stream.append(inputs_size);
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

void Emulator::sign_add_input_start(uint64_t amount, size_t output_indexes_count) {
	invariant(sign.state == SigningState::EXPECT_ADD_INPUT_START && sign.inputs_counter < sign.inputs_size, "");
	invariant(add_amount(sign.inputs_amount, amount), "");
	const uint8_t tag = cn::InputKey::type_tag;
	sign.tx_prefix_stream.append_byte(tag);
	sign.tx_inputs_stream.append_byte(tag);
	sign.tx_prefix_stream.append(amount);
	sign.tx_inputs_stream.append(amount);
	sign.tx_prefix_stream.append(output_indexes_count);
	sign.tx_inputs_stream.append(output_indexes_count);
	sign.mixin_counter = 0;
	sign.mixin_size    = output_indexes_count;
	sign.state         = SigningState::EXPECT_ADD_INPUT_INDEXES;
}

void Emulator::sign_add_input_indexes(const std::vector<size_t> &output_indexes_chunk) {
	invariant(sign.state == SigningState::EXPECT_ADD_INPUT_INDEXES &&
	              sign.mixin_counter + output_indexes_chunk.size() <= sign.mixin_size,
	    "");
	for (size_t j = 0; j != output_indexes_chunk.size(); ++j) {
		sign.tx_prefix_stream.append(output_indexes_chunk[j]);
		sign.tx_inputs_stream.append(output_indexes_chunk[j]);
	}
	sign.mixin_counter += output_indexes_chunk.size();
	if (sign.mixin_counter < sign.mixin_size)
		return;
	sign.state = SigningState::EXPECT_ADD_INPUT_FINISH;
}

void Emulator::sign_add_input_finish(const common::BinaryArray &output_secret_hash_arg, size_t address_index) {
	invariant(sign.state == SigningState::EXPECT_ADD_INPUT_FINISH, "");
	SecretKey inv_output_secret_hash =
	    sc_invert(hash_to_scalar(output_secret_hash_arg.data(), output_secret_hash_arg.size()));
	prepare_address(address_index);
	SecretKey output_secret_key_a = last_address_audit_secret_key * inv_output_secret_hash;
	SecretKey output_secret_key_s = m_spend_secret_key * inv_output_secret_hash;
	PublicKey output_public_key   = secret_keys_to_public_key(output_secret_key_a, output_secret_key_s);
	KeyImage key_image            = generate_key_image(output_public_key, output_secret_key_a);

	sign.tx_prefix_stream.append(key_image.data, 32);
	sign.tx_inputs_stream.append(key_image.data, 32);

	if (++sign.inputs_counter < sign.inputs_size) {
		sign.state = SigningState::EXPECT_ADD_INPUT_START;
		return;
	}
	sign.state          = SigningState::EXPECT_ADD_OUTPUT;
	sign.tx_inputs_hash = sign.tx_inputs_stream.cn_fast_hash();
	sign.tx_prefix_stream.append(sign.outputs_size);
}

const size_t MAX_INPUT_INDEXES_CHUNK = 4;

void Emulator::sign_add_input(uint64_t amount, const std::vector<size_t> &output_indexes,
    const common::BinaryArray &output_secret_hash_arg, size_t address_index) {
	sign_add_input_start(amount, output_indexes.size());
	for (size_t pos = 0; pos != output_indexes.size();) {
		size_t stop = std::min(output_indexes.size(), pos + MAX_INPUT_INDEXES_CHUNK);
		sign_add_input_indexes(std::vector<size_t>{output_indexes.begin() + pos, output_indexes.begin() + stop});
		pos = stop;
	}
	sign_add_input_finish(output_secret_hash_arg, address_index);
}

void Emulator::add_output_or_change(uint64_t amount, uint8_t dst_address_tag, PublicKey dst_address_s,
    PublicKey dst_address_s_v, PublicKey *public_key, PublicKey *encrypted_secret,
    uint8_t *encrypted_address_type) const {
	Hash output_seed =
	    cn::TransactionBuilder::generate_output_seed(sign.tx_inputs_hash, m_view_seed, sign.outputs_counter);
	if (debug_print)
		std::cout << "output_seed=" << output_seed << std::endl;
	SecretKey output_secret_scalar;
	PublicKey output_secret_point;
	uint8_t output_secret_address_type = 0;
	cn::TransactionBuilder::generate_output_secrets(
	    output_seed, &output_secret_scalar, &output_secret_point, &output_secret_address_type);
	if (debug_print) {
		std::cout << "output_secret_scalar=" << output_secret_scalar << std::endl;
		std::cout << "output_secret_point=" << output_secret_point << std::endl;
		std::cout << "output_secret_address_type=" << output_secret_address_type << std::endl;
	}
	uint8_t output_tag = cn::OutputKey::type_tag;

	*encrypted_address_type = dst_address_tag ^ output_secret_address_type;
	if (dst_address_tag == cn::AccountAddressLegacy::type_tag) {
		*public_key = linkable_derive_output_public_key(output_secret_scalar, sign.tx_inputs_hash, sign.outputs_counter,
		    dst_address_s, dst_address_s_v, encrypted_secret);
	} else {
		*public_key = unlinkable_derive_output_public_key(output_secret_point, sign.tx_inputs_hash,
		    sign.outputs_counter, dst_address_s, dst_address_s_v, encrypted_secret);
	}

	sign.tx_prefix_stream.append_byte(output_tag);
	sign.tx_prefix_stream.append(amount);
	sign.tx_prefix_stream.append(public_key->data, 32);
	sign.tx_prefix_stream.append(encrypted_secret->data, 32);
	sign.tx_prefix_stream.append_byte(*encrypted_address_type);
}

void Emulator::sign_add_output(bool change, uint64_t amount, size_t change_address_index, uint8_t dst_address_tag,
    PublicKey dst_address_s, PublicKey dst_address_s_v, PublicKey *public_key, PublicKey *encrypted_secret,
    uint8_t *encrypted_address_type) {
	invariant(sign.state == SigningState::EXPECT_ADD_OUTPUT && sign.outputs_counter < sign.outputs_size, "");
	if (change) {
		invariant(add_amount(sign.change_amount, amount), "");
		PublicKey change_address_s;
		PublicKey change_address_s_v;
		prepare_address(change_address_index, &change_address_s, &change_address_s_v);

		add_output_or_change(amount, cn::AccountAddressAmethyst::type_tag, change_address_s, change_address_s_v,
		    public_key, encrypted_secret, encrypted_address_type);
	} else {
		if (!sign.dst_address_set) {
			sign.dst_address_set = true;
			sign.dst_address_tag = dst_address_tag;
			sign.dst_address_s   = dst_address_s;
			sign.dst_address_s_v = dst_address_s_v;
		} else {
			invariant(sign.dst_address_tag == dst_address_tag && sign.dst_address_s == dst_address_s &&
			              sign.dst_address_s_v == dst_address_s_v,
			    "");
		}
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
	sign.state = SigningState::EXPECT_ADD_EXTRA_CHUNK;
	sign.tx_prefix_stream.append(sign.extra_size);
}

void Emulator::sign_add_extra(const BinaryArray &chunk) {
	invariant(sign.state == SigningState::EXPECT_ADD_EXTRA_CHUNK, "");
	invariant(sign.extra_counter + chunk.size() <= sign.extra_size, "");  // <= because we call it also for empty extra
	sign.tx_prefix_stream.append(chunk.data(), chunk.size());
	sign.extra_counter += chunk.size();
	if (sign.extra_counter < sign.extra_size)
		return;
	sign.state            = SigningState::EXPECT_STEP_A;
	Hash tx_prefix_hash   = sign.tx_prefix_stream.cn_fast_hash();
	sign.inputs_counter   = 0;
	sign.tx_inputs_stream = KeccakStream{};
	sign.tx_inputs_stream.append(tx_prefix_hash.data, 32);
	sign.tx_prefix_stream = KeccakStream{};

	sign.random_seed    = debug_seed ? cn_fast_hash("bcn", 3) : crypto::rand<Hash>();
	sign.encryption_key = debug_seed ? cn_fast_hash("bcn", 3) : crypto::rand<Hash>();
}

void Emulator::sign_step_a(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
    EllipticCurvePoint *sig_p, EllipticCurvePoint *y, EllipticCurvePoint *z) {
	if (sign.state == SigningState::EXPECT_STEP_A_MORE_DATA && sign.inputs_counter + 1 < sign.inputs_size) {
		sign.inputs_counter += 1;
		sign.state = SigningState::EXPECT_STEP_A;
	}
	invariant(sign.state == SigningState::EXPECT_STEP_A && sign.inputs_counter < sign.inputs_size, "");

	SecretKey inv_output_secret_hash =
	    sc_invert(hash_to_scalar(output_secret_hash_arg.data(), output_secret_hash_arg.size()));
	sign.tx_prefix_stream.append(inv_output_secret_hash.data, 32);
	sign.tx_prefix_stream.append(address_index);

	prepare_address(address_index);
	SecretKey output_secret_key_a = last_address_audit_secret_key * inv_output_secret_hash;
	SecretKey output_secret_key_s = m_spend_secret_key * inv_output_secret_hash;
	PublicKey output_public_key   = secret_keys_to_public_key(output_secret_key_a, output_secret_key_s);
	KeyImage key_image            = generate_key_image(output_public_key, output_secret_key_a);

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

	const SecretKey kr = generate_sign_secret(sign.inputs_counter, "kr");
	const SecretKey ks = generate_sign_secret(sign.inputs_counter, "ks");
	const SecretKey ka = generate_sign_secret(sign.inputs_counter, "ka");

	const PublicKey x = to_bytes(ks * H + ka * b_coin_p3);
	if (debug_print)
		std::cout << "x[" << sign.inputs_counter << "]=" << x << std::endl;
	sign.tx_inputs_stream.append(x.data, 32);

	const P3 G_plus_B_p3 = P3(G) + b_coin_p3;
	if (debug_print)
		std::cout << "pk[" << sign.inputs_counter << ", my]=" << output_public_key << std::endl;
	*y = to_bytes(kr * G_plus_B_p3);
	if (debug_print)
		std::cout << "y[" << sign.inputs_counter << ", my]=" << *y << std::endl;
	*z = to_bytes(kr * hash_pubs_sec_p3);
	if (debug_print)
		std::cout << "z[" << sign.inputs_counter << ", my]=" << *z << std::endl;

	sign.state = SigningState::EXPECT_STEP_A_MORE_DATA;
}

void Emulator::sign_step_a_more_data(const BinaryArray &data) {
	invariant(sign.state == SigningState::EXPECT_STEP_A_MORE_DATA, "");

	sign.tx_inputs_stream.append(data.data(), data.size());
}

EllipticCurveScalar Emulator::sign_get_c0() {
	invariant(sign.state == SigningState::EXPECT_STEP_A_MORE_DATA && sign.inputs_counter + 1 == sign.inputs_size, "");

	sign.c0               = sign.tx_inputs_stream.hash_to_scalar();
	sign.step_args_hash   = sign.tx_prefix_stream.cn_fast_hash();
	sign.tx_prefix_stream = KeccakStream{};
	if (debug_print)
		std::cout << "c0=" << sign.c0 << std::endl;

	sign.state          = SigningState::EXPECT_STEP_B;
	sign.inputs_counter = 0;

	return sign.c0;
}

void Emulator::sign_step_b(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
    EllipticCurveScalar my_c, Hash *sig_my_rr, Hash *sig_rs, Hash *sig_ra, Hash *e_key) {
	invariant(sign.state == SigningState::EXPECT_STEP_B && sign.inputs_counter < sign.inputs_size, "");

	SecretKey inv_output_secret_hash =
	    sc_invert(hash_to_scalar(output_secret_hash_arg.data(), output_secret_hash_arg.size()));
	sign.tx_prefix_stream.append(inv_output_secret_hash.data, 32);  // for NEW protocol
	sign.tx_prefix_stream.append(address_index);                    // for NEW protocol

	prepare_address(address_index);
	SecretKey output_secret_key_a = last_address_audit_secret_key * inv_output_secret_hash;
	SecretKey output_secret_key_s = m_spend_secret_key * inv_output_secret_hash;

	const SecretKey kr = generate_sign_secret(sign.inputs_counter, "kr");
	const SecretKey ks = generate_sign_secret(sign.inputs_counter, "ks");
	const SecretKey ka = generate_sign_secret(sign.inputs_counter, "ka");

	SecretKey rsig_rs    = ks - sign.c0 * output_secret_key_s;
	SecretKey rsig_ra    = ka + sign.c0 * output_secret_key_a;
	SecretKey rsig_my_rr = kr - my_c * output_secret_key_a;

	*sig_my_rr = encrypt_scalar(sign.encryption_key, rsig_my_rr, sign.inputs_counter, "rr");
	*sig_rs    = encrypt_scalar(sign.encryption_key, rsig_rs, sign.inputs_counter, "rs");
	*sig_ra    = encrypt_scalar(sign.encryption_key, rsig_ra, sign.inputs_counter, "ra");

	if (debug_print)
		std::cout << "rr[" << sign.inputs_counter << ", my]=" << rsig_my_rr << " encrypted=" << *sig_my_rr << std::endl;
	if (debug_print)
		std::cout << "rs[" << sign.inputs_counter << "]=" << rsig_rs << " encrypted=" << *sig_rs << std::endl;
	if (debug_print)
		std::cout << "ra[" << sign.inputs_counter << "]=" << rsig_ra << " encrypted=" << *sig_ra << std::endl;

	if (++sign.inputs_counter < sign.inputs_size) {
		*e_key = Hash{};  // We return encryption key only after last iteration
		return;
	}
	sign.state           = SigningState::FINISHED;
	Hash step_args_hash2 = sign.tx_prefix_stream.cn_fast_hash();
	if (sign.step_args_hash != step_args_hash2)
		sign.encryption_key = Hash{};
	*e_key = sign.encryption_key;
}

void Emulator::proof_start(const common::BinaryArray &data) {
	sign             = SigningState{};
	sign.inputs_size = 1;

	sign.tx_prefix_stream.append_byte(0);                    // guard_byte
	sign.tx_prefix_stream.append(data.data(), data.size());  // will require separate sign.state on real device
	Hash tx_prefix_hash   = sign.tx_prefix_stream.cn_fast_hash();
	sign.tx_prefix_stream = KeccakStream{};

	sign.random_seed    = debug_seed ? cn_fast_hash("bcn", 3) : crypto::rand<Hash>();
	sign.encryption_key = debug_seed ? cn_fast_hash("bcn", 3) : crypto::rand<Hash>();

	sign.tx_inputs_stream.append(tx_prefix_hash.data, 32);
	sign.state = SigningState::EXPECT_STEP_A;
}

void Emulator::export_view_only(SecretKey *audit_key_base_secret_key, SecretKey *view_secret_key, Hash *view_seed,
    Signature *view_secrets_signature) {
	*view_secret_key           = m_view_secret_key;
	*audit_key_base_secret_key = m_audit_key_base_secret_key;
	// Ask user if he wants view wallet to view outgoing addresses
	bool view_outgoing_addresses = true;
	if (view_outgoing_addresses)
		*view_seed = m_view_seed;

	*view_secrets_signature = generate_proof_H(m_spend_secret_key);
	if (debug_print) {
		std::cout << "audit_key_base_secret_key=" << *audit_key_base_secret_key << std::endl;
		std::cout << "view_secret_key=" << view_secret_key << std::endl;
		std::cout << "m_sH=" << m_sH << std::endl;
		std::cout << "view_secrets_signature=" << view_secrets_signature->c << view_secrets_signature->r << std::endl;
	}
}
