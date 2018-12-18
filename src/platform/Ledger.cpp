// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Ledger.hpp"
#include <ctime>
#include <iostream>
#include "common/Invariant.hpp"

using namespace platform;
using namespace crypto;

Ledger::Ledger() {
	// read m_wallet_key, m_spend_key_base_public_key from device

	// Code to be run on device, m_address_type == 1 for now

	// cn::Bip32Key k0             = master_key.derive_key(0x8000002c);
	// cn::Bip32Key k1             = k0.derive_key(0x80000300);
	// cn::Bip32Key k2             = k1.derive_key(0x80000000 + m_address_type);
	// cn::Bip32Key k3             = k2.derive_key(0);
	// cn::Bip32Key k4             = k3.derive_key(0);
	// m_seed                      = crypto::cn_fast_hash(k4.get_priv_key().data(), k4.get_priv_key().size());
	// m_tx_derivation_seed        = derive_from_seed(m_seed, "tx_derivation");
	// BinaryArray sk_data         = m_seed | "spend_key_base";
	// m_spend_key_base.secret_key = crypto::hash_to_scalar(sk_data.data(), sk_data.size());
	// invariant(crypto::secret_key_to_public_key(m_spend_key_base.secret_key, &m_spend_key_base.public_key), "");
	// BinaryArray vk_data =
	// 		BinaryArray{std::begin(m_spend_key_base.public_key.data), std::end(m_spend_key_base.public_key.data)} |
	//		"view_key";
	// m_view_secret_key = crypto::hash_to_scalar(vk_data.data(), vk_data.size());
	// invariant(crypto::secret_key_to_public_key(m_view_secret_key, &m_view_public_key), "");

	// m_wallet_key = chacha_key{derive_from_seed(m_seed, "wallet_key")};
}

Ledger::~Ledger() {}

std::vector<PublicKey> Ledger::mul_by_view_secret_key(const std::vector<PublicKey> &output_public_keys) const {
	// multiply by m_view_secret_key on device, throw if PublicKey detected to be invalid by device

	// const ge_p3 output_public_key_p3       = ge_frombytes_vartime(output_public_key);
	// const ge_p3 p_v                    = ge_scalarmult3(view_secret_key, output_public_key_p3);

	// then either convert ge_p3 to PublicKey on device or computer

	// const PublicKey p_v_packed = ge_tobytes(p_v);

	return std::vector<PublicKey>();
}
