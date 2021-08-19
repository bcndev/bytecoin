// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "Core/Wallet.hpp"  // for WalletRecord
#include "common/Streams.hpp"
#include "crypto/chacha.hpp"
#include "seria/ISeria.hpp"

namespace cn {

class WalletSerializerV1 {
public:
	WalletSerializerV1(
	    PublicKey &view_public_key, SecretKey &view_secret_key, std::vector<WalletRecord> &wallets_container);

	void load(const crypto::chacha_key &key, common::IInputStream &source);

	struct CryptoContext {
		crypto::chacha_key key;
		crypto::chacha_iv iv;

		void inc_iv();
	};

private:
	static const uint32_t SERIALIZATION_VERSION;

	void load_wallet(common::IInputStream &source, const crypto::chacha_key &key, uint32_t version);
	void load_wallet_v1(common::IInputStream &source, const crypto::chacha_key &key);

	uint32_t load_version(common::IInputStream &source);
	void load_iv(common::IInputStream &source, crypto::chacha_iv &iv);
	void load_keys(common::IInputStream &source, CryptoContext &);
	void load_public_key(common::IInputStream &source, CryptoContext &);
	void load_secret_key(common::IInputStream &source, CryptoContext &);
	void check_keys();
	//	void load_flags(bool &details, bool &cache, common::IInputStream &source, CryptoContext &);
	void load_wallets(common::IInputStream &source, CryptoContext &);

	void load_wallet_v1_keys(seria::ISeria &s);

	PublicKey &m_view_public_key;
	SecretKey &m_view_secret_key;

	std::vector<WalletRecord> &m_wallets_container;
};

}  // namespace cn
