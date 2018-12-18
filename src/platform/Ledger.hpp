// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include "crypto/chacha.hpp"
#include "crypto/crypto.hpp"

namespace platform {

// Prototype - max simplified synchronous calls

// All funs including constructor throw std::runtime_error when connection to ledger lost before end of fun.
// All funs must quickly try reestablishing connection at the start if it was lost during previous call
// Calls might be from different threads, but will be externally synchronized

class Ledger {
	crypto::chacha_key m_wallet_key;                // wallet encryption key, derived from secret
	crypto::PublicKey m_spend_key_base_public_key;  // derived from secret
public:
	Ledger();
	~Ledger();
	crypto::chacha_key get_wallet_key() const { return m_wallet_key; }
	crypto::PublicKey get_spend_key_base_public_key() const { return m_spend_key_base_public_key; }
	std::vector<crypto::PublicKey> mul_by_view_secret_key(
	    const std::vector<crypto::PublicKey> &output_public_keys) const;
	bool sign_transaction() const { return false; }  // TODO - params
	bool create_sendproof() const { return false; }  // TODO - params
};

}  // namespace platform
