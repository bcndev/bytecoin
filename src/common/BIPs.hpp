// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <stdexcept>
#include <string>
#include "common/BinaryArray.hpp"

namespace cn {

class Bip32Key {
	common::BinaryArray priv_key;
	common::BinaryArray pub_key;
	common::BinaryArray chain_code;
	uint32_t key_num = 0;

	void make_pub();
	Bip32Key() = default;

public:
	class Exception : public std::runtime_error {
	public:
		using std::runtime_error::runtime_error;
	};
	static std::string create_random_bip39_mnemonic(size_t bits);
	static std::string check_bip39_mnemonic(const std::string &bip39_mnemonic);  // normalizes mnemonic
	static Bip32Key create_master_key(const std::string &bip39_mnemonic, const std::string &passphrase);
	Bip32Key derive_key(uint32_t child_num) const;
	uint32_t get_key_num() const { return key_num; }
	const common::BinaryArray get_chain_code() const { return chain_code; }
	const common::BinaryArray get_priv_key() const { return priv_key; }
	const common::BinaryArray get_pub_key() const { return pub_key; }
};

}  // namespace cn
