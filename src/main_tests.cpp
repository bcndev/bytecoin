// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <iostream>
#include <thread>

#include "common/CommandLine.hpp"
#include "version.hpp"

#include "../tests/blockchain/test_blockchain.hpp"
#include "../tests/crypto/test_crypto.hpp"
#include "../tests/hash/test_hash.hpp"
#include "../tests/json/test_json.hpp"
#include "../tests/wallet_file/test_wallet_file.hpp"
#include "../tests/wallet_state/test_wallet_state.hpp"

static const char USAGE[] =
    R"(tests. return code 0 means success

uses relative paths and should be run from bin folder

Usage:
  tests [options]

Options:
  -h --help                    Show this screen.
  -v --version                 Show version.
)";

int main(int argc, const char *argv[]) {
	common::CommandLine cmd(argc, argv);

	std::cout << "Testing Block Chain" << std::endl;
	test_blockchain(cmd);

	std::cout << "Testing Wallet State" << std::endl;
	test_wallet_state(cmd);

	std::cout << "Testing Wallet Files" << std::endl;
	test_wallet_file("../tests/wallet_file");

	std::cout << "Testing Hashes" << std::endl;
	test_hashes("../tests/hash");

	std::cout << "Testing Json" << std::endl;
	test_json("../tests/json");

	std::cout << "Testing Crypto" << std::endl;
	test_crypto("../tests/crypto/tests.txt");

	if (cmd.should_quit(USAGE, bytecoin::app_version()))
		return 0;
	return 0;
}
