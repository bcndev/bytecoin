// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <iostream>
#include <thread>

#include "common/BIPs.hpp"
#include "common/CommandLine.hpp"
#include "common/Invariant.hpp"
#include "common/StringTools.hpp"
#include "platform/DB.hpp"
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

	std::cout << "Testing Wallet State" << std::endl;
	test_wallet_state(cmd);

	cn::Bip32Key master_key = cn::Bip32Key::create_master_key(
	    "sausage coast tank shrug idle hub fun amused display inquiry bone unfold fish stumble clerk skate mango pause cage glide lens armed point segment",
	    std::string());
	cn::Bip32Key k0 = master_key.derive_key(0x8000002c);
	cn::Bip32Key k1 = k0.derive_key(0x80000300);
	cn::Bip32Key k2 = k1.derive_key(0x80000000);
	cn::Bip32Key k3 = k2.derive_key(0);
	cn::Bip32Key k4 = k3.derive_key(2);

	//	bip39
	// seed=d0cc66008a89740ea666c4b3250e5d25a63a5666a6a5f77284d33f760cff053d712b3c78b42195666dd405945b15a2724c8e7ff3b79b684ce5bd43c4cffa5528
	//	bip39 master chain code=9fe854cc0cbf704f8eeef3f2b61176ca2e00504a38c791d49b55e2fdcb7218bc
	//	bip39 master key=aae196e2b5bb55d152fbdf0e9583bbd16505bbae1bcb6fd19368363965afd284
	//	pub_key=03e28d0b5e906ea2aefc19420dd3a357b6bcf7e4c27b1788283f829ae060fbffa3
	//	chain code=d760d20ed394f2b7d71ee2d9d48628b53ca7775f3d938597bc9c5b23464309ec
	//	priv_key=4445ee9af9d19e5c88c9cc26a9668d8316a2b7b51468a4d01e9bafa162efe6b9
	//	pub_key=02fab90dee1b41cfb0d00dab79a777b3685f64ea8108f7b1aab99ff1533fc0a9e5
	//	chain code=7328c2df4a5882aa79f32fb3a7680b44106b1579a5a4b5140477c0ea13bec4fe
	//	priv_key=3b3d34d03a8777c0e63ed36237c1e28803cf5128e4de3085becb952f19b4c357
	//	pub_key=0374914b04e8d7a216e1ee311a907b5f2f98e028dfd1f50f17d6f240eda91845f0
	//	chain code=1a788c76c7c4ccd0f45db963936a067a636b20a0fd8b151835d86bf63ce9f209
	//	priv_key=d30b6b4a74a4c35d5035e463b383ec9afd063a930b46215d5047e0cdc4df7456
	//	pub_key=025ea990407a5364f3ae4d2870d9320b9b8e6c8a717a0eb901e3e0202617ccae40
	//	chain code=19424a7a78cc723cddcf6e68c24beff4e2eceadc1a64a6ebd95da8e728dc7359
	//	priv_key=84234ef942b01e01110037d5a6aa8a5f2452bd79ea97066a83497370eae7f689
	//	pub_key=02603f3ecf4a35ad071afe019dec00cd35bd4f21b5dc2886c4102a8032f79c54e2
	//	chain code=cb2c6daa6205f9f6fb71a0cb855ba9169e6784adbb4d280ecff4b4f734a3102c
	//	priv_key=897bbe02c75ec6f982d656985a4cbf5ef9cf423a7bd5a5edf9d1a69e1e650b6a
	//	pub_key=02482087feeba3e891e628ca66224ccd90eae8855ec15eed1bdd46d7163b935927
	invariant(
	    common::to_hex(k4.get_priv_key()) == "897bbe02c75ec6f982d656985a4cbf5ef9cf423a7bd5a5edf9d1a69e1e650b6a", "");
	invariant(
	    common::to_hex(k4.get_chain_code()) == "cb2c6daa6205f9f6fb71a0cb855ba9169e6784adbb4d280ecff4b4f734a3102c", "");

	std::cout << "Testing Crypto" << std::endl;
	test_crypto("../tests/crypto/tests.txt");

	std::cout << "Testing Hashes" << std::endl;
	test_hashes("../tests/hash");

	std::cout << "Testing Wallet Files" << std::endl;
	test_wallet_file("../tests/wallet_file");

	std::cout << "Testing Block Chain" << std::endl;
	test_blockchain(cmd);

	std::cout << "Testing DB" << std::endl;
	platform::DB::run_tests();

	std::cout << "Testing Json" << std::endl;
	test_json("../tests/json");

	if (cmd.should_quit(USAGE, cn::app_version()))
		return 0;
	return 0;
}
