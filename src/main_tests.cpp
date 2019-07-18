// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <thread>

#include "Core/hardware/HardwareWallet.hpp"
#include "common/BIPs.hpp"
#include "common/Base58.hpp"
#include "common/CommandLine.hpp"
#include "common/Invariant.hpp"
#include "common/StringTools.hpp"
#include "platform/DB.hpp"
#include "version.hpp"

#include "../tests/crypto/benchmarks.hpp"
#include "../tests/crypto/test_crypto.hpp"
#include "../tests/hash/test_hash.hpp"
#include "../tests/json/test_json.hpp"

#ifndef __EMSCRIPTEN__
#include "../tests/blockchain/test_blockchain.hpp"
#include "../tests/wallet_file/test_wallet_file.hpp"
#include "../tests/wallet_state/test_wallet_state.hpp"
#endif

void test_bip32() {
	// TODO move this code to a proper test suite
	cn::Bip32Key master_key = cn::Bip32Key::create_master_key(
	    "sausage coast tank shrug idle hub fun amused display inquiry bone unfold fish stumble clerk skate mango pause cage glide lens armed point segment",
	    std::string{});
	cn::Bip32Key k0 = master_key.derive_key(0x8000002c);
	cn::Bip32Key k1 = k0.derive_key(0x80000300);
	cn::Bip32Key k2 = k1.derive_key(0x80000000);
	cn::Bip32Key k3 = k2.derive_key(0);
	cn::Bip32Key k4 = k3.derive_key(2);

	//	bip39
	//
	//   seed=d0cc66008a89740ea666c4b3250e5d25a63a5666a6a5f77284d33f760cff053d712b3c78b42195666dd405945b15a2724c8e7ff3b79b684ce5bd43c4cffa5528
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
}

std::string format_test_name(const std::string &name) {
	std::stringstream stream;
	const int linewidth = 70;
	stream << std::endl;
	stream << "<" << std::setw(linewidth) << std::setfill('-') << "-"
	       << ">" << std::endl;
	stream << std::setw(linewidth / 4) << std::setfill(' ') << "" << name << std::endl;
	stream << "<" << std::setw(linewidth) << std::setfill('-') << "-"
	       << ">" << std::endl;
	stream << std::endl;
	return stream.str();
}

int main(int argc, const char *argv[]) {
	std::string USAGE(
	    "Execute subsystem tests. Return code 0 means success.\n"
	    "Uses relative paths and should be run from the {PROJECT_ROOT}/build folder. "
	    "This is the default when building the project with CMake.\n"
	    "Available options (each runs corresponding test)\n");
	common::CommandLine cmd(argc, argv);

	std::map<std::string, std::function<void()>> all;

	std::string test_folder = "../tests";
#ifdef __EMSCRIPTEN__
	test_folder = "/tests";
#endif

	std::vector<std::string> crypto_function_tests{};
	all["--crypto"]    = std::bind(test_crypto, "../tests/crypto", crypto_function_tests, "", false);
	all["--bip32"]     = test_bip32;
	all["--benchmark"] = std::bind(benchmark_crypto_ops, 10000, std::ref(std::cout));
	all["--hash"]      = std::bind(test_hashes, test_folder + "/hash");
#ifndef __EMSCRIPTEN__
	all["--blockchain"]   = std::bind(test_blockchain, std::ref(cmd));
	all["--db"]           = platform::DB::run_tests;
	all["--json"]         = std::bind(test_json, test_folder + "/json");
	all["--wallet"]       = std::bind(test_wallet_file, test_folder + "/wallet_file");
	all["--wallet-state"] = std::bind(test_wallet_state, std::ref(cmd));
#endif
	for (const auto &t : all)
		USAGE += "    " + t.first + "\n";
	if (cmd.show_help(USAGE.c_str(), cn::app_version()))
		return 0;

	int found_on_cmd_line = 0;
	for (const auto &t : all) {
		if (cmd.get_bool(t.first.c_str()))
			found_on_cmd_line += 1;
	}

	if (cmd.show_errors())
		return 1;

	for (const auto &t : all)
		if (found_on_cmd_line == 0 || cmd.get_bool(t.first.c_str())) {
			std::cout << format_test_name("Running test " + t.first) << std::endl;
			t.second();
		}
	std::cout << format_test_name("Done!") << std::endl;
	return 0;
}
