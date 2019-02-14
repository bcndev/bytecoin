// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
//#include <boost/program_options.hpp>
#include <map>

#include "Core/hardware/HardwareWallet.hpp"
#include "common/BIPs.hpp"
#include "common/Base58.hpp"
#include "common/CommandLine.hpp"
#include "common/Invariant.hpp"
#include "common/StringTools.hpp"
#include "platform/DB.hpp"
#include "version.hpp"

#include "../tests/blockchain/test_blockchain.hpp"
#include "../tests/crypto/benchmarks.hpp"
#include "../tests/crypto/test_crypto.hpp"
#include "../tests/hash/test_hash.hpp"
#include "../tests/json/test_json.hpp"
#include "../tests/wallet_file/test_wallet_file.hpp"
#include "../tests/wallet_state/test_wallet_state.hpp"

/*struct MemoryRecord {
    std::string key;

    std::string parent_key;
    std::string children_key[2];
    std::string value;
    bool dirty = false;
    Hash hash;
    size_t level = 0;
};

class SignedState {
//	platform::DB m_db;
    std::string mega_root;
    std::map<std::string, MemoryRecord> mem;
    void make_dirty(const std::string & key){
        MemoryRecord & rec = mem.at(key);
        if(rec.dirty)
            return;
        rec.dirty = true;
        if(rec.parent_key.empty())
            return;
        make_dirty(rec.parent_key);
    }
    std::string jsw_insert(const std::string & root, const std::string &key, const std::string &value){
        if(root.empty()){
            MemoryRecord & rec = mem[key];
            rec.key = key;
            rec.dirty = true;
            rec.value = value;
            rec.level = 1;
            return key;
        }
        MemoryRecord & root_rec = mem.at(root);
        int dir = root_rec.value < value;
        root_rec.children_key.at(dir) = jsw_insert(root_rec.children_key.at(dir), key, value);
    }
public:
//	explicit SignedState(const std::string &full_path):m_db(platform::O_OPEN_ALWAYS, full_path){
//	}
    explicit SignedState(){

    }
    void commit_db_txn(){

    }
    void put(const std::string &key, const std::string &value, bool nooverwrite){
        auto mit = mem.find(key);
        if(mit != mem.end()){
            if(nooverwrite)
                throw std::runtime_error("nooverwrite");
            mit->second.value = value;
            make_dirty(key);
            return;
        }
        mega_root = jsw_insert(mega_root, key, value);
    }
    bool get(const std::string &key, std::string &value) const{

    }
    void del(const std::string &key, bool mustexist){

    }
};*/

void test_signed_state() {}

// namespace po = boost::program_options;

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

void test_bip32();

int main(int argc, const char *argv[]) {
	auto co = cn::hardware::HardwareWallet::get_connected();

	test_signed_state();
	/*    const std::string USAGE(
	            "Execute subsystem tests. Return code 0 means success.\n"
	            "Uses relative paths and should be run from the {PROJECT_ROOT}/bin folder. "
	            "This is the default when building the project with CMake.\n"
	    );

	    po::options_description all_options("Available options");

	    po::options_description test_flags("Flags to test individual subsystems. If none are set, test everything");
	    test_flags.add_options()
	            ("crypto", "test cryptographic primitives")
	            ("benchmark", "run cryptography benchmarks")
	            ("blockchain", "test blockchain subsystem")
	            ("db", "test database operations")
	            ("json", "test JSON (de-)serialization")
	            ("hash", "test hash calculations")
	            ("wallet", "test wallet file operations")
	            ("wallet-state", "test wallet state integrity");

	//    test_flags.add_options()
	//            ("crypto", po::bool_switch(), "test cryptographic primitives")
	//            ("benchmark", po::bool_switch(), "run cryptography benchmarks")
	//            ("blockchain", po::bool_switch(), "test blockchain subsystem")
	//            ("db", po::bool_switch(), "test database operations")
	//            ("json", po::bool_switch(), "test JSON (de-)serialization")
	//            ("hash", po::bool_switch(), "test hash calculations")
	//            ("wallet", po::bool_switch(), "test wallet file operations")
	//            ("wallet-state", po::bool_switch(), "test wallet state integrity");
	//
	    po::options_description help_messages("Print help message and quit");
	    help_messages.add_options()
	            ("help,h", "display this help message and quit")
	            ("version,v", "show test module version");

	    all_options.add(test_flags).add(help_messages);


	    po::variables_map vm;
	    po::store(po::parse_command_line(argc, argv, all_options), vm);
	    vm.notify();

	    if (vm.count("help") + vm.count("version")) {
	        std::cout << "Bytecoin version " << cn::app_version() << std::endl;
	        if (vm.count("help")) {
	            std::cout << USAGE << std::endl;
	            std::cout << all_options << std::endl;
	        }
	        return 0;
	    }

	//    if (vm.count("crypto") || vm.empty()) {
	std::cout << format_test_name("Testing Crypto...") << std::endl;
	test_crypto("../tests/crypto/tests.txt");
	//    }

	    if (vm.count("benchmark") || vm.empty()) {
	        std::cout << format_test_name("Running cryptographic primitives benchmark...") << std::endl;
	        benchmark_crypto_ops(10000, std::cout);
	    }

	    common::CommandLine cmd(argc, argv);

	    if (vm.count("wallet-state") || vm.empty()) {
	        std::cout << format_test_name("Testing Wallet State...") << std::endl;
	        test_wallet_state(cmd);
	    }

	    if (vm.count("hash") || vm.empty()) {
	        std::cout << format_test_name("Testing Hashes...") << std::endl;
	        test_hashes("../tests/hash");
	    }

	    if (vm.count("wallet") || vm.empty()) {
	        std::cout << format_test_name("Testing Wallet Files...") << std::endl;
	        test_wallet_file("../tests/wallet_file");
	    }

	    if (vm.count("blockchain") || vm.empty()) {
	        std::cout << format_test_name("Testing Block Chain...") << std::endl;
	        test_blockchain(cmd);
	    }

	    if (vm.count("db") || vm.empty()) {
	        std::cout << format_test_name("Testing DB...") << std::endl;
	        platform::DB::run_tests();
	    }

	    if (vm.count("json") || vm.empty()) {
	        std::cout << format_test_name("Testing Json...") << std::endl;
	        test_json("../tests/json");
	    }
	*/
	std::string USAGE(
	    "Execute subsystem tests. Return code 0 means success.\n"
	    "Uses relative paths and should be run from the {PROJECT_ROOT}/build folder. "
	    "This is the default when building the project with CMake.\n"
	    "Available options (each runs corresponding test)\n");
	common::CommandLine cmd(argc, argv);

	std::map<std::string, std::function<void()>> all;

	all["--crypto"]       = std::bind(test_crypto, "../tests/crypto/tests.txt");
	all["--bip32"]        = test_bip32;
	all["--benchmark"]    = std::bind(benchmark_crypto_ops, 10000, std::ref(std::cout));
	all["--blockchain"]   = std::bind(test_blockchain, std::ref(cmd));
	all["--db"]           = platform::DB::run_tests;
	all["--json"]         = std::bind(test_json, "../tests/json");
	all["--hash"]         = std::bind(test_hashes, "../tests/hash");
	all["--wallet"]       = std::bind(test_wallet_file, "../tests/wallet_file");
	all["--wallet-state"] = std::bind(test_wallet_state, std::ref(cmd));

	int found_on_cmd_line = 0;
	for (const auto &t : all) {
		USAGE += "    " + t.first + "\n";
		if (cmd.get_bool(t.first.c_str()))
			found_on_cmd_line += 1;
	}

	if (int r = cmd.should_quit(USAGE.c_str(), cn::app_version()))
		return r == 1 ? 0 : -1;

	for (const auto &t : all)
		if (found_on_cmd_line == 0 || cmd.get_bool(t.first.c_str())) {
			std::cout << format_test_name("Running test " + t.first) << std::endl;
			t.second();
		}
	std::cout << format_test_name("Done!") << std::endl;
	return 0;
}

void test_bip32() {
	// TODO move this code to a proper test suite
	cn::Bip32Key master_key = cn::Bip32Key::create_master_key(
	    "sausage coast tank shrug idle hub fun amused display inquiry bone unfold fish stumble clerk skate mango pause cage glide lens armed point segment",
	    std::string());
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

////[.. 00] ffffff < prefix 111111111111111111
////[.. 01] ffffff < prefix 111111111111111111
//
////[.. k-1] ffffff <  prefix 111111111111111111
////[.. k  ] ffffff >= prefix 111111111111111111
//
// bool interactive_find_mi(const std::string &prefix, BinaryArray & tag){
//	tag.push_back(0);
//	for(size_t to = 0; to < 0x100; ++to){
//		tag.back() = to;
//		BinaryArray buf = tag;
//		append(buf, BinaryArray(64, 0xff));
//		std::string a1 = encode(buf);
//		if(a1.substr(0, prefix.size()) >= prefix){
//			if(tag.size() >= 16){
//				std::cout << "mi: " << common::to_hex(tag) << std::endl;
//				return true;
//			}
//			return interactive_find_mi(prefix, tag);
//		}
//	}
//	return false;
//}
//
////[.. ff] 000000 substr > prefix
////[.. fe] 000000 > prefix zzzzzzzzzzzzzzzzzz
//
////[.. k+1] 000000 >  prefix zzzzzzzzzzzzzzzzzz
////[.. k  ] 000000 <= prefix zzzzzzzzzzzzzzzzzz
//
// bool interactive_find_ma(const std::string &prefix, BinaryArray & tag){
//	tag.push_back(0);
//	for(size_t to = 0x100; to-- > 1;){
//		tag.back() = to;
//		BinaryArray buf = tag;
//		append(buf, BinaryArray(64, 0));
//		std::string a1 = encode(buf);
//		if(a1.substr(0, prefix.size()) <= prefix){
//			if(tag.size() >= 16){
//				std::cout << "ma: " << common::to_hex(tag) << std::endl;
//				return true;
//			}
//			return interactive_find_ma(prefix, tag);
//		}
//	}
//	return false;
//}
//
// bool inc_before_pos(BinaryArray & tag, size_t pos){
//	size_t carry = 1;
//	for(size_t j = pos; j-- > 0; )
//		if(tag.at(j) + carry == 0x100){
//			tag.at(j) = 0;
//			carry = 1;
//		}else{
//			tag.at(j) += carry;
//			carry = 0;
//		}
//	return carry == 0;
//}
//
// bool find_shortest_varint_between(BinaryArray & tag, size_t max_depth, const BinaryArray & ma){
//	if(tag >= ma)
//		return false;
//	for(size_t i = 0; i != max_depth; ++i){
//		if(i == max_depth - 1 && tag.at(i) == 0){
//			tag.at(i) = 1;
//		}
//		if(i == max_depth - 1 && tag.at(i) >= 0x80){
//			tag.at(i) = 1;
//			for(size_t j = i + 1; j != tag.size(); ++j)
//				tag.at(j) = 0;
//			if(!inc_before_pos(tag, i))
//				return false;
//		}
//		if(i != max_depth - 1 && tag.at(i) < 0x80){
//			tag.at(i) = 0x80;
//			for(size_t j = i + 1; j != tag.size(); ++j)
//				tag.at(j) = 0;
//		}
//	}
//	if(tag >= ma)
//		return false;
//	return true;
//}
//
////	for(; from < 0x100; ++from){
////		invariant (common::read_varint<64>(be, en, &utag) > 0, "");
////		auto a1 = encode_addr(utag, BinaryArray(64, 0));
////		auto a2 = encode_addr(utag, BinaryArray(64, 0xff));
////		if (a1.substr(0, prefix.size()) != prefix || a2.substr(0, prefix.size()) != prefix )// || a1.substr(0, 4) !=
/// a2.substr(0, 4)) /			continue; /		std::cout << a1.substr(0, 18) << "..." << a1.substr(0, 18) << " " <<utag
///<< " " << common::to_hex(tag) << std::endl; /	} /	tag.pop_back(); /	return false;
////}
//
// uint64_t find_tag(const std::string &prefix) {
//	BinaryArray interactive_mi;
//	BinaryArray interactive_ma;
//	if(!interactive_find_mi(prefix, interactive_mi)){
//		std::cout << "prefix too small" << std::endl;
//		return 0;
//	}
//	if(!interactive_find_ma(prefix, interactive_ma)){
//		std::cout << "prefix too big" << std::endl;
//		return 0;
//	}
//	for(size_t varintsize = 1; varintsize != 10; ++varintsize){
//		BinaryArray tag = interactive_mi;
//		BinaryArray ma = interactive_ma;
//		for(size_t j = varintsize; j != tag.size(); ++j){
//			tag.at(j) = 0;
//			ma.at(j) = 0;
//		}
//		if(!inc_before_pos(tag, varintsize))
//			continue;
//		if(find_shortest_varint_between(tag, varintsize, ma)){
//			while(true){
//				uint64_t utag = 0;
//				unsigned char *be = tag.data();
//				unsigned char *en = tag.data() + tag.size();
//				if (common::read_varint<64>(be, en, &utag) <= 0)
//					continue;
//				auto a1 = encode_addr(utag, BinaryArray(64, 0));
//				auto a2 = encode_addr(utag, BinaryArray(64, 0xff));
//				std::cout << a1.substr(0, 18) << " - " << a2.substr(0, 18) << " " << utag << " " << common::to_hex(tag)
//<< std::endl; 				if(!inc_before_pos(tag, varintsize)) 					break;
// if(!find_shortest_varint_between(tag, varintsize, interactive_ma)) 					break;
//			}
//			break;
//		}
//	}
//	invariant(prefix.size() <= full_encoded_block_size - 1, "");
//	std::string good;
//	bool first_good = false;
//	BinaryArray result_all;
//	for(size_t i = 0; i != alphabet_size; ++i){
//		std::string str1 = prefix + std::string(full_encoded_block_size - prefix.size(), alphabet[i]);
////		std::string str2 = prefix + std::string(full_encoded_block_size - prefix.size(), alphabet[alphabet_size -
/// 1]);
//		uint8_t result1[full_block_size]{};
//		if(!decode_block(str1.data(), str1.size(), result1))
//			continue;
//		if(!first_good){
//			first_good = true;
//			result_all.assign(std::begin(result1), std::end(result1));
//			continue;
//		}
//		size_t pre = 0;
//		for(; pre != result_all.size(); ++pre)
//			if(result_all[pre] != result1[pre])
//				break;
//		result_all.resize(pre);
//	}
//	if( !first_good || result_all.empty() ){
//		std::cout << "Prefix too short" << std::endl;
//		return 0;
//	}
//	std::cout << "Common bytes are: " << common::to_hex(result_all) << std::endl;
//	std::cout << "Possible prefixes" << std::endl;
//	std::set<std::string> used;
//	uint64_t utag = 0;
//	//	for(size_t j = 0xe1; j != 0xe5; ++j)
//	for (size_t i = 0x0; i != 0x80; ++i) {
//		//	BinaryArray tag{0xce, 0xf5, uint8_t(j), uint8_t(i)};
//		BinaryArray tag{0xce, 0xf5, 0xe2, 0x80, 0x91, 0xdd, uint8_t(i)};
//		auto a1 = encode_addr(utag, BinaryArray(64, 0));
//		auto a2 = encode_addr(utag, BinaryArray(64, 0xff));
////		std::cout << a1.substr(0, 18) << " " << a2.substr(0, 18) << std::endl;
//		//		if(a1.substr(0, 4) != "bcn1" || a1.substr(0, 5) != a2.substr(0, 5))
//		//			continue;
//		if (a1.substr(0, prefix.size()) != prefix || a2.substr(0, prefix.size()) != prefix )// || a1.substr(0, 4) !=
// a2.substr(0, 4)) 			continue;
//		//	std::cout << "tag= " << common::to_hex(tag) << std::endl;
//		//	std::cout << "address min= " << a1 << std::endl;
//		//	std::cout << "address max= " << a2 << std::endl;
////		if (!used.insert(a2.substr(0, prefix.size())).second)
////			continue;
//		std::cout << a2.substr(0, prefix.size()) << " - " << a2.substr(0, 18) << "... tag=" << utag
//		          << " varintdata=" << common::to_hex(tag) << std::endl;
//	}
//	return utag;
//}
