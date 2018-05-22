// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <thread>
#include "Core/BlockChainState.hpp"
#include "Core/Config.hpp"
#include "Core/Difficulty.hpp"
#include "Core/TransactionExtra.hpp"
#include "crypto/crypto.hpp"
#include "logging/ConsoleLogger.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"
#include "version.hpp"

#include "../tests/crypto/test_crypto.hpp"
#include "../tests/hash/test_hash.hpp"
#include "../tests/json/test_json.hpp"
#include "../tests/wallet_file/test_wallet_file.hpp"

static const char USAGE[] =
    R"(tests. return code 0 means success

uses relative paths and should be run from bin folder

Usage:
  tests [options]

Options:
  -h --help                    Show this screen.
  -v --version                 Show version.
)";

using namespace bytecoin;

static void fix_merge_mining_tag(BlockTemplate &block) {
	if (block.major_version >= 2) {
		bytecoin::TransactionExtraMergeMiningTag mmTag;
		mmTag.depth = 0;
		block.parent_block.base_transaction.extra.clear();
		mmTag.merkle_root = get_auxiliary_block_header_hash(block);
		if (!bytecoin::append_merge_mining_tag_to_extra(block.parent_block.base_transaction.extra, mmTag))
			throw std::runtime_error("bytecoin::append_merge_mining_tag_to_extra failed");
	}
}

void test_blockchain(common::CommandLine &cmd) {
	logging::ConsoleLogger logger;
	Config config(cmd);
	config.data_folder = "../tests";
	bytecoin::BlockChain::DB::delete_db(config.data_folder + "/blockchain");
	Currency currency(config.is_testnet);
	BlockChainState block_chain(logger, config, currency);
	block_chain.test_print_structure(0);
	AccountPublicAddress address;
	crypto::CryptoNightContext cryptoContext;
	if (!currency.parse_account_address_string(
	        "21mQ7KPdmLbjfpg3Coayi4hZzAEgjeL87QXGeDTHahKeJsvKHc6DoprAJmqUcLhWTUXtxCL6rQFSwEUe6NZdEoqZNpSq1iC", address))
		throw std::runtime_error("parse_account_address_string failed");
	Timestamp ts = block_chain.get_tip().timestamp;
	std::vector<BlockTemplate> templates;
	std::vector<Difficulty> difficulties;
	for (int i = 0; i != 100; ++i) {
		BlockTemplate block;
		Difficulty difficulty = 0;
		Height height         = 0;
		if (!block_chain.create_mining_block_template(block, address, bytecoin::BinaryArray{}, difficulty, height))
			throw std::runtime_error("create_mining_block_template failed");
		fix_merge_mining_tag(block);
		block.timestamp = ts + (i + 1) * currency.difficulty_target;
		templates.push_back(block);
		difficulties.push_back(difficulty);
		block.nonce = crypto::rand<uint32_t>();
		while (true) {
			crypto::Hash hash = get_block_long_hash(block, cryptoContext);
			if (check_hash(hash, difficulty))
				break;
			block.nonce += 1;
		}
		RawBlock rb;
		api::BlockHeader info;
		BinaryArray raw_block_template = seria::to_binary(block);
		if (block_chain.add_mined_block(raw_block_template, rb, info) == BroadcastAction::BAN)
			throw std::runtime_error("add_mined_block failed");
		std::cout << "ts=" << block.timestamp << " mts=" << info.timestamp_median << " height=" << info.height
		          << " bid=" << common::pod_to_hex(info.hash) << std::endl;
	}
	// Mine alternatives
	block_chain.test_print_structure(0);
	for (int i = 0; i != 100; ++i) {
		size_t ha             = crypto::rand<size_t>() % templates.size();
		BlockTemplate block   = templates.at(ha);
		Difficulty difficulty = difficulties.at(ha);
		block.nonce           = crypto::rand<uint32_t>();
		while (true) {
			crypto::Hash hash = get_block_long_hash(block, cryptoContext);
			if (check_hash(hash, difficulty))
				break;
			block.nonce += 1;
		}
		RawBlock rb;
		api::BlockHeader info;
		BinaryArray raw_block_template = seria::to_binary(block);
		if (block_chain.add_mined_block(raw_block_template, rb, info) == BroadcastAction::BAN)
			throw std::runtime_error("add_mined_block failed");
		std::cout << "ts=" << block.timestamp << " mts=" << info.timestamp_median << " height=" << info.height
		          << " bid=" << common::pod_to_hex(info.hash) << std::endl;
	}
	block_chain.db_commit();
	block_chain.test_print_structure(0);
	for (int i = 0; i != 50; ++i) {
		block_chain.test_prune_oldest();
		block_chain.test_print_structure(0);
	}
}

int main(int argc, const char *argv[]) {
	common::CommandLine cmd(argc, argv);

	std::cout << "Testing Wallet Files" << std::endl;
	test_wallet_file("../tests/wallet_file");
	std::cout << "Testing Json" << std::endl;
	test_json("../tests/json");
	std::cout << "Testing Hashes" << std::endl;
	test_hashes("../tests/hash");
	std::cout << "Testing Crypto" << std::endl;
	test_crypto("../tests/crypto/tests.txt");
	//	test_blockchain(cmd); TODO - make this test runnable again
	if (cmd.should_quit(USAGE, bytecoin::app_version()))
		return 0;
	return 0;
}
