// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "test_blockchain.hpp"

#include <fstream>
#include <vector>
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

void test_grow_chain(BlockChainState &block_chain,
    const Currency &currency,
    const AccountPublicAddress &address,
    crypto::CryptoNightContext &cryptoContext,
    Hash bid,
    Timestamp ts,
    Height length) {
	for (Height i = 0; i != length; ++i) {
		BlockTemplate block;
		Difficulty difficulty = 0;
		if (!block_chain.create_mining_block_template2(&block, address, bytecoin::BinaryArray{}, &difficulty, bid))
			throw std::runtime_error("create_mining_block_template failed");
		// fix_merge_mining_tag(block);
		block.timestamp = ts + currency.difficulty_target;
		//        templates.push_back(block);
		//        difficulties.push_back(difficulty);
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
		if (block_chain.add_mined_block(raw_block_template, &rb, &info) == BroadcastAction::BAN)
			throw std::runtime_error("add_mined_block failed");
		std::cout << "ts=" << block.timestamp << " mts=" << info.timestamp_median << " height=" << info.height
		          << " bid=" << common::pod_to_hex(info.hash) << std::endl;

		bid = info.hash;
		ts  = info.timestamp;
	}
}

void test_blockchain2(common::CommandLine &cmd) {
	logging::ConsoleLogger logger;
	Config config(cmd);
	config.data_folder = "../tests";
	bytecoin::BlockChain::DB::delete_db(config.data_folder + "/blockchain");
	Currency currency(config.is_testnet);
	BlockChainState block_chain(logger, config, currency, /*read only*/ false);
	block_chain.test_print_structure(0);
	AccountPublicAddress address;
	crypto::CryptoNightContext cryptoContext;
	if (!currency.parse_account_address_string(
	        "21mQ7KPdmLbjfpg3Coayi4hZzAEgjeL87QXGeDTHahKeJsvKHc6DoprAJmqUcLhWTUXtxCL6rQFSwEUe6NZdEoqZNpSq1iC",
	        &address))
		throw std::runtime_error("parse_account_address_string failed");
	const Timestamp ts = block_chain.get_tip().timestamp;
	test_grow_chain(block_chain, currency, address, cryptoContext, block_chain.get_tip().hash, ts, 50);

	block_chain.test_print_structure(0);

	const Height split_height = 25;
	const Timestamp split_ts  = ts + (currency.difficulty_target * split_height);
	Hash split_bid;
	block_chain.read_chain(split_height, &split_bid);
	test_grow_chain(block_chain, currency, address, cryptoContext, split_bid, split_ts, 50);

	block_chain.test_print_structure(0);
}

void test_blockchain(common::CommandLine &cmd) {
	logging::ConsoleLogger logger;
	Config config(cmd);
	config.data_folder = "../tests/scratchpad";
	bytecoin::BlockChain::DB::delete_db(config.data_folder + "/blockchain");
	Currency currency(config.is_testnet);
	BlockChainState block_chain(logger, config, currency, false);
	block_chain.test_print_structure(0);
	AccountPublicAddress address;
	crypto::CryptoNightContext cryptoContext;
	if (!currency.parse_account_address_string(
	        "21mQ7KPdmLbjfpg3Coayi4hZzAEgjeL87QXGeDTHahKeJsvKHc6DoprAJmqUcLhWTUXtxCL6rQFSwEUe6NZdEoqZNpSq1iC",
	        &address))
		throw std::runtime_error("parse_account_address_string failed");
	Timestamp ts = block_chain.get_tip().timestamp;
	std::vector<BlockTemplate> templates;
	std::vector<Difficulty> difficulties;
	for (int i = 0; i != 100; ++i) {
		BlockTemplate block;
		Difficulty difficulty = 0;
		Height height         = 0;
		if (!block_chain.create_mining_block_template(&block, address, bytecoin::BinaryArray{}, &difficulty, &height))
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
		if (block_chain.add_mined_block(raw_block_template, &rb, &info) == BroadcastAction::BAN)
			throw std::runtime_error("add_mined_block failed");
		std::cout << "ts=" << block.timestamp << " mts=" << info.timestamp_median << " height=" << info.height
		          << " bid=" << info.hash << std::endl;
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
		if (block_chain.add_mined_block(raw_block_template, &rb, &info) == BroadcastAction::BAN)
			throw std::runtime_error("add_mined_block failed");
		std::cout << "ts=" << block.timestamp << " mts=" << info.timestamp_median << " height=" << info.height
		          << " bid=" << info.hash << std::endl;
	}
	block_chain.db_commit();
	block_chain.test_print_structure(0);
	for (int i = 0; i != 50; ++i) {
		block_chain.test_prune_oldest();
		block_chain.test_print_structure(0);
	}
}
