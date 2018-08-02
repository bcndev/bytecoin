// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "test_blockchain.hpp"

#include <fstream>
#include <vector>
#include "Core/BlockChainState.hpp"
#include "Core/Config.hpp"
#include "Core/CryptoNoteTools.hpp"
#include "Core/Currency.hpp"
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

struct MinedBlockDesc {
	BlockTemplate block_template;
	BinaryArray binary_block_template;
	Hash hash;
	Height height = 0;
};

class TestMiner {
public:
	BlockChainState &block_chain;
	const Currency &currency;
	AccountPublicAddress address;
	crypto::CryptoNightContext cryptoContext;
	std::vector<KeyPair> checkpoint_keypairs;

	TestMiner(BlockChainState &block_chain, const Currency &currency) : block_chain(block_chain), currency(currency) {
		invariant(currency.parse_account_address_string(
		              "21mQ7KPdmLbjfpg3Coayi4hZzAEgjeL87QXGeDTHahKeJsvKHc6DoprAJmqUcLhWTUXtxCL6rQFSwEUe6NZdEoqZNpSq1iC",
		              &address),
		    "");
		std::vector<std::string> skeys{"dacb828348483011f63ebb538401b3f3d52e8ce1916278f9b189f820d1ec730e",
		    "3ab19160e48f77b41a9b7f87322542b1e977577f30886db3dce3076806709d0d",
		    "16d4d146d8ba2bbff13a4bb174b4c5d73d3ca22817a6585956a697337be26a09"};
		for (auto &&sk : skeys) {
			checkpoint_keypairs.push_back(KeyPair{});
			invariant(common::pod_from_hex(sk, checkpoint_keypairs.back().secret_key), "");
			invariant(crypto::secret_key_to_public_key(
			              checkpoint_keypairs.back().secret_key, checkpoint_keypairs.back().public_key),
			    "");
		}
	}
	MinedBlockDesc mine_block(Hash bid) {
		api::BlockHeader parent;
		invariant(block_chain.read_header(bid, &parent), "");

		BlockTemplate block;
		Difficulty difficulty = 0;
		invariant(
		    block_chain.create_mining_block_template2(&block, address, bytecoin::BinaryArray{}, &difficulty, bid), "");
		fix_merge_mining_tag(block);
		block.timestamp = parent.timestamp + currency.difficulty_target;
		block.nonce     = crypto::rand<uint32_t>();
		while (true) {
			crypto::Hash hash = get_block_long_hash(block, cryptoContext);
			if (check_hash(hash, difficulty))
				break;
			block.nonce += 1;
		}
		RawBlock rb;
		MinedBlockDesc desc{block, seria::to_binary(block), get_block_hash(block), parent.height + 1};
		return desc;
	}
	void add_mined_block(const MinedBlockDesc &desc, bool log = true) {
		RawBlock rb;
		api::BlockHeader info;
		invariant(block_chain.add_mined_block(desc.binary_block_template, &rb, &info) != BroadcastAction::BAN, "");
		if (log)
			std::cout << "---- After add_mined_block tip=" << block_chain.get_tip_height() << " : "
			          << block_chain.get_tip_bid() << std::endl;
	}
	MinedBlockDesc test_grow_chain(Hash bid, Height length) {
		MinedBlockDesc desc;
		for (Height i = 0; i != length; ++i) {
			desc = mine_block(bid);
			add_mined_block(desc, false);
			bid = desc.hash;
		}
		std::cout << "---- After test_grow_chain tip=" << block_chain.get_tip_height() << " : "
		          << block_chain.get_tip_bid() << std::endl;
		return desc;
	}
	void add_checkpoint(uint32_t key_id, uint64_t counter, Hash hash, Height height) {
		SignedCheckPoint small_checkpoint;
		small_checkpoint.height  = height;
		small_checkpoint.hash    = hash;
		small_checkpoint.key_id  = key_id;
		small_checkpoint.counter = counter;
		crypto::generate_signature(small_checkpoint.get_message_hash(), checkpoint_keypairs.at(key_id).public_key,
		    checkpoint_keypairs.at(key_id).secret_key, small_checkpoint.signature);
		invariant(block_chain.add_checkpoint(small_checkpoint, ""), "");
		std::cout << "---- After add_checkpoint tip=" << block_chain.get_tip_height() << " : "
		          << block_chain.get_tip_bid() << std::endl;
	}
};

void test_blockchain(common::CommandLine &cmd) {
	logging::ConsoleLogger logger;
	Config config(cmd);
	config.data_folder = "../tests/scratchpad";
	config.is_testnet  = true;
	bytecoin::BlockChain::DB::delete_db(config.data_folder + "/blockchain");

	Currency currency(config.is_testnet);

	BlockChainState block_chain(logger, config, currency, /*read only*/ false);

	TestMiner test_miner(block_chain, currency);

	auto middle_desc = test_miner.test_grow_chain(block_chain.get_tip().hash, 25);

	auto small_desc = test_miner.test_grow_chain(middle_desc.hash, 25);

	invariant(block_chain.get_tip_bid() == small_desc.hash, "");

	auto big_desc = test_miner.test_grow_chain(middle_desc.hash, 50);

	invariant(block_chain.get_tip_bid() == big_desc.hash, "");

	auto small_plus_1_desc = test_miner.mine_block(small_desc.hash);
	auto big_plus_1_desc   = test_miner.mine_block(big_desc.hash);

	test_miner.add_checkpoint(0, 1, small_desc.hash, small_desc.height);

	invariant(block_chain.get_tip_bid() == small_desc.hash, "");

	test_miner.add_checkpoint(0, 2, big_plus_1_desc.hash, big_plus_1_desc.height);

	invariant(block_chain.get_tip_bid() == small_desc.hash, "");

	test_miner.add_mined_block(big_plus_1_desc);

	invariant(block_chain.get_tip_bid() == big_plus_1_desc.hash, "");

	test_miner.add_checkpoint(1, 1, small_desc.hash, small_desc.height);

	invariant(block_chain.get_tip_bid() == big_plus_1_desc.hash, "");

	test_miner.add_checkpoint(2, 1, small_plus_1_desc.hash, small_plus_1_desc.height);

	invariant(block_chain.get_tip_bid() == big_plus_1_desc.hash, "");

	test_miner.add_mined_block(small_plus_1_desc);

	invariant(block_chain.get_tip_bid() == small_plus_1_desc.hash, "");

	test_miner.add_checkpoint(1, std::numeric_limits<uint64_t>::max(), Hash{}, 0);

	invariant(block_chain.get_tip_bid() == big_plus_1_desc.hash, "");
}

// Sometimes in the future we will test consistency with simple model
class TestBlockChain {
	const Currency &m_currency;
	Hash m_tip_bid;
	Height m_tip_height = Height(-1);
	struct TestBlock {
		api::BlockHeader header;

		std::bitset<64> checkpoint_key_ids;
		BlockChain::CheckPointDifficulty checkpoint_difficulty;  // (key_count-1)->max_height

		TestBlock *parent = nullptr;
		std::vector<TestBlock *> children;
	};
	std::map<Hash, TestBlock> blocks;
	std::map<uint32_t, SignedCheckPoint> checkpoints;
	std::map<uint32_t, SignedCheckPoint> stable_checkpoints;

	bool add_block(const api::BlockHeader &info) {
		auto bit = blocks.find(info.hash);
		if (bit != blocks.end())
			return true;
		auto pit = blocks.find(info.previous_block_hash);
		if (pit == blocks.end())
			return false;
		auto &block  = blocks[info.hash];
		block.header = info;
		block.parent = &pit->second;
		pit->second.children.push_back(&block);
		return true;
	}

public:
	explicit TestBlockChain(const Currency &currency) : m_currency(currency) {
		auto &block             = blocks[m_currency.genesis_block_hash];
		block.header.hash       = m_currency.genesis_block_hash;
		block.header.height     = 0;
		block.header.difficulty = 1;
		block.header.timestamp  = m_currency.genesis_block_template.timestamp;
	}
	Hash get_tip_bid() const { return m_tip_bid; }
	Height get_tip_height() const { return m_tip_height; }
	bool add_checkpoint(const SignedCheckPoint &checkpoint) { return false; }
	BroadcastAction add_block(const PreparedBlock &pb, api::BlockHeader *info) { return BroadcastAction::NOTHING; }
	BroadcastAction add_mined_block(const BinaryArray &raw_block_template,
	    RawBlock *raw_block,
	    api::BlockHeader *info) {
		return BroadcastAction::NOTHING;
	}
};
