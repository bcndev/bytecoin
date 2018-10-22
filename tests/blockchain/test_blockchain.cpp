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
		Height height         = 0;
		block_chain.create_mining_block_template(address, BinaryArray{}, &block, &difficulty, &height, bid);
		set_solo_mining_tag(block);
		block.parent_block.timestamp = parent.timestamp + currency.difficulty_target;
		block.timestamp              = block.parent_block.timestamp;
		block.parent_block.nonce     = crypto::rand<uint32_t>();
		block.nonce                  = block.parent_block.nonce;
		auto body_proxy              = get_body_proxy_from_template(block);
		while (true) {
			BinaryArray ba = currency.get_block_long_hashing_data(block, body_proxy);
			Hash hash      = cryptoContext.cn_slow_hash(ba.data(), ba.size());
			if (check_hash(hash, difficulty))
				break;
			block.parent_block.nonce += 1;
			block.nonce = block.parent_block.nonce;
		}
		RawBlock rb;
		MinedBlockDesc desc{block, seria::to_binary(block), get_block_hash(block, body_proxy), parent.height + 1};
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
		SignedCheckpoint small_checkpoint;
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
	config.net         = "test";
	BlockChain::DB::delete_db(config.data_folder + "/blockchain");

	std::cout << "Point 1" << std::endl;
	Currency currency(config.net);

	std::cout << "Point 2" << std::endl;
	BlockChainState block_chain(logger, config, currency, /*read only*/ false);

	std::cout << "Point 3" << std::endl;
	TestMiner test_miner(block_chain, currency);

	std::cout << "Point 4" << std::endl;
	auto middle_desc = test_miner.test_grow_chain(block_chain.get_tip().hash, 25);

	std::cout << "Point 5" << std::endl;
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
		BlockChain::CheckpointDifficulty checkpoint_difficulty;  // (key_count-1)->max_height

		TestBlock *parent = nullptr;
		std::vector<TestBlock *> children;
	};
	std::map<Hash, TestBlock> blocks;
	std::map<uint32_t, SignedCheckpoint> checkpoints;
	std::map<uint32_t, SignedCheckpoint> stable_checkpoints;

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
	bool add_checkpoint(const SignedCheckpoint &checkpoint) { return false; }
	BroadcastAction add_block(const PreparedBlock &pb, api::BlockHeader *info) { return BroadcastAction::NOTHING; }
	BroadcastAction add_mined_block(const BinaryArray &raw_block_template,
	    RawBlock *raw_block,
	    api::BlockHeader *info) {
		return BroadcastAction::NOTHING;
	}
};
