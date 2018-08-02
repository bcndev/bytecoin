// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <condition_variable>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>
#include "BlockChain.hpp"
#include "CryptoNote.hpp"
#include "platform/Files.hpp"

namespace bytecoin {

class BlockChainState;
// TODO - convert all read/writes to little endian
class LegacyBlockChainReader {
	std::unique_ptr<platform::FileStream> m_items_file;
	std::unique_ptr<platform::FileStream> m_indexes_file;
	Height m_count = 0;
	std::vector<uint64_t> m_offsets;  // we artifically add offset of the end of file
	void load_offsets();

	std::thread th;
	std::mutex mu;
	std::condition_variable have_work;
	std::condition_variable prepared_blocks_ready;
	bool quit = false;

	std::map<Height, PreparedBlock> prepared_blocks;
	size_t total_prepared_data_size = 0;
	Height last_load_height         = 0;
	Height next_load_height         = 0;
	void thread_run();

public:
	// No exceptions, just return block count 0
	explicit LegacyBlockChainReader(const std::string &index_file_name, const std::string &item_file_name);
	~LegacyBlockChainReader();
	Height get_block_count() const { return m_count; }
	BinaryArray get_block_data_by_index(Height);
	PreparedBlock get_prepared_block_by_index(Height);

	bool import_blocks(BlockChainState *block_chain);  // return false when no more blocks remain

	static bool import_blockchain2(const std::string &coin_folder, BlockChainState *block_chain,
	    Height max_height = std::numeric_limits<Height>::max());
};

class LegacyBlockChainWriter {
	platform::FileStream m_items_file;
	platform::FileStream m_indexes_file;

public:
	LegacyBlockChainWriter(const std::string &index_file_name, const std::string &item_file_name, uint64_t count);
	void write_block(const bytecoin::RawBlock &raw_block);

	static bool export_blockchain2(const std::string &export_folder, const BlockChainState &block_chain);
};

}  // namespace bytecoin
