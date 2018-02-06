// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <thread>
#include <condition_variable>
#include "CryptoNote.hpp"
#include "BlockChain.hpp"
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
    Height last_load_height = 0;
    Height next_load_height = 0;
    void thread_run();
public:
	// No exceptions, just return block count 0
	explicit LegacyBlockChainReader(const std::string &index_file_name, const std::string &item_file_name);
	~LegacyBlockChainReader();
	Height get_block_count() const { return m_count; }
	BinaryArray get_block_data_by_index(Height);
	PreparedBlock get_prepared_block_by_index(Height);

	bool import_blocks(BlockChainState &block_chain, Height count);  // return false when no more blocks remain

	static bool import_blockchain2(const std::string &coin_folder, BlockChainState &block_chain);
};

class LegacyBlockChainWriter {
	platform::FileStream m_items_file;
	platform::FileStream m_indexes_file;
public:
	LegacyBlockChainWriter(const std::string &index_file_name, const std::string &item_file_name, uint64_t count);
	void write_block(const bytecoin::RawBlock &raw_block);

	static bool export_blockchain2(const std::string &export_folder, BlockChainState &block_chain);
};

}  // namespace bytecoin
