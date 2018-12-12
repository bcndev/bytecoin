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

namespace cn {

class BlockChainState;
// TODO - convert all read/writes to explicit little endian
class LegacyBlockChainReader {
	const Currency &m_currency;
	std::unique_ptr<platform::FileStream> m_items_file;
	std::unique_ptr<platform::FileStream> m_indexes_file;
	Height m_count = 0;
	std::vector<uint64_t> m_offsets;  // we artifically add offset of the end of file
	void load_offsets();

	std::thread m_th;
	std::mutex m_mu;
	std::condition_variable m_have_work;
	std::condition_variable m_prepared_blocks_ready;
	bool m_quit = false;

	std::map<Height, PreparedBlock> m_prepared_blocks;
	std::set<Height> m_blocks_to_load;
	size_t m_total_prepared_data_size = 0;
	void thread_run();

public:
	// No exceptions, just return block count 0
	explicit LegacyBlockChainReader(
	    const Currency &currency, const std::string &index_file_name, const std::string &item_file_name);
	~LegacyBlockChainReader();
	Height get_block_count() const { return m_count; }
	BinaryArray get_block_data_by_index(Height);
	PreparedBlock get_prepared_block_by_index(Height);

	bool import_blocks(BlockChainState *block_chain);  // return false when no more blocks remain

	static bool import_blockchain2(const std::string &index_file_name, const std::string &item_file_name,
	    BlockChainState *block_chain, Height max_height = std::numeric_limits<Height>::max());
};

class LegacyBlockChainWriter {
	platform::FileStream m_items_file;
	platform::FileStream m_indexes_file;

public:
	LegacyBlockChainWriter(const std::string &index_file_name, const std::string &item_file_name, uint64_t count);
	void write_block(const RawBlock &raw_block);

	static bool export_blockchain2(
	    const std::string &index_file_name, const std::string &item_file_name, const BlockChainState &block_chain);
};

}  // namespace cn
