// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "BlockChainFileFormat.hpp"
#include "BlockChainState.hpp"
#include "common/Math.hpp"
#include "platform/PathTools.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace common;
using namespace cn;

// Example
//	LegacyBlockChainReader reader(import_path + "/blockindexes.bin", import_path + "/blocks.bin");
//	std::cout << "Importing blocks count=" << reader.get_block_count() << std::endl;
//	for(Height h = 0; h != reader.get_block_count(); ++h){
//		PreparedBlock pb = reader.get_prepared_block_by_index(h);
//		std::cout << "Block tx count=" << pb.block.transactions.size() << std::endl;
//	}

const bool multicore = true;

LegacyBlockChainReader::LegacyBlockChainReader(const Currency &currency,
    const std::string &index_file_name,
    const std::string &item_file_name)
    : m_currency(currency) {
	try {
		m_indexes_file = std::make_unique<platform::FileStream>(index_file_name, platform::O_READ_EXISTING);
		m_items_file   = std::make_unique<platform::FileStream>(item_file_name, platform::O_READ_EXISTING);

		m_indexes_file->seek(0, SEEK_END);
		uint64_t m_indexesFileSize = m_indexes_file->tellp();
		m_indexes_file->seek(0, SEEK_SET);
		uint64_t max_hei  = (m_indexesFileSize - sizeof(uint64_t)) / sizeof(uint32_t);
		uint64_t read_hei = 0;
		m_indexes_file->read(reinterpret_cast<char *>(&read_hei), sizeof(uint64_t));
		m_count = common::integer_cast<Height>(std::min(read_hei, max_hei));
	} catch (const std::runtime_error &) {
	}
}

LegacyBlockChainReader::~LegacyBlockChainReader() {
	{
		std::unique_lock<std::mutex> lock(m_mu);
		m_quit = true;
		m_have_work.notify_all();
	}
	if (m_th.joinable())
		m_th.join();
}

void LegacyBlockChainReader::load_offsets() {
	if (m_count == 0 || !m_offsets.empty())
		return;
	uint64_t pos = 0;
	try {
		m_items_file->seek(0, SEEK_END);
		uint64_t m_itemsFileSize = m_items_file->tellp();
		std::vector<uint32_t> item_sizes(m_count);
		m_indexes_file->read(reinterpret_cast<char *>(item_sizes.data()), m_count * sizeof(uint32_t));
		for (size_t i = 0; i < item_sizes.size(); ++i) {
			m_offsets.emplace_back(pos);
			pos += item_sizes[i];
			if (pos > m_itemsFileSize)  // index offset outside item file
				return;
		}
	} catch (const std::runtime_error &) {
	}
	m_offsets.emplace_back(pos);
}

BinaryArray LegacyBlockChainReader::get_block_data_by_index(Height i) {
	load_offsets();
	if (i + 1 >= m_offsets.size())
		return BinaryArray{};
	try {
		size_t si = common::integer_cast<size_t>(m_offsets.at(i + 1) - m_offsets.at(i));
		m_items_file->seek(m_offsets.at(i), SEEK_SET);
		BinaryArray data_cache(si);
		m_items_file->read(reinterpret_cast<char *>(data_cache.data()), si);
		return data_cache;
	} catch (const std::runtime_error &) {
		return BinaryArray{};
	}
}

const size_t MAX_PRELOAD_BLOCKS = 100;
// const size_t MAX_PRELOAD_TOTAL_SIZE = 50 * 1024 * 1024;

void LegacyBlockChainReader::thread_run() {
	while (true) {
		Height to_load = 0;
		{
			std::unique_lock<std::mutex> lock(m_mu);
			if (m_quit)
				return;
			if (m_blocks_to_load.empty()) {
				m_have_work.wait(lock);
				continue;
			}
			to_load = *m_blocks_to_load.begin();
		}
		BinaryArray rba = get_block_data_by_index(to_load);
		PreparedBlock pb(std::move(rba), m_currency, nullptr);
		{
			std::unique_lock<std::mutex> lock(m_mu);
			m_blocks_to_load.erase(to_load);
			m_total_prepared_data_size += pb.block_data.size();
			m_prepared_blocks[to_load] = std::move(pb);
			m_prepared_blocks_ready.notify_all();
		}
	}
}

PreparedBlock LegacyBlockChainReader::get_prepared_block_by_index(Height height) {
	load_offsets();
	if (!multicore) {
		BinaryArray rba = get_block_data_by_index(height);
		PreparedBlock pb(std::move(rba), m_currency, nullptr);
		return pb;
	}
	{
		std::unique_lock<std::mutex> lock(m_mu);
		if (!m_th.joinable())
			m_th = std::thread(&LegacyBlockChainReader::thread_run, this);
		for (Height i = height; i != height + MAX_PRELOAD_BLOCKS; ++i) {
			if (m_prepared_blocks.count(i) == 0)
				m_blocks_to_load.insert(i);
		}
		m_have_work.notify_all();
	}
	while (true) {
		std::unique_lock<std::mutex> lock(m_mu);
		auto pit = m_prepared_blocks.find(height);
		if (pit == m_prepared_blocks.end()) {
			m_prepared_blocks_ready.wait(lock);
			continue;
		}
		PreparedBlock result = std::move(pit->second);
		pit                  = m_prepared_blocks.erase(pit);
		m_total_prepared_data_size -= result.block_data.size();
		return result;
	}
}

bool LegacyBlockChainReader::import_blocks(BlockChainState *block_chain) {
	try {
		auto idea_start = std::chrono::high_resolution_clock::now();
		// size_t bs_count = std::min(block_chain.get_tip_height() + 1 + count, get_block_count());
		while (block_chain->get_tip_height() + 1 < get_block_count()) {
			BinaryArray rba = get_block_data_by_index(block_chain->get_tip_height() + 1);
			PreparedBlock pb(std::move(rba), m_currency, nullptr);
			api::BlockHeader info;
			if (!block_chain->add_block(pb, &info, "blocks_file")) {
				std::cout << "block_chain.add_block !BROADCAST_ALL block=" << block_chain->get_tip_height() + 1
				          << std::endl;
				block_chain->db_commit();
				return false;
			}
			auto idea_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			    std::chrono::high_resolution_clock::now() - idea_start);
			if (idea_ms.count() > 200)  // import in chunks of 0.2 seconds
				break;
		}
	} catch (const std::exception &ex) {
		std::cout << "Exception while importing blockchain file, what=" << common::what(ex) << std::endl;
		return false;
	} catch (...) {
		std::cout << "Unknown exception while importing blockchain file" << std::endl;
		return false;
	}
	return block_chain->get_tip_height() + 1 < get_block_count();  // Not finished
}

bool LegacyBlockChainReader::import_blockchain2(const std::string &index_file_name, const std::string &item_file_name,
    BlockChainState *block_chain, Height max_height) {
	auto idea_start    = std::chrono::high_resolution_clock::now();
	Height start_block = 0;
	try {
		LegacyBlockChainReader reader(block_chain->get_currency(), index_file_name, item_file_name);
		if (reader.get_block_count() == 0)
			return true;
		const size_t import_height = std::min(max_height, reader.get_block_count() - 1);
		if (block_chain->get_tip_height() >= import_height) {
			//		std::cout << "Skipping block chain import - we have more blocks than "
			//		             "blocks.bin tip_height="
			//		          << block_chain->get_tip_height() << " bs_count=" << bs_count << std::endl;
			return true;
		}
		std::cout << "Importing blocks up to height " << import_height << std::endl;
		start_block = block_chain->get_tip_height();
		//	api::BlockHeader prev_info;
		while (block_chain->get_tip_height() < import_height) {
			PreparedBlock pb = reader.get_prepared_block_by_index(block_chain->get_tip_height() + 1);
			api::BlockHeader info;
			if (!block_chain->add_block(pb, &info, "blocks_file")) {
				std::cout << "block_chain.add_block !BROADCAST_ALL block=" << block_chain->get_tip_height() + 1
				          << std::endl;
				block_chain->db_commit();
				return false;
			}
			//		if (block_chain->get_tip_height() % 50000 == 0)
			//			block_chain->db_commit();
			// ts_file << info.timestamp << "\t" << info.timestamp_median << "\t" <<
			// info.timestamp_unlock << "\t"
			//		        << int64_t(info.timestamp) -
			// int64_t(prev_info.timestamp) << "\t"
			//		        << int64_t(info.timestamp_median) -
			// int64_t(prev_info.timestamp_median) << "\t"
			//		        << int64_t(info.timestamp) -
			// int64_t(info.timestamp_median) << std::endl;
			//		prev_info = info;
			//		if (block_chain->get_tip_height() == 1370000)  // 1370000
			//			break;
		}
	} catch (const std::exception &ex) {
		std::cout << "Exception while importing blockchain file, what=" << common::what(ex) << std::endl;
		return false;
	} catch (...) {
		std::cout << "Unknown exception while importing blockchain file" << std::endl;
		return false;
	}
	block_chain->db_commit();
	auto idea_ms =
	    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - idea_start);
	std::cout << "Import blocks " << start_block << ":" << block_chain->get_tip_height()
	          << " seconds=" << double(idea_ms.count()) / 1000 << std::endl;
	return true;
}

LegacyBlockChainWriter::LegacyBlockChainWriter(const std::string &index_file_name,
    const std::string &item_file_name,
    uint64_t count)
    : m_items_file(item_file_name, platform::O_CREATE_ALWAYS)
    , m_indexes_file(index_file_name, platform::O_CREATE_ALWAYS) {
	m_indexes_file.write(&count, sizeof(count));
}

void LegacyBlockChainWriter::write_block(const RawBlock &raw_block) {
	BinaryArray ba = seria::to_binary(raw_block);
	m_items_file.write(ba.data(), ba.size());
	uint32_t si = static_cast<uint32_t>(ba.size());
	m_indexes_file.write(&si, sizeof si);
}

bool LegacyBlockChainWriter::export_blockchain2(const std::string &index_file_name, const std::string &item_file_name,
    const BlockChainState &block_chain, Height max_height) {
	auto idea_start = std::chrono::high_resolution_clock::now();
	std::cout << "Start exporting blocks" << std::endl;
	LegacyBlockChainWriter writer(index_file_name, item_file_name, block_chain.get_tip_height() + 1);
	for (Height ha = 0; ha != block_chain.get_tip_height() + 1; ++ha) {
		if (ha >= max_height)
			break;
		Hash bid{};
		BinaryArray block_data;
		RawBlock raw_block;
		if (!block_chain.get_chain(ha, &bid) || !block_chain.get_block(bid, &block_data, &raw_block))
			throw std::runtime_error("block_chain.get_block failed");
		writer.write_block(raw_block);
		if (ha % 10000 == 0)
			std::cout << "Exporting block " << ha << "/" << block_chain.get_tip_height() << std::endl;
		//		Block block(raw_block);
		//		if(block.header.is_merge_mined() && block.header.root_block.base_transaction.version >= 2)
		//			std::cout << "Base transaction with strange version found, height=" << ha << " version=" <<
		// block.header.root_block.base_transaction.version << std::endl;
		//		for (auto &&tr : block.transactions) {
		//			for (auto &&input : tr.inputs)
		//				if (input.type() == typeid(InputKey)) {
		//					const InputKey &in = boost::get<InputKey>(input);
		//				}
		//		}
	}
	auto idea_ms =
	    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - idea_start);
	std::cout << "Last exported block " << block_chain.get_tip_height() << " seconds=" << double(idea_ms.count()) / 1000
	          << std::endl;
	return true;
}
