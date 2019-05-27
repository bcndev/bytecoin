// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Archive.hpp"
#include <iostream>
#include "CryptoNoteTools.hpp"
#include "Currency.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "crypto/crypto.hpp"
#include "platform/Time.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

using namespace cn;
using namespace platform;

static const std::string RECORDS_PREFIX = "r";
static const std::string HASHES_PREFIX  = "h";

const std::string Archive::BLOCK("b");
const std::string Archive::TRANSACTION("t");
const std::string Archive::CHECKPOINT("c");

Archive::Archive(bool read_only, const std::string &path) : m_read_only(read_only) {
#if !platform_USE_SQLITE
	try {
		m_db = std::make_unique<DB>(read_only ? platform::O_READ_EXISTING : platform::O_OPEN_ALWAYS, path);
		if (!m_db->get("$unique_id", m_unique_id)) {
			DB::Cursor cur = m_db->begin(std::string());
			if (!cur.end())
				throw std::runtime_error("Archive database format unknown version, please delete " + m_db->get_path());
			m_unique_id = common::pod_to_hex(crypto::rand<crypto::Hash>());
			m_db->put("$unique_id", m_unique_id, true);
			std::cout << "Created archive with unique id: " << m_unique_id << std::endl;
		}
		DB::Cursor cur2  = m_db->rbegin(RECORDS_PREFIX);
		m_next_record_id = cur2.end() ? 0 : 1 + common::read_varint_sqlite4(cur2.get_suffix());
	} catch (const std::exception &) {
		if (read_only)
			m_db = nullptr;
		else
			throw;
	}
#endif
	//	commit_timer.once(DB_COMMIT_PERIOD);
}

void Archive::add(const std::string &type,
    const BinaryArray &data,
    const Hash &hash,
    const std::string &source_address) {
	if (!m_db || m_read_only || source_address.empty())
		return;
	auto hash_key = HASHES_PREFIX + DB::to_binary_key(hash.data, sizeof(hash.data));
	DB::Value value;
	if (!m_db->get(hash_key, value)) {
		//		std::cout << "Adding to archive: " << type << " hash=" << hash << " size=" << data.size()
		//				  << " source_address=" << source_address << std::endl;
		m_db->put(hash_key, data, true);
	}
	api::cnd::GetArchive::ArchiveRecord rec;
	rec.timestamp      = now_unix_timestamp(&rec.timestamp_usec);
	rec.type           = type;
	rec.hash           = hash;
	rec.source_address = source_address;
	m_db->put(RECORDS_PREFIX + common::write_varint_sqlite4(m_next_record_id), seria::to_binary(rec), true);
	m_next_record_id += 1;
}

void Archive::db_commit() {
	if (!m_db || m_read_only)
		return;
	m_db->commit_db_txn();
}

void Archive::read_archive(api::cnd::GetArchive::Request &&req, api::cnd::GetArchive::Response &resp) {
	if (m_unique_id.empty())
		throw api::cnd::GetArchive::Error(
		    api::cnd::GetArchive::ARCHIVE_NOT_ENABLED, "Archive was never enabled on this node", m_unique_id);
	if (req.archive_id != m_unique_id)
		throw api::cnd::GetArchive::Error(api::cnd::GetArchive::WRONG_ARCHIVE_ID, "Archive id changed", m_unique_id);
	resp.from_record = req.from_record;
	if (resp.from_record > m_next_record_id)
		resp.from_record = m_next_record_id;
	if (req.max_count > api::cnd::GetArchive::Request::MAX_COUNT)
		req.max_count = api::cnd::GetArchive::Request::MAX_COUNT;
	if (!m_db)
		return;
	resp.records.reserve(static_cast<size_t>(req.max_count));
	for (DB::Cursor cur = m_db->begin(RECORDS_PREFIX, common::write_varint_sqlite4(resp.from_record)); !cur.end();
	     cur.next()) {
		if (resp.records.size() >= req.max_count)
			break;
		api::cnd::GetArchive::ArchiveRecord rec;
		seria::from_binary(rec, cur.get_value_array());
		resp.records.push_back(rec);
		if (req.records_only)
			continue;
		std::string str_hash = common::pod_to_hex(rec.hash);
		const auto hash_key  = HASHES_PREFIX + DB::to_binary_key(rec.hash.data, sizeof(rec.hash.data));
		if (rec.type == BLOCK) {
			if (resp.blocks.count(str_hash) == 0) {
				BinaryArray data;
				invariant(m_db->get(hash_key, data), "");
				api::cnd::GetArchive::ArchiveBlock &bl = resp.blocks[str_hash];
				RawBlock raw_block;
				seria::from_binary(raw_block, data);
				Block block(raw_block);
				bl.raw_header = block.header;
				bl.raw_transactions.reserve(block.transactions.size());
				bl.transaction_binary_sizes.reserve(block.transactions.size() + 1);
				auto coinbase_size = static_cast<uint32_t>(seria::binary_size(block.header.base_transaction));
				bl.transaction_binary_sizes.push_back(coinbase_size);
				for (size_t i = 0; i != block.transactions.size(); ++i) {
					bl.raw_transactions.push_back(static_cast<TransactionPrefix &>(block.transactions.at(i)));
					bl.transaction_binary_sizes.push_back(static_cast<uint32_t>(raw_block.transactions.at(i).size()));
				}
				bl.base_transaction_hash = get_transaction_hash(block.header.base_transaction);
			}
		}
		if (rec.type == TRANSACTION) {
			if (resp.transactions.count(str_hash) == 0) {
				BinaryArray data;
				invariant(m_db->get(hash_key, data), "");
				TransactionPrefix &tr = resp.transactions[str_hash];
				Transaction transaction;
				seria::from_binary(transaction, data);
				tr = static_cast<TransactionPrefix &>(transaction);
			}
		}
		if (rec.type == CHECKPOINT) {
			if (resp.checkpoints.count(str_hash) == 0) {
				BinaryArray data;
				invariant(m_db->get(hash_key, data), "");
				SignedCheckpoint &ch = resp.checkpoints[str_hash];
				seria::from_binary(ch, data);
			}
		}
	}
}
