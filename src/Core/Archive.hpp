// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "platform/DB.hpp"
#include "rpc_api.hpp"

namespace cn {

class Archive {
	const bool m_read_only;
	std::unique_ptr<platform::DB> m_db;
	uint64_t m_next_record_id = 0;
	std::string m_unique_id;

	//	platform::Timer commit_timer;
public:
	explicit Archive(bool read_only, const std::string &path);
	std::string get_unique_id() const { return m_unique_id; }
	void add(
	    const std::string &type, const common::BinaryArray &data, const Hash &hash, const std::string &source_address);
	void read_archive(api::cnd::GetArchive::Request &&req, api::cnd::GetArchive::Response &resp);
	void db_commit();

	static const std::string BLOCK;
	static const std::string TRANSACTION;
	static const std::string CHECKPOINT;
};

}  // namespace cn
