// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <sqlite3.h>
#include <algorithm>
#include <memory>
#include <string>
#include "common/BinaryArray.hpp"
#include "common/Nocopy.hpp"

namespace platform {

namespace sqlite {
struct Dbi : private common::Nocopy {
	sqlite3 *handle = nullptr;
	~Dbi();
};
struct Stmt : private common::Nocopy {
	sqlite3_stmt *handle = nullptr;
	Stmt() {}
	Stmt(Stmt &&other);
	~Stmt();
};

class Error : public std::runtime_error {
public:
	explicit Error(const std::string &msg) : std::runtime_error(msg) {}
};
}
class DBsqlite {
	const std::string full_path;
	sqlite::Dbi db_dbi;
	sqlite::Stmt stmt_get;
	sqlite::Stmt stmt_insert;
	sqlite::Stmt stmt_update;
	sqlite::Stmt stmt_del;
	sqlite::Stmt stmt_select_star;

public:
	explicit DBsqlite(
	    bool read_only, const std::string &full_path, uint64_t max_db_size = 0);  // no max size in sqlite3
	const std::string &get_path() const { return full_path; }

	void commit_db_txn();
	size_t test_get_approximate_size() const;
	size_t get_approximate_items_count() const;

	void put(const std::string &key, const common::BinaryArray &value, bool nooverwrite);
	void put(const std::string &key, const std::string &value, bool nooverwrite);

	bool get(const std::string &key, common::BinaryArray &value) const;
	bool get(const std::string &key, std::string &value) const;

	typedef std::string Value;
	//	bool get(const std::string &key, lmdb::Val &value) const;

	void del(const std::string &key, bool mustexist);

	class Cursor {
		const DBsqlite *const db;
		sqlite::Stmt stmt_get;
		std::string suffix;
		const char *data = nullptr;
		size_t size      = 0;
		bool is_end      = false;  // data, size == nullptr, 0 if value is empty
		const std::string prefix;
		const bool forward;
		void step_and_check();
		friend class DBsqlite;
		Cursor(const DBsqlite *db, const sqlite::Dbi &db_dbi, const std::string &prefix, const std::string &middle,
		    bool forward);

	public:
		const std::string &get_suffix() const noexcept { return suffix; }
		std::string get_value_string() const;
		common::BinaryArray get_value_array() const;
		bool end() const noexcept { return is_end; }
		void next();
		void erase();  // moves to the next value
	};
	Cursor begin(const std::string &prefix, const std::string &middle = std::string()) const;
	Cursor rbegin(const std::string &prefix, const std::string &middle = std::string()) const;

	static std::string to_binary_key(const unsigned char *data, size_t size) {
		std::string result;
		result.append(reinterpret_cast<const char *>(data), size);
		return result;
	}
	static void from_binary_key(const std::string &str, size_t pos, unsigned char *data, size_t size) {
		auto si = std::min(str.size() - pos, size);
		std::char_traits<unsigned char>::copy(data, reinterpret_cast<const unsigned char *>(str.data()) + pos, si);
	}

	static std::string to_ascending_key(uint32_t key);
	static uint32_t from_ascending_key(const std::string &key);
	static std::string clean_key(const std::string &key);  // replace invalid chars for printing

	static void run_tests();
	static void delete_db(const std::string &path);
	static void backup_db(const std::string &path, const std::string &dst_path);
};
}
