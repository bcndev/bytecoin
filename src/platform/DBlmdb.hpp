// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <lmdb.h>
#include <algorithm>
#include <memory>
#include <string>
#include "common/BinaryArray.hpp"
#include "common/Nocopy.hpp"

namespace platform {

namespace lmdb {
struct Val {
	MDB_val impl{};

	Val() noexcept {}
	explicit Val(const std::string &data) noexcept : Val{data.data(), data.size()} {}
	Val(const void *const data, const std::size_t size) noexcept : impl{size, const_cast<void *>(data)} {}
	operator MDB_val *() noexcept { return &impl; }
	operator const MDB_val *() const noexcept { return &impl; }
	bool empty() const noexcept { return size() == 0; }
	std::size_t size() const noexcept { return impl.mv_size; }
	char *data() noexcept { return reinterpret_cast<char *>(impl.mv_data); }
	const char *data() const noexcept { return reinterpret_cast<char *>(impl.mv_data); }
};
struct Env : private common::Nocopy {
	const bool m_read_only;
	MDB_env *handle = nullptr;
	explicit Env(bool read_only);
	~Env();
};
struct Txn : private common::Nocopy {
	MDB_txn *handle = nullptr;
	explicit Txn(Env &db_env);
	void commit();
	~Txn();
};
struct Dbi : private common::Nocopy {
	MDB_dbi handle = 0;
	explicit Dbi(Txn &db_txn);
	bool get(Txn &db_txn, MDB_val *const key, MDB_val *const data);
};
struct Cur : private common::Nocopy {
	MDB_cursor *handle = nullptr;
	explicit Cur(Txn &db_txn, Dbi &db_dbi);
	explicit Cur(Cur &&other) noexcept;
	bool get(MDB_val *const key, MDB_val *const data, const MDB_cursor_op op);
	~Cur();
};
class Error : public std::runtime_error {
public:
	explicit Error(const std::string &msg) : std::runtime_error(msg) {}
	static void do_throw(const std::string &msg, int rc);
};
}

class DBlmdb {
	const std::string full_path;  // TODO - change fields to m_
	lmdb::Env db_env;
	std::unique_ptr<lmdb::Dbi> db_dbi;
	std::unique_ptr<lmdb::Txn> db_txn;

public:
	explicit DBlmdb(bool read_only, const std::string &full_path,
	    uint64_t max_db_size = 0x8000000000);  // 0.5 Tb default, out of total 4 Tb on windows
	const std::string &get_path() const { return full_path; }
	void commit_db_txn();
	size_t test_get_approximate_size() const;
	size_t get_approximate_items_count() const;

	void put(const std::string &key, const common::BinaryArray &value, bool nooverwrite);
	void put(const std::string &key, const std::string &value, bool nooverwrite);

	bool get(const std::string &key, common::BinaryArray &value) const;
	bool get(const std::string &key, std::string &value) const;

	typedef lmdb::Val Value;
	bool get(const std::string &key, Value &value) const;

	void del(const std::string &key, bool mustexist);

	class Cursor {
		lmdb::Cur db_cur;
		std::string suffix;
		lmdb::Val data;
		bool is_end = false;
		const std::string prefix;
		const bool forward;
		void check_prefix(const lmdb::Val &itkey);
		friend class DBlmdb;
		Cursor(lmdb::Cur &&db_cur, const std::string &prefix, const std::string &middle, size_t max_key_size,
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
	static void delete_db(const std::string &full_path);
	static void backup_db(const std::string &full_path, const std::string &dst_path);
};
}
