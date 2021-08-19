// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <functional>
#include <map>
#include <string>
#include "Files.hpp"  // For OpenMode
#include "common/BinaryArray.hpp"
#include "common/Nocopy.hpp"

namespace platform {

class AsyncIndexDBOperation;
class DBmemory {
public:
	struct JournalEntry {
		std::string key;
		common::BinaryArray value;
		bool is_deleted = false;
	};
	typedef common::BinaryArray Value;
	struct CmpByUnsigned {
		int compare(const std::string &a, const std::string &b) const;
		bool operator()(const std::string &a, const std::string &b) const { return compare(a, b) < 0; }
	};
	typedef std::map<std::string, common::BinaryArray, CmpByUnsigned> Storage;

	explicit DBmemory(OpenMode open_mode, const std::string &full_path, std::function<void()> &&o_handler);
	~DBmemory();
	const std::string &get_path() const { return full_path; }

	std::vector<JournalEntry> move_journal();

	void commit_db_txn();
	size_t test_get_approximate_size() const;
	size_t get_approximate_items_count() const;

	void put(const std::string &key, const common::BinaryArray &value, bool nooverwrite);
	void put(const std::string &key, const std::string &value, bool nooverwrite);

	bool get(const std::string &key, common::BinaryArray &value) const;
	bool get(const std::string &key, std::string &value) const;

	void del(const std::string &key, bool mustexist);

	class Cursor {
		DBmemory *const db;
		std::string suffix;
		const std::string prefix;
		bool forward = false;
		std::map<std::string, common::BinaryArray>::iterator it;
		friend class DBmemory;
		void check_prefix();
		Cursor(DBmemory *db, const std::string &prefix, const std::string &middle, bool forward);

	public:
		const std::string &get_suffix() const noexcept { return suffix; }
		std::string get_value_string() const;
		common::BinaryArray get_value_array() const;
		bool end() const noexcept { return it == db->storage.end(); }
		void next();
		void erase();  // moves to the next value
	};
	friend class Cursor;
	Cursor begin(const std::string &prefix, const std::string &middle = std::string{}, bool forward = true) const;
	Cursor rbegin(const std::string &prefix, const std::string &middle = std::string{}) const;

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

private:
	const std::string full_path;
#ifdef __EMSCRIPTEN__
	std::unique_ptr<AsyncIndexDBOperation> async_op;
#endif
	std::function<void()> o_handler;
	Storage storage;
	std::vector<JournalEntry> journal;
	bool use_journal    = false;
	size_t total_size   = 0;
	size_t max_key_size = 0;
};

}  // namespace platform
