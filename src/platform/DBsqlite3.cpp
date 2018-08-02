// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "DBsqlite3.hpp"
#include <boost/lexical_cast.hpp>
#include <iostream>
#include "PathTools.hpp"
#include "common/string.hpp"

using namespace platform;

static void sqlite_check(int rc, const char *msg) {
	if (rc != SQLITE_OK)
		throw platform::sqlite::Error(msg + common::to_string(rc));
}

sqlite::Dbi::~Dbi() {
	sqlite3_close(handle);
	handle = nullptr;
}
sqlite::Stmt::Stmt(Stmt &&other) { std::swap(handle, other.handle); }
sqlite::Stmt::~Stmt() {
	sqlite3_finalize(handle);
	handle = nullptr;
}

DBsqlite::DBsqlite(bool read_only, const std::string &full_path, uint64_t max_db_size)
    : full_path(full_path + ".sqlite") {
	if (read_only)
		throw platform::sqlite::Error("SQLite cannot be used in read-only mode for now");
	//	lmdb_check(::mdb_env_set_mapsize(db_env.handle, max_db_size), "mdb_env_set_mapsize ");
	std::cout << "sqlite3_libversion=" << sqlite3_libversion() << std::endl;
	//	create_directories_if_necessary(full_path);
	sqlite_check(sqlite3_open(this->full_path.c_str(), &db_dbi.handle), "sqlite3_open ");
	char *err_msg = nullptr;  // TODO - we leak err_msg
	sqlite_check(
	    sqlite3_exec(db_dbi.handle,
	        "CREATE TABLE IF NOT EXISTS kv_table(kk BLOB PRIMARY KEY COLLATE BINARY, vv BLOB NOT NULL) WITHOUT ROWID",
	        0, 0, &err_msg),
	    err_msg);
	sqlite_check(sqlite3_prepare_v2(db_dbi.handle, "SELECT kk, vv FROM kv_table WHERE kk = ?", -1, &stmt_get.handle, 0),
	    "sqlite3_prepare_v2 stmt_get ");
	sqlite_check(
	    sqlite3_prepare_v2(db_dbi.handle, "INSERT INTO kv_table (kk, vv) VALUES (?, ?)", -1, &stmt_insert.handle, 0),
	    "sqlite3_prepare_v2 stmt_insert ");
	sqlite_check(
	    sqlite3_prepare_v2(db_dbi.handle, "REPLACE INTO kv_table (kk, vv) VALUES (?, ?)", -1, &stmt_update.handle, 0),
	    "sqlite3_prepare_v2 stmt_update ");
	sqlite_check(sqlite3_prepare_v2(db_dbi.handle, "DELETE FROM kv_table WHERE kk = ?", -1, &stmt_del.handle, 0),
	    "sqlite3_prepare_v2 stmt_del ");
	sqlite_check(sqlite3_prepare_v2(db_dbi.handle, "SELECT count(kk) FROM kv_table", -1, &stmt_select_star.handle, 0),
	    "sqlite3_prepare_v2 stmt_select_star ");

	sqlite_check(sqlite3_exec(db_dbi.handle, "BEGIN TRANSACTION", 0, 0, &err_msg), err_msg);
	std::cout << "SQLite applying DB journal, can take up to several minutes..." << std::endl;
	commit_db_txn();  // We apply journal from last crash/exit immediately
	                  //	std::cout << "rows=" << get_approximate_items_count() << std::endl;
}

size_t DBsqlite::test_get_approximate_size() const { return 0; }

size_t DBsqlite::get_approximate_items_count() const {
	return 1;  // Sqlite does full table scan on select count(*), we do not want that behavior
	           //	sqlite3_reset(stmt_select_star.handle);
	           //	auto rc = sqlite3_step(stmt_select_star.handle);
	           //	if (rc != SQLITE_ROW)
	           //		throw platform::sqlite::Error("DB::get_approximate_items_count failed sqlite3_step in get " +
	           // common::to_string(rc));
	           //	return boost::lexical_cast<size_t>(sqlite3_column_int64(stmt_select_star.handle, 0));
}

static const size_t max_key_size = 128;

DBsqlite::Cursor::Cursor(
    const DBsqlite *db, const sqlite::Dbi &db_dbi, const std::string &prefix, const std::string &middle, bool forward)
    : db(db), prefix(prefix), forward(forward) {
	std::string start  = prefix + middle;
	std::string finish = start;
	if (finish.size() < max_key_size)
		finish += std::string(max_key_size - finish.size(), char(0xff));  // char('~')
	std::string sql = forward ? "SELECT kk, vv FROM kv_table WHERE kk >= ? ORDER BY kk ASC"
	                          : "SELECT kk, vv FROM kv_table WHERE kk <= ? ORDER BY kk DESC";
	sqlite_check(
	    sqlite3_prepare_v2(db_dbi.handle, sql.c_str(), -1, &stmt_get.handle, 0), "sqlite3_prepare_v2 Cursor stmt_get ");
	sqlite_check(sqlite3_bind_blob(stmt_get.handle, 1, forward ? start.data() : finish.data(),
	                 static_cast<int>(forward ? start.size() : finish.size()), SQLITE_TRANSIENT),
	    "DB::Cursor sqlite3_bind_blob 1 ");
	step_and_check();
}

void DBsqlite::Cursor::next() { step_and_check(); }

void DBsqlite::Cursor::erase() {
	if (is_end)
		return;  // Some precaution
	sqlite3_reset(stmt_get.handle);
	std::string mykey = prefix + suffix;
	const_cast<DBsqlite *>(db)->del(mykey, true);
	sqlite_check(sqlite3_bind_blob(stmt_get.handle, 1, mykey.data(), static_cast<int>(mykey.size()), SQLITE_TRANSIENT),
	    "DB::Cursor erase sqlite3_bind_blob 1 ");
	step_and_check();
}

void DBsqlite::Cursor::step_and_check() {
	auto rc = sqlite3_step(stmt_get.handle);
	if (rc == SQLITE_DONE) {
		data   = nullptr;
		size   = 0;
		is_end = true;
		suffix = std::string();
		return;
	}
	if (rc != SQLITE_ROW)
		throw platform::sqlite::Error("Cursor step failed sqlite3_step in step_and_check " + common::to_string(rc));
	size = sqlite3_column_bytes(stmt_get.handle, 0);
	data = reinterpret_cast<const char *>(sqlite3_column_blob(stmt_get.handle, 0));
	std::string itkey(data, size);
	size = sqlite3_column_bytes(stmt_get.handle, 1);
	data = reinterpret_cast<const char *>(sqlite3_column_blob(stmt_get.handle, 1));
	if (itkey.size() < prefix.size() ||
	    std::char_traits<char>::compare(prefix.data(), itkey.data(), prefix.size()) != 0) {
		data   = nullptr;
		size   = 0;
		is_end = true;
		suffix = std::string();
		return;
	}
	suffix = std::string(itkey.data() + prefix.size(), itkey.size() - prefix.size());
}

/*void DB::Cursor::check_prefix(const lmdb::Val &itkey) {
    if (is_end || itkey.size() < prefix.size() ||
        std::char_traits<char>::compare(prefix.data(), itkey.data(), prefix.size()) != 0) {
        is_end = true;
        suffix = std::string();
        return;
    }
    suffix = std::string(itkey.data() + prefix.size(), itkey.size() - prefix.size());
}*/

std::string DBsqlite::Cursor::get_value_string() const { return std::string(data, size); }
common::BinaryArray DBsqlite::Cursor::get_value_array() const { return common::BinaryArray(data, data + size); }

DBsqlite::Cursor DBsqlite::begin(const std::string &prefix, const std::string &middle) const {
	return Cursor(this, db_dbi, prefix, middle, true);
}

DBsqlite::Cursor DBsqlite::rbegin(const std::string &prefix, const std::string &middle) const {
	return Cursor(this, db_dbi, prefix, middle, false);
}

void DBsqlite::commit_db_txn() {
	char *err_msg = nullptr;  // TODO - we leak err_msg
	sqlite_check(sqlite3_exec(db_dbi.handle, "COMMIT TRANSACTION", 0, 0, &err_msg), err_msg);
	sqlite_check(sqlite3_exec(db_dbi.handle, "BEGIN TRANSACTION", 0, 0, &err_msg), err_msg);
}

static void put(sqlite::Stmt &stmt, const std::string &key, const void *data, size_t size) {
	sqlite3_reset(stmt.handle);
	sqlite_check(
	    sqlite3_bind_blob(stmt.handle, 1, key.data(), static_cast<int>(key.size()), 0), "DB::put sqlite3_bind_blob 1 ");
	sqlite_check(sqlite3_bind_blob(stmt.handle, 2, data, static_cast<int>(size), 0), "DB::put sqlite3_bind_blob 2 ");
	auto rc = sqlite3_step(stmt.handle);
	if (rc != SQLITE_DONE)
		throw platform::sqlite::Error("DB::put failed sqlite3_step in put " + common::to_string(rc));
}

void DBsqlite::put(const std::string &key, const common::BinaryArray &value, bool nooverwrite) {
	sqlite::Stmt &stmt = nooverwrite ? stmt_insert : stmt_update;
	::put(stmt, key, value.data(), value.size());
}

void DBsqlite::put(const std::string &key, const std::string &value, bool nooverwrite) {
	sqlite::Stmt &stmt = nooverwrite ? stmt_insert : stmt_update;
	::put(stmt, key, value.data(), value.size());
}

static std::pair<const unsigned char *, size_t> get(const sqlite::Stmt &stmt, const std::string &key) {
	sqlite3_reset(stmt.handle);
	sqlite_check(
	    sqlite3_bind_blob(stmt.handle, 1, key.data(), static_cast<int>(key.size()), 0), "DB::get sqlite3_bind_blob 1 ");
	auto rc = sqlite3_step(stmt.handle);
	if (rc == SQLITE_DONE)
		return std::make_pair(nullptr, 0);
	if (rc != SQLITE_ROW)
		throw platform::sqlite::Error("DB::get failed sqlite3_step in get " + common::to_string(rc));
	auto si = sqlite3_column_bytes(stmt.handle, 0);
	auto da = reinterpret_cast<const unsigned char *>(sqlite3_column_blob(stmt.handle, 0));
	si      = sqlite3_column_bytes(stmt.handle, 1);
	da      = reinterpret_cast<const unsigned char *>(sqlite3_column_blob(stmt.handle, 1));
	return std::make_pair(da, si);
}

bool DBsqlite::get(const std::string &key, common::BinaryArray &value) const {
	auto result = ::get(stmt_get, key);
	if (!result.first)
		return false;
	value.assign(result.first, result.first + result.second);
	return true;
}

bool DBsqlite::get(const std::string &key, std::string &value) const {
	auto result = ::get(stmt_get, key);
	if (!result.first)
		return false;
	value.assign(result.first, result.first + result.second);
	return true;
}

void DBsqlite::del(const std::string &key, bool mustexist) {
	sqlite3_reset(stmt_del.handle);
	sqlite_check(sqlite3_bind_blob(stmt_del.handle, 1, key.data(), static_cast<int>(key.size()), 0),
	    "DB::del sqlite3_bind_blob 1 ");
	auto rc = sqlite3_step(stmt_del.handle);
	if (rc != SQLITE_DONE)
		throw platform::sqlite::Error("DB::del failed sqlite3_step in del " + common::to_string(rc));
	int deleted_rows = sqlite3_changes(db_dbi.handle);
	if (mustexist && deleted_rows != 1)
		throw platform::sqlite::Error("DB::del row does not exits");
}

std::string DBsqlite::to_ascending_key(uint32_t key) {
	char buf[32] = {};
	sprintf(buf, "%08X", key);
	return std::string(buf);
}

uint32_t DBsqlite::from_ascending_key(const std::string &key) {
	long long unsigned val = 0;
	if (sscanf(key.c_str(), "%llx", &val) != 1)
		throw std::runtime_error("from_ascending_key failed to convert key=" + key);
	return boost::lexical_cast<uint32_t>(val);  // TODO - std::stoull(key, nullptr, 16) when Google updates NDK compiler
}

std::string DBsqlite::clean_key(const std::string &key) {
	std::string result = key;
	for (char &ch : result) {
		unsigned char uch = ch;
		if (uch >= 128)
			uch -= 128;
		if (uch == 127)
			uch = 'F';
		if (uch < 32)
			uch = '0' + uch;
		ch      = uch;
	}
	return result;
}

void DBsqlite::delete_db(const std::string &path) {
	//	std::remove((path + "/data.mdb").c_str());
	//	std::remove((path + "/lock.mdb").c_str());
	std::remove(path.c_str());
}
void DBsqlite::backup_db(const std::string &path, const std::string &dst_path) {
	throw platform::sqlite::Error("SQlite backed does not support hot backup - stop daemons, then copy database");
}

void DBsqlite::run_tests() {
	delete_db("temp_db");
	{
		DBsqlite db(false, "temp_db");
		std::string str;
		bool res = db.get("history/ha", str);
		std::cout << "res=" << res << std::endl;

		db.put("history/ha", "ua", false);
		db.put("history/hb", "ub", false);
		db.put("history/hc", "uc", false);

		db.put("history/ha", "uaa", false);
		try {
			db.put("history/ha", "uab", true);
			std::cout << "value erroneously overwritten" << std::endl;
		} catch (...) {
		}
		db.del("history/hd", false);
		try {
			db.del("history/hd", true);
			std::cout << "value erroneously deleted" << std::endl;
		} catch (...) {
		}
		res = db.get("history/ha", str);
		std::cout << "res=" << res << std::endl;

		db.put("unspent/ua", "ua", false);
		db.put("unspent/ub", "ub", false);
		db.put("unspent/uc", "uc", false);
		db.commit_db_txn();

		std::cout << "-- all keys forward --" << std::endl;
		for (auto cur = db.begin(std::string()); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- all keys backward --" << std::endl;
		for (auto cur = db.rbegin(std::string()); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- history forward --" << std::endl;
		for (auto cur = db.begin("history/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- history backward --" << std::endl;
		for (auto cur = db.rbegin("history/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- unspent forward --" << std::endl;
		for (auto cur = db.begin("unspent/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- unspent backward --" << std::endl;
		for (auto cur = db.rbegin("unspent/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- alpha forward --" << std::endl;
		for (auto cur = db.begin("alpha/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- alpha backward --" << std::endl;
		for (auto cur = db.rbegin("alpha/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- zero forward --" << std::endl;
		for (auto cur = db.begin("zero/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		std::cout << "-- zero backward --" << std::endl;
		for (auto cur = db.rbegin("zero/"); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		int c = 0;
		std::cout << "-- deleting c=2 iterating forward --" << std::endl;
		for (auto cur = db.begin(std::string()); !cur.end(); ++c) {
			if (c == 2) {
				std::cout << "deleting " << cur.get_suffix() << std::endl;
				cur.erase();
			} else {
				std::cout << cur.get_suffix() << std::endl;
				cur.next();
			}
		}
		std::cout << "-- all keys forward --" << std::endl;
		for (auto cur = db.begin(std::string()); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
		c = 0;
		std::cout << "-- deleting c=2 iterating backward --" << std::endl;
		for (auto cur = db.rbegin(std::string()); !cur.end(); ++c) {
			if (c == 2) {
				std::cout << "deleting " << cur.get_suffix() << std::endl;
				cur.erase();
			} else {
				std::cout << cur.get_suffix() << std::endl;
				cur.next();
			}
		}
		std::cout << "-- all keys forward --" << std::endl;
		for (auto cur = db.begin(std::string()); !cur.end(); cur.next()) {
			std::cout << cur.get_suffix() << std::endl;
		}
	}
	delete_db("temp_db");
}
