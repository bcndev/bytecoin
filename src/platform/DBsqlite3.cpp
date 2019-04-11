// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "DBsqlite3.hpp"
#include <iostream>
#include "PathTools.hpp"
#include "common/Invariant.hpp"
#include "common/Math.hpp"
#include "common/string.hpp"

using namespace platform;

void sqlite::check(int rc, const char *msg) {
	if (rc != SQLITE_OK)
		throw Error((msg ? msg : "") + common::to_string(rc));
}

void sqlite::Dbi::open_check_create(OpenMode open_mode, const std::string &full_path, bool *created) {
	this->full_path = full_path;
	sqlite::check(sqlite3_open_v2(full_path.c_str(),
	                  &handle,
	                  open_mode == OpenMode::O_READ_EXISTING
	                      ? SQLITE_OPEN_READONLY
	                      : open_mode == OpenMode::O_OPEN_EXISTING ? SQLITE_OPEN_READWRITE
	                                                               : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE),
	                  nullptr),
	    "sqlite3_open ");
	invariant(open_mode != OpenMode::O_CREATE_ALWAYS, "sqlite database does not support clearing existing data");
	if (open_mode == OpenMode::O_READ_EXISTING)
		exec("BEGIN TRANSACTION", "modifying database impossible. Disk read-only or database used by other running instance?");
	else
		exec("BEGIN IMMEDIATE TRANSACTION", "modifying database impossible. Disk read-only or database used by other running instance?");
	sqlite::Stmt stmt_get_tables;
	stmt_get_tables.prepare(*this, "SELECT name FROM sqlite_master WHERE type = 'table'");
	*created = !stmt_get_tables.step();
	if (open_mode == OpenMode::O_CREATE_NEW && !*created)
		throw Error("sqlite database " + full_path + " already exists and will not be overwritten");
	sqlite::check(sqlite3_busy_timeout(handle, 5000), "sqlite3_busy_timeout");  // ms
}

void sqlite::Dbi::exec(const char *statement, const char * err_msg) {
	auto rc = sqlite3_exec(handle, statement, nullptr, nullptr, nullptr);
	if (rc != SQLITE_OK)
		throw Error((err_msg ? err_msg : "") + std::string(" sqlite error code=") + common::to_string(rc) + " for db path=" + full_path);
}
void sqlite::Dbi::commit_txn() { exec("COMMIT TRANSACTION", "saving database data failed. Disk unplugged or out of disk space?"); }
void sqlite::Dbi::begin_txn() {
	exec("BEGIN IMMEDIATE TRANSACTION", "modifying database impossible. Disk read-only or database used by other running instance?");  // TODO - if readonly, will throw
}

sqlite::Dbi::~Dbi() {
	sqlite3_close(handle);
	handle = nullptr;
}

void sqlite::Stmt::prepare(const Dbi &dbi, const char *statement) {
	sqlite::check(sqlite3_prepare_v2(dbi.handle, statement, -1, &handle, nullptr), statement);
}
void sqlite::Stmt::bind_blob(int position, const void *data, size_t size) const {
	sqlite::check(sqlite3_bind_blob(handle, position, data == nullptr ? "" : data, static_cast<int>(size), nullptr),
	    "sqlite3_bind_blob failed");
	// sqlite3_bind_blob uses nullptr as a NULL indicator. Empty arrays can have nullptr as a data().
}

bool sqlite::Stmt::step() const {
	auto rc = sqlite3_step(handle);
	if (rc == SQLITE_DONE)
		return false;
	if (rc != SQLITE_ROW)
		throw platform::sqlite::Error("Cursor step failed sqlite3_step in step_and_check " + common::to_string(rc));
	return true;
}

size_t sqlite::Stmt::column_bytes(int column) const {
	return static_cast<size_t>(sqlite3_column_bytes(handle, column));
}
const uint8_t *sqlite::Stmt::column_blob(int column) const {
	return reinterpret_cast<const uint8_t *>(sqlite3_column_blob(handle, column));
}

sqlite::Stmt::Stmt(Stmt &&other) noexcept { std::swap(handle, other.handle); }
sqlite::Stmt::~Stmt() {
	sqlite3_finalize(handle);
	handle = nullptr;
}

DBsqliteKV::DBsqliteKV(OpenMode open_mode, const std::string &full_path, uint64_t max_db_size)
    : full_path(full_path + ".sqlite") {
	//	if ()
	//		throw platform::sqlite::Error("SQLite cannot be used in read-only mode for now");
	//	lmdb_check(::mdb_env_set_mapsize(db_env.handle, max_db_size), "mdb_env_set_mapsize ");
	//	std::cout << "sqlite3_libversion=" << sqlite3_libversion() << std::endl;
	//	create_directories_if_necessary(full_path);
	bool created = false;
	db_dbi.open_check_create(open_mode, this->full_path.c_str(), &created);
	if (created)
		db_dbi.exec("CREATE TABLE kv_table(kk BLOB PRIMARY KEY COLLATE BINARY, vv BLOB NOT NULL) WITHOUT ROWID");
	stmt_get.prepare(db_dbi, "SELECT kk, vv FROM kv_table WHERE kk = ?");
	stmt_insert.prepare(db_dbi, "INSERT INTO kv_table (kk, vv) VALUES (?, ?)");
	stmt_update.prepare(db_dbi, "REPLACE INTO kv_table (kk, vv) VALUES (?, ?)");
	stmt_del.prepare(db_dbi, "DELETE FROM kv_table WHERE kk = ?");
}

size_t DBsqliteKV::test_get_approximate_size() const { return 0; }

size_t DBsqliteKV::get_approximate_items_count() const {
	return std::numeric_limits<size_t>::
	    max();  // Sqlite does full table scan on select count(*), we do not want that behavior
	            //	sqlite3_reset(stmt_select_star.handle);
	            //	auto rc = sqlite3_step(stmt_select_star.handle);
	            //	if (rc != SQLITE_ROW)
	            //		throw platform::sqlite::Error("DB::get_approximate_items_count failed sqlite3_step in get " +
	            // common::to_string(rc));
	            //	return common::integer_cast<size_t>(sqlite3_column_int64(stmt_select_star.handle, 0));
}

static const size_t max_key_size = 128;

DBsqliteKV::Cursor::Cursor(const DBsqliteKV *db,
    const sqlite::Dbi &db_dbi,
    const std::string &prefix,
    const std::string &middle,
    bool forward)
    : db(db), prefix(prefix) {
	std::string start  = prefix + middle;
	std::string finish = start;
	if (finish.size() < max_key_size)
		finish += std::string(max_key_size - finish.size(), char(0xff));  // char('~')
	const char *sql = forward ? "SELECT kk, vv FROM kv_table WHERE kk >= ? ORDER BY kk ASC"
	                          : "SELECT kk, vv FROM kv_table WHERE kk <= ? ORDER BY kk DESC";
	stmt_get.prepare(db_dbi, sql);
	stmt_get.bind_blob(1, forward ? start.data() : finish.data(), forward ? start.size() : finish.size());
	step_and_check();
}

void DBsqliteKV::Cursor::next() { step_and_check(); }

void DBsqliteKV::Cursor::erase() {
	if (is_end)
		return;  // Some precaution
	sqlite3_reset(stmt_get.handle);
	std::string my_key = prefix + suffix;
	const_cast<DBsqliteKV *>(db)->del(my_key, true);
	stmt_get.bind_blob(1, my_key.data(), my_key.size());
	step_and_check();
}

void DBsqliteKV::Cursor::step_and_check() {
	if (!stmt_get.step()) {
		data   = nullptr;
		size   = 0;
		is_end = true;
		suffix = std::string();
		return;
	}
	size = stmt_get.column_bytes(0);
	data = reinterpret_cast<const char *>(sqlite3_column_blob(stmt_get.handle, 0));
	std::string it_key(data, size);
	size = stmt_get.column_bytes(1);
	data = reinterpret_cast<const char *>(sqlite3_column_blob(stmt_get.handle, 1));
	if (it_key.size() < prefix.size() ||
	    std::char_traits<char>::compare(prefix.data(), it_key.data(), prefix.size()) != 0) {
		data   = nullptr;
		size   = 0;
		is_end = true;
		suffix = std::string();
		return;
	}
	suffix = std::string(it_key.data() + prefix.size(), it_key.size() - prefix.size());
}

std::string DBsqliteKV::Cursor::get_value_string() const { return std::string(data, size); }
common::BinaryArray DBsqliteKV::Cursor::get_value_array() const { return common::BinaryArray(data, data + size); }

DBsqliteKV::Cursor DBsqliteKV::begin(const std::string &prefix, const std::string &middle) const {
	return Cursor(this, db_dbi, prefix, middle, true);
}

DBsqliteKV::Cursor DBsqliteKV::rbegin(const std::string &prefix, const std::string &middle) const {
	return Cursor(this, db_dbi, prefix, middle, false);
}

void DBsqliteKV::commit_db_txn() {
	db_dbi.commit_txn();
	db_dbi.begin_txn();
}

static void put(sqlite::Stmt &stmt, const std::string &key, const void *data, size_t size) {
	invariant(data || size == 0, "");
	sqlite3_reset(stmt.handle);
	stmt.bind_blob(1, key.data(), key.size());
	stmt.bind_blob(2, data, size);
	invariant(!stmt.step(), "put returned rows");
}

void DBsqliteKV::put(const std::string &key, const common::BinaryArray &value, bool nooverwrite) {
	sqlite::Stmt &stmt = nooverwrite ? stmt_insert : stmt_update;
	::put(stmt, key, value.data(), value.size());
}

void DBsqliteKV::put(const std::string &key, const std::string &value, bool nooverwrite) {
	sqlite::Stmt &stmt = nooverwrite ? stmt_insert : stmt_update;
	::put(stmt, key, value.data(), value.size());
}

static std::pair<const unsigned char *, size_t> get(const sqlite::Stmt &stmt, const std::string &key) {
	sqlite3_reset(stmt.handle);
	stmt.bind_blob(1, key.data(), key.size());
	if (!stmt.step())
		return std::make_pair(nullptr, 0);
	auto si = stmt.column_bytes(0);
	auto da = stmt.column_blob(0);
	si      = stmt.column_bytes(1);
	da      = stmt.column_blob(1);
	return std::make_pair(da, si);
}

bool DBsqliteKV::get(const std::string &key, common::BinaryArray &value) const {
	auto result = ::get(stmt_get, key);
	if (!result.first)
		return false;
	value.assign(result.first, result.first + result.second);
	return true;
}

bool DBsqliteKV::get(const std::string &key, std::string &value) const {
	auto result = ::get(stmt_get, key);
	if (!result.first)
		return false;
	value.assign(result.first, result.first + result.second);
	return true;
}

void DBsqliteKV::del(const std::string &key, bool mustexist) {
	sqlite3_reset(stmt_del.handle);
	stmt_del.bind_blob(1, key.data(), key.size());
	invariant(!stmt_del.step(), "sqlite del returned rows");
	int deleted_rows = sqlite3_changes(db_dbi.handle);
	if (mustexist && deleted_rows != 1)
		throw platform::sqlite::Error("DB::del row does not exits");
}

std::string DBsqliteKV::to_ascending_key(uint32_t key) {
	char buf[32] = {};
	sprintf(buf, "%08X", key);
	return std::string(buf);
}

uint32_t DBsqliteKV::from_ascending_key(const std::string &key) {
	long long unsigned val = 0;
	if (sscanf(key.c_str(), "%llx", &val) != 1)
		throw std::runtime_error("from_ascending_key failed to convert key=" + key);
	// TODO - std::stoull(key, nullptr, 16) when Google updates NDK compiler
	return common::integer_cast<uint32_t>(val);
}

std::string DBsqliteKV::clean_key(const std::string &key) {
	std::string result = key;
	for (char &ch : result) {
		unsigned char uch = ch;
		if (uch >= 128)
			uch -= 128;
		if (uch == 127)
			uch = 'F';
		if (uch < 32)
			uch = '0' + uch;
		ch = uch;
	}
	return result;
}

void DBsqliteKV::delete_db(const std::string &path) {
	//	std::remove((path + "/data.mdb").c_str());
	//	std::remove((path + "/lock.mdb").c_str());
	std::remove((path + ".sqlite").c_str());
	std::remove((path + ".sqlite-journal").c_str());
}
void DBsqliteKV::backup_db(const std::string &path, const std::string &dst_path) {
	throw platform::sqlite::Error("SQlite backed does not support hot backup - stop daemons, then copy database");
	/*	bool src_created = false;
	    sqlite::Dbi src;
	    src.open_check_create(platform::O_READ_EXISTING, path + ".sqlite", &src_created);

	    bool dst_created = false;
	    sqlite::Dbi dst;
	    dst.open_check_create(platform::O_CREATE_NEW, dst_path + ".sqlite", &dst_created);

	    auto ba = sqlite3_backup_init(dst.handle, "main", src.handle, "main");
	    if(!ba)
	        throw platform::sqlite::Error("SQlite failed to start hot backup - stop daemons, then copy database");
	//	while(true){
	    auto res = sqlite3_backup_step(ba, -1);
	    sqlite3_backup_finish(ba); ba = nullptr;
	    if(res != SQLITE_DONE)
	        sqlite::check(res, "sqlite3_backup_step failed");
	//		std::cout << "." << std::flush;
	//	}
	*/
}

void DBsqliteKV::run_tests() {
	delete_db("temp_db");
	{
		DBsqliteKV db(platform::O_CREATE_NEW, "temp_db");
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
