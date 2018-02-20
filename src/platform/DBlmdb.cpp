// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include "DBlmdb.hpp"
#include <boost/lexical_cast.hpp>
#include <iostream>
#include "PathTools.hpp"

using namespace platform;

#ifdef _WIN32
#pragma comment(lib, "ntdll.lib")  // dependency of lmdb, here to avoid linker arguments
#endif

static void lmdb_check(int rc, const char *msg) {
	if (rc != MDB_SUCCESS)
		throw platform::lmdb::Error(msg + std::to_string(rc));
}

platform::lmdb::Env::Env() { lmdb_check(::mdb_env_create(&handle), "mdb_env_create "); }

platform::lmdb::Env::~Env() {
	::mdb_env_close(handle);
	handle = nullptr;
}

platform::lmdb::Txn::Txn(Env &db_env) {
	lmdb_check(::mdb_txn_begin(db_env.handle, nullptr, 0, &handle), "mdb_txn_begin ");
}

void platform::lmdb::Txn::commit() {
	lmdb_check(::mdb_txn_commit(handle), "mdb_txn_commit ");
	handle = nullptr;
}

platform::lmdb::Txn::~Txn() {
	::mdb_txn_abort(handle);
	handle = nullptr;
}

// ::mdb_dbi_close should never be called according to docs
platform::lmdb::Dbi::Dbi(Txn &db_txn) {
	lmdb_check(::mdb_dbi_open(db_txn.handle, nullptr, 0, &handle), "mdb_dbi_open ");
}

bool platform::lmdb::Dbi::get(Txn &db_txn, MDB_val *const key, MDB_val *const data) {
	const int rc = ::mdb_get(db_txn.handle, handle, key, data);
	if (rc != MDB_SUCCESS && rc != MDB_NOTFOUND)
		throw Error("mdb_get " + std::to_string(rc));
	return (rc == MDB_SUCCESS);
}

platform::lmdb::Cur::Cur(Txn &db_txn, Dbi &db_dbi) {
	lmdb_check(::mdb_cursor_open(db_txn.handle, db_dbi.handle, &handle), "mdb_cursor_open ");
}

platform::lmdb::Cur::Cur(Cur &&other) noexcept { std::swap(handle, other.handle); }

bool platform::lmdb::Cur::get(MDB_val *const key, MDB_val *const data, const MDB_cursor_op op) {
	const int rc = ::mdb_cursor_get(handle, key, data, op);
	if (rc != MDB_SUCCESS && rc != MDB_NOTFOUND)
		throw Error("mdb_cursor_get" + std::to_string(rc));
	return (rc == MDB_SUCCESS);
}
platform::lmdb::Cur::~Cur() {
	::mdb_cursor_close(handle);
	handle = nullptr;
}

DBlmdb::DBlmdb(const std::string &full_path, uint64_t max_db_size) : full_path(full_path) {
	std::cout << "lmdb libversion=" << mdb_version(nullptr, nullptr, nullptr) << std::endl;
	lmdb_check(::mdb_env_set_mapsize(db_env.handle, max_db_size), "mdb_env_set_mapsize ");
	create_directories_if_necessary(full_path);
	lmdb_check(::mdb_env_open(db_env.handle, full_path.c_str(), MDB_NOMETASYNC, 0644), "mdb_env_open ");
	// MDB_NOMETASYNC - We agree to trade chance of losing 1 last transaction for 2x performance boost
	db_txn.reset(new lmdb::Txn(db_env));
	db_dbi.reset(new lmdb::Dbi(*db_txn));
}

size_t DBlmdb::test_get_approximate_size() const {
	MDB_stat sta{};
	lmdb_check(::mdb_env_stat(db_env.handle, &sta), "mdb_env_stat ");
	return sta.ms_psize * (sta.ms_branch_pages + sta.ms_leaf_pages + sta.ms_overflow_pages);
}

size_t DBlmdb::get_approximate_items_count() const {
	MDB_stat sta{};
	lmdb_check(::mdb_env_stat(db_env.handle, &sta), "mdb_env_stat ");
	return sta.ms_entries;
}

DBlmdb::Cursor::Cursor(
    lmdb::Cur &&cur, const std::string &prefix, const std::string &middle, size_t max_key_size, bool forward)
    : db_cur(std::move(cur)), prefix(prefix), forward(forward) {
	std::string start = prefix + middle;
	lmdb::Val itkey(start);
	if (forward)
		is_end = !db_cur.get(itkey, data, start.empty() ? MDB_FIRST : MDB_SET_RANGE);
	else {
		if (start.empty())
			is_end = !db_cur.get(itkey, data, MDB_LAST);
		else {
			if (start.size() < max_key_size)
				start += std::string(max_key_size - start.size(), char(0xff));
			itkey  = lmdb::Val(start);
			is_end = !db_cur.get(itkey, data, MDB_SET_RANGE);
			is_end = !db_cur.get(itkey, data,
			    is_end ? MDB_LAST : MDB_PREV);  // If failed to find a key >= prefix, then it should be last in db
		}
	}
	check_prefix(itkey);
}

void DBlmdb::Cursor::next() {
	lmdb::Val itkey;
	is_end = !db_cur.get(itkey, &*data, forward ? MDB_NEXT : MDB_PREV);
	check_prefix(itkey);
}

void DBlmdb::Cursor::erase() {
	if (is_end)
		return;  // Some precaution
	lmdb_check(::mdb_cursor_del(db_cur.handle, 0), "mdb_cursor_del ");
	next();
}

void DBlmdb::Cursor::check_prefix(const lmdb::Val &itkey) {
	if (is_end || itkey.size() < prefix.size() ||
	    std::char_traits<char>::compare(prefix.data(), itkey.data(), prefix.size()) != 0) {
		is_end = true;
		data   = lmdb::Val{};
		suffix = std::string();
		return;
	}
	suffix = std::string(itkey.data() + prefix.size(), itkey.size() - prefix.size());
}

std::string DBlmdb::Cursor::get_value_string() const { return std::string(data.data(), data.size()); }
common::BinaryArray DBlmdb::Cursor::get_value_array() const {
	return common::BinaryArray(data.data(), data.data() + data.size());
}

DBlmdb::Cursor DBlmdb::begin(const std::string &prefix, const std::string &middle) const {
	int max_key_size = ::mdb_env_get_maxkeysize(db_env.handle);
	return Cursor(lmdb::Cur(*db_txn, *db_dbi), prefix, middle, max_key_size, true);
}

DBlmdb::Cursor DBlmdb::rbegin(const std::string &prefix, const std::string &middle) const {
	int max_key_size = ::mdb_env_get_maxkeysize(db_env.handle);
	return Cursor(lmdb::Cur(*db_txn, *db_dbi), prefix, middle, max_key_size, false);
}

void DBlmdb::commit_db_txn() {
	db_txn->commit();
	db_txn.reset();
	db_txn.reset(new lmdb::Txn(db_env));
}

void DBlmdb::put(const std::string &key, const common::BinaryArray &value, bool nooverwrite) {
	lmdb::Val temp_value(value.data(), value.size());
	const int rc =
	    ::mdb_put(db_txn->handle, db_dbi->handle, lmdb::Val(key), temp_value, nooverwrite ? MDB_NOOVERWRITE : 0);
	if (rc != MDB_SUCCESS && rc != MDB_KEYEXIST)
		throw lmdb::Error("DBlmdb::put failed " + std::string(key.data(), key.size()));
	if (nooverwrite && rc == MDB_KEYEXIST)
		throw lmdb::Error(
		    "DBlmdb::put failed or nooverwrite key already exists " + std::string(key.data(), key.size()));
}

void DBlmdb::put(const std::string &key, const std::string &value, bool nooverwrite) {
	lmdb::Val temp_value(value.data(), value.size());
	const int rc =
	    ::mdb_put(db_txn->handle, db_dbi->handle, lmdb::Val(key), temp_value, nooverwrite ? MDB_NOOVERWRITE : 0);
	if (rc != MDB_SUCCESS && rc != MDB_KEYEXIST)
		throw lmdb::Error("DBlmdb::put failed " + std::string(key.data(), key.size()));
	if (nooverwrite && rc == MDB_KEYEXIST)
		throw lmdb::Error(
		    "DBlmdb::put failed or nooverwrite key already exists " + std::string(key.data(), key.size()));
}

bool DBlmdb::get(const std::string &key, common::BinaryArray &value) const {
	lmdb::Val val1;
	if (!db_dbi->get(*db_txn, lmdb::Val(key), val1))
		return false;
	value.assign(val1.data(), val1.data() + val1.size());
	return true;
}

bool DBlmdb::get(const std::string &key, std::string &value) const {
	lmdb::Val val1;
	if (!db_dbi->get(*db_txn, lmdb::Val(key), val1))
		return false;
	value = std::string(val1.data(), val1.size());
	return true;
}

bool DBlmdb::get(const std::string &key, lmdb::Val &value) const { return db_dbi->get(*db_txn, lmdb::Val(key), value); }

void DBlmdb::del(const std::string &key, bool mustexist) {
	const int rc = ::mdb_del(db_txn->handle, db_dbi->handle, lmdb::Val(key), nullptr);
	if (rc != MDB_SUCCESS && rc != MDB_NOTFOUND)
		throw lmdb::Error("DBlmdb::del failed " + std::string(key.data(), key.size()));
	if (mustexist &&
	    rc == MDB_NOTFOUND)  // Soemtimes lmdb returns 0 for non existing keys, we have to get our own check upwards
		throw lmdb::Error("DBlmdb::del key does not exist " + std::string(key.data(), key.size()));
}

std::string DBlmdb::to_ascending_key(uint32_t key) {
	char buf[32] = {};
	sprintf(buf, "%08X", key);
	return std::string(buf);
}

uint32_t DBlmdb::from_ascending_key(const std::string &key) {
	return boost::lexical_cast<uint32_t>(std::stoull(key, nullptr, 16));
}

std::string DBlmdb::clean_key(const std::string &key) {
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

void DBlmdb::delete_db(const std::string &path) {
	std::remove((path + "/data.mdb").c_str());
	std::remove((path + "/lock.mdb").c_str());
	std::remove(path.c_str());
}

void DBlmdb::run_tests() {
	delete_db("temp_db");
	{
		DBlmdb db("temp_db");
		db.put("history/ha", "ua", false);
		db.put("history/hb", "ub", false);
		db.put("history/hc", "uc", false);
		db.put("unspent/ua", "ua", false);
		db.put("unspent/ub", "ub", false);
		db.put("unspent/uc", "uc", false);
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
