// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "DBmemory.hpp"
#include <string.h>
#include <iostream>
#include "common/Invariant.hpp"
#include "common/Math.hpp"
#include "common/StringTools.hpp"
#include "common/string.hpp"

using namespace platform;

int DBmemory::CmpByUnsigned::compare(const std::string &a, const std::string &b) const {
	size_t s = std::min(a.size(), b.size());
	int res  = memcmp(a.data(), b.data(), s);
	if (res != 0)
		return res;
	return int(a.size()) - int(b.size());
}

DBmemory::DBmemory(OpenMode open_mode, const std::string &full_path, uint64_t max_tx_size)
    : full_path(full_path + ".memory") {}

std::vector<DBmemory::JournalEntry> DBmemory::move_journal() {
	std::vector<JournalEntry> new_journal;
	journal.swap(new_journal);
	return new_journal;
}

size_t DBmemory::test_get_approximate_size() const { return total_size; }

size_t DBmemory::get_approximate_items_count() const { return storage.size(); }

DBmemory::Cursor::Cursor(DBmemory *db, const std::string &prefix, const std::string &middle, bool forward)
    : db(db), prefix(prefix), forward(forward) {
	std::string start  = prefix + middle;
	std::string finish = start;
	if (finish.size() < db->max_key_size)
		finish += std::string(db->max_key_size - finish.size(), char(0xff));  // char('~')
	if (forward)
		it = db->storage.lower_bound(start);
	else {
		it = db->storage.upper_bound(finish);
		if (it == db->storage.begin())
			it = db->storage.end();
		else
			--it;
	}
	check_prefix();
}

void DBmemory::Cursor::check_prefix() {
	if (it == db->storage.end())
		return;
	if (!common::starts_with(it->first, prefix)) {
		it = db->storage.end();
		return;
	}
	suffix = it->first.substr(prefix.size());
}

void DBmemory::Cursor::next() {
	if (it == db->storage.end())
		return;
	if (forward)
		++it;
	else {
		if (it == db->storage.begin())
			it = db->storage.end();
		else
			--it;
	}
	check_prefix();
}

void DBmemory::Cursor::erase() {
	if (it == db->storage.end())
		return;
	db->total_size -= it->first.size() + it->second.size();
	if (db->use_journal)
		db->journal.push_back(JournalEntry{it->first, common::BinaryArray{}, true});
	it = db->storage.erase(it);
	if (!forward) {
		if (it == db->storage.begin())
			it = db->storage.end();
		else
			--it;
	}
	check_prefix();
}

std::string DBmemory::Cursor::get_value_string() const { return common::as_string(it->second); }
common::BinaryArray DBmemory::Cursor::get_value_array() const { return it->second; }

DBmemory::Cursor DBmemory::begin(const std::string &prefix, const std::string &middle, bool forward) const {
	return Cursor(const_cast<DBmemory *>(this), prefix, middle, forward);
}

DBmemory::Cursor DBmemory::rbegin(const std::string &prefix, const std::string &middle) const {
	return begin(prefix, middle, false);
}

void DBmemory::commit_db_txn() {}

void DBmemory::put(const std::string &key, const common::BinaryArray &value, bool nooverwrite) {
	auto res = storage.emplace(key, value);
	if (res.second) {
		total_size += key.size() + value.size();
		if (key.size() > max_key_size)
			std::cout << "max_key_size=" << key.size() << std::endl;
		max_key_size = std::max(max_key_size, key.size());
		if (use_journal)
			journal.push_back(JournalEntry{key, value, false});
		return;
	}
	if (nooverwrite)
		throw std::runtime_error("DBmemory::put will overwrite row");
	total_size -= res.first->second.size();
	total_size += value.size();
	res.first->second = value;
	if (use_journal)
		journal.push_back(JournalEntry{key, value, false});
}

void DBmemory::put(const std::string &key, const std::string &svalue, bool nooverwrite) {
	put(key, common::as_binary_array(svalue), nooverwrite);
}

bool DBmemory::get(const std::string &key, common::BinaryArray &value) const {
	auto it = storage.find(key);
	if (it == storage.end())
		return false;
	value = it->second;
	return true;
}

bool DBmemory::get(const std::string &key, std::string &value) const {
	auto it = storage.find(key);
	if (it == storage.end())
		return false;
	value = common::as_string(it->second);
	return true;
}

void DBmemory::del(const std::string &key, bool mustexist) {
	auto it = storage.find(key);
	if (it == storage.end()) {
		if (mustexist)
			throw std::runtime_error("DBmemory::del row does not exits");
		return;
	}
	total_size -= key.size() + it->second.size();
	it = storage.erase(it);
	if (use_journal)
		journal.push_back(JournalEntry{key, common::BinaryArray{}, true});
}

std::string DBmemory::to_ascending_key(uint32_t key) {
	char buf[32] = {};
	sprintf(buf, "%08X", key);
	return std::string(buf);
}

uint32_t DBmemory::from_ascending_key(const std::string &key) {
	long long unsigned val = 0;
	if (sscanf(key.c_str(), "%llx", &val) != 1)
		throw std::runtime_error("from_ascending_key failed to convert key=" + key);
	// TODO - std::stoull(key, nullptr, 16) when Google updates NDK compiler
	return common::integer_cast<uint32_t>(val);
}

std::string DBmemory::clean_key(const std::string &key) {
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

void DBmemory::delete_db(const std::string &path) {}

void DBmemory::backup_db(const std::string &path, const std::string &dst_path) {
	throw std::runtime_error("Memory backed does not support hot backup");
}

void DBmemory::run_tests() {
	delete_db("temp_db");
	{
		DBmemory db(platform::O_CREATE_NEW, "temp_db");
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
