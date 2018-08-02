// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "PeerDB.hpp"
#include "Core/Config.hpp"

#include <time.h>
#include <iostream>
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

#include "common/Ipv4Address.hpp"
#include "common/string.hpp"
#include "crypto/crypto.hpp"
#include "seria/ISeria.hpp"

using namespace bytecoin;
using namespace platform;

namespace seria {
void ser_members(PeerDB::Entry &v, ISeria &s) {
	ser_members(static_cast<PeerlistEntry &>(v), s);
	seria_kv("ban_until", v.ban_until, s);
	seria_kv("shuffle_random", v.shuffle_random, s);
	seria_kv("next_connection_attempt", v.next_connection_attempt, s);
	seria_kv("error", v.error, s);
}
}

static const std::string GRAY_LIST("graylist/");
static const std::string WHITE_LIST("whitelist/");
const Timestamp BAN_PERIOD                = 600;
const Timestamp RECONNECT_PERIOD          = 300;
const Timestamp PRIORITY_RECONNECT_PERIOD = 30;
static const float DB_COMMIT_PERIOD       = 60;  // 1 minute sounds good compromise

PeerDB::PeerDB(const Config &config)
    : config(config)
    , db(false, config.get_data_folder() + "/peer_db", 1024 * 1024 * 128)
    ,  // make sure this is enough for seed node
    commit_timer(std::bind(&PeerDB::db_commit, this)) {
	read_db(WHITE_LIST, whitelist);
	read_db(GRAY_LIST, graylist);
	for (auto &&addr : config.exclusive_nodes) {
		Entry new_entry{};
		new_entry.adr            = addr;
		new_entry.shuffle_random = crypto::rand<uint64_t>();
		exclusivelist.insert(new_entry);
	}
	for (auto &&addr : config.seed_nodes) {
		auto &by_addr_index = whitelist.get<by_addr>();
		auto git            = by_addr_index.find(addr);
		if (git != by_addr_index.end())  // Already in whitelist
			continue;
		Entry new_entry{};
		new_entry.adr            = addr;
		new_entry.shuffle_random = crypto::rand<uint64_t>();
		whitelist.insert(new_entry);
	}
	commit_timer.once(DB_COMMIT_PERIOD);
}

void PeerDB::db_commit() {
	db.commit_db_txn();
	commit_timer.once(DB_COMMIT_PERIOD);
}

void PeerDB::read_db(const std::string &prefix, peers_indexed &list) {
	//	std::cout << "PeerDB known peers:" << std::endl;
	list.clear();
	for (auto db_cur = db.begin(prefix); !db_cur.end(); db_cur.next()) {
		//        std::cout << db_cur.get_suffix() << std::endl;
		try {
			Entry peer{};
			seria::from_binary(peer, db_cur.get_value_array());
			//            std::cout << common::ip_address_and_port_to_string(peer.adr.ip, peer.adr.port) << std::endl;
			list.insert(peer);
		} catch (...) {
			// No problem, will get everything from seed nodes
			// TODO - log
		}
	}
}

void PeerDB::update_db(const std::string &prefix, const Entry &entry) {
	auto key = prefix + common::to_string(entry.adr.ip) + ":" + common::to_string(entry.adr.port);
	db.put(key, seria::to_binary(entry), false);
}

void PeerDB::del_db(const std::string &prefix, const NetworkAddress &addr) {
	auto key = prefix + common::to_string(addr.ip) + ":" + common::to_string(addr.port);
	db.del(key, false);
}

void PeerDB::print() {
	auto &by_time_index = whitelist.get<by_addr>();
	for (auto it = by_time_index.begin(); it != by_time_index.end(); ++it) {
		std::string a = common::ip_address_and_port_to_string(it->adr.ip, it->adr.port);
		std::cout << a << " b=" << it->ban_until << " na=" << it->next_connection_attempt << " ls=" << it->last_seen
		          << std::endl;
	}
}

void PeerDB::trim(Timestamp now) {
	trim(GRAY_LIST, now, graylist, config.p2p_local_gray_list_limit);
	trim(WHITE_LIST, now, whitelist, config.p2p_local_white_list_limit);
}

size_t PeerDB::get_gray_size() const {
	auto &by_time_index = graylist.get<by_addr>();
	return by_time_index.size();
}
size_t PeerDB::get_white_size() const {
	auto &by_time_index = whitelist.get<by_addr>();
	return by_time_index.size();
}

void PeerDB::trim(const std::string &prefix, Timestamp now, peers_indexed &list, size_t count) {
	auto &by_ban_index = list.get<by_ban_until>();
	while (by_ban_index.size() > count) {
		auto lit = --by_ban_index.end();
		del_db(prefix, lit->adr);
		by_ban_index.erase(lit);
	}
}

void PeerDB::unban(Timestamp now) {
	unban(GRAY_LIST, now, graylist);
	unban(WHITE_LIST, now, whitelist);
}

void PeerDB::unban(const std::string &prefix, Timestamp now, peers_indexed &list) {
	auto &by_time_index = list.get<by_ban_until>();
	std::vector<Entry> unbanned;
	auto sta = by_time_index.lower_bound(boost::make_tuple(Timestamp(1), Timestamp(0), 0));
	auto fin = by_time_index.lower_bound(boost::make_tuple(now, Timestamp(0), 0));
	for (auto iit = sta; iit != fin; ++iit) {
		unbanned.push_back(*iit);
		unbanned.back().ban_until               = 0;
		unbanned.back().next_connection_attempt = 0;
		update_db(prefix, unbanned.back());
	}
	by_time_index.erase(sta, fin);
	for (auto &&unb : unbanned)
		list.insert(unb);
}

std::vector<PeerlistEntry> PeerDB::get_peerlist_to_p2p(const NetworkAddress &for_addr, Timestamp now, size_t depth) {
	std::vector<PeerlistEntry> bs_head;
	unban(now);
	auto &by_time_index     = whitelist.get<by_ban_until>();
	auto fin                = by_time_index.lower_bound(boost::make_tuple(Timestamp(1), Timestamp(0), 0));
	int for_addr_network_id = common::get_private_network_prefix(for_addr.ip);
	//	std::cout << "for_addr_network_id" << common::ip_address_to_string(for_addr.ip) << std::endl;
	for (auto it = by_time_index.begin(); it != fin; ++it) {
		//		std::cout << "network_id" << common::ip_address_to_string(it->adr.ip) << std::endl;
		int network_id = common::get_private_network_prefix(it->adr.ip);
		if (for_addr_network_id != network_id && network_id != 0)
			continue;
		bs_head.push_back(static_cast<PeerlistEntry>(*it));
		bs_head.back().last_seen = 0;
		if (bs_head.size() >= depth)
			break;
	}
	std::shuffle(bs_head.begin(), bs_head.end(), crypto::random_engine<size_t>{});
	return bs_head;
}

void PeerDB::merge_peerlist_from_p2p(const std::vector<PeerlistEntry> &outer_bs, Timestamp now) {
	unban(now);
	for (auto &&pp : outer_bs) {
		add_incoming_peer_impl(pp.adr, pp.id, now);
	}
	trim(now);
}
void PeerDB::add_incoming_peer(const NetworkAddress &addr, PeerIdType peer_id, Timestamp now) {
	unban(now);
	add_incoming_peer_impl(addr, peer_id, now);
	trim(now);
}

void PeerDB::add_incoming_peer_impl(const NetworkAddress &addr, PeerIdType peer_id, Timestamp now) {
	if (addr.port == 0)  // client does not want to be in peer lists
		return;
	//	if (!is_ip_allowed(addr.ip))
	//		return;
	auto &by_addr_index = whitelist.get<by_addr>();
	auto git            = by_addr_index.find(addr);
	if (git != by_addr_index.end())  // Already in whitelist
		return;
	auto &gray_by_addr_index = graylist.get<by_addr>();
	git                      = gray_by_addr_index.find(addr);
	if (git != gray_by_addr_index.end())  // Already in gray list
		return;
	Entry new_entry{};
	new_entry.adr = addr;
	new_entry.id  = peer_id;
	// We ignore last_seen here
	new_entry.shuffle_random = crypto::rand<uint64_t>();
	graylist.insert(new_entry);
	update_db(GRAY_LIST, new_entry);
}

void PeerDB::set_peer_just_seen(PeerIdType peer_id,
    const NetworkAddress &addr,
    Timestamp now,
    bool reset_next_connection_attempt) {
	//	auto &exclusive_by_addr_index = exclusivelist.get<by_addr>();
	//	auto git                      = exclusive_by_addr_index.find(addr);
	//	if (git != exclusive_by_addr_index.end()) {
	//		return;
	//	}
	auto &gray_by_addr_index = graylist.get<by_addr>();
	auto git                 = gray_by_addr_index.find(addr);
	if (git != gray_by_addr_index.end()) {
		gray_by_addr_index.erase(git);
		del_db(GRAY_LIST, addr);
	}
	Entry new_entry{};
	new_entry.adr            = addr;
	new_entry.shuffle_random = crypto::rand<uint64_t>();
	auto &by_addr_index      = whitelist.get<by_addr>();
	git                      = by_addr_index.find(addr);
	if (git != by_addr_index.end()) {
		new_entry = *git;
		by_addr_index.erase(git);
	}
	new_entry.id        = peer_id;
	new_entry.ban_until = 0;
	// do not reconnect immediately if called inside seed node or if connecting to seed node
	if (reset_next_connection_attempt && !is_seed(addr))
		new_entry.next_connection_attempt = 0;
	new_entry.last_seen                   = now;
	whitelist.insert(new_entry);
	update_db(WHITE_LIST, new_entry);
}

void PeerDB::delay_connection_attempt(const NetworkAddress &addr, Timestamp now) {
	auto &white_by_addr_index = whitelist.get<by_addr>();
	auto git                  = white_by_addr_index.find(addr);
	if (git != white_by_addr_index.end()) {
		Entry entry = *git;
		white_by_addr_index.erase(git);
		entry.next_connection_attempt = now + (!is_priority(addr) ? BAN_PERIOD : PRIORITY_RECONNECT_PERIOD);
		whitelist.insert(entry);
		update_db(WHITE_LIST, entry);
	}
}

void PeerDB::set_peer_banned(const NetworkAddress &addr, const std::string &error, Timestamp now) {
	auto &exclusive_by_addr_index = exclusivelist.get<by_addr>();
	auto git                      = exclusive_by_addr_index.find(addr);
	if (git != exclusive_by_addr_index.end()) {
		Entry entry = *git;
		exclusive_by_addr_index.erase(git);
		entry.error                   = error;
		entry.ban_until               = now + PRIORITY_RECONNECT_PERIOD;
		entry.next_connection_attempt = entry.ban_until;
		exclusive_by_addr_index.insert(entry);
		return;
	}
	auto &gray_by_addr_index = graylist.get<by_addr>();
	git                      = gray_by_addr_index.find(addr);
	if (git != gray_by_addr_index.end()) {
		Entry entry = *git;
		gray_by_addr_index.erase(git);
		entry.error                   = error;
		entry.ban_until               = now + (is_priority(addr) ? PRIORITY_RECONNECT_PERIOD : BAN_PERIOD);
		entry.next_connection_attempt = entry.ban_until;
		graylist.insert(entry);
		update_db(GRAY_LIST, entry);
	}
	auto &white_by_addr_index = whitelist.get<by_addr>();
	git                       = white_by_addr_index.find(addr);
	if (git != white_by_addr_index.end()) {
		Entry entry = *git;
		white_by_addr_index.erase(git);
		entry.error     = error;
		entry.ban_until = now + (is_seed(addr) ? PRIORITY_RECONNECT_PERIOD
		                                       : is_priority(addr) ? PRIORITY_RECONNECT_PERIOD : BAN_PERIOD);
		entry.next_connection_attempt = entry.ban_until;
		whitelist.insert(entry);
		update_db(WHITE_LIST, entry);
	}
}

bool PeerDB::is_peer_banned(NetworkAddress address, Timestamp now) const {
	auto &gray_by_addr_index = graylist.get<by_addr>();
	auto git                 = gray_by_addr_index.find(address);
	if (git != gray_by_addr_index.end()) {
		if (now < git->ban_until)
			return true;
	}
	auto &white_by_addr_index = whitelist.get<by_addr>();
	git                       = white_by_addr_index.find(address);
	if (git != white_by_addr_index.end()) {
		if (now < git->ban_until)
			return true;
	}
	return false;
}

bool PeerDB::get_peer_to_connect(NetworkAddress &best_address,
    const std::set<NetworkAddress> &connected,
    Timestamp now) {
	auto &exclusive_by_time_index = exclusivelist.get<by_next_connection_attempt>();
	if (!exclusive_by_time_index.empty()) {
		auto exclusive_sta = exclusive_by_time_index.begin();
		auto exclusive_fin = exclusive_by_time_index.lower_bound(boost::make_tuple(now, Timestamp(0), 0));
		while (exclusive_sta != exclusive_fin && connected.count(exclusive_sta->adr) != 0)
			++exclusive_sta;
		if (exclusive_sta == exclusive_fin)
			return false;
		Entry entry = *exclusive_sta;
		exclusive_by_time_index.erase(exclusive_sta);
		entry.next_connection_attempt = now + PRIORITY_RECONNECT_PERIOD;
		exclusivelist.insert(entry);
		best_address = entry.adr;
		return true;
	}
	unban(now);
	std::vector<NetworkAddress> connected_seeds;
	std::vector<NetworkAddress> not_connected_seeds;
	for (auto &&cc : config.seed_nodes)
		if (connected.count(cc) == 0)
			not_connected_seeds.push_back(cc);
		else
			connected_seeds.push_back(cc);
	std::vector<NetworkAddress> connected_priorities;
	std::vector<NetworkAddress> not_connected_priorities;
	for (auto &&cc : config.priority_nodes)
		if (connected.count(cc) == 0)
			not_connected_priorities.push_back(cc);
		else
			connected_priorities.push_back(cc);
	const bool enough_connected_seeds = connected_seeds.size() >= 2;
	auto &white_by_time_index         = whitelist.get<by_next_connection_attempt>();
	auto white_sta                    = white_by_time_index.begin();
	auto white_fin                    = white_by_time_index.lower_bound(boost::make_tuple(now, Timestamp(0), 0));
	while (white_sta != white_fin &&
	       (connected.count(white_sta->adr) != 0 ||
	           (enough_connected_seeds && is_seed(white_sta->adr))))  // Skip connected and seeds if enough connected
		++white_sta;
	auto &gray_by_time_index = graylist.get<by_next_connection_attempt>();
	auto gray_sta            = gray_by_time_index.begin();
	auto gray_fin            = gray_by_time_index.lower_bound(boost::make_tuple(now, Timestamp(0), 0));
	while (gray_sta != gray_fin && (connected.count(gray_sta->adr) != 0 ||
	                                   (enough_connected_seeds && is_seed(gray_sta->adr))))  // Skip connected and seeds
		++gray_sta;
	bool use_white = (crypto::rand<uint32_t>() % 100 < config.p2p_whitelist_connections_percent) &&
	                 white_sta != white_fin && now >= white_sta->next_connection_attempt;
	if (use_white) {
		Entry entry = *white_sta;
		white_by_time_index.erase(white_sta);
		entry.next_connection_attempt = now + (is_priority(entry.adr) ? PRIORITY_RECONNECT_PERIOD : RECONNECT_PERIOD);
		whitelist.insert(entry);
		update_db(WHITE_LIST, entry);
		best_address = entry.adr;
		return true;
	}
	if (gray_sta != gray_fin && now >= gray_sta->next_connection_attempt) {
		Entry entry = *gray_sta;
		gray_by_time_index.erase(gray_sta);
		entry.next_connection_attempt = now + (is_priority(entry.adr) ? PRIORITY_RECONNECT_PERIOD : RECONNECT_PERIOD);
		graylist.insert(entry);
		update_db(GRAY_LIST, entry);
		best_address = entry.adr;
		return true;
	}
	/*	if (connected_seeds.size() >= 2) // Already connected/connecting to 2 seed node
	        return false;
	    if (not_connected_seeds.empty())
	        return false;
	    size_t pos = crypto::rand<uint32_t>() % not_connected_seeds.size();
	    best_address = not_connected_seeds[pos];*/
	return false;
}

bool PeerDB::is_priority(const NetworkAddress &addr) const {
	return std::binary_search(config.priority_nodes.begin(), config.priority_nodes.end(), addr);
}
bool PeerDB::is_seed(const NetworkAddress &addr) const {
	return std::binary_search(config.seed_nodes.begin(), config.seed_nodes.end(), addr);
}

/*bool PeerDB::is_ip_allowed(uint32_t ip) const {
    // TODO - allow exclusive ips

    // never allow loopback ip
    if (common::is_ip_address_loopback(ip))
        return false;
    if (!config.p2p_allow_local_ip && common::is_ip_address_private(ip))
        return false;
    return true;
}*/

void PeerDB::test() {
	/*	std::vector<PeerlistEntry> list;
	    for (int i = 11; i != 22; ++i) {
	        PeerlistEntry e{};
	        e.adr.ip   = i;
	        e.adr.port = i;
	        list.push_back(e);
	    }
	    merge_peerlist_from_p2p(list, 100);
	    list = get_peerlist_to_p2p(100, 3);
	    NetworkAddress ad1;
	    NetworkAddress ad2;
	    NetworkAddress ad3;
	    NetworkAddress ad4;
	    std::set<NetworkAddress> connected;
	    get_peer_to_connect(ad1, connected, 101);
	    get_peer_to_connect(ad2, connected, 101);
	    get_peer_to_connect(ad3, connected, 101);
	    get_peer_to_connect(ad4, connected, 101);

	    set_peer_just_seen(0, ad1, 102);
	    set_peer_just_seen(0, ad2, 103);
	    set_peer_just_seen(0, ad3, 104);
	    set_peer_banned(ad3, "reason", 105);
	    set_peer_banned(ad4, "reason", 106);

	    list = get_peerlist_to_p2p(200, 3);

	    get_peer_to_connect(ad1, connected, 501);
	    get_peer_to_connect(ad2, connected, 501);
	    get_peer_to_connect(ad3, connected, 501);

	    list = get_peerlist_to_p2p(900, 3);
	    db_commit();*/
}
