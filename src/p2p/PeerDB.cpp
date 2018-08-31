// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "PeerDB.hpp"
#include "Core/Config.hpp"

#include <time.h>
#include <iostream>
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

#include "common/Ipv4Address.hpp"
#include "common/Math.hpp"
#include "common/string.hpp"
#include "crypto/crypto.hpp"
#include "platform/Time.hpp"
#include "seria/ISeria.hpp"

using namespace bytecoin;
using namespace platform;

namespace seria {
void ser_members(PeerDB::Entry &v, ISeria &s) {
	ser_members(static_cast<PeerlistEntry &>(v), s);
	seria_kv("shuffle_random", v.shuffle_random, s);
	seria_kv("next_connection_attempt", v.next_connection_attempt, s);
}
}

static const std::string GRAY_LIST("graylist/");
static const std::string WHITE_LIST("whitelist/");
const Timestamp BAN_PERIOD                = 600;
const Timestamp RECONNECT_PERIOD          = 300;
const Timestamp PRIORITY_RECONNECT_PERIOD = 30;
const Timestamp SEED_RECONNECT_PERIOD     = 86400;
static const float DB_COMMIT_PERIOD       = 60;  // 1 minute sounds good compromise
static const std::string version_current  = "2";

static Timestamp fix_time_delta(Timestamp delta) {
	return std::max<Timestamp>(1, delta / platform::get_time_multiplier_for_tests());
}

PeerDB::PeerDB(logging::ILogger &log, const Config &config, const std::string &db_suffix)
    : m_log(log, "PeerDB")
    , config(config)
    , db(false, config.get_data_folder() + "/" + db_suffix, 1024 * 1024 * 128)
    ,  // make sure this DB size is enough for seed node
    commit_timer(std::bind(&PeerDB::db_commit, this)) {
	std::string version;
	db.get("$version", version);
	if (version != version_current) {
		if (!version.empty())
			m_log(logging::INFO) << "PeerDB format different, old version=" << version
			                     << " current version=" << version_current << ", clearing Peer DB..." << std::endl;
		for (DB::Cursor cur = db.rbegin(std::string()); !cur.end(); cur.erase()) {
		}
		db.put("$version", version_current, true);
	}
	read_db(WHITE_LIST, whitelist);
	read_db(GRAY_LIST, graylist);
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
		} catch (const std::exception &) {
			// No problem, will get everything from seed nodes
			// TODO - log
		}
	}
}

void PeerDB::update_db(const std::string &prefix, const Entry &entry) {
	auto key = prefix + common::ip_address_and_port_to_string(entry.address.ip, entry.address.port);
	db.put(key, seria::to_binary(entry), false);
}

void PeerDB::del_db(const std::string &prefix, const NetworkAddress &addr) {
	auto key = prefix + common::ip_address_and_port_to_string(addr.ip, addr.port);
	db.del(key, false);
}

void PeerDB::print() {
	auto &by_time_index = whitelist.get<by_addr>();
	for (auto it = by_time_index.begin(); it != by_time_index.end(); ++it) {
		std::string a = common::ip_address_and_port_to_string(it->address.ip, it->address.port);
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
		del_db(prefix, lit->address);
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

std::vector<NetworkAddress> PeerDB::get_peerlist_to_p2p(const NetworkAddress &for_addr, Timestamp now, size_t depth) {
	std::vector<NetworkAddress> bs_head;
	unban(now);
	auto &by_time_index     = whitelist.get<by_ban_until>();
	auto fin                = by_time_index.lower_bound(boost::make_tuple(Timestamp(1), Timestamp(0), 0));
	int for_addr_network_id = common::get_private_network_prefix(for_addr.ip);
	for (auto it = by_time_index.begin(); it != fin; ++it) {
		if (is_seed(it->address))
			continue;
		int network_id = common::get_private_network_prefix(it->address.ip);
		if (for_addr_network_id != network_id && network_id != 0)
			continue;
		if (it->address.ip.size() != 4)  // For now
			continue;
		bs_head.push_back(it->address);
		if (bs_head.size() >= depth)
			break;
	}
	std::shuffle(bs_head.begin(), bs_head.end(), crypto::random_engine<size_t>{});
	return bs_head;
}

std::vector<PeerlistEntryLegacy> PeerDB::get_peerlist_to_p2p_legacy(const NetworkAddress &for_addr,
    Timestamp now,
    size_t depth) {
	std::vector<PeerlistEntryLegacy> bs_head;
	unban(now);
	auto &by_time_index     = whitelist.get<by_ban_until>();
	auto fin                = by_time_index.lower_bound(boost::make_tuple(Timestamp(1), Timestamp(0), 0));
	int for_addr_network_id = common::get_private_network_prefix(for_addr.ip);
	//	std::cout << "for_addr_network_id" << common::ip_address_to_string(for_addr.ip) << std::endl;
	for (auto it = by_time_index.begin(); it != fin; ++it) {
		if (is_seed(it->address))
			continue;
		int network_id = common::get_private_network_prefix(it->address.ip);
		if (for_addr_network_id != network_id && network_id != 0)
			continue;
		if (it->address.ip.size() != 4)  // For now
			continue;
		bs_head.push_back(PeerlistEntryLegacy{});
		bs_head.back().id        = it->peer_id;
		bs_head.back().adr.port  = it->address.port;
		bs_head.back().adr.ip    = ip_address_to_legacy(it->address.ip);
		bs_head.back().last_seen = 0;
		if (bs_head.size() >= depth)
			break;
	}
	std::shuffle(bs_head.begin(), bs_head.end(), crypto::random_engine<size_t>{});
	return bs_head;
}

void PeerDB::merge_peerlist_from_p2p(const NetworkAddress &addr,
    const std::vector<NetworkAddress> &outer_bs,
    Timestamp now) {
	unban(now);
	for (auto &&pp : outer_bs) {
		add_incoming_peer_impl(pp, now);
	}
	if (is_seed(addr)) {
		m_log(logging::INFO) << "Delaying connect to seed " << addr << " because got peer list size=" << outer_bs.size()
		                     << std::endl;
		delay_connection_attempt(addr, now);
	}
	trim(now);
}

void PeerDB::merge_peerlist_from_p2p(const NetworkAddress &addr,
    const std::vector<PeerlistEntryLegacy> &outer_bs,
    Timestamp now) {
	unban(now);
	for (auto &&pp : outer_bs) {
		NetworkAddress na;
		na.ip   = common::ip_address_from_legacy(pp.adr.ip);
		na.port = pp.adr.port;
		add_incoming_peer_impl(na, now);
	}
	if (is_seed(addr)) {
		m_log(logging::INFO) << "Delaying connect to seed " << addr << " because got peer list size=" << outer_bs.size()
		                     << std::endl;
		delay_connection_attempt(addr, now);
	}
	trim(now);
}

bool PeerDB::add_incoming_peer(const NetworkAddress &addr, Timestamp now) {
	unban(now);
	if (!add_incoming_peer_impl(addr, now))
		return false;
	trim(now);
	return true;
}

bool PeerDB::add_incoming_peer_impl(const NetworkAddress &addr, Timestamp now) {
	if (addr.port == 0)  // client does not want to be in peer lists
		return false;
	auto &by_addr_index = whitelist.get<by_addr>();
	auto git            = by_addr_index.find(addr);
	if (git != by_addr_index.end())  // Already in whitelist
		return false;
	auto &gray_by_addr_index = graylist.get<by_addr>();
	git                      = gray_by_addr_index.find(addr);
	if (git != gray_by_addr_index.end())  // Already in gray list
		return false;
	Entry new_entry{};
	new_entry.address = addr;
	// We ignore peer_id here
	// We ignore last_seen here
	new_entry.shuffle_random = crypto::rand<uint64_t>();
	graylist.insert(new_entry);
	update_db(GRAY_LIST, new_entry);
	return true;
}

PeerDB::Entry PeerDB::get_entry_from_lists(const NetworkAddress &addr) const {
	auto &gray_by_addr_index = graylist.get<by_addr>();
	auto git                 = gray_by_addr_index.find(addr);
	if (git != gray_by_addr_index.end())
		return *git;
	auto &white_by_addr_index = whitelist.get<by_addr>();
	git                       = white_by_addr_index.find(addr);
	if (git != white_by_addr_index.end())
		return *git;
	Entry new_entry{};
	new_entry.address        = addr;
	new_entry.shuffle_random = crypto::rand<uint64_t>();
	return new_entry;
}

void PeerDB::update_lists(const NetworkAddress &addr, std::function<void(Entry &)> fun) {
	auto &gray_by_addr_index = graylist.get<by_addr>();
	auto git                 = gray_by_addr_index.find(addr);
	if (git != gray_by_addr_index.end()) {
		Entry entry = *git;
		fun(entry);
		gray_by_addr_index.replace(git, entry);
		update_db(GRAY_LIST, entry);
		return;
	}
	auto &white_by_addr_index = whitelist.get<by_addr>();
	git                       = white_by_addr_index.find(addr);
	if (git != white_by_addr_index.end()) {
		Entry entry = *git;
		fun(entry);
		white_by_addr_index.replace(git, entry);
		update_db(WHITE_LIST, entry);
		return;
	}
	Entry entry{};
	entry.address        = addr;
	entry.shuffle_random = crypto::rand<uint64_t>();
	fun(entry);
	graylist.insert(entry);
	update_db(GRAY_LIST, entry);
}

void PeerDB::set_peer_just_seen(PeerIdType peer_id,
    const NetworkAddress &addr,
    Timestamp now,
    bool reset_next_connection_attempt) {
	auto &gray_by_addr_index = graylist.get<by_addr>();
	auto git                 = gray_by_addr_index.find(addr);
	if (git != gray_by_addr_index.end()) {
		gray_by_addr_index.erase(git);
		del_db(GRAY_LIST, addr);
	}
	Entry new_entry{};
	new_entry.address        = addr;
	new_entry.shuffle_random = crypto::rand<uint64_t>();
	auto &by_addr_index      = whitelist.get<by_addr>();
	git                      = by_addr_index.find(addr);
	if (git != by_addr_index.end()) {
		new_entry = *git;
		by_addr_index.erase(git);
	}
	new_entry.peer_id   = peer_id;
	new_entry.ban_until = 0;
	// do not reconnect immediately if called inside seed node or if connecting to seed node
	if (reset_next_connection_attempt && !is_seed(addr))
		new_entry.next_connection_attempt = 0;
	new_entry.last_seen                   = now;
	whitelist.insert(new_entry);
	update_db(WHITE_LIST, new_entry);
}

void PeerDB::delay_connection_attempt(const NetworkAddress &addr, Timestamp now) {
	// Used by downloader for slackers and to advance connect attempt for seeds
	// We delay slackers always by PRIORITY_RECONNECT_PERIOD (even if they are not priority)
	update_lists(addr, [&](Entry &entry) {
		entry.next_connection_attempt =
		    now + fix_time_delta(is_seed(entry.address) ? SEED_RECONNECT_PERIOD : PRIORITY_RECONNECT_PERIOD);
	});
}

void PeerDB::set_peer_banned(const NetworkAddress &addr, const std::string &ban_reason, Timestamp now) {
	update_lists(addr, [&](Entry &entry) {
		entry.ban_reason = ban_reason;
		entry.ban_until =
		    now + fix_time_delta(is_priority_or_seed(entry.address) ? PRIORITY_RECONNECT_PERIOD : BAN_PERIOD);
		entry.next_connection_attempt = entry.ban_until;
	});
}

bool PeerDB::is_peer_banned(NetworkAddress address, Timestamp now) const {
	Entry entry = get_entry_from_lists(address);
	return now < entry.ban_until;
}

bool PeerDB::get_peer_to_connect(NetworkAddress &best_address,
    const std::set<NetworkAddress> &connected,
    Timestamp now) {
	unban(now);
	peers_indexed not_connected_priorities;
	size_t connected_priorities = 0;
	for (auto &&cc : config.priority_nodes)
		if (connected.count(cc))
			connected_priorities += 1;
		else
			not_connected_priorities.insert(get_entry_from_lists(cc));
	if (connected_priorities < config.priority_nodes.size()) {
		auto &ncp_by_time_index = not_connected_priorities.get<by_next_connection_attempt>();
		auto ncp_sta            = ncp_by_time_index.begin();
		auto ncp_fin            = ncp_by_time_index.lower_bound(boost::make_tuple(now, Timestamp(0), 0));
		if (ncp_sta != ncp_fin && now >= ncp_sta->next_connection_attempt) {
			update_lists(ncp_sta->address,
			    [&](Entry &entry) { entry.next_connection_attempt = now + fix_time_delta(PRIORITY_RECONNECT_PERIOD); });
			best_address = ncp_sta->address;
			return true;
		}
	}
	if (config.priority_nodes.size() >= config.p2p_max_outgoing_connections || config.exclusive_nodes)
		return false;  // Leave slots for all priorities even if some are banned/delayed
	const size_t remaining_slots = config.p2p_max_outgoing_connections - config.priority_nodes.size();
	if (connected.size() - connected_priorities >= remaining_slots)
		return false;  // Leave slots for all priorities even if some are banned/delayed
	peers_indexed not_connected_seeds;
	size_t connected_seeds = 0;
	std::vector<Timestamp> seed_next_connection_attempts;
	for (auto &&cc : config.seed_nodes) {
		Entry entry = get_entry_from_lists(cc);
		seed_next_connection_attempts.push_back(entry.next_connection_attempt);
		if (connected.count(cc))
			connected_seeds += 1;
		else
			not_connected_seeds.insert(entry);
	}
	if (now >= common::median_value(&seed_next_connection_attempts) &&
	    connected_seeds < 2) {  // TODO - constant in code
		auto &ncp_by_time_index = not_connected_seeds.get<by_next_connection_attempt>();
		auto ncp_sta            = ncp_by_time_index.begin();
		auto ncp_fin            = ncp_by_time_index.lower_bound(boost::make_tuple(now, Timestamp(0), 0));
		if (ncp_sta != ncp_fin && now >= ncp_sta->next_connection_attempt) {
			update_lists(ncp_sta->address,
			    [&](Entry &entry) { entry.next_connection_attempt = now + fix_time_delta(PRIORITY_RECONNECT_PERIOD); });
			best_address = ncp_sta->address;
			return true;
		}
	}
	auto &white_by_time_index = whitelist.get<by_next_connection_attempt>();
	auto white_sta            = white_by_time_index.begin();
	auto white_fin            = white_by_time_index.lower_bound(boost::make_tuple(now, Timestamp(0), 0));
	while (
	    white_sta != white_fin && (connected.count(white_sta->address) != 0 || is_priority_or_seed(white_sta->address)))
		++white_sta;
	auto &gray_by_time_index = graylist.get<by_next_connection_attempt>();
	auto gray_sta            = gray_by_time_index.begin();
	auto gray_fin            = gray_by_time_index.lower_bound(boost::make_tuple(now, Timestamp(0), 0));
	while (gray_sta != gray_fin && (connected.count(gray_sta->address) != 0 || is_priority_or_seed(gray_sta->address)))
		++gray_sta;
	bool use_white = (crypto::rand<uint32_t>() % 100 < config.p2p_whitelist_connections_percent) &&
	                 white_sta != white_fin && now >= white_sta->next_connection_attempt;
	if (use_white) {
		Entry entry = *white_sta;
		white_by_time_index.erase(white_sta);
		entry.next_connection_attempt =
		    now + fix_time_delta(is_priority_or_seed(entry.address) ? PRIORITY_RECONNECT_PERIOD : RECONNECT_PERIOD);
		whitelist.insert(entry);
		update_db(WHITE_LIST, entry);
		best_address = entry.address;
		return true;
	}
	if (gray_sta != gray_fin && now >= gray_sta->next_connection_attempt) {
		Entry entry = *gray_sta;
		gray_by_time_index.erase(gray_sta);
		entry.next_connection_attempt =
		    now + fix_time_delta(is_priority_or_seed(entry.address) ? PRIORITY_RECONNECT_PERIOD : RECONNECT_PERIOD);
		graylist.insert(entry);
		update_db(GRAY_LIST, entry);
		best_address = entry.address;
		return true;
	}
	return false;
}

bool PeerDB::is_priority(const NetworkAddress &addr) const {
	return std::binary_search(config.priority_nodes.begin(), config.priority_nodes.end(), addr);
}
bool PeerDB::is_seed(const NetworkAddress &addr) const {
	return std::binary_search(config.seed_nodes.begin(), config.seed_nodes.end(), addr);
}

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
