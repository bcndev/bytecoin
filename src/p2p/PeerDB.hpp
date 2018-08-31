// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <list>
#include <map>
#include <set>
#include "CryptoNote.hpp"

#include "Core/Currency.hpp"
#include "logging/LoggerMessage.hpp"
#include "p2p/P2pProtocolTypes.hpp"
#include "platform/DB.hpp"
#include "platform/Network.hpp"

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

namespace bytecoin {
class Config;
class PeerDB {
public:
	typedef platform::DB DB;

	struct Entry : public PeerlistEntry {
		Timestamp next_connection_attempt = 0;
		uint64_t shuffle_random = 0;  // We assign random number to each record, for deterministic order of equal items
	};

	struct by_addr {};
	struct by_ban_until {};
	struct by_next_connection_attempt {};

	typedef boost::multi_index_container<Entry,
	    boost::multi_index::indexed_by<
	        boost::multi_index::ordered_unique<boost::multi_index::tag<by_addr>,
	            boost::multi_index::member<PeerlistEntry, NetworkAddress, &PeerlistEntry::address>>,
	        boost::multi_index::ordered_non_unique<boost::multi_index::tag<by_ban_until>,
	            boost::multi_index::composite_key<Entry,
	                boost::multi_index::member<PeerlistEntry, Timestamp, &PeerlistEntry::ban_until>,
	                boost::multi_index::member<PeerlistEntry, Timestamp, &PeerlistEntry::last_seen>,
	                boost::multi_index::member<Entry, uint64_t, &Entry::shuffle_random>>,
	            boost::multi_index::composite_key_compare<std::less<Timestamp>, std::greater<Timestamp>,
	                std::less<uint64_t>>>,
	        boost::multi_index::ordered_non_unique<boost::multi_index::tag<by_next_connection_attempt>,
	            boost::multi_index::composite_key<Entry,
	                boost::multi_index::member<Entry, Timestamp, &Entry::next_connection_attempt>,
	                boost::multi_index::member<PeerlistEntry, Timestamp, &PeerlistEntry::last_seen>,
	                boost::multi_index::member<Entry, uint64_t, &Entry::shuffle_random>>,
	            boost::multi_index::composite_key_compare<std::less<Timestamp>, std::greater<Timestamp>,
	                std::less<uint64_t>>>>>
	    peers_indexed;

	explicit PeerDB(logging::ILogger &log, const Config &config, const std::string &db_suffix);

	void merge_peerlist_from_p2p(
	    const NetworkAddress &addr, const std::vector<NetworkAddress> &outer_bs, Timestamp now);
	void merge_peerlist_from_p2p(
	    const NetworkAddress &addr, const std::vector<PeerlistEntryLegacy> &outer_bs, Timestamp now);
	bool add_incoming_peer(const NetworkAddress &addr, Timestamp now);
	std::vector<NetworkAddress> get_peerlist_to_p2p(const NetworkAddress &for_addr, Timestamp now, size_t depth);
	std::vector<PeerlistEntryLegacy> get_peerlist_to_p2p_legacy(
	    const NetworkAddress &for_addr, Timestamp now, size_t depth);
	void set_peer_just_seen(
	    PeerIdType peer_id, const NetworkAddress &addr, Timestamp now, bool reset_next_connection_attempt = true);
	// seed nodes do not update next connection attempt, in effect rolling lists around
	void set_peer_banned(const NetworkAddress &addr, const std::string &ban_reason, Timestamp now);
	void delay_connection_attempt(const NetworkAddress &addr, Timestamp now);

	bool is_peer_banned(NetworkAddress address, Timestamp now) const;

	bool get_peer_to_connect(NetworkAddress &best_address, const std::set<NetworkAddress> &connected, Timestamp now);
	bool is_priority(const NetworkAddress &addr) const;
	bool is_seed(const NetworkAddress &addr) const;
	bool is_priority_or_seed(const NetworkAddress &addr) const { return is_priority(addr) || is_seed(addr); }
	size_t get_gray_size() const;
	size_t get_white_size() const;

	void test();

private:
	bool add_incoming_peer_impl(const NetworkAddress &addr, Timestamp now);
	Entry get_entry_from_lists(const NetworkAddress &addr) const;
	void update_lists(const NetworkAddress &addr, std::function<void(Entry &)> fun);

	logging::LoggerRef m_log;
	const Config &config;
	peers_indexed whitelist;
	peers_indexed graylist;
	DB db;
	platform::Timer commit_timer;
	void db_commit();

	void read_db(const std::string &prefix, peers_indexed &list);
	void update_db(const std::string &prefix, const Entry &entry);
	void del_db(const std::string &prefix, const NetworkAddress &addr);
	void trim(Timestamp now);
	void trim(const std::string &prefix, Timestamp now, peers_indexed &list, size_t count);
	void unban(Timestamp now);
	void unban(const std::string &prefix, Timestamp now, peers_indexed &list);
	void print();
};
}
