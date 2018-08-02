// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <list>
#include <map>
#include <set>
#include "CryptoNote.hpp"

#include "Core/Currency.hpp"
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
		Entry()
		    : PeerlistEntry{}  // Initialize all fields
		{}
		Timestamp ban_until               = 0;
		Timestamp next_connection_attempt = 0;
		uint64_t shuffle_random = 0;  // We assign random number to each record, for deterministic order of equal items
		std::string error;            // last ban reason
	};

	struct by_addr {};
	struct by_ban_until {};
	struct by_next_connection_attempt {};

	typedef boost::multi_index_container<Entry,
	    boost::multi_index::indexed_by<
	        boost::multi_index::ordered_unique<boost::multi_index::tag<by_addr>,
	            boost::multi_index::member<PeerlistEntry, NetworkAddress, &PeerlistEntry::adr>>,
	        boost::multi_index::ordered_non_unique<boost::multi_index::tag<by_ban_until>,
	            boost::multi_index::composite_key<Entry,
	                boost::multi_index::member<Entry, Timestamp, &Entry::ban_until>,
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

	explicit PeerDB(const Config &config);

	void merge_peerlist_from_p2p(const std::vector<PeerlistEntry> &outer_bs, Timestamp now);
	void add_incoming_peer(const NetworkAddress &addr, PeerIdType peer_id, Timestamp now);
	std::vector<PeerlistEntry> get_peerlist_to_p2p(const NetworkAddress &for_addr, Timestamp now, size_t depth);

	void set_peer_just_seen(
	    PeerIdType peer_id, const NetworkAddress &addr, Timestamp now, bool reset_next_connection_attempt = true);
	// seed nodes do not update next connection attempt, in effect rolling lists around
	void set_peer_banned(const NetworkAddress &addr, const std::string &error, Timestamp now);
	void delay_connection_attempt(const NetworkAddress &addr, Timestamp now);

	bool is_peer_banned(NetworkAddress address, Timestamp now) const;

	bool get_peer_to_connect(NetworkAddress &best_address, const std::set<NetworkAddress> &connected, Timestamp now);
	//	bool is_ip_allowed(uint32_t ip) const;
	bool is_priority(const NetworkAddress &addr) const;
	bool is_seed(const NetworkAddress &addr) const;
	size_t get_gray_size() const;
	size_t get_white_size() const;

	void test();

private:
	void add_incoming_peer_impl(const NetworkAddress &addr, PeerIdType peer_id, Timestamp now);

	const Config &config;
	peers_indexed exclusivelist;
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
