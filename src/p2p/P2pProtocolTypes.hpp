// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <string.h>
#include <tuple>
#include "common/Ipv4Address.hpp"
#include "common/StringTools.hpp"
#include "crypto/generic-ops.hpp"
#include "seria/ISeria.hpp"

namespace bytecoin {

typedef uint64_t PeerIdType;

#pragma pack(push, 1)
struct UUID {
	uint8_t data[16];  // TODO - return {} initializer when Google updates NDK compiler
};

struct NetworkAddress {
	uint32_t ip   = 0;
	uint32_t port = 0;
};

struct PeerlistEntry {
	NetworkAddress adr;
	PeerIdType id      = 0;
	uint32_t last_seen = 0;  // coincides with Timestamp
	uint32_t reserved  = 0;  // High part of former 64-bit last_seen
};

struct connection_entry {
	NetworkAddress adr;
	PeerIdType id  = 0;
	bool is_income = false;
};
#pragma pack(pop)

inline bool operator<(const NetworkAddress &a, const NetworkAddress &b) {
	return std::tie(a.ip, a.port) < std::tie(b.ip, b.port);
}

inline bool operator==(const NetworkAddress &a, const NetworkAddress &b) { return a.ip == b.ip && a.port == b.port; }

inline std::ostream &operator<<(std::ostream &s, const NetworkAddress &na) {
	return s << common::ip_address_and_port_to_string(na.ip, na.port);
}
}
CRYPTO_MAKE_COMPARABLE(bytecoin, UUID, std::memcmp)

namespace seria {
void ser(bytecoin::UUID &v, seria::ISeria &s);
void ser_members(bytecoin::PeerlistEntry &v, seria::ISeria &s);
void ser_members(bytecoin::NetworkAddress &v, seria::ISeria &s);
void ser_members(bytecoin::connection_entry &v, seria::ISeria &s);
}
