// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <string.h>
#include <tuple>
#include "common/StringTools.hpp"
#include "seria/ISeria.hpp"
#include "common/Ipv4Address.hpp"
#include "crypto/generic-ops.hpp"

namespace bytecoin {

typedef uint64_t PeerIdType;

#pragma pack (push, 1)
struct UUID {
	uint8_t data[16]{};
};

struct NetworkAddress {
	uint32_t ip = 0;
	uint32_t port = 0;
};

struct PeerlistEntry {
	NetworkAddress adr;
	PeerIdType id = 0;
	uint32_t last_seen = 0; // coincides with Timestamp
	uint32_t reserved = 0; // High part of former 64-bit last_seen
};

struct connection_entry {
	NetworkAddress adr;
	PeerIdType id = 0;
	bool is_income = false;
};
#pragma pack(pop)

inline bool operator<(const NetworkAddress &a, const NetworkAddress &b) {
	return std::tie(a.ip, a.port) < std::tie(b.ip, b.port);
}

inline bool operator==(const NetworkAddress &a, const NetworkAddress &b) {
	return a.ip == b.ip && a.port == b.port;
}

inline std::ostream &operator<<(std::ostream &s, const NetworkAddress &na) {
	return s << common::ip_address_and_port_to_string(na.ip, na.port);
}

}
CRYPTO_MAKE_COMPARABLE(bytecoin, UUID, std::memcmp)

namespace seria {
void ser(bytecoin::UUID &v, seria::ISeria &s);
void serMembers(bytecoin::PeerlistEntry &v, seria::ISeria &s);
void serMembers(bytecoin::NetworkAddress &v, seria::ISeria &s);
void serMembers(bytecoin::connection_entry &v, seria::ISeria &s);
}
