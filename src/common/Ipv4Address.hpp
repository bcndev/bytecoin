// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include "BinaryArray.hpp"

namespace common {

struct NetworkAddress {
	BinaryArray ip;  // 4 or 16 bytes, depending on version
	uint16_t port = 0;

	std::string to_string() const;
	int compare(const NetworkAddress &other) const {
		if (ip != other.ip)
			return ip < other.ip ? -1 : 1;
		if (port != other.port)
			return port < other.port ? -1 : 1;
		return 0;
	}
	bool operator<(const NetworkAddress &other) const { return compare(other) < 0; }
	bool operator>(const NetworkAddress &other) const { return compare(other) > 0; }
	bool operator<=(const NetworkAddress &other) const { return compare(other) <= 0; }
	bool operator>=(const NetworkAddress &other) const { return compare(other) >= 0; }
	bool operator==(const NetworkAddress &other) const { return compare(other) == 0; }
	bool operator!=(const NetworkAddress &other) const { return compare(other) != 0; }
};

inline std::ostream &operator<<(std::ostream &s, const NetworkAddress &na) { return s << na.to_string(); }

std::string ip_address_to_string(const BinaryArray &ip);
uint32_t ip_address_to_legacy(const BinaryArray &ip);
BinaryArray ip_address_from_legacy(uint32_t ip);
std::string ip_address_and_port_to_string(const BinaryArray &ip, uint16_t port);
bool parse_ip_address(const std::string &addr, BinaryArray *ip);
BinaryArray parse_ip_address(const std::string &addr);
void parse_ip_address_and_port(const std::string &addr, BinaryArray *ip, uint16_t *port);
void parse_ip_address_and_port(const std::string &addr, std::string *ip, uint16_t *port);
int get_private_network_prefix(
    const BinaryArray &ip);  // 0, 10, 127, 172, 192 for all classes of IPv4 private addresses
inline bool is_ip_address_loopback(const BinaryArray &ip) { return get_private_network_prefix(ip) == 127; }
inline bool is_ip_address_private(const BinaryArray &ip) { return get_private_network_prefix(ip) == 0; }
}  // namespace common
