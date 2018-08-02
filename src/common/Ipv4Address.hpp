// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstdint>
#include <string>

namespace common {

std::string ip_address_to_string(uint32_t ip);
std::string ip_address_and_port_to_string(uint32_t ip, uint32_t port);
bool parse_ip_address(const std::string &addr, uint32_t *ip);
bool parse_ip_address_and_port(const std::string &addr, uint32_t *ip, uint32_t *port);
bool parse_ip_address_and_port(const std::string &addr, std::string *ip, uint16_t *port);
int get_private_network_prefix(uint32_t ip);  // 0, 10, 127, 172, 192 for all classes of private addresses
inline bool is_ip_address_loopback(uint32_t ip) { return get_private_network_prefix(ip) == 127; }
inline bool is_ip_address_private(uint32_t ip) { return get_private_network_prefix(ip) == 0; }
}
