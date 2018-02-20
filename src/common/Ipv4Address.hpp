// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include <cstdint>
#include <string>

namespace common {

std::string ip_address_to_string(uint32_t ip);
std::string ip_address_and_port_to_string(uint32_t ip, uint32_t port);
bool parse_ip_address(uint32_t &ip, const std::string &addr);
bool parse_ip_address_and_port(uint32_t &ip, uint32_t &port, const std::string &addr);
bool parse_ip_address_and_port(
    std::string &ip, uint16_t &port, const std::string &addr);  // convenient for config parsing
bool is_ip_address_loopback(uint32_t ip);
bool is_ip_address_private(uint32_t ip);
}
