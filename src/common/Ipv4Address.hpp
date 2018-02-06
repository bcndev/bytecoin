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

#include <cstdint>
#include <string>

namespace common {

std::string ip_address_to_string(uint32_t ip);
std::string ip_address_and_port_to_string(uint32_t ip, uint32_t port);
bool parse_ip_address(uint32_t &ip, const std::string &addr);
bool parse_ip_address_and_port(uint32_t &ip, uint32_t &port, const std::string &addr);
bool parse_ip_address_and_port(std::string &ip, uint16_t &port, const std::string &addr); // convenient for config parsing
bool is_ip_address_loopback(uint32_t ip);
bool is_ip_address_private(uint32_t ip);

}
