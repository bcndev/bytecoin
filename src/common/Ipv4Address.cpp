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

#include "Ipv4Address.hpp"
#include <stdexcept>

namespace common {

std::string ip_address_to_string(uint32_t ip) {
	uint8_t bytes[4]{};
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;

	char buf[16]{};
	sprintf(buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

	return std::string(buf);
}

std::string ip_address_and_port_to_string(uint32_t ip, uint32_t port) {
	uint8_t bytes[4]{};
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;

	char buf[24]{};
	sprintf(buf, "%d.%d.%d.%d:%d", bytes[0], bytes[1], bytes[2], bytes[3], port);

	return std::string(buf);
}

bool parse_ip_address(uint32_t &ip, const std::string &addr) {
	uint32_t v[4]{};

	if (sscanf(addr.c_str(), "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]) != 4) {
		return false;
	}

	for (int i = 0; i < 4; ++i) {
		if (v[i] > 0xff) {
			return false;
		}
	}

	ip = (v[3] << 24) | (v[2] << 16) | (v[1] << 8) | v[0];
	return true;
}

bool parse_ip_address_and_port(uint32_t &ip, uint32_t &port, const std::string &addr) {
	uint32_t v[4]{};
	uint32_t localPort = 0;

	if (sscanf(addr.c_str(), "%u.%u.%u.%u:%u", &v[0], &v[1], &v[2], &v[3], &localPort) != 5) {
		return false;
	}

	for (int i = 0; i < 4; ++i) {
		if (v[i] > 0xff) {
			return false;
		}
	}

	ip = (v[3] << 24) | (v[2] << 16) | (v[1] << 8) | v[0];
	if( localPort > 65535 )
		return false;
	port = localPort;
	return true;
}

bool parse_ip_address_and_port(std::string &ip, uint16_t &port, const std::string &addr){
	uint32_t sip = 0, sport = 0;
	if(!parse_ip_address_and_port(sip, sport, addr))
		return false;
	port = static_cast<uint16_t>(sport);
	ip = ip_address_to_string(sip);
	return true;
}

bool is_ip_address_loopback(uint32_t ip) {
	return (ip & 0xff000000) == (127 << 24);
}

bool is_ip_address_private(uint32_t ip) {
	return
		// 10.0.0.0/8
			(ip & 0xff000000) == (10u << 24) ||
			// 172.16.0.0/12
			(ip & 0xfff00000) == ((172u << 24) | (16u << 16)) ||
			// 192.168.0.0/16
			(ip & 0xffff0000) == ((192u << 24) | (168u << 16));
}

}
