// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Ipv4Address.hpp"
#include <boost/lexical_cast.hpp>
#include <stdexcept>
#include "StringTools.hpp"

namespace common {

std::string ip_address_to_string(uint32_t ip) {
	uint8_t bytes[4]{};
	bytes[0] = uint8_t(ip & 0xFF);
	bytes[1] = uint8_t((ip >> 8) & 0xFF);
	bytes[2] = uint8_t((ip >> 16) & 0xFF);
	bytes[3] = uint8_t((ip >> 24) & 0xFF);

	char buf[16]{};
	sprintf(buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

	return std::string(buf);
}

std::string ip_address_and_port_to_string(uint32_t ip, uint32_t port) {
	uint8_t bytes[4]{};
	bytes[0] = uint8_t(ip & 0xFF);
	bytes[1] = uint8_t((ip >> 8) & 0xFF);
	bytes[2] = uint8_t((ip >> 16) & 0xFF);
	bytes[3] = uint8_t((ip >> 24) & 0xFF);

	char buf[24]{};
	sprintf(buf, "%d.%d.%d.%d:%d", bytes[0], bytes[1], bytes[2], bytes[3], port);

	return std::string(buf);
}

bool parse_ip_address(const std::string &addr, uint32_t *ip) {
	uint32_t v[4]{};

	if (sscanf(addr.c_str(), "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]) != 4) {
		return false;
	}

	for (int i = 0; i < 4; ++i) {
		if (v[i] > 0xff) {
			return false;
		}
	}

	*ip = (v[3] << 24u) | (v[2] << 16u) | (v[1] << 8u) | v[0];
	return true;
}

bool parse_ip_address_and_port(const std::string &addr, uint32_t *ip, uint32_t *port) {
	uint32_t v[4]{};
	uint32_t local_port = 0;

	if (sscanf(addr.c_str(), "%u.%u.%u.%u:%u", &v[0], &v[1], &v[2], &v[3], &local_port) != 5) {
		return false;
	}

	for (int i = 0; i < 4; ++i) {
		if (v[i] > 0xff) {
			return false;
		}
	}

	*ip = (v[3] << 24u) | (v[2] << 16u) | (v[1] << 8u) | v[0];
	if (local_port > 65535)
		return false;
	*port = local_port;
	return true;
}

bool parse_ip_address_and_port(const std::string &addr, std::string *ip, uint16_t *port) {
	uint32_t sip = 0, sport = 0;
	if (!parse_ip_address_and_port(addr, &sip, &sport))
		return false;
	*port = static_cast<uint16_t>(sport);
	*ip   = ip_address_to_string(sip);
	return true;
}

int get_private_network_prefix(uint32_t ip) {
	uint8_t bytes[4]{};
	bytes[0] = uint8_t(ip & 0xFF);
	bytes[1] = uint8_t((ip >> 8) & 0xFF);
	bytes[2] = uint8_t((ip >> 16) & 0xFF);
	bytes[3] = uint8_t((ip >> 24) & 0xFF);
	if (bytes[0] == 127)  // 127.x.x.x
		return 127;
	if (bytes[0] == 10)  // 10.0.0.0/8
		return 10;
	if (bytes[0] == 192 && bytes[1] == 168)  // 192.168.0.0/16
		return 192;
	if (bytes[0] == 172 && (bytes[1] & 0xf0) == 16)  // 172.16.0.0/12
		return 172;
	return 0;
}
}
