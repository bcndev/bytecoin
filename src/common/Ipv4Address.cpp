// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Ipv4Address.hpp"
#include <stdexcept>
#include "StringTools.hpp"

namespace common {

std::string NetworkAddress::to_string() const { return common::ip_address_and_port_to_string(ip, port); }

std::string ip_address_to_string(const BinaryArray &ip) {
	if (ip.size() != 4)
		return "?.?.?.?";
	char buf[16]{};
	sprintf(buf, "%u.%u.%u.%u", ip.data()[0], ip.data()[1], ip.data()[2], ip.data()[3]);

	return std::string(buf);
}

uint32_t ip_address_to_legacy(const BinaryArray &ip) {
	if (ip.size() != 4)
		return 0;
	return (static_cast<uint32_t>(ip.data()[0])) | (static_cast<uint32_t>(ip.data()[1]) << 8) |
	       (static_cast<uint32_t>(ip.data()[2]) << 16) | (static_cast<uint32_t>(ip.data()[3]) << 24);
}
BinaryArray ip_address_from_legacy(uint32_t ip) {
	return BinaryArray{static_cast<uint8_t>(ip), static_cast<uint8_t>(ip >> 8), static_cast<uint8_t>(ip >> 16),
	    static_cast<uint8_t>(ip >> 24)};
}

std::string ip_address_and_port_to_string(const BinaryArray &ip, uint16_t port) {
	if (ip.size() != 4)
		return "?.?.?.?";
	char buf[24]{};
	sprintf(buf, "%u.%u.%u.%u:%u", ip.data()[0], ip.data()[1], ip.data()[2], ip.data()[3], port);

	return std::string(buf);
}

bool parse_ip_address(const std::string &addr, BinaryArray *ip) {
	uint32_t v[4]{};

	if (sscanf(addr.c_str(), "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]) != 4) {
		return false;
	}

	for (size_t i = 0; i < 4; ++i) {
		if (v[i] > 0xff) {
			return false;
		}
	}
	*ip = BinaryArray{
	    static_cast<uint8_t>(v[0]), static_cast<uint8_t>(v[1]), static_cast<uint8_t>(v[2]), static_cast<uint8_t>(v[3])};
	//	*ip = (v[3] << 24) | (v[2] << 16) | (v[1] << 8) | v[0];
	return true;
}

// TODO - add IPv6 support
bool parse_ip_address_and_port(const std::string &addr, BinaryArray *ip, uint16_t *port) {
	uint32_t v[4]{};
	uint32_t local_port = 0;

	if (sscanf(addr.c_str(), "%u.%u.%u.%u:%u", &v[0], &v[1], &v[2], &v[3], &local_port) != 5) {
		return false;
	}

	for (size_t i = 0; i < 4; ++i) {
		if (v[i] > 0xff) {
			return false;
		}
	}

	*ip = BinaryArray{
	    static_cast<uint8_t>(v[0]), static_cast<uint8_t>(v[1]), static_cast<uint8_t>(v[2]), static_cast<uint8_t>(v[3])};
	if (local_port > 65535)
		return false;
	*port = static_cast<uint16_t>(local_port);
	return true;
}

bool parse_ip_address_and_port(const std::string &addr, std::string *ip, uint16_t *port) {
	BinaryArray sip;
	if (!parse_ip_address_and_port(addr, &sip, port))
		return false;
	//	*port = static_cast<uint16_t>(sport);
	*ip = ip_address_to_string(sip);
	return true;
}

int get_private_network_prefix(const BinaryArray &ip) {
	if (ip.size() != 4)
		return 6;
	if (ip.data()[0] == 127)  // 127.x.x.x
		return 127;
	if (ip.data()[0] == 10)  // 10.0.0.0/8
		return 10;
	if (ip.data()[0] == 192 && ip.data()[1] == 168)  // 192.168.0.0/16
		return 192;
	if (ip.data()[0] == 172 && (ip.data()[1] & 0xf0) == 16)  // 172.16.0.0/12
		return 172;
	return 0;
}
}  // namespace common
