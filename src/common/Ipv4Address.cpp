// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Ipv4Address.hpp"
#include "Math.hpp"
#include "StringTools.hpp"
#include "exception.hpp"

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

BinaryArray parse_ip_address(const std::string &addr) {
	std::string v[4];
	if (!common::split_string(addr, ".", v[0], v[1], v[2], v[3]))
		throw std::runtime_error("IP Address must be in a.b.c.d format");
	try {
		return BinaryArray{integer_cast<uint8_t>(v[0]), integer_cast<uint8_t>(v[1]), integer_cast<uint8_t>(v[2]),
		    integer_cast<uint8_t>(v[3])};
	} catch (const std::exception &) {
		std::throw_with_nested(std::runtime_error("IP Address component must be in range 0.255"));
	}
}

bool parse_ip_address(const std::string &addr, BinaryArray *ip) {
	try {
		*ip = parse_ip_address(addr);
		return true;
	} catch (const std::exception &) {
	}
	return false;
}

// TODO - add IPv6 support
void parse_ip_address_and_port(const std::string &addr, BinaryArray *ip, uint16_t *port) {
	std::string sip;
	std::string sport;
	if (!common::split_string(addr, ":", sip, sport))
		throw std::runtime_error("Address must be in ip:port format");
	*ip = parse_ip_address(sip);
	ewrap(*port = integer_cast<uint16_t>(sport), std::runtime_error("Port must be in range 0..65535"));
}

void parse_ip_address_and_port(const std::string &addr, std::string *ip, uint16_t *port) {
	BinaryArray sip;
	parse_ip_address_and_port(addr, &sip, port);
	*ip = ip_address_to_string(sip);
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
