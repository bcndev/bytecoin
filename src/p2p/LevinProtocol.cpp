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

#include "LevinProtocol.hpp"

using namespace bytecoin;

namespace {

const uint64_t LEVIN_SIGNATURE = 0x0101010101012101LL;  //Bender's nightmare
const uint32_t LEVIN_PACKET_REQUEST = 0x00000001;
const uint32_t LEVIN_PACKET_RESPONSE = 0x00000002;
const uint32_t LEVIN_DEFAULT_MAX_PACKET_SIZE = 100000000;      //100MB by default
const uint32_t LEVIN_PROTOCOL_VER_1 = 1;

#pragma pack(push)
#pragma pack(1)
struct bucket_head2 {
	uint64_t m_signature;
	uint64_t m_cb;
	uint8_t m_have_to_return_data;
	uint32_t m_command;
	int32_t m_return_code;
	uint32_t m_flags;
	uint32_t m_protocol_version;
};
#pragma pack(pop)

}

BinaryArray LevinProtocol::sendMessage(uint32_t command, const BinaryArray &out, bool needResponse) {
	bucket_head2 head = {};
	head.m_signature = LEVIN_SIGNATURE;
	head.m_cb = out.size();
	head.m_have_to_return_data = needResponse;
	head.m_command = command;
	head.m_protocol_version = LEVIN_PROTOCOL_VER_1;
	head.m_flags = LEVIN_PACKET_REQUEST;

	// write header and body in one operation
	BinaryArray writeBuffer;
	writeBuffer.reserve(sizeof(head) + out.size());

	common::VectorOutputStream stream(writeBuffer);
    stream.write_some(&head, sizeof(head));
    stream.write_some(out.data(), out.size());

	return writeBuffer;
}

size_t LevinProtocol::HEADER_SIZE() {
	return sizeof(bucket_head2);
}

size_t LevinProtocol::readCommandHeader(const BinaryArray &raw_header, Command &cmd, std::string &ban_reason) {
	bucket_head2 head = {};
	if (raw_header.size() != sizeof(head)) {
		ban_reason = "Levin wrong header size";
		return std::string::npos;
	}
	memmove(&head, raw_header.data(), sizeof(head));

	if (head.m_signature != LEVIN_SIGNATURE) {
		ban_reason = "Levin signature mismatch";
		return std::string::npos;
	}

	if (head.m_cb > LEVIN_DEFAULT_MAX_PACKET_SIZE) {
		ban_reason = "Levin packet size is too big";
		return std::string::npos;
	}

	cmd.command = head.m_command;
//  cmd.buf = std::move(buf);
	cmd.isNotify = !head.m_have_to_return_data;
	cmd.isResponse = (head.m_flags & LEVIN_PACKET_RESPONSE) == LEVIN_PACKET_RESPONSE;

	return static_cast<size_t>(head.m_cb);
}

BinaryArray LevinProtocol::sendReply(uint32_t command, const BinaryArray &out, int32_t returnCode) {
	bucket_head2 head = {};
	head.m_signature = LEVIN_SIGNATURE;
	head.m_cb = out.size();
	head.m_have_to_return_data = false;
	head.m_command = command;
	head.m_protocol_version = LEVIN_PROTOCOL_VER_1;
	head.m_flags = LEVIN_PACKET_RESPONSE;
	head.m_return_code = returnCode;

	BinaryArray writeBuffer;
	writeBuffer.reserve(sizeof(head) + out.size());

	common::VectorOutputStream stream(writeBuffer);
    stream.write_some(&head, sizeof(head));
    stream.write_some(out.data(), out.size());

	return writeBuffer;
}

