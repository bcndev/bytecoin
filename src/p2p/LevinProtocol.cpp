// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "LevinProtocol.hpp"
#include "common/Math.hpp"
#include "common/StringTools.hpp"

using namespace cn;

namespace {

const uint64_t LEVIN_MAGIC           = 0x0101010101012101LL;  // Bender's nightmare
const uint32_t LEVIN_PACKET_REQUEST  = 1;
const uint32_t LEVIN_PACKET_RESPONSE = 2;
const uint32_t LEVIN_PROTOCOL_VER_1  = 1;

#pragma pack(push)
#pragma pack(1)
struct bucket_head2 {  // also good description of a person who invented this data structure
	uint64_t m_magic;
	uint64_t m_cb;
	uint8_t m_have_to_return_data;  // should be in flags
	uint32_t m_command;
	int32_t m_return_code;  // never checked
	uint32_t m_flags;
	uint32_t m_protocol_version;  // never checked. stupid to be last variable anyway
};
#pragma pack(pop)
}  // namespace

BinaryArray LevinProtocol::send(CommandType rrn, uint32_t command, const BinaryArray &out, int32_t return_code) {
	bucket_head2 head          = {};
	head.m_magic               = LEVIN_MAGIC;
	head.m_cb                  = out.size();
	head.m_have_to_return_data = (rrn == REQUEST) ? uint8_t(1) : uint8_t(0);
	head.m_command             = command;
	head.m_return_code         = return_code;
	head.m_protocol_version    = LEVIN_PROTOCOL_VER_1;
	head.m_flags               = rrn == RESPONSE ? LEVIN_PACKET_RESPONSE : LEVIN_PACKET_REQUEST;

	// write header and body in one operation
	BinaryArray write_buffer;
	write_buffer.reserve(sizeof(head) + out.size());

	common::VectorOutputStream stream(write_buffer);
	stream.write_some(&head, sizeof(head));
	stream.write_some(out.data(), out.size());

	return write_buffer;
}

size_t LevinProtocol::HEADER_SIZE() { return sizeof(bucket_head2); }

size_t LevinProtocol::read_command_header(const BinaryArray &raw_header, CommandType *rrn, uint32_t *command) {
	bucket_head2 head = {};
	if (raw_header.size() != sizeof(head))
		throw std::runtime_error("Levin wrong header size " + common::to_string(raw_header.size()));
	memmove(&head, raw_header.data(), sizeof(head));  // TODO - endian

	if (head.m_magic != LEVIN_MAGIC)
		throw std::runtime_error("Levin magic mismatch raw_header=" + common::to_hex(raw_header));

	*command = head.m_command;
	*rrn     = (head.m_flags & LEVIN_PACKET_RESPONSE) == LEVIN_PACKET_RESPONSE
	           ? RESPONSE
	           : head.m_have_to_return_data ? REQUEST : NOTIFY;
	return common::integer_cast<size_t>(head.m_cb);
}
