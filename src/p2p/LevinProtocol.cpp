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

#pragma pack(push)
#pragma pack(1)
struct bucket_head2 {  // also good description of a person who invented this data structure
	uint64_t m_magic;
	uint32_t m_cb;
	uint32_t ignored_cb;     // former high 32 bits of 64-bit m_cb
	uint8_t m_command_type;  // former m_have_to_return_data
	uint32_t m_command;
	uint32_t ignored1;  // former m_return_code
	uint32_t m_flags;
	uint32_t ignored3;  // former m_protocol_version
};
#pragma pack(pop)
}  // namespace

// We made some changes so we can simplify in future
// Versions up to 3.5.0 encode command type in this way
//          m_command_type   m_flags
// NOTIFY                0         1
// REQUEST               1         1
// RESPONSE              0         2

// And decode as follows
// type = (m_flags & 2) == 2 ? RESPONSE : head.m_command_type ? REQUEST : NOTIFY;

// From 3.5.1 we encode as follows
//          m_command_type   m_flags
// NOTIFY                0         1
// REQUEST               1         1
// RESPONSE              2         2

// So that we can have direct mapping between command type and the m_command_type

// Also we can wish to get rid of type later and just assign new id to all commands
// and put it into ignored_cb field, so that header is clean (magic|size|command) tuple

BinaryArray LevinProtocol::send(CommandType rrn, uint32_t command, const BinaryArray &out) {
	bucket_head2 head   = {};
	head.m_magic        = LEVIN_MAGIC;
	head.m_cb           = common::integer_cast<uint32_t>(out.size());
	head.m_command_type = rrn;
	head.m_command      = command;
	head.m_flags        = rrn == RESPONSE ? LEVIN_PACKET_RESPONSE : LEVIN_PACKET_REQUEST;

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
	*rrn     = (head.m_flags & LEVIN_PACKET_RESPONSE) == LEVIN_PACKET_RESPONSE ? RESPONSE
	                                                                       : head.m_command_type ? REQUEST : NOTIFY;
	return common::integer_cast<size_t>(head.m_cb);
}
