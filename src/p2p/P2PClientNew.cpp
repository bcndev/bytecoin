// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "P2PClientNew.hpp"
#include <iostream>
#include "Core/Config.hpp"
#include "platform/Time.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

const float NO_INCOMING_HANDSHAKE_DISCONNECT_TIMEOUT = 30;
const float NO_INCOMING_MESSAGE_DISCONNECT_TIMEOUT   = 60 * 3;
const float NO_OUTGOING_MESSAGE_PING_TIMEOUT         = 60 * 2;

using namespace bytecoin;

bool P2PProtocolNew::parse_header(const BinaryArray &header_data, np::Header &header, std::string &ban_reason) {
	if (header_data.size() != sizeof(np::Header)) {
		ban_reason = "P2P wrong header size";
		return false;
	}
	memmove(&header, header_data.data(), sizeof(np::Header));

	if (header.magic != np::Header::MAGIC) {
		ban_reason = "P2P magic mismatch";
		return false;
	}
	if (header.body_size > np::Header::MAX_PACKET_SIZE) {
		ban_reason = "P2P packet size is too big";
		return false;
	}
	return true;
}

BinaryArray P2PProtocolNew::create_multicast_announce(Hash genesis_bid, uint16_t p2p_external_port) {
	np::Handshake::Request resp;
	resp.peer_desc.p2p_version        = P2PProtocolVersion::V3_NEW;
	resp.peer_desc.p2p_external_port  = p2p_external_port;
	resp.peer_desc.genesis_block_hash = genesis_bid;
	resp.top_block_desc.cd            = 1;
	resp.top_block_desc.hash          = genesis_bid;

	BinaryArray msg = seria::to_binary_kv(resp);
	BinaryArray ha  = P2PProtocolNew::create_header(np::Handshake::Request::ID, msg.size());
	common::append(ha, msg.begin(), msg.end());
	return ha;
}

uint16_t P2PProtocolNew::parse_multicast_announce(const unsigned char *data, size_t size, Hash genesis_bid) {
	try {
		if (size < sizeof(np::Header))
			return 0;
		np::Header header;
		std::string ban_reason;
		if (!parse_header(BinaryArray(data, data + sizeof(np::Header)), header, ban_reason))
			return 0;
		if (header.command != np::Handshake::Request::ID || header.body_size != size - sizeof(np::Header))
			return 0;
		np::Handshake::Request req;
		seria::from_binary_kv(req, BinaryArray(data + sizeof(np::Header), data + size));
		if (req.peer_desc.p2p_version != P2PProtocolVersion::V3_NEW || req.peer_desc.genesis_block_hash != genesis_bid)
			return 0;
		return req.peer_desc.p2p_external_port;
	} catch (const std::exception &) {
	}
	return false;
}

BinaryArray P2PProtocolNew::create_header(uint32_t cmd, size_t size) {
	if (size > np::Header::MAX_PACKET_SIZE)
		throw std::runtime_error("Attempt to send packet with too big size");
	np::Header header{};
	header.magic     = np::Header::MAGIC;
	header.command   = cmd;
	header.body_size = static_cast<uint32_t>(size);
	BinaryArray result(
	    reinterpret_cast<const char *>(&header), reinterpret_cast<const char *>(&header) + sizeof(np::Header));
	return result;
}

template<typename Cmd>
P2PProtocolNew::HandlerFunction handler_method(void (P2PProtocolNew::*handler)(Cmd &&)) {
	return [handler](P2PProtocolNew *who, BinaryArray &&body) {
		Cmd req{};
		seria::from_binary_kv(req, body);
		(who->*handler)(std::move(req));
	};
}

std::map<uint32_t, P2PProtocolNew::HandlerFunction> P2PProtocolNew::handler_functions = {
    {np::Handshake::Request::ID, handler_method<np::Handshake::Request>(&P2PProtocolNew::msg_handshake)},
    {np::Handshake::Response::ID, handler_method<np::Handshake::Response>(&P2PProtocolNew::msg_handshake)},
    {np::FindDiff::Request::ID, handler_method<np::FindDiff::Request>(&P2PProtocolNew::on_msg_find_diff)},
    {np::FindDiff::Response::ID, handler_method<np::FindDiff::Response>(&P2PProtocolNew::on_msg_find_diff)}};

/*std::map<std::pair<uint32_t, bool>, P2PClientBasic::LevinHandlerFunction> P2PClientBasic::before_handshake_handlers =
{
    {{COMMAND_PING::ID, false}, levin_method<COMMAND_PING::request>(&P2PClientBasic::msg_ping)},
    {{COMMAND_PING::ID, true}, levin_method<COMMAND_PING::response>(&P2PClientBasic::msg_ping)},
    {{COMMAND_HANDSHAKE::ID, false}, levin_method<COMMAND_HANDSHAKE::request>(&P2PClientBasic::msg_handshake)},
    {{COMMAND_HANDSHAKE::ID, true}, levin_method<COMMAND_HANDSHAKE::response>(&P2PClientBasic::msg_handshake)}};

std::map<std::pair<uint32_t, bool>, P2PClientBasic::LevinHandlerFunction> P2PClientBasic::after_handshake_handlers = {
    {{COMMAND_TIMED_SYNC::ID, false}, levin_method<COMMAND_TIMED_SYNC::request>(&P2PClientBasic::msg_timed_sync)},
    {{COMMAND_TIMED_SYNC::ID, true}, levin_method<COMMAND_TIMED_SYNC::response>(&P2PClientBasic::msg_timed_sync)},
#if bytecoin_ALLOW_DEBUG_COMMANDS
    {{COMMAND_REQUEST_NETWORK_STATE::ID, false},
        levin_method<COMMAND_REQUEST_NETWORK_STATE::request>(&P2PClientBasic::on_msg_network_state)},
    {{COMMAND_REQUEST_NETWORK_STATE::ID, true},
        levin_method<COMMAND_REQUEST_NETWORK_STATE::response>(&P2PClientBasic::on_msg_network_state)},
    {{COMMAND_REQUEST_STAT_INFO::ID, false},
        levin_method<COMMAND_REQUEST_STAT_INFO::request>(&P2PClientBasic::on_msg_stat_info)},
    {{COMMAND_REQUEST_STAT_INFO::ID, true},
        levin_method<COMMAND_REQUEST_STAT_INFO::response>(&P2PClientBasic::on_msg_stat_info)},
#endif
    {{NOTIFY_NEW_BLOCK::ID, false}, levin_method<NOTIFY_NEW_BLOCK::request>(&P2PClientBasic::on_msg_notify_new_block)},
    {{NOTIFY_NEW_TRANSACTIONS::ID, false},
        levin_method<NOTIFY_NEW_TRANSACTIONS::request>(&P2PClientBasic::on_msg_notify_new_transactions)},
    {{NOTIFY_REQUEST_TX_POOL::ID, false},
        levin_method<NOTIFY_REQUEST_TX_POOL::request>(&P2PClientBasic::on_msg_notify_request_tx_pool)},
    {{NOTIFY_REQUEST_CHAIN::ID, false},
        levin_method<NOTIFY_REQUEST_CHAIN::request>(&P2PClientBasic::on_msg_notify_request_chain)},
    {{NOTIFY_RESPONSE_CHAIN_ENTRY::ID, false},
        levin_method<NOTIFY_RESPONSE_CHAIN_ENTRY::request>(&P2PClientBasic::on_msg_notify_request_chain)},
    {{NOTIFY_REQUEST_GET_OBJECTS::ID, false},
        levin_method<NOTIFY_REQUEST_GET_OBJECTS::request>(&P2PClientBasic::on_msg_notify_request_objects)},
    {{NOTIFY_RESPONSE_GET_OBJECTS::ID, false},
        levin_method<NOTIFY_RESPONSE_GET_OBJECTS::request>(&P2PClientBasic::on_msg_notify_request_objects)}};
*/

P2PProtocolNew::P2PProtocolNew(const Config &config,
    const Currency &currency,
    uint64_t unique_number,
    P2PClient *client)
    : P2PProtocol(client)
    , no_incoming_timer([this]() { disconnect(std::string()); })
    , no_outgoing_timer(std::bind(&P2PProtocolNew::send_timed_sync, this))
    , unique_number(unique_number)
    , m_config(config)
    , m_currency(currency) {}

void P2PProtocolNew::send_timed_sync() {
	np::RelayTransactionDescs resp;
	resp.top_block_desc = get_top_block_desc();

	BinaryArray msg = seria::to_binary_kv(resp);
	send(create_header(np::RelayTransactionDescs::ID, msg.size()));
	send(std::move(msg));
}

void P2PProtocolNew::send(BinaryArray &&body) {
	no_outgoing_timer.once(NO_OUTGOING_MESSAGE_PING_TIMEOUT);
	on_msg_bytes(0, body.size());
	P2PProtocol::send(std::move(body));
}

Timestamp P2PProtocolNew::get_local_time() const { return platform::now_unix_timestamp(); }

np::PeerDesc P2PProtocolNew::get_peer_desc() const {
	np::PeerDesc result;
	result.p2p_version        = P2PProtocolVersion::V3_NEW;
	result.local_time         = get_local_time();
	result.peer_id            = unique_number;
	result.p2p_external_port  = m_config.p2p_external_port;
	result.genesis_block_hash = m_currency.genesis_block_hash;  // TODO
	return result;
}

void P2PProtocolNew::on_connect() {
	no_incoming_timer.once(NO_INCOMING_HANDSHAKE_DISCONNECT_TIMEOUT);
	if (is_incoming())
		return;
	np::Handshake::Request resp;
	resp.peer_desc      = get_peer_desc();
	resp.top_block_desc = get_top_block_desc();

	BinaryArray msg = seria::to_binary_kv(resp);
	send(create_header(np::Handshake::Request::ID, msg.size()));
	send(std::move(msg));
}

void P2PProtocolNew::on_disconnect(const std::string &ban_reason) {
	P2PProtocol::on_disconnect(ban_reason);
	no_incoming_timer.cancel();
	no_outgoing_timer.cancel();
	other_peer_desc      = np::PeerDesc{};  // We reuse client instances between connects, so we reinit vars here
	other_top_block_desc = np::TopBlockDesc{};
	first_message_after_handshake_processed = false;
}

size_t P2PProtocolNew::on_parse_header(common::CircularBuffer &buffer, BinaryArray &request, std::string &ban_reason) {
	np::Header header{};
	if (buffer.size() < sizeof(np::Header))
		return std::string::npos;
	request.resize(sizeof(np::Header));
	buffer.read(request.data(), request.size());
	if (!parse_header(request, header, ban_reason))
		return std::string::npos;  // ban_reason set by parse_header
	return static_cast<size_t>(header.body_size);
}
void P2PProtocolNew::msg_handshake(np::Handshake::Request &&req) {
	if (!is_incoming()) {
		disconnect("Handshake::Request from outgoing node");
		return;
	}
	if (req.peer_desc.genesis_block_hash != m_currency.genesis_block_hash) {
		disconnect("202 wrong network");
		return;
	}
	// on self-connect, incoming side replies so that outgoing side can add to ban
	np::Handshake::Response resp;
	resp.peer_desc      = get_peer_desc();
	resp.top_block_desc = get_top_block_desc();
	resp.peerlist       = get_peers_to_share();

	BinaryArray msg = seria::to_binary_kv(resp);
	send(create_header(np::Handshake::Response::ID, msg.size()));
	send(std::move(msg));

	other_peer_desc      = req.peer_desc;
	other_top_block_desc = req.top_block_desc;
	std::cout << "NewP2p COMMAND_HANDSHAKE request version=" << int(other_peer_desc.p2p_version)
	          << " unique_number=" << other_peer_desc.peer_id << " current_cd=" << other_top_block_desc.cd << std::endl;
	on_msg_handshake(std::move(req));
	//	no_outgoing_timer.once(NO_OUTGOING_MESSAGE_PING_TIMEOUT);
}

void P2PProtocolNew::msg_handshake(np::Handshake::Response &&req) {
	if (is_incoming()) {
		disconnect("Handshake::Response response from incoming node");
		return;
	}
	if (req.peer_desc.genesis_block_hash != m_currency.genesis_block_hash) {
		disconnect("202 wrong network");
		return;
	}
	// self-connect, incoming side replies so that outgoing side can add to ban
	if (req.peer_desc.peer_id == unique_number) {
		disconnect("203 self-connect");
		return;
	}
	other_peer_desc      = req.peer_desc;
	other_top_block_desc = req.top_block_desc;
	std::cout << "NewP2p COMMAND_HANDSHAKE response version=" << int(other_peer_desc.p2p_version)
	          << " unique_number=" << other_peer_desc.peer_id << " current_cd=" << other_top_block_desc.cd
	          << " peerlist.size=" << req.peerlist.size() << std::endl;
	on_msg_handshake(std::move(req));
	//	no_outgoing_timer.once(NO_OUTGOING_MESSAGE_PING_TIMEOUT);
}

void P2PProtocolNew::on_request_ready(BinaryArray &&binary_header, BinaryArray &&body) {
	try {
		no_incoming_timer.once(NO_INCOMING_MESSAGE_DISCONNECT_TIMEOUT);
		on_msg_bytes(binary_header.size() + body.size(), 0);
		np::Header header;
		std::string ban_reason;
		if (!parse_header(binary_header, header, ban_reason)) {
			disconnect(ban_reason);
			return;
		}
		if (!handshake_ok()) {
			if (header.command == np::Handshake::Request::ID) {
				np::Handshake::Request req;
				seria::from_binary_kv(req, body);
				msg_handshake(std::move(req));
				return;
			}
			if (header.command == np::Handshake::Response::ID) {
				np::Handshake::Response req;
				seria::from_binary_kv(req, body);
				msg_handshake(std::move(req));
				return;
			}
			disconnect("202 Expecting handshake");
			return;
		}
		auto ha = handler_functions.find(header.command);
		if (ha != handler_functions.end()) {
			(ha->second)(this, std::move(body));
			if (!first_message_after_handshake_processed) {
				first_message_after_handshake_processed = true;
				on_first_message_after_handshake();
			}
			return;
		}
		std::cout << "Skipping unknown bytecoin::P2P cmd=" << header.command << " size=" << header.body_size
		          << std::endl;
	} catch (const std::exception &ex) {
		disconnect(std::string("299 Exception processing p2p message what=") + common::what(ex));
		return;
	} catch (...) {
		disconnect("299 Exception processing p2p message");
		return;
	}
}
