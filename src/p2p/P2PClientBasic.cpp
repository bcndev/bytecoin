// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "P2PClientBasic.hpp"
#include <iostream>
#include "Core/Config.hpp"
#include "platform/Time.hpp"

const float HANDSHAKE_TIMEOUT  = 30;
const float MESSAGE_TIMEOUT    = 60 * 6;
const float TIMED_SYNC_TIMEOUT = 60 * 4;

using namespace bytecoin;

template<typename Cmd>
P2PProtocolBasic::LevinHandlerFunction levin_method(void (P2PProtocolBasic::*handler)(Cmd &&)) {
	return [handler](P2PProtocolBasic *who, BinaryArray &&body) {

		Cmd req{};
		if (!LevinProtocol::decode(body, req)) {
			who->disconnect("Request failed to parse");
			return;
		}

		(who->*handler)(std::move(req));
	};
}

std::map<std::pair<uint32_t, bool>, P2PProtocolBasic::LevinHandlerFunction>
    P2PProtocolBasic::before_handshake_handlers = {
        {{COMMAND_PING::ID, false}, levin_method<COMMAND_PING::request>(&P2PProtocolBasic::msg_ping)},
        {{COMMAND_PING::ID, true}, levin_method<COMMAND_PING::response>(&P2PProtocolBasic::msg_ping)},
        {{COMMAND_HANDSHAKE::ID, false}, levin_method<COMMAND_HANDSHAKE::request>(&P2PProtocolBasic::msg_handshake)},
        {{COMMAND_HANDSHAKE::ID, true}, levin_method<COMMAND_HANDSHAKE::response>(&P2PProtocolBasic::msg_handshake)}};

std::map<std::pair<uint32_t, bool>, P2PProtocolBasic::LevinHandlerFunction> P2PProtocolBasic::after_handshake_handlers =
    {{{COMMAND_TIMED_SYNC::ID, false}, levin_method<COMMAND_TIMED_SYNC::request>(&P2PProtocolBasic::msg_timed_sync)},
        {{COMMAND_TIMED_SYNC::ID, true}, levin_method<COMMAND_TIMED_SYNC::response>(&P2PProtocolBasic::msg_timed_sync)},
#if bytecoin_ALLOW_DEBUG_COMMANDS
        {{COMMAND_REQUEST_NETWORK_STATE::ID, false},
            levin_method<COMMAND_REQUEST_NETWORK_STATE::request>(&P2PProtocolBasic::on_msg_network_state)},
        {{COMMAND_REQUEST_NETWORK_STATE::ID, true},
            levin_method<COMMAND_REQUEST_NETWORK_STATE::response>(&P2PProtocolBasic::on_msg_network_state)},
        {{COMMAND_REQUEST_STAT_INFO::ID, false},
            levin_method<COMMAND_REQUEST_STAT_INFO::request>(&P2PProtocolBasic::on_msg_stat_info)},
        {{COMMAND_REQUEST_STAT_INFO::ID, true},
            levin_method<COMMAND_REQUEST_STAT_INFO::response>(&P2PProtocolBasic::on_msg_stat_info)},
#endif
        {{NOTIFY_NEW_BLOCK::ID, false},
            levin_method<NOTIFY_NEW_BLOCK::request>(&P2PProtocolBasic::on_msg_notify_new_block)},
        {{NOTIFY_NEW_TRANSACTIONS::ID, false},
            levin_method<NOTIFY_NEW_TRANSACTIONS::request>(&P2PProtocolBasic::on_msg_notify_new_transactions)},
        {{NOTIFY_REQUEST_TX_POOL::ID, false},
            levin_method<NOTIFY_REQUEST_TX_POOL::request>(&P2PProtocolBasic::on_msg_notify_request_tx_pool)},
        {{NOTIFY_REQUEST_CHAIN::ID, false},
            levin_method<NOTIFY_REQUEST_CHAIN::request>(&P2PProtocolBasic::on_msg_notify_request_chain)},
        {{NOTIFY_RESPONSE_CHAIN_ENTRY::ID, false},
            levin_method<NOTIFY_RESPONSE_CHAIN_ENTRY::request>(&P2PProtocolBasic::on_msg_notify_request_chain)},
        {{NOTIFY_CHECKPOINT::ID, false},
            levin_method<NOTIFY_CHECKPOINT::request>(&P2PProtocolBasic::on_msg_notify_checkpoint)},
        {{NOTIFY_REQUEST_GET_OBJECTS::ID, false},
            levin_method<NOTIFY_REQUEST_GET_OBJECTS::request>(&P2PProtocolBasic::on_msg_notify_request_objects)},
        {{NOTIFY_RESPONSE_GET_OBJECTS::ID, false},
            levin_method<NOTIFY_RESPONSE_GET_OBJECTS::request>(&P2PProtocolBasic::on_msg_notify_request_objects)}};

P2PProtocolBasic::P2PProtocolBasic(const Config &config, uint64_t unique_number, P2PClient *client)
    : P2PProtocol(client)
    , no_activity_timer([this]() { disconnect(std::string()); })
    , timed_sync_timer(std::bind(&P2PProtocolBasic::send_timed_sync, this))
    , unique_number(unique_number)
    , config(config) {}

void P2PProtocolBasic::send_timed_sync() {
	COMMAND_TIMED_SYNC::request req;
	req.payload_data = get_sync_data();

	BinaryArray msg = LevinProtocol::send_message(COMMAND_TIMED_SYNC::ID, LevinProtocol::encode(req), true);

	send(std::move(msg));

	timed_sync_timer.once(TIMED_SYNC_TIMEOUT);
}

void P2PProtocolBasic::send(BinaryArray &&body) {
	timed_sync_timer.once(TIMED_SYNC_TIMEOUT);
	on_msg_bytes(0, body.size());
	P2PProtocol::send(std::move(body));
}

Timestamp P2PProtocolBasic::get_local_time() const { return platform::now_unix_timestamp(); }

basic_node_data P2PProtocolBasic::get_node_data() const {
	basic_node_data node_data;
	node_data.version    = P2PProtocolVersion::CURRENT;
	node_data.local_time = get_local_time();
	node_data.peer_id    = unique_number;
	node_data.my_port    = config.p2p_external_port;
	node_data.network_id = config.network_id;
	return node_data;
}

void P2PProtocolBasic::on_connect() {
	no_activity_timer.once(HANDSHAKE_TIMEOUT);
	if (is_incoming())
		return;
	COMMAND_HANDSHAKE::request req;
	req.payload_data = get_sync_data();
	req.node_data    = get_node_data();

	BinaryArray msg = LevinProtocol::send_message(COMMAND_HANDSHAKE::ID, LevinProtocol::encode(req), true);

	send(std::move(msg));
}

void P2PProtocolBasic::on_disconnect(const std::string &ban_reason) {
	P2PProtocol::on_disconnect(ban_reason);
	timed_sync_timer.cancel();
	no_activity_timer.cancel();
	version                                 = 0;  // We reuse client instances between connects, so we reinit vars here
	first_message_after_handshake_processed = false;
	last_received_sync_data                 = CORE_SYNC_DATA{};
	last_received_unique_number             = 0;
}

size_t P2PProtocolBasic::on_parse_header(
    common::CircularBuffer &buffer, BinaryArray &request, std::string &ban_reason) {
	if (!handshake_ok() && buffer.size() > 0 && *buffer.read_ptr() != LevinProtocol::FIRST_BYTE()) {
		on_immediate_protocol_switch(*buffer.read_ptr());
		return std::string::npos;
	}
	LevinProtocol::Command cmd;
	if (buffer.size() < LevinProtocol::HEADER_SIZE())
		return std::string::npos;
	request.resize(LevinProtocol::HEADER_SIZE());
	buffer.read(request.data(), request.size());
	auto body_size = LevinProtocol::read_command_header(request, cmd, ban_reason);
	if (body_size == std::string::npos)
		return std::string::npos;  // ban_reason set by LevinProtocol
	return static_cast<size_t>(body_size);
}

void P2PProtocolBasic::msg_handshake(COMMAND_HANDSHAKE::request &&req) {
	if (!is_incoming()) {
		disconnect("COMMAND_HANDSHAKE from outgoing node");
		return;
	}
	if (req.node_data.network_id != config.network_id) {
		disconnect("202 wrong network");
		return;
	}
	// on self-connect, incoming side replies so that outgoing side can add to ban
	COMMAND_HANDSHAKE::response msg;
	msg.payload_data   = get_sync_data();
	msg.node_data      = get_node_data();
	msg.local_peerlist = get_peers_to_share();

	BinaryArray raw_msg = LevinProtocol::send_reply(COMMAND_HANDSHAKE::ID, LevinProtocol::encode(msg), 0);
	send(std::move(raw_msg));
	version                     = req.node_data.version;
	last_received_sync_data     = req.payload_data;
	last_received_unique_number = req.node_data.peer_id;
	update_my_port(req.node_data.my_port);  // We set port to unknown on accept

	std::cout << "P2p COMMAND_HANDSHAKE request version=" << int(req.node_data.version)
	          << " unique_number=" << req.node_data.peer_id << " current_height=" << req.payload_data.current_height
	          << " from " << get_address() << std::endl;
	timed_sync_timer.once(TIMED_SYNC_TIMEOUT);  // Order important, can switch to different protocol
	on_msg_handshake(std::move(req));
}
void P2PProtocolBasic::msg_handshake(COMMAND_HANDSHAKE::response &&req) {
	if (is_incoming()) {
		disconnect("COMMAND_HANDSHAKE response from incoming node");
		return;
	}
	if (req.node_data.network_id != config.network_id) {
		disconnect("202 wrong network");
		return;
	}
	// self-connect, incoming side replies so that outgoing side can add to ban
	if (req.node_data.peer_id == unique_number) {
		disconnect("203 self-connect");
		return;
	}
	version                     = req.node_data.version;
	last_received_unique_number = req.node_data.peer_id;
	last_received_sync_data     = req.payload_data;
	std::cout << "P2p COMMAND_HANDSHAKE response version=" << int(req.node_data.version)
	          << " unique_number=" << req.node_data.peer_id << " current_height=" << req.payload_data.current_height
	          << " local_peerlist.size=" << req.local_peerlist.size() << " from " << get_address() << std::endl;
	timed_sync_timer.once(TIMED_SYNC_TIMEOUT);  // Order important, can switch to different protocol
	on_msg_handshake(std::move(req));
}
void P2PProtocolBasic::msg_ping(COMMAND_PING::request &&req) {
	if (!is_incoming()) {
		disconnect("COMMAND_PING from outgoing node");
		return;
	}
	COMMAND_PING::response msg;
	msg.status  = COMMAND_PING::status_ok();
	msg.peer_id = unique_number;

	BinaryArray raw_msg = LevinProtocol::send_reply(COMMAND_PING::ID, LevinProtocol::encode(msg), 0);
	send(std::move(raw_msg));
	send_shutdown();
	std::cout << "P2p PING" << std::endl;
	on_msg_ping(std::move(req));
}
void P2PProtocolBasic::msg_ping(COMMAND_PING::response &&req) {
	if (is_incoming()) {
		disconnect("COMMAND_PING response from incoming node");
		return;
	}
	std::cout << "P2p PONG" << std::endl;
	on_msg_ping(std::move(req));
}
void P2PProtocolBasic::msg_timed_sync(COMMAND_TIMED_SYNC::request &&req) {
	//	std::cout << "P2p COMMAND_TIMED_SYNC request height=" << req.payload_data.current_height << std::endl;
	last_received_sync_data = req.payload_data;

	COMMAND_TIMED_SYNC::response msg;
	msg.payload_data   = get_sync_data();
	msg.local_time     = get_local_time();
	msg.local_peerlist = get_peers_to_share();

	BinaryArray raw_msg = LevinProtocol::send_reply(COMMAND_TIMED_SYNC::ID, LevinProtocol::encode(msg), 0);
	send(std::move(raw_msg));
	on_msg_timed_sync(std::move(req));
}
void P2PProtocolBasic::msg_timed_sync(COMMAND_TIMED_SYNC::response &&req) {
	//	std::cout << "P2p COMMAND_TIMED_SYNC response height=" << req.payload_data.current_height << std::endl;
	last_received_sync_data = req.payload_data;
	on_msg_timed_sync(std::move(req));
}

void P2PProtocolBasic::on_request_ready(BinaryArray &&header, BinaryArray &&body) {
	try {
		no_activity_timer.once(MESSAGE_TIMEOUT);
		on_msg_bytes(header.size() + body.size(), 0);
		LevinProtocol::Command cmd;
		std::string ban_reason;
		if (LevinProtocol::read_command_header(header, cmd, ban_reason) == std::string::npos) {
			disconnect(ban_reason);
			return;
		}
		if (!handshake_ok()) {
			auto ha = before_handshake_handlers.find({cmd.command, cmd.is_response});
			if (ha != before_handshake_handlers.end()) {
				(ha->second)(this, std::move(body));
				return;
			}
			disconnect("202 Expecting handshake or ping");
			return;
		}
		auto ha = after_handshake_handlers.find({cmd.command, cmd.is_response});
		if (ha != after_handshake_handlers.end()) {
			if (!first_message_after_handshake_processed) {
				first_message_after_handshake_processed = true;
				on_first_message_after_handshake();
			}
			(ha->second)(this, std::move(body));
			return;
		}
		std::cout << "generic bytecoin::P2P cmd={" << cmd.command << "} " << cmd.is_response << " " << cmd.is_notify
		          << std::endl;
	} catch (const std::exception &ex) {
		disconnect(std::string("299 Exception processing p2p message what=") + common::what(ex));
		return;
	} catch (...) {
		disconnect("299 Exception processing p2p message");
		return;
	}
}
