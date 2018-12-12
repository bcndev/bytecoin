// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "P2PProtocolBasic.hpp"
#include <iostream>
#include "Core/Config.hpp"
#include "platform/Time.hpp"

using namespace cn;

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

template<typename Cmd>
std::pair<std::pair<uint32_t, LevinProtocol::CommandType>, std::pair<P2PProtocolBasic::LevinHandlerFunction, size_t>>
levin_pair(void (P2PProtocolBasic::*handler)(Cmd &&)) {
	return std::make_pair(std::make_pair(Cmd::ID, static_cast<LevinProtocol::CommandType>(Cmd::TYPE)),
	    std::make_pair(levin_method(handler), Cmd::MAX_SIZE));
}

const std::map<std::pair<uint32_t, LevinProtocol::CommandType>,
    std::pair<P2PProtocolBasic::LevinHandlerFunction, size_t>>
    P2PProtocolBasic::before_handshake_handlers = {levin_pair<p2p::PingLegacy::Request>(&P2PProtocolBasic::msg_ping),
        levin_pair<p2p::PingLegacy::Response>(&P2PProtocolBasic::msg_ping),
        levin_pair<p2p::Handshake::Request>(&P2PProtocolBasic::msg_handshake),
        levin_pair<p2p::Handshake::Response>(&P2PProtocolBasic::msg_handshake)};

const std::map<std::pair<uint32_t, LevinProtocol::CommandType>,
    std::pair<P2PProtocolBasic::LevinHandlerFunction, size_t>>
    P2PProtocolBasic::after_handshake_handlers = {
        levin_pair<p2p::TimedSync::Request>(&P2PProtocolBasic::msg_timed_sync),
        levin_pair<p2p::TimedSync::Response>(&P2PProtocolBasic::msg_timed_sync),
#if bytecoin_ALLOW_DEBUG_COMMANDS
        levin_pair<p2p::GetStatInfo::Request>(&P2PProtocolBasic::on_msg_stat_info),
        levin_pair<p2p::GetStatInfo::Response>(&P2PProtocolBasic::on_msg_stat_info),
#endif
        levin_pair<p2p::RelayBlock::Notify>(&P2PProtocolBasic::on_msg_notify_new_block),
        levin_pair<p2p::RelayTransactions::Notify>(&P2PProtocolBasic::on_msg_notify_new_transactions),
        levin_pair<p2p::SyncPool::Notify>(&P2PProtocolBasic::on_msg_notify_request_tx_pool),
        levin_pair<p2p::SyncPool::Request>(&P2PProtocolBasic::on_msg_notify_request_tx_pool),
        levin_pair<p2p::SyncPool::Response>(&P2PProtocolBasic::on_msg_notify_request_tx_pool),
        levin_pair<p2p::GetChainRequest::Notify>(&P2PProtocolBasic::on_msg_notify_request_chain),
        levin_pair<p2p::GetChainResponse::Notify>(&P2PProtocolBasic::on_msg_notify_request_chain),
        levin_pair<p2p::Checkpoint::Notify>(&P2PProtocolBasic::on_msg_notify_checkpoint),
        levin_pair<p2p::GetObjectsRequest::Notify>(&P2PProtocolBasic::on_msg_notify_request_objects),
        levin_pair<p2p::GetObjectsResponse::Notify>(&P2PProtocolBasic::on_msg_notify_request_objects)};

P2PProtocolBasic::P2PProtocolBasic(const Config &config, uint64_t my_unique_number, P2PClient *client)
    : P2PProtocol(client)
    , no_incoming_timer([this]() { disconnect(std::string()); })
    , no_outgoing_timer(std::bind(&P2PProtocolBasic::send_timed_sync, this))
    , my_unique_number(my_unique_number)
    , config(config) {}

void P2PProtocolBasic::send_timed_sync() {
	p2p::TimedSync::Request req;
	req.payload_data = get_my_sync_data();

	BinaryArray msg = LevinProtocol::send(req);

	send(std::move(msg));
}

void P2PProtocolBasic::send(BinaryArray &&body) {
	no_outgoing_timer.once(float(config.p2p_no_outgoing_message_ping_timeout));
	on_msg_bytes(0, body.size());
	P2PProtocol::send(std::move(body));
}

Timestamp P2PProtocolBasic::get_local_time() const { return platform::now_unix_timestamp(); }

BasicNodeData P2PProtocolBasic::get_my_node_data() const {
	BasicNodeData node_data;
	node_data.version    = P2PProtocolVersion::AMETHYST;
	node_data.local_time = get_local_time();
	node_data.peer_id    = my_unique_number;
	node_data.my_port    = config.p2p_external_port;
	node_data.network_id = config.network_id;
	return node_data;
}

void P2PProtocolBasic::on_connect() {
	no_incoming_timer.once(float(config.p2p_no_incoming_handshake_disconnect_timeout));
	if (is_incoming())
		return;
	p2p::Handshake::Request req;
	req.payload_data = get_my_sync_data();
	req.node_data    = get_my_node_data();

	BinaryArray msg = LevinProtocol::send(req);

	send(std::move(msg));
}

void P2PProtocolBasic::on_disconnect(const std::string &ban_reason) {
	P2PProtocol::on_disconnect(ban_reason);
	// We reuse client instances between connects, so we reinit vars here
	no_outgoing_timer.cancel();
	no_incoming_timer.cancel();
	peer_version                            = P2PProtocolVersion::NO_HANDSHAKE_YET;
	first_message_after_handshake_processed = false;
	set_peer_sync_data(CoreSyncData{});
	peer_unique_number = 0;
}

size_t P2PProtocolBasic::on_parse_header(common::CircularBuffer &buffer, BinaryArray &request) {
	if (buffer.size() < LevinProtocol::HEADER_SIZE())
		return std::string::npos;
	request.resize(LevinProtocol::HEADER_SIZE());
	buffer.read(request.data(), request.size());
	uint32_t command                        = 0;
	LevinProtocol::CommandType command_type = LevinProtocol::REQUEST;
	size_t size                             = LevinProtocol::read_command_header(request, &command_type, &command);
	size_t max_size                         = p2p::UNKNOWN_COMMAND_MAX_SIZE;
	if (!handshake_ok()) {  // peer_version unknown
		auto ha = before_handshake_handlers.find({command, command_type});
		if (ha == before_handshake_handlers.end())
			throw std::runtime_error("202 Expecting handshake or ping");
		max_size = ha->second.second;
	} else {
		if (peer_version < P2PProtocolVersion::AMETHYST)  // Legacy rules are very primitive
			max_size = p2p::LEVIN_DEFAULT_MAX_PACKET_SIZE;
		else {
			auto ha = after_handshake_handlers.find({command, command_type});
			if (ha != after_handshake_handlers.end())
				max_size = ha->second.second;
		}
	}
	if (size > max_size)
		throw std::runtime_error("Command too big cmd=" + common::to_string(command) +
		                         " size=" + common::to_string(size) + " max_size=" + common::to_string(max_size));
	return size;
}

void P2PProtocolBasic::msg_handshake(p2p::Handshake::Request &&req) {
	if (!is_incoming()) {
		disconnect("p2p::Handshake from outgoing node");
		return;
	}
	if (req.node_data.network_id != config.network_id) {
		if (!config.allow_empty_network_id || req.node_data.network_id != UUID{}) {
			disconnect("202 wrong network");
			return;
		}
	}
	// on self-connect, incoming side replies so that outgoing side can add to ban
	p2p::Handshake::Response msg;
	msg.payload_data   = get_my_sync_data();
	msg.node_data      = get_my_node_data();
	msg.local_peerlist = get_peers_to_share(true);
	if (msg.local_peerlist.size() > p2p::Handshake::Response::MAX_PEER_COUNT)
		msg.local_peerlist.resize(p2p::Handshake::Response::MAX_PEER_COUNT);

	BinaryArray raw_msg = LevinProtocol::send(msg);
	send(std::move(raw_msg));
	peer_version = req.node_data.version;
	set_peer_sync_data(req.payload_data);
	peer_unique_number = req.node_data.peer_id;
	update_my_port(req.node_data.my_port);  // We set port to unknown on accept

	std::cout << "P2p p2p::Handshake request version=" << int(req.node_data.version)
	          << " unique_number=" << req.node_data.peer_id << " current_height=" << req.payload_data.current_height
	          << " from " << get_address() << std::endl;
	on_msg_handshake(std::move(req));
}
void P2PProtocolBasic::msg_handshake(p2p::Handshake::Response &&req) {
	if (is_incoming())
		return disconnect("p2p::Handshake response from incoming node");
	if (req.node_data.network_id != config.network_id)
		return disconnect("202 wrong network");
	// self-connect, incoming side replies so that outgoing side can add to ban
	if (req.node_data.peer_id == my_unique_number)
		return disconnect("203 self-connect");
	peer_version = req.node_data.version;
	if (peer_version >= P2PProtocolVersion::AMETHYST &&
	    req.local_peerlist.size() > p2p::Handshake::Response::MAX_PEER_COUNT)
		return disconnect("204 max_peer_count");
	peer_unique_number = req.node_data.peer_id;
	set_peer_sync_data(req.payload_data);
	std::cout << "P2p p2p::Handshake response version=" << int(req.node_data.version)
	          << " unique_number=" << req.node_data.peer_id << " current_height=" << req.payload_data.current_height
	          << " local_peerlist.size=" << req.local_peerlist.size() << " from " << get_address() << std::endl;
	on_msg_handshake(std::move(req));
}
void P2PProtocolBasic::msg_ping(p2p::PingLegacy::Request &&req) {
	if (!is_incoming()) {
		disconnect("p2p::PingLegacy from outgoing node");
		return;
	}
	p2p::PingLegacy::Response msg;
	msg.status  = p2p::PingLegacy::status_ok();
	msg.peer_id = my_unique_number;

	BinaryArray raw_msg = LevinProtocol::send(msg);
	send(std::move(raw_msg));
	send_shutdown();
	std::cout << "P2p PING" << std::endl;
	on_msg_ping(std::move(req));
}
void P2PProtocolBasic::msg_ping(p2p::PingLegacy::Response &&req) {
	if (is_incoming()) {
		disconnect("p2p::PingLegacy response from incoming node");
		return;
	}
	std::cout << "P2p PONG" << std::endl;
	on_msg_ping(std::move(req));
}
void P2PProtocolBasic::msg_timed_sync(p2p::TimedSync::Request &&req) {
	//	std::cout << "P2p p2p::TimedSync request height=" << req.payload_data.current_height << std::endl;
	set_peer_sync_data(req.payload_data);

	p2p::TimedSync::Response msg;
	msg.payload_data   = get_my_sync_data();
	msg.local_time     = get_local_time();
	msg.local_peerlist = get_peers_to_share(false);
	if (msg.local_peerlist.size() > p2p::TimedSync::Response::MAX_PEER_COUNT)
		msg.local_peerlist.resize(p2p::TimedSync::Response::MAX_PEER_COUNT);

	BinaryArray raw_msg = LevinProtocol::send(msg);
	send(std::move(raw_msg));
	on_msg_timed_sync(std::move(req));
}
void P2PProtocolBasic::msg_timed_sync(p2p::TimedSync::Response &&req) {
	//	std::cout << "P2p p2p::TimedSync response height=" << req.payload_data.current_height << std::endl;
	if (peer_version >= P2PProtocolVersion::AMETHYST &&
	    req.local_peerlist.size() > p2p::TimedSync::Response::MAX_PEER_COUNT)
		return disconnect("204 max_peer_count");
	set_peer_sync_data(req.payload_data);
	on_msg_timed_sync(std::move(req));
}

void P2PProtocolBasic::on_request_ready(BinaryArray &&header, BinaryArray &&body) {
	try {
		no_incoming_timer.once(float(config.p2p_no_incoming_message_disconnect_timeout));
		on_msg_bytes(header.size() + body.size(), 0);
		uint32_t command                        = 0;
		LevinProtocol::CommandType command_type = LevinProtocol::REQUEST;
		LevinProtocol::read_command_header(header, &command_type, &command);
		if (!handshake_ok()) {
			auto ha = before_handshake_handlers.find({command, command_type});
			if (ha != before_handshake_handlers.end()) {
				(ha->second.first)(this, std::move(body));
				return;
			}
			disconnect("202 Expecting handshake or ping");
			return;
		}
		auto ha = after_handshake_handlers.find({command, command_type});
		if (ha != after_handshake_handlers.end()) {
			if (!first_message_after_handshake_processed) {
				first_message_after_handshake_processed = true;
				on_first_message_after_handshake();
			}
			(ha->second.first)(this, std::move(body));
			return;
		}
		std::cout << "generic cn::P2P cmd={" << command << "} type=" << command_type << std::endl;
	} catch (const std::exception &ex) {
		disconnect(std::string("299 Exception processing p2p message what=") + common::what(ex));
		return;
	} catch (...) {
		disconnect("299 Exception processing p2p message");
		return;
	}
}

BinaryArray P2PProtocolBasic::create_multicast_announce(const UUID &network_id,
    Hash genesis_bid,
    uint16_t p2p_external_port) {
	p2p::Handshake::Response resp;
	resp.node_data.version           = P2PProtocolVersion::NO_HANDSHAKE_YET;  // We do not check it, though
	resp.node_data.my_port           = p2p_external_port;
	resp.node_data.network_id        = network_id;
	resp.payload_data.current_height = 0;
	resp.payload_data.top_id         = genesis_bid;

	BinaryArray raw_msg = LevinProtocol::send(resp);
	return raw_msg;
}

uint16_t P2PProtocolBasic::parse_multicast_announce(const unsigned char *data,
    size_t size,
    const UUID &network_id,
    Hash genesis_bid) {
	try {
		if (size < LevinProtocol::HEADER_SIZE())
			return 0;
		LevinProtocol::CommandType cct;
		uint32_t command = 0;
		size_t packet_size =
		    LevinProtocol::read_command_header(BinaryArray{data, data + LevinProtocol::HEADER_SIZE()}, &cct, &command);
		if (cct != static_cast<LevinProtocol::CommandType>(p2p::Handshake::Response::TYPE) ||
		    command != p2p::Handshake::Response::ID || LevinProtocol::HEADER_SIZE() + packet_size > size)
			return 0;
		p2p::Handshake::Response req;
		if (!LevinProtocol::decode(
		        BinaryArray{data + LevinProtocol::HEADER_SIZE(), data + LevinProtocol::HEADER_SIZE() + packet_size},
		        req))
			return 0;
		if (req.node_data.network_id != network_id || req.payload_data.top_id != genesis_bid)
			return 0;
		return req.node_data.my_port;
	} catch (const std::exception &) {
	}
	return 0;
}
