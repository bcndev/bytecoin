// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "P2PClientNew.hpp"
#include <iostream>
#include "Core/Config.hpp"
#include "platform/Time.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"

const float NO_INCOMING_HANDSHAKE_DISCONNECT_TIMEOUT = 30;
const float NO_INCOMING_MESSAGE_DISCONNECT_TIMEOUT   = 60 * 6;
const float NO_OUTGOING_MESSAGE_PING_TIMEOUT         = 60 * 4;

using namespace bytecoin;

static size_t parse_header(const BinaryArray &header_data, np::Header &header, std::string &ban_reason) {
	if (header_data.size() != sizeof(np::Header)) {
		ban_reason = "Levin wrong header size";
		return std::string::npos;
	}
	memmove(&header, header_data.data(), sizeof(np::Header));

	if (header.magic != np::Header::MAGIC) {
		ban_reason = "Magic mismatch";
		return std::string::npos;
	}
	if (header.body_size > np::Header::MAX_PACKET_SIZE) {
		ban_reason = "Packet size is too big";
		return std::string::npos;
	}
	return static_cast<size_t>(header.body_size);
}

static BinaryArray create_header(uint32_t cmd, size_t size) {
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
bytecoin::P2PClientNew::HandlerFunction handler_method(void (bytecoin::P2PClientNew::*handler)(Cmd &&)) {
	return [handler](P2PClientNew *who, BinaryArray &&body) {
		Cmd req{};
		seria::from_binary(req, body);
		(who->*handler)(std::move(req));
	};
}

std::map<uint32_t, P2PClientNew::HandlerFunction> P2PClientNew::handler_functions = {
    {np::Handshake::Request::ID, handler_method<np::Handshake::Request>(&P2PClientNew::msg_handshake)},
    {np::Handshake::Response::ID, handler_method<np::Handshake::Response>(&P2PClientNew::msg_handshake)},
    {np::FindDiff::Request::ID, handler_method<np::FindDiff::Request>(&P2PClientNew::on_msg_find_diff)},
    {np::FindDiff::Response::ID, handler_method<np::FindDiff::Response>(&P2PClientNew::on_msg_find_diff)}};

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

P2PClientNew::P2PClientNew(
    const Config &config, const Currency &currency, uint64_t unique_number, bool incoming, D_handler d_handler)
    : P2PClient(sizeof(np::Header), incoming, d_handler)
    , no_incoming_timer([this]() { disconnect(std::string()); })
    , no_outgoing_timer(std::bind(&P2PClientNew::send_timed_sync, this))
    , unique_number(unique_number)
    , m_config(config)
    , m_currency(currency) {}

void P2PClientNew::send_timed_sync() {
	np::RelayTransactionDescs resp;
	resp.top_block_desc = get_top_block_desc();

	BinaryArray msg = seria::to_binary(resp);
	send(create_header(np::RelayTransactionDescs::ID, msg.size()));
	send(std::move(msg));

	//	no_outgoing_timer.once(NO_OUTGOING_MESSAGE_PING_TIMEOUT);
}

void P2PClientNew::send(BinaryArray &&body) {
	no_outgoing_timer.once(NO_OUTGOING_MESSAGE_PING_TIMEOUT);
	on_msg_bytes(0, body.size());
	P2PClient::send(std::move(body));
}

Timestamp P2PClientNew::get_local_time() const { return platform::now_unix_timestamp(); }

np::PeerDesc P2PClientNew::get_peer_desc() const {
	np::PeerDesc result;
	result.p2p_version        = np::P2PProtocolVersion::EXPERIMENTAL;
	result.local_time         = get_local_time();
	result.peer_id            = unique_number;
	result.my_external_port   = m_config.p2p_external_port;
	result.genesis_block_hash = m_currency.genesis_block_hash;  // TODO
	return result;
}

void P2PClientNew::on_connect() {
	no_incoming_timer.once(NO_INCOMING_HANDSHAKE_DISCONNECT_TIMEOUT);
	if (is_incoming())
		return;
	np::Handshake::Request resp;
	resp.peer_desc      = get_peer_desc();
	resp.top_block_desc = get_top_block_desc();

	BinaryArray msg = seria::to_binary(resp);
	send(create_header(np::Handshake::Request::ID, msg.size()));
	send(std::move(msg));
}

void P2PClientNew::on_disconnect(const std::string &ban_reason) {
	peer_desc = np::PeerDesc{};  // We reuse client instances between connects, so we reinit vars here
	last_received_top_block_desc            = np::TopBlockDesc{};
	first_message_after_handshake_processed = false;
}

size_t P2PClientNew::on_request_header(const BinaryArray &header_data, std::string &ban_reason) const {
	np::Header header{};
	return parse_header(header_data, header, ban_reason);
}

void P2PClientNew::msg_handshake(np::Handshake::Request &&req) {
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

	BinaryArray msg = seria::to_binary(resp);
	send(create_header(np::Handshake::Response::ID, msg.size()));
	send(std::move(msg));

	peer_desc                    = req.peer_desc;
	last_received_top_block_desc = req.top_block_desc;
	std::cout << "P2p COMMAND_HANDSHAKE request version=" << int(peer_desc.p2p_version)
	          << " unique_number=" << peer_desc.peer_id << " current_cd=" << last_received_top_block_desc.cd
	          << std::endl;
	on_msg_handshake(std::move(req));
	//	no_outgoing_timer.once(NO_OUTGOING_MESSAGE_PING_TIMEOUT);
}

void P2PClientNew::msg_handshake(np::Handshake::Response &&req) {
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
	peer_desc                    = req.peer_desc;
	last_received_top_block_desc = req.top_block_desc;
	std::cout << "P2p COMMAND_HANDSHAKE response version=" << int(peer_desc.p2p_version)
	          << " unique_number=" << peer_desc.peer_id << " current_cd=" << last_received_top_block_desc.cd
	          << " peerlist.size=" << req.peerlist.size() << std::endl;
	on_msg_handshake(std::move(req));
	//	no_outgoing_timer.once(NO_OUTGOING_MESSAGE_PING_TIMEOUT);
}
/*void P2PClientNew::msg_ping(COMMAND_PING::request &&req) {
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
void P2PClientNew::msg_ping(COMMAND_PING::response &&req) {
    if (is_incoming()) {
        disconnect("COMMAND_PING response from incoming node");
        return;
    }
    std::cout << "P2p PONG" << std::endl;
    on_msg_ping(std::move(req));
}
void P2PClientNew::msg_timed_sync(COMMAND_TIMED_SYNC::request &&req) {
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
void P2PClientNew::msg_timed_sync(COMMAND_TIMED_SYNC::response &&req) {
    //	std::cout << "P2p COMMAND_TIMED_SYNC response height=" << req.payload_data.current_height << std::endl;
    last_received_sync_data = req.payload_data;
    on_msg_timed_sync(std::move(req));
}*/

void P2PClientNew::on_request_ready() {
	BinaryArray binary_header;
	BinaryArray body;
	while (read_next_request(binary_header, body)) {
		try {
			no_incoming_timer.once(NO_INCOMING_MESSAGE_DISCONNECT_TIMEOUT);
			on_msg_bytes(binary_header.size() + body.size(), 0);
			np::Header header;
			std::string ban_reason;
			if (parse_header(binary_header, header, ban_reason) == std::string::npos) {
				disconnect(ban_reason);
				return;
			}
			if (!handshake_ok()) {
				if (header.command == np::Handshake::Request::ID) {
					np::Handshake::Request req;
					seria::from_binary(req, body);
					msg_handshake(std::move(req));
					continue;
				}
				if (header.command == np::Handshake::Response::ID) {
					np::Handshake::Response req;
					seria::from_binary(req, body);
					msg_handshake(std::move(req));
					continue;
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
				continue;
			}
			std::cout << "Skipping unknown bytecoin::P2P cmd=" << header.command << " size=" << header.body_size
			          << std::endl;
		} catch (const std::exception &ex) {
			disconnect(std::string("299 Exception processing p2p message what=") + ex.what());
			return;
		} catch (...) {
			disconnect("299 Exception processing p2p message");
			return;
		}
	}
}
