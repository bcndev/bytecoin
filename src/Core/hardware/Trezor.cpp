// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Trezor.hpp"
#include <ctime>
#include <iostream>
#include "Core/TransactionBuilder.hpp"
#include "CryptoNote.hpp"
#include "common/BIPs.hpp"
#include "common/Invariant.hpp"
#include "common/MemoryStreams.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "http/ResponseParser.hpp"
#include "seria/BinaryInputStream.hpp"

#include "trezor/messages-bytecoin.hpp"
#include "trezor/messages-common.hpp"
#include "trezor/messages.hpp"

using namespace cn;
using namespace cn::hardware;
using namespace common;
using namespace hw::trezor;

using namespace boost::asio::ip;

// Good description is here - https://github.com/trezor/trezord-go/blob/master/README.md

static http::ResponseBody sync_http_request(tcp::socket &socket, const http::RequestBody &req) {
	std::string str = req.r.to_string();
	boost::system::error_code error;
	boost::asio::write(socket, boost::asio::buffer(str.data(), str.size()), error);
	if (error)
		throw boost::system::system_error(error);
	boost::asio::write(socket, boost::asio::buffer(req.body.data(), req.body.size()), error);
	if (error)
		throw boost::system::system_error(error);

	http::ResponseBody response;
	http::ResponseParser parser;
	bool receiving_body = false;

	while (!receiving_body || response.body.size() < response.r.content_length) {
		boost::array<char, 128> buf;
		char *ptr = buf.data();
		boost::system::error_code error;

		size_t len = socket.read_some(boost::asio::buffer(ptr, buf.size()), error);
		if (error == boost::asio::error::eof)
			throw boost::system::system_error(error);
		if (error)
			throw boost::system::system_error(error);
		if (!receiving_body) {
			auto header_end = parser.parse(response.r, ptr, ptr + len) - ptr;
			if (!parser.is_bad() && !parser.is_good())
				continue;
			if (!response.r.has_content_length())
				throw std::runtime_error("no content length in reply");
			ptr += header_end;
			len -= header_end;
			receiving_body = true;
		}
		if (len + response.body.size() > response.r.content_length)
			throw std::runtime_error("too much body");
		response.body += std::string(ptr, len);
	}
	return response;
}

static http::ResponseBody trezor_post(tcp::socket &socket, std::string uri, std::string &&body) {
	http::RequestBody req;
	req.r.set_firstline("POST", uri, 1, 1);
	req.r.headers.push_back({"Host", "127.0.0.1:21325"});
	req.r.headers.push_back({"Accept", "*/*"});
	req.r.headers.push_back({"Origin", "https://beta-wallet.trezor.io"});
	req.set_body(std::move(body));
	return sync_http_request(socket, req);
}

template<class M>
std::string encode(const M &mbody, int mid) {
	std::string str = protobuf::write(mbody);  // mbody.SerializeAsString();
	uint8_t header[6];
	common::uint_be_to_bytes(header, 2, unsigned(mid));
	common::uint_be_to_bytes(header + 2, 4, str.size());
	return common::to_hex(header, 6) + common::to_hex(str.data(), str.size());
}

template<class M>
bool decode_any(M &msg, int should_be_mid, tcp::socket &socket, const std::string &session, const std::string &body) {
	//	std::cout << body << std::endl;
	unsigned char header[6];
	if (!common::from_hex(body.substr(0, 12), header, 6))
		return false;
	size_t mid       = common::uint_be_from_bytes<size_t>(header, 2);
	std::string str2 = common::as_string(common::from_hex(body.substr(12)));
	std::cout << "Trezor msg mid=" << mid << " body size=" << str2.size() << std::endl;
	if (mid == messages::MessageType_Failure) {
		messages::common::Failure mad;
		protobuf::read(mad, str2.begin(), str2.end());
		//		mad.ParseFromString(str2);
		std::cout << mad.code << " " << mad.message << std::endl;
		return false;
	}
	if (mid == messages::MessageType_ButtonRequest) {
		messages::common::ButtonRequest mad;
		protobuf::read(mad, str2.begin(), str2.end());
		//		mad.ParseFromString(str2);
		std::cout << mad.code << " " << mad.data << std::endl;
		messages::common::ButtonAck bac;
		auto resp = trezor_post(socket, "/call/" + session, encode(bac, messages::MessageType_ButtonAck));
		return decode_any(msg, should_be_mid, socket, session, resp.body);
	}
	if (mid == size_t(should_be_mid)) {
		protobuf::read(msg, str2.begin(), str2.end());
		//		msg.ParseFromString(str2);
		return true;
	}
	return false;
}

void Trezor::add_connected(std::vector<std::unique_ptr<HardwareWallet>> *result) {
	tcp::socket socket(platform::EventLoop::current()->io());
	//	boost::system::error_code error;
	//	if (error)
	//		return;
	try {
		tcp::endpoint trezor_ep(boost::asio::ip::address::from_string("127.0.0.1"), 21325);
		socket.connect(trezor_ep);
		auto resp = trezor_post(socket, "/enumerate", "");
		std::cout << resp.body << std::endl;

		auto en = common::JsonValue::from_string(resp.body);
		if (en.get_array().size() == 0) {
			std::cout << "No Trezor devices connected" << std::endl;
			return;
		}
		for (const auto &o : en.get_array()) {
			auto path = o("path").get_string();
			auto s    = o("session");
			if (s.is_string()) {
				std::cout << "Trezor device locked, try again or disconnect and reconnect it from USB. path=" << path
				          << " session=" << s.get_string() << std::endl;
				auto resp = trezor_post(socket, "/release/" + s.get_string(), "");
				std::cout << resp.body << std::endl;
			}
			try {
				result->emplace_back(std::make_unique<Trezor>(path));
			} catch (const std::exception &) {
			}
		}
	} catch (const std::exception &) {
	}
}

void Trezor::acquire() {
	//	if(!m_session.empty()) throw Exception("Trezor device locked");
	//    auto resp = trezor_post(m_socket, "/acquire/" + m_path + "/null", "");
	//    std::cout << resp.body << std::endl;
	//    auto en = common::JsonValue::from_string(resp.body);
	//    m_session = en("session").get_string();
}

void Trezor::release() {
	//	if(m_session.empty()) throw Exception("Trezor device locked");
	//    auto resp = trezor_post(m_socket, "/release/" + m_session, "");
	//    std::cout << resp.body << std::endl;
	//    m_session.clear();
}

Trezor::Trezor(const std::string &path) : m_path(path), m_socket(platform::EventLoop::current()->io()) {
	//	GOOGLE_PROTOBUF_VERIFY_VERSION;

	tcp::endpoint trezor_ep(boost::asio::ip::address::from_string("127.0.0.1"), 21325);
	m_socket.connect(trezor_ep);

	{
		if (!m_session.empty())
			throw Exception("Trezor device locked, session=" + m_session);
		auto resp = trezor_post(m_socket, "/acquire/" + m_path + "/null", "");
		//		std::cout << resp.body << std::endl;
		auto en   = common::JsonValue::from_string(resp.body);
		m_session = en("session").get_string();
	}
	acquire();

	//	messages::monero::MoneroGetWatchKey ga;
	//	ga.add_address_n(0x8000002c); // 0x80000031
	//	ga.add_address_n(0x80000080); // 0x80000080
	//	ga.add_address_n(0x80000000);
	//	ga.add_address_n(0);
	//	ga.add_address_n(0);
	//    auto http_resp = trezor_post(m_socket, "/call/" + m_session, encode(ga,
	//    messages::MessageType_MoneroGetWatchKey)); messages::monero::MoneroWatchKey resp2;
	//    invariant(decode_any(resp2, messages::MessageType_MoneroWatchKey, m_socket, m_session,
	//    http_resp.body), "");

	messages::bytecoin::BytecoinStartRequest req;

	//	messages::bytecoin::BytecoinStartRequest req2;
	//	messages::bytecoin::BytecoinStartRequest req3;
	//	auto tmp = req.SerializeAsString();
	//	protobuf::read(req2, tmp.begin(), tmp.end());
	//	req3.ParseFromString(protobuf::write(req2));

	auto http_resp =
	    trezor_post(m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinStartRequest));
	messages::bytecoin::BytecoinStartResponse resp;
	if (!decode_any(resp, messages::MessageType_BytecoinStartResponse, m_socket, m_session, http_resp.body))
		throw Exception("Trezor bytecoin init message failed to decode, msg=" + http_resp.body);
	std::string major;
	std::string minor;
	if (!split_string(resp.version, ".", major, minor))
		throw Exception("Trezor wrong version format " + resp.version + ", please update your Trezor");
	try {
		unsigned ma = common::integer_cast<unsigned>(major);
		//		unsigned mi = common::integer_cast<unsigned>(minor);
		if (ma < 4)
			throw Exception("Trezor app version too low " + resp.version + ", please update your Trezor");
	} catch (const std::exception &) {
		std::throw_with_nested(
		    Exception("Trezor wrong version format " + resp.version + ", please update your Trezor"));
	}
	//	messages::bytecoin::BytecoinStartResponse resp2;
	//	messages::bytecoin::BytecoinStartResponse resp3;
	//	tmp = resp.SerializeAsString();
	//	std::cout << common::to_hex(common::as_binary_array(tmp)) << std::endl;
	//	protobuf::read(resp2, tmp.begin(), tmp.end());
	//	resp3.ParseFromString(protobuf::write(resp2));

	auto dr = resp.version;
	std::cout << common::to_hex(dr.data(), dr.size()) << std::endl;

	seria::from_binary(m_wallet_key, resp.wallet_key);
	seria::from_binary(m_A_plus_sH, resp.A_plus_sH);
	seria::from_binary(m_v_mul_A_plus_sH, resp.v_mul_A_plus_sH);
	seria::from_binary(m_view_public_key, resp.view_public_key);

	release();
	//	messages::monero::MoneroGetAddress ga;
	//    std::string str = ga.SerializeAsString();
	//    uint8_t header[6];
	// common::uint_be_to_bytes(header, 2, unsigned(messages::MessageType_MoneroGetAddress));
	//    common::uint_be_to_bytes(header, 2, unsigned(messages::MessageType_BytecoinStartRequest));
	//    common::uint_be_to_bytes(header + 2, 4, str.size());
	//    resp = trezor_post(socket, "/call/" + session, common::to_hex(header, 6) + common::to_hex(str.data(),
	//    str.size())); decode_any(socket, session, resp.body); resp = trezor_post(socket, "/release/" + session, "");
	//    std::cout << resp.body << std::endl;
}

Trezor::~Trezor() {}

std::string Trezor::get_hardware_type() const { return "Trezor path=" + m_path; }

std::vector<cn::PublicKey> Trezor::scan_outputs(const std::vector<cn::PublicKey> &output_public_keys) {
	invariant(output_public_keys.size() <= get_scan_outputs_max_batch(), "");
	std::vector<PublicKey> result;
	acquire();
	messages::bytecoin::BytecoinScanOutputsRequest req;
	for (const auto &src : output_public_keys)
		req.output_public_key.push_back(common::as_string(src.data, sizeof(PublicKey)));
	auto http_resp =
	    trezor_post(m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinScanOutputsRequest));
	messages::bytecoin::BytecoinScanOutputsResponse resp;
	if (!decode_any(resp, messages::MessageType_BytecoinScanOutputsResponse, m_socket, m_session, http_resp.body))
		throw Exception("Trezor bytecoin scan_outputs message failed to decode, msg=" + http_resp.body);
	for (const auto &dst : resp.Pv) {
		PublicKey pv;
		seria::from_binary(pv, dst);
		result.push_back(pv);
	}
	release();
	return result;
}

cn::KeyImage Trezor::generate_keyimage(const common::BinaryArray &output_secret_hash_arg, size_t address_index) {
	acquire();
	messages::bytecoin::BytecoinGenerateKeyimageRequest req;
	req.output_secret_hash_arg = common::as_string(output_secret_hash_arg);
	req.address_index          = static_cast<uint32_t>(address_index);
	auto http_resp =
	    trezor_post(m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinGenerateKeyimageRequest));
	messages::bytecoin::BytecoinGenerateKeyimageResponse resp;
	if (!decode_any(resp, messages::MessageType_BytecoinGenerateKeyimageResponse, m_socket, m_session, http_resp.body))
		throw Exception("Trezor bytecoin generate_keyimage message failed to decode, msg=" + http_resp.body);
	KeyImage result;
	seria::from_binary(result, resp.keyimage);
	release();
	return result;
}

Hash Trezor::generate_output_seed(const Hash &tx_inputs_hash, size_t out_index) {
	acquire();
	messages::bytecoin::BytecoinGenerateOutputSeedRequest req;
	req.tx_inputs_hash = common::as_string(tx_inputs_hash.data, sizeof(Hash));
	req.out_index      = static_cast<uint32_t>(out_index);
	auto http_resp     = trezor_post(
        m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinGenerateOutputSeedRequest));
	messages::bytecoin::BytecoinGenerateOutputSeedResponse resp;
	if (!decode_any(
	        resp, messages::MessageType_BytecoinGenerateOutputSeedResponse, m_socket, m_session, http_resp.body))
		throw Exception("Trezor bytecoin generate_output_seed message failed to decode, msg=" + http_resp.body);
	Hash result;
	seria::from_binary(result, resp.output_seed);
	release();
	return result;
}

void Trezor::sign_start(size_t version, uint64_t ut, size_t inputs_size, size_t outputs_size, size_t extra_size) {
	acquire();
	messages::bytecoin::BytecoinSignStartRequest req;
	req.version      = static_cast<uint32_t>(version);
	req.ut           = ut;
	req.inputs_size  = static_cast<uint32_t>(inputs_size);
	req.outputs_size = static_cast<uint32_t>(outputs_size);
	req.extra_size   = static_cast<uint32_t>(extra_size);
	auto http_resp =
	    trezor_post(m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinSignStartRequest));
	messages::bytecoin::BytecoinEmptyResponse resp;
	if (!decode_any(resp, messages::MessageType_BytecoinEmptyResponse, m_socket, m_session, http_resp.body))
		throw Exception("Trezor bytecoin sign_start message failed to decode, msg=" + http_resp.body);
	release();
}

void Trezor::sign_add_input(uint64_t amount, const std::vector<size_t> &output_indexes,
    const common::BinaryArray &output_secret_hash_arg, size_t address_index) {
	acquire();
	messages::bytecoin::BytecoinSignAddInputRequest req;
	req.amount = amount;
	for (auto index : output_indexes)
		req.output_indexes.push_back(static_cast<uint32_t>(index));
	req.output_secret_hash_arg = common::as_string(output_secret_hash_arg);
	req.address_index          = static_cast<uint32_t>(address_index);
	auto http_resp =
	    trezor_post(m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinSignAddInputRequest));
	messages::bytecoin::BytecoinEmptyResponse resp;
	if (!decode_any(resp, messages::MessageType_BytecoinEmptyResponse, m_socket, m_session, http_resp.body))
		throw Exception("Trezor bytecoin sign_add_input message failed to decode, msg=" + http_resp.body);
	release();
}

void Trezor::sign_add_output(bool change, uint64_t amount, size_t change_address_index, uint8_t dst_address_tag,
    PublicKey dst_address_s, PublicKey dst_address_s_v, PublicKey *public_key, PublicKey *encrypted_secret,
    uint8_t *encrypted_address_type) {
	acquire();
	messages::bytecoin::BytecoinSignAddOutputRequest req;
	req.change               = change;
	req.amount               = amount;
	req.change_address_index = static_cast<uint32_t>(change_address_index);
	req.dst_address_tag      = dst_address_tag;
	req.dst_address_S        = common::as_string(dst_address_s.data, sizeof(PublicKey));
	req.dst_address_Sv       = common::as_string(dst_address_s_v.data, sizeof(PublicKey));
	auto http_resp =
	    trezor_post(m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinSignAddOutputRequest));
	messages::bytecoin::BytecoinSignAddOutputResponse resp;
	if (!decode_any(resp, messages::MessageType_BytecoinSignAddOutputResponse, m_socket, m_session, http_resp.body))
		throw Exception("Trezor bytecoin sign_add_output message failed to decode, msg=" + http_resp.body);
	seria::from_binary(*public_key, resp.public_key);
	seria::from_binary(*encrypted_secret, resp.encrypted_secret);
	*encrypted_address_type = common::integer_cast<uint8_t>(resp.encrypted_address_type);
	release();
}

const size_t MAX_EXTRA_CHUNK = 128;

void Trezor::sign_add_extra(const BinaryArray &chunk) {
	acquire();
	size_t pos = 0;
	while (true) {
		size_t stop = std::min(chunk.size(), pos + MAX_EXTRA_CHUNK);
		messages::bytecoin::BytecoinSignAddExtraRequest req;
		req.extra_chunk = common::as_string(chunk.data() + pos, stop - pos);
		auto http_resp =
		    trezor_post(m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinSignAddExtraRequest));
		messages::bytecoin::BytecoinEmptyResponse resp;
		if (!decode_any(resp, messages::MessageType_BytecoinEmptyResponse, m_socket, m_session, http_resp.body))
			throw Exception("Trezor bytecoin sign_add_extra message failed to decode, msg=" + http_resp.body);
		pos = stop;
		if (pos == chunk.size())
			break;
	}
	release();
}

void Trezor::sign_step_a(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
    crypto::EllipticCurvePoint *sig_p, crypto::EllipticCurvePoint *y, crypto::EllipticCurvePoint *z) {
	acquire();
	messages::bytecoin::BytecoinSignStepARequest req;
	req.output_secret_hash_arg = common::as_string(output_secret_hash_arg);
	req.address_index          = static_cast<uint32_t>(address_index);
	auto http_resp =
	    trezor_post(m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinSignStepARequest));
	messages::bytecoin::BytecoinSignStepAResponse resp;
	if (!decode_any(resp, messages::MessageType_BytecoinSignStepAResponse, m_socket, m_session, http_resp.body))
		throw Exception("Trezor bytecoin sign_step_a message failed to decode, msg=" + http_resp.body);
	seria::from_binary(*sig_p, resp.sig_p);
	seria::from_binary(*y, resp.y);
	seria::from_binary(*z, resp.z);
	release();
}

void Trezor::sign_step_a_more_data(const BinaryArray &data) {
	acquire();
	size_t pos = 0;
	while (true) {
		size_t stop = std::min(data.size(), pos + MAX_EXTRA_CHUNK);
		messages::bytecoin::BytecoinSignStepAMoreDataRequest req;
		req.data_chunk = common::as_string(data.data() + pos, stop - pos);
		auto http_resp = trezor_post(
		    m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinSignStepAMoreDataRequest));
		messages::bytecoin::BytecoinEmptyResponse resp;
		if (!decode_any(resp, messages::MessageType_BytecoinEmptyResponse, m_socket, m_session, http_resp.body))
			throw Exception("Trezor bytecoin sign_step_a_more_data message failed to decode, msg=" + http_resp.body);
		pos = stop;
		if (pos == data.size())
			break;
	}
	release();
}

crypto::EllipticCurveScalar Trezor::sign_get_c0() {
	acquire();
	messages::bytecoin::BytecoinSignGetC0Request req;
	auto http_resp =
	    trezor_post(m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinSignGetC0Request));
	messages::bytecoin::BytecoinSignGetC0Response resp;
	if (!decode_any(resp, messages::MessageType_BytecoinSignGetC0Response, m_socket, m_session, http_resp.body))
		throw Exception("Trezor bytecoin sign_get_c0 message failed to decode, msg=" + http_resp.body);
	crypto::EllipticCurveScalar c0;
	seria::from_binary(c0, resp.c0);
	release();
	return c0;
}

void Trezor::sign_step_b(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
    crypto::EllipticCurveScalar my_c, Hash *sig_my_rr, Hash *sig_rs, Hash *sig_ra, Hash *e_key) {
	acquire();
	messages::bytecoin::BytecoinSignStepBRequest req;
	req.output_secret_hash_arg = common::as_string(output_secret_hash_arg);
	req.address_index          = static_cast<uint32_t>(address_index);
	req.my_c                   = common::as_string(my_c.data, sizeof(crypto::EllipticCurveScalar));
	auto http_resp =
	    trezor_post(m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinSignStepBRequest));
	messages::bytecoin::BytecoinSignStepBResponse resp;
	if (!decode_any(resp, messages::MessageType_BytecoinSignStepBResponse, m_socket, m_session, http_resp.body))
		throw Exception("Trezor bytecoin sign_step_b message failed to decode, msg=" + http_resp.body);
	seria::from_binary(*sig_my_rr, resp.my_rr);
	seria::from_binary(*sig_rs, resp.rs);
	seria::from_binary(*sig_ra, resp.ra);
	seria::from_binary(*e_key, resp.encryption_key);
	release();
}

void Trezor::proof_start(const common::BinaryArray &data) {
	acquire();
	messages::bytecoin::BytecoinStartProofRequest req;
	req.data_size = common::integer_cast<uint32_t>(data.size());
	auto http_resp =
	    trezor_post(m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinStartProofRequest));
	messages::bytecoin::BytecoinEmptyResponse resp;
	if (!decode_any(resp, messages::MessageType_BytecoinEmptyResponse, m_socket, m_session, http_resp.body))
		throw Exception("Trezor bytecoin proof_start message failed to decode, msg=" + http_resp.body);
	release();
	sign_add_extra(data);
}

void Trezor::export_view_only(SecretKey *audit_key_base_secret_key, SecretKey *view_secret_key, Hash *view_seed,
    Signature *view_secrets_signature) {
	acquire();
	messages::bytecoin::BytecoinExportViewWalletRequest req;
	auto http_resp =
	    trezor_post(m_socket, "/call/" + m_session, encode(req, messages::MessageType_BytecoinExportViewWalletRequest));
	messages::bytecoin::BytecoinExportViewWalletResponse resp;
	if (!decode_any(resp, messages::MessageType_BytecoinExportViewWalletResponse, m_socket, m_session, http_resp.body))
		throw Exception("Trezor bytecoin export_view_only message failed to decode, msg=" + http_resp.body);
	seria::from_binary(*audit_key_base_secret_key, resp.audit_key_base_secret_key);
	seria::from_binary(*view_secret_key, resp.view_secret_key);
	seria::from_binary(*view_seed, resp.view_seed);
	seria::from_binary(*view_secrets_signature, resp.view_secrets_signature);
	release();
}
