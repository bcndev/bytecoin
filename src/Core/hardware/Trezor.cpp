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

#if cn_WITH_TREZOR

#include "protob/messages-bytecoin.pb.h"
#include "protob/messages-common.pb.h"
#include "protob/messages.pb.h"

using namespace cn::hardware;
using namespace common;

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
	std::string str = mbody.SerializeAsString();
	uint8_t header[6];
	common::uint_be_to_bytes(header, 2, unsigned(mid));
	common::uint_be_to_bytes(header + 2, 4, str.size());
	return common::to_hex(header, 6) + common::to_hex(str.data(), str.size());
}

template<class M>
bool decode_any(M &msg, int should_be_mid, tcp::socket &socket, const std::string &session, const std::string &body) {
	std::cout << body << std::endl;
	unsigned char header[6];
	if (!common::from_hex(body.substr(0, 12), header, 6))
		return false;
	size_t mid       = common::uint_be_from_bytes<size_t>(header, 2);
	std::string str2 = common::as_string(common::from_hex(body.substr(12)));
	std::cout << "mid=" << mid << " body=" << str2 << std::endl;
	if (mid == hw::trezor::messages::MessageType_Failure) {
		hw::trezor::messages::common::Failure mad;
		mad.ParseFromString(str2);
		std::cout << mad.code() << " " << mad.message() << std::endl;
		return false;
	}
	if (mid == hw::trezor::messages::MessageType_ButtonRequest) {
		hw::trezor::messages::common::ButtonRequest mad;
		mad.ParseFromString(str2);
		std::cout << mad.code() << " " << mad.data() << std::endl;
		hw::trezor::messages::common::ButtonAck bac;
		auto resp = trezor_post(socket, "/call/" + session, encode(bac, hw::trezor::messages::MessageType_ButtonAck));
		return decode_any(msg, should_be_mid, socket, session, resp.body);
	}
	if (mid == size_t(should_be_mid)) {
		msg.ParseFromString(str2);
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
			std::cout << "No device connected" << std::endl;
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
			//			else
			result->emplace_back(std::make_unique<Trezor>(path));
		}
	} catch (const std::exception &) {
	}
}

void Trezor::acquire() {
	//	invariant(m_session.empty(), "Trezor device locked");
	//    auto resp = trezor_post(m_socket, "/acquire/" + m_path + "/null", "");
	//    std::cout << resp.body << std::endl;
	//    auto en = common::JsonValue::from_string(resp.body);
	//    m_session = en("session").get_string();
}

void Trezor::release() {
	//	invariant(!m_session.empty(), "Trezor device locked");
	//    auto resp = trezor_post(m_socket, "/release/" + m_session, "");
	//    std::cout << resp.body << std::endl;
	//    m_session.clear();
}

Trezor::Trezor(const std::string &path) : m_path(path), m_socket(platform::EventLoop::current()->io()) {
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	tcp::endpoint trezor_ep(boost::asio::ip::address::from_string("127.0.0.1"), 21325);
	m_socket.connect(trezor_ep);

	{
		invariant(m_session.empty(), "Trezor device locked");
		auto resp = trezor_post(m_socket, "/acquire/" + m_path + "/null", "");
		std::cout << resp.body << std::endl;
		auto en   = common::JsonValue::from_string(resp.body);
		m_session = en("session").get_string();
	}
	acquire();

	//	hw::trezor::messages::monero::MoneroGetWatchKey ga;
	//	ga.add_address_n(0x8000002c); // 0x80000031
	//	ga.add_address_n(0x80000080); // 0x80000080
	//	ga.add_address_n(0x80000000);
	//	ga.add_address_n(0);
	//	ga.add_address_n(0);
	//    auto http_resp = trezor_post(m_socket, "/call/" + m_session, encode(ga,
	//    hw::trezor::messages::MessageType_MoneroGetWatchKey)); hw::trezor::messages::monero::MoneroWatchKey resp2;
	//    invariant(decode_any(resp2, hw::trezor::messages::MessageType_MoneroWatchKey, m_socket, m_session,
	//    http_resp.body), "");

	hw::trezor::messages::bytecoin::BytecoinStartRequest req;
	req.set_debug_request("computer");
	auto http_resp = trezor_post(
	    m_socket, "/call/" + m_session, encode(req, hw::trezor::messages::MessageType_BytecoinStartRequest));
	hw::trezor::messages::bytecoin::BytecoinStartResponse resp;
	invariant(
	    decode_any(resp, hw::trezor::messages::MessageType_BytecoinStartResponse, m_socket, m_session, http_resp.body),
	    "");

	auto dr = resp.debug_response();
	std::cout << common::to_hex(dr.data(), dr.size()) << std::endl;

	seria::from_binary(m_wallet_key, resp.wallet_key());
	seria::from_binary(m_A_plus_sH, resp.a_plus_sh());
	seria::from_binary(m_v_mul_A_plus_sH, resp.v_mul_a_plus_sh());
	seria::from_binary(m_view_public_key, resp.view_public_key());

	release();
	std::cout << "That's all" << std::endl;
	//	hw::trezor::messages::monero::MoneroGetAddress ga;
	//    std::string str = ga.SerializeAsString();
	//    uint8_t header[6];
	// common::uint_be_to_bytes(header, 2, unsigned(hw::trezor::messages::MessageType_MoneroGetAddress));
	//    common::uint_be_to_bytes(header, 2, unsigned(hw::trezor::messages::MessageType_BytecoinStartRequest));
	//    common::uint_be_to_bytes(header + 2, 4, str.size());
	//    resp = trezor_post(socket, "/call/" + session, common::to_hex(header, 6) + common::to_hex(str.data(),
	//    str.size())); decode_any(socket, session, resp.body); resp = trezor_post(socket, "/release/" + session, "");
	//    std::cout << resp.body << std::endl;
}

Trezor::~Trezor() {}

std::string Trezor::get_hardware_type() const { return "Trezor path=" + m_path; }

const size_t SCAN_OUTPUTS_MAX_SIZE = 10;

std::vector<cn::PublicKey> Trezor::mul_by_view_secret_key(const std::vector<PublicKey> &output_public_keys) {
	std::vector<PublicKey> result;
	acquire();
	for (size_t i = 0; i != output_public_keys.size();) {
		size_t stop = std::min(output_public_keys.size(), i + SCAN_OUTPUTS_MAX_SIZE);
		hw::trezor::messages::bytecoin::BytecoinScanOutputsRequest req;
		for (; i != stop; ++i) {
			req.add_output_public_key(output_public_keys.at(i).data, sizeof(PublicKey));
		}
		auto http_resp = trezor_post(
		    m_socket, "/call/" + m_session, encode(req, hw::trezor::messages::MessageType_BytecoinScanOutputsRequest));
		hw::trezor::messages::bytecoin::BytecoinScanOutputsResponse resp;
		invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinScanOutputsResponse, m_socket, m_session,
		              http_resp.body),
		    "");
		for (int j = 0; j != resp.pv_size(); ++j) {
			PublicKey pv;
			seria::from_binary(pv, resp.pv(j));
			result.push_back(pv);
		}
	}
	release();
	return result;
}

cn::KeyImage Trezor::generate_keyimage(
    const PublicKey &output_public_key, const SecretKey &inv_output_secret_hash, size_t address_index) {
	acquire();
	hw::trezor::messages::bytecoin::BytecoinGenerateKeyimageRequest req;
	req.set_output_public_key(output_public_key.data, sizeof(PublicKey));
	req.set_inv_output_main_hash(inv_output_secret_hash.data, sizeof(SecretKey));
	req.set_address_index(static_cast<uint32_t>(address_index));
	auto http_resp = trezor_post(
	    m_socket, "/call/" + m_session, encode(req, hw::trezor::messages::MessageType_BytecoinGenerateKeyimageRequest));
	hw::trezor::messages::bytecoin::BytecoinGenerateKeyimageResponse resp;
	invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinGenerateKeyimageResponse, m_socket, m_session,
	              http_resp.body),
	    "");
	KeyImage result;
	seria::from_binary(result, resp.keyimage());
	release();
	return result;
}

void Trezor::generate_output_seed(const Hash &tx_inputs_hash, size_t out_index, PublicKey *output_seed) {
	acquire();
	hw::trezor::messages::bytecoin::BytecoinGenerateOutputSeedRequest req;
	req.set_tx_inputs_hash(tx_inputs_hash.data, sizeof(Hash));
	req.set_out_index(static_cast<uint32_t>(out_index));
	auto http_resp = trezor_post(m_socket, "/call/" + m_session,
	    encode(req, hw::trezor::messages::MessageType_BytecoinGenerateOutputSeedRequest));
	hw::trezor::messages::bytecoin::BytecoinGenerateOutputSeedResponse resp;
	invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinGenerateOutputSeedResponse, m_socket,
	              m_session, http_resp.body),
	    "");
	seria::from_binary(*output_seed, resp.output_seed());
	release();
}

void Trezor::sign_start(size_t version, uint64_t ut, size_t inputs_size, size_t outputs_size, size_t extra_size) {
	acquire();
	hw::trezor::messages::bytecoin::BytecoinSignStartRequest req;
	req.set_version(static_cast<uint32_t>(version));
	req.set_ut(ut);
	req.set_inputs_size(static_cast<uint32_t>(inputs_size));
	req.set_outputs_size(static_cast<uint32_t>(outputs_size));
	req.set_extra_size(static_cast<uint32_t>(extra_size));
	auto http_resp = trezor_post(
	    m_socket, "/call/" + m_session, encode(req, hw::trezor::messages::MessageType_BytecoinSignStartRequest));
	hw::trezor::messages::bytecoin::BytecoinEmptyResponse resp;
	invariant(
	    decode_any(resp, hw::trezor::messages::MessageType_BytecoinEmptyResponse, m_socket, m_session, http_resp.body),
	    "");
	release();
}

void Trezor::sign_add_input(uint64_t amount, const std::vector<size_t> &output_indexes,
    SecretKey inv_output_secret_hash, size_t address_index) {
	acquire();
	hw::trezor::messages::bytecoin::BytecoinSignAddInputRequest req;
	req.set_amount(amount);
	for (auto index : output_indexes)
		req.add_output_indexes(static_cast<uint32_t>(index));
	req.set_inv_output_main_hash(inv_output_secret_hash.data, sizeof(SecretKey));
	req.set_address_index(static_cast<uint32_t>(address_index));
	auto http_resp = trezor_post(
	    m_socket, "/call/" + m_session, encode(req, hw::trezor::messages::MessageType_BytecoinSignAddInputRequest));
	hw::trezor::messages::bytecoin::BytecoinEmptyResponse resp;
	invariant(
	    decode_any(resp, hw::trezor::messages::MessageType_BytecoinEmptyResponse, m_socket, m_session, http_resp.body),
	    "");
	release();
}

void Trezor::sign_add_output(bool change, uint64_t amount, size_t change_address_index, uint8_t dst_address_tag,
    PublicKey dst_address_s, PublicKey dst_address_s_v, PublicKey *public_key, PublicKey *encrypted_secret,
    uint8_t *encrypted_address_type) {
	acquire();
	hw::trezor::messages::bytecoin::BytecoinSignAddOutputRequest req;
	req.set_change(change);
	req.set_amount(amount);
	req.set_change_address_index(static_cast<uint32_t>(change_address_index));
	req.set_dst_address_tag(dst_address_tag);
	req.set_dst_address_s(dst_address_s.data, sizeof(PublicKey));
	req.set_dst_address_sv(dst_address_s_v.data, sizeof(PublicKey));
	auto http_resp = trezor_post(
	    m_socket, "/call/" + m_session, encode(req, hw::trezor::messages::MessageType_BytecoinSignAddOutputRequest));
	hw::trezor::messages::bytecoin::BytecoinSignAddOutputResponse resp;
	invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinSignAddOutputResponse, m_socket, m_session,
	              http_resp.body),
	    "");
	seria::from_binary(*public_key, resp.public_key());
	seria::from_binary(*encrypted_secret, resp.encrypted_secret());
	*encrypted_address_type = common::integer_cast<uint8_t>(resp.encrypted_address_type());
	release();
}

const size_t MAX_EXTRA_CHUNK = 128;

void Trezor::sign_add_extra(const BinaryArray &chunk) {
	acquire();
	size_t pos = 0;
	while (true) {
		size_t stop = std::min(chunk.size(), pos + MAX_EXTRA_CHUNK);
		hw::trezor::messages::bytecoin::BytecoinSignAddExtraRequest req;
		req.set_extra_chunk(chunk.data() + pos, stop - pos);
		auto http_resp = trezor_post(
		    m_socket, "/call/" + m_session, encode(req, hw::trezor::messages::MessageType_BytecoinSignAddExtraRequest));
		hw::trezor::messages::bytecoin::BytecoinEmptyResponse resp;
		invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinEmptyResponse, m_socket, m_session,
		              http_resp.body),
		    "");
		pos = stop;
		if (pos == chunk.size())
			break;
	}
	release();
}

void Trezor::sign_step_a(SecretKey inv_output_secret_hash, size_t address_index, crypto::EllipticCurvePoint *sig_p,
    crypto::EllipticCurvePoint *x, crypto::EllipticCurvePoint *y) {
	acquire();
	hw::trezor::messages::bytecoin::BytecoinSignStepARequest req;
	req.set_inv_output_main_hash(inv_output_secret_hash.data, sizeof(SecretKey));
	req.set_address_index(static_cast<uint32_t>(address_index));
	auto http_resp = trezor_post(
	    m_socket, "/call/" + m_session, encode(req, hw::trezor::messages::MessageType_BytecoinSignStepARequest));
	hw::trezor::messages::bytecoin::BytecoinSignStepAResponse resp;
	invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinSignStepAResponse, m_socket, m_session,
	              http_resp.body),
	    "");
	seria::from_binary(*sig_p, resp.sig_p());
	seria::from_binary(*x, resp.x());
	seria::from_binary(*y, resp.y());
	release();
}

void Trezor::sign_step_a_more_data(const BinaryArray &data) {
	acquire();
	size_t pos = 0;
	while (true) {
		size_t stop = std::min(data.size(), pos + MAX_EXTRA_CHUNK);
		hw::trezor::messages::bytecoin::BytecoinSignStepAMoreDataRequest req;
		req.set_data_chunk(data.data() + pos, stop - pos);
		auto http_resp = trezor_post(m_socket, "/call/" + m_session,
		    encode(req, hw::trezor::messages::MessageType_BytecoinSignStepAMoreDataRequest));
		hw::trezor::messages::bytecoin::BytecoinEmptyResponse resp;
		invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinEmptyResponse, m_socket, m_session,
		              http_resp.body),
		    "");
		pos = stop;
		if (pos == data.size())
			break;
	}
	release();
}

crypto::EllipticCurveScalar Trezor::sign_get_c0() {
	acquire();
	hw::trezor::messages::bytecoin::BytecoinSignGetC0Request req;
	auto http_resp = trezor_post(
	    m_socket, "/call/" + m_session, encode(req, hw::trezor::messages::MessageType_BytecoinSignGetC0Request));
	hw::trezor::messages::bytecoin::BytecoinSignGetC0Response resp;
	invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinSignGetC0Response, m_socket, m_session,
	              http_resp.body),
	    "");
	crypto::EllipticCurveScalar c0;
	seria::from_binary(c0, resp.c0());
	release();
	return c0;
}

void Trezor::sign_step_b(SecretKey inv_output_secret_hash, size_t address_index, crypto::EllipticCurveScalar my_c,
    crypto::EllipticCurveScalar *sig_my_ra, crypto::EllipticCurveScalar *sig_rb, crypto::EllipticCurveScalar *sig_rc) {
	acquire();
	hw::trezor::messages::bytecoin::BytecoinSignStepBRequest req;
	req.set_inv_output_main_hash(inv_output_secret_hash.data, sizeof(SecretKey));
	req.set_address_index(static_cast<uint32_t>(address_index));
	req.set_my_c(my_c.data, sizeof(crypto::EllipticCurveScalar));
	auto http_resp = trezor_post(
	    m_socket, "/call/" + m_session, encode(req, hw::trezor::messages::MessageType_BytecoinSignStepBRequest));
	hw::trezor::messages::bytecoin::BytecoinSignStepBResponse resp;
	invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinSignStepBResponse, m_socket, m_session,
	              http_resp.body),
	    "");
	seria::from_binary(*sig_my_ra, resp.my_ra());
	seria::from_binary(*sig_rb, resp.rb());
	seria::from_binary(*sig_rc, resp.rc());
	release();
}

void Trezor::proof_start(const common::BinaryArray &data) {
	acquire();
	hw::trezor::messages::bytecoin::BytecoinStartProofRequest req;
	req.set_data_size(common::integer_cast<uint32_t>(data.size()));
	auto http_resp = trezor_post(
	    m_socket, "/call/" + m_session, encode(req, hw::trezor::messages::MessageType_BytecoinStartProofRequest));
	hw::trezor::messages::bytecoin::BytecoinEmptyResponse resp;
	invariant(
	    decode_any(resp, hw::trezor::messages::MessageType_BytecoinEmptyResponse, m_socket, m_session, http_resp.body),
	    "");
	release();
	sign_add_extra(data);
}

void Trezor::export_view_only(SecretKey *audit_key_base_secret_key, SecretKey *view_secret_key,
    Hash *tx_derivation_seed, Signature *view_secrets_signature) {
	acquire();
	hw::trezor::messages::bytecoin::BytecoinExportViewWalletRequest req;
	auto http_resp = trezor_post(
	    m_socket, "/call/" + m_session, encode(req, hw::trezor::messages::MessageType_BytecoinExportViewWalletRequest));
	hw::trezor::messages::bytecoin::BytecoinExportViewWalletResponse resp;
	invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinExportViewWalletResponse, m_socket, m_session,
	              http_resp.body),
	    "");
	seria::from_binary(*audit_key_base_secret_key, resp.audit_key_base_secret_key());
	seria::from_binary(*view_secret_key, resp.view_secret_key());
	seria::from_binary(*tx_derivation_seed, resp.tx_derivation_seed());
	seria::from_binary(*view_secrets_signature, resp.view_secrets_signature());
	release();
}

/*
struct Success {
    std::string message; // id = 1
    bool ba = false; // id = 2

    struct Inside {
        int ha = 0; // id = 1
        void save(nanoproto::Ostream * s)const{
            return nanoproto::save_uint32(s, 1, ha);
        }
    };
    std::vector<Inside> inside; // id = 5

    void save(nanoproto::Ostream * s)const{
        nanoproto::save_string(s, 1, message);
        nanoproto::save_bool(s, 2, ba);
        nanoproto::save_array(s, 5, inside);
    }
    void parse(nanoproto::Istream * s){
        while(!s->empty()){
            int id = 0;
            int type = nanproto::read_type_data(s, &id);
            switch(id){
                case 1:
                    nanoproto::read_string(s, &message);
                    break;
                case 2:
                    nanoproto::read_bool(s, &ba);
                    break;
                case 5:
                    nanoproto::read_array(s, &inside);
                    break;
                default:
                    nanoproto::skip_by_type(s, type);
            }
        }
    }
};*/

#endif  // cn_WITH_TREZOR
