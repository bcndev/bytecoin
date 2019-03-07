// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Ledger.hpp"
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

#if cn_WITH_LEDGER

#ifdef _WIN32
#include <libusb/libusb.h>
#include "platform/Windows.hpp"
// libusb leaks windows.h garbage pile into our project, have to do damage prevention
#else
#include <libusb-1.0/libusb.h>
#endif
// For now will work with only libusb as transport

using namespace cn::hardware;
using namespace common;
using namespace crypto;

// Good description is here - https://github.com/trezor/trezord-go/blob/master/README.md

#define BTCHIP_VID 0x2c97
#define BTCHIP_PID 0x0001

struct USBLib {
	bool good = false;
	USBLib() : good(libusb_init(nullptr) >= 0) {}
	~USBLib() {
		if (good)
			libusb_exit(nullptr);
	}
};

USBDevice::~USBDevice() {
	libusb_close(handle);
	handle = nullptr;
}

static USBLib usb_lib;  // do not do that aha

void Ledger::add_connected(std::vector<std::unique_ptr<HardwareWallet>> *result) {
	if (!usb_lib.good)
		return;
	//    libusb_device_handle *rd = libusb_open_device_with_vid_pid(NULL, BTCHIP_VID, BTCHIP_PID);

	libusb_device **devs = nullptr;
	ssize_t cnt          = libusb_get_device_list(nullptr, &devs);
	if (cnt < 0)
		return;

	libusb_device *dev = nullptr;
	int i = 0, j = 0;
	uint8_t path[8];

	while ((dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor desc {};
		int r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0) {
			fprintf(stderr, "failed to get device descriptor");
			break;
		}
		printf("%04x:%04x (bus %d, device %d)", desc.idVendor, desc.idProduct, libusb_get_bus_number(dev),
		    libusb_get_device_address(dev));

		r = libusb_get_port_numbers(dev, path, sizeof(path));
		if (r > 0) {
			printf(" path: %d", path[0]);
			for (j = 1; j < r; j++)
				printf(".%d", path[j]);
		}
		printf("\n");
		if (desc.idVendor == BTCHIP_VID && desc.idProduct == BTCHIP_PID) {
			libusb_device_handle *dev_handle = nullptr;
			int open_r                       = libusb_open(dev, &dev_handle);
			if (open_r == 0)
				result->push_back(std::make_unique<Ledger>(dev_handle));
			else
				fprintf(stderr, "failed to open device");
		}
	}
	libusb_free_device_list(devs, 1);
}

Ledger::Ledger(libusb_device_handle *dev_handle) : m_device(dev_handle) {}

Ledger::~Ledger() {}

std::string Ledger::get_hardware_type() const { return "Ledger"; }

const size_t SCAN_OUTPUTS_MAX_SIZE = 10;

std::vector<cn::PublicKey> Ledger::scan_outputs(const std::vector<PublicKey> &output_public_keys) {
	std::vector<PublicKey> result;
	for (size_t i = 0; i != output_public_keys.size();) {
		size_t stop = std::min(output_public_keys.size(), i + SCAN_OUTPUTS_MAX_SIZE);
		//        hw::trezor::messages::bytecoin::BytecoinScanOutputsRequest req;
		for (; i != stop; ++i) {
			//            req.add_output_public_key(output_public_keys.at(i).data, sizeof(PublicKey));
		}
		//        auto http_resp = trezor_post(m_socket, "/call/" + m_session, encode(req,
		//        hw::trezor::messages::MessageType_BytecoinScanOutputsRequest));
		//        hw::trezor::messages::bytecoin::BytecoinScanOutputsResponse resp;
		//        invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinScanOutputsResponse, m_socket,
		//        m_session, http_resp.body), ""); for(int j = 0; j != resp.pv_size(); ++j){
		//            PublicKey pv;
		//            seria::from_binary(pv, resp.pv(j));
		//            result.push_back(pv);
		//        }
	}
	return result;
}

cn::KeyImage Ledger::generate_keyimage(const common::BinaryArray &output_secret_hash_arg, size_t address_index) {
	KeyImage result;
	return result;
}

void Ledger::generate_output_seed(const Hash &tx_inputs_hash, size_t out_index, Hash *output_seed) {}

void Ledger::sign_start(size_t version, uint64_t ut, size_t inputs_size, size_t outputs_size, size_t extra_size) {}

void Ledger::sign_add_input(uint64_t amount, const std::vector<size_t> &output_indexes,
    const common::BinaryArray &output_secret_hash_arg, size_t address_index) {}

void Ledger::sign_add_output(bool change, uint64_t amount, size_t change_address_index, uint8_t dst_address_tag,
    PublicKey dst_address_s, PublicKey dst_address_s_v, PublicKey *public_key, PublicKey *encrypted_secret,
    uint8_t *encrypted_address_type) {}

const size_t MAX_EXTRA_CHUNK = 128;

void Ledger::sign_add_extra(const BinaryArray &chunk) {
	size_t pos = 0;
	while (true) {
		size_t stop = std::min(chunk.size(), pos + MAX_EXTRA_CHUNK);
		//		hw::trezor::messages::bytecoin::BytecoinSignAddExtraRequest req;
		//		req.set_extra_chunk(chunk.data() + pos, stop - pos);
		//		auto http_resp = trezor_post(m_socket, "/call/" + m_session, encode(req,
		// hw::trezor::messages::MessageType_BytecoinSignAddExtraRequest));
		//		hw::trezor::messages::bytecoin::BytecoinEmptyResponse resp;
		//		invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinEmptyResponse, m_socket, m_session,
		// http_resp.body), "");
		pos = stop;
		if (pos == chunk.size())
			break;
	}
}

void Ledger::sign_step_a(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
    crypto::EllipticCurvePoint *sig_p, crypto::EllipticCurvePoint *y, crypto::EllipticCurvePoint *z) {}

void Ledger::sign_step_a_more_data(const BinaryArray &data) {
	size_t pos = 0;
	while (true) {
		size_t stop = std::min(data.size(), pos + MAX_EXTRA_CHUNK);
		//		hw::trezor::messages::bytecoin::BytecoinSignStepAMoreDataRequest req;
		//		req.set_data_chunk(data.data() + pos, stop - pos);
		//		auto http_resp = trezor_post(m_socket, "/call/" + m_session, encode(req,
		// hw::trezor::messages::MessageType_BytecoinSignStepAMoreDataRequest));
		//		hw::trezor::messages::bytecoin::BytecoinEmptyResponse resp;
		//		invariant(decode_any(resp, hw::trezor::messages::MessageType_BytecoinEmptyResponse, m_socket, m_session,
		// http_resp.body), "");
		pos = stop;
		if (pos == data.size())
			break;
	}
}

crypto::EllipticCurveScalar Ledger::sign_get_c0() {
	crypto::EllipticCurveScalar c0;
	return c0;
}

void Ledger::sign_step_b(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
    crypto::EllipticCurveScalar my_c, Hash *sig_my_rr, Hash *sig_rs, Hash *sig_ra, Hash *e_key) {}

void Ledger::proof_start(const common::BinaryArray &data) {}

void Ledger::export_view_only(SecretKey *audit_key_base_secret_key, SecretKey *view_secret_key, Hash *view_seed,
    Signature *view_secrets_signature) {}

#endif  // cn_WITH_LEDGER
