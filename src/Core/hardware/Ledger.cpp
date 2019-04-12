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
#include "ledger/bytecoin_ledger_api.h"
#include "seria/BinaryInputStream.hpp"

#if cn_WITH_LEDGER

using namespace cn::hardware;
using namespace crypto;

#include <libusb-1.0/libusb.h>

#ifdef _WIN32
#include "platform/Windows.hpp"
// libusb leaks windows.h garbage pile into our project, have to do damage prevention
#endif
// For now will work with only libusb as transport

#define BTCHIP_VID 0x2c97
#define BTCHIP_PID 0x0001
#define DEFAULT_LEDGER_CHANNEL 0x0101
#define LEDGER_HID_PACKET_SIZE 64
#define TAG_APDU 0x05

USBLib::USBLib() {
	if (libusb_init(nullptr) < 0)
		throw std::runtime_error("USBLib init failed");
}

USBLib::~USBLib() { libusb_exit(nullptr); }

void USBDevice::attach_kernel_driver(bool attach) {
	if (attach == attached_kernel_driver)
		return;
	attached_kernel_driver = attach;
	if (attach) {
		libusb_release_interface(handle, 0);
		libusb_attach_kernel_driver(handle, 0);
	} else {
		libusb_detach_kernel_driver(handle, 0);
		libusb_claim_interface(handle, 0);
		// TODO - error checks
	}
}

USBDevice::~USBDevice() {
	attach_kernel_driver(true);
	libusb_close(handle);
	handle = nullptr;
}

void Ledger::add_connected(std::vector<std::unique_ptr<HardwareWallet>> *result) try {
	USBLib usb_lib;
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
		std::string spath;
		const auto bn = libusb_get_bus_number(dev);
		const auto da = libusb_get_device_address(dev);
		printf("%04x:%04x (bus %d, device %d)", desc.idVendor, desc.idProduct, bn, da);
		spath = "(bus " + common::to_string(bn) + ", device " + common::to_string(da) + ")";

		r = libusb_get_port_numbers(dev, path, sizeof(path));
		if (r > 0) {
			printf(" path: %d", path[0]);
			spath += ", path " + common::to_string(path[0]);
			for (j = 1; j < r; j++) {
				printf(".%d", path[j]);
				spath += "." + common::to_string(path[j]);
			}
		}
		printf("\n");
		if (desc.idVendor == BTCHIP_VID && desc.idProduct == BTCHIP_PID) {
			libusb_device_handle *dev_handle = nullptr;
			int open_r                       = libusb_open(dev, &dev_handle);
			if (open_r == 0) {
				try {
					result->push_back(std::make_unique<Ledger>(dev_handle, spath));
				} catch (const std::exception &) {
					// OK, this Ledger probably disconnected while we were communicating
				}
			} else
				fprintf(stderr, "failed to open device");
		}
	}
	libusb_free_device_list(devs, 1);
} catch (const std::exception &) {
	// OK, no lib
}

static int wrapCommandApdu(unsigned int channel, const unsigned char *command, size_t commandLength,
    unsigned int packetSize, unsigned char *out, size_t outLength) {
	size_t sequenceIdx = 0;
	size_t offset      = 0;
	size_t offsetOut   = 0;
	if (packetSize < 3) {
		return -1;
	}
	if (outLength < 7) {
		return -1;
	}
	outLength -= 7;
	out[offsetOut++] = ((channel >> 8) & 0xff);
	out[offsetOut++] = (channel & 0xff);
	out[offsetOut++] = TAG_APDU;
	out[offsetOut++] = ((sequenceIdx >> 8) & 0xff);
	out[offsetOut++] = (sequenceIdx & 0xff);
	sequenceIdx++;
	out[offsetOut++] = ((commandLength >> 8) & 0xff);
	out[offsetOut++] = (commandLength & 0xff);
	size_t blockSize = (commandLength > packetSize - 7 ? packetSize - 7 : commandLength);
	if (outLength < blockSize) {
		return -1;
	}
	outLength -= blockSize;
	memcpy(out + offsetOut, command + offset, blockSize);
	offsetOut += blockSize;
	offset += blockSize;
	while (offset != commandLength) {
		if (outLength < 5) {
			return -1;
		}
		outLength -= 5;
		out[offsetOut++] = ((channel >> 8) & 0xff);
		out[offsetOut++] = (channel & 0xff);
		out[offsetOut++] = TAG_APDU;
		out[offsetOut++] = ((sequenceIdx >> 8) & 0xff);
		out[offsetOut++] = (sequenceIdx & 0xff);
		sequenceIdx++;
		blockSize = ((commandLength - offset) > packetSize - 5 ? packetSize - 5 : commandLength - offset);
		if (outLength < blockSize) {
			return -1;
		}
		outLength -= blockSize;
		memcpy(out + offsetOut, command + offset, blockSize);
		offsetOut += blockSize;
		offset += blockSize;
	}
	while ((offsetOut % packetSize) != 0) {
		if (outLength < 1) {
			return -1;
		}
		outLength--;
		out[offsetOut++] = 0;
	}
	return static_cast<int>(offsetOut);
}

static int unwrapReponseApdu(unsigned int channel, const unsigned char *data, size_t dataLength,
    unsigned int packetSize, unsigned char *out, size_t outLength) {
	size_t sequenceIdx = 0;
	size_t offset      = 0;
	size_t offsetOut   = 0;
	if ((data == NULL) || (dataLength < 7 + 5)) {
		return 0;
	}
	if (data[offset++] != ((channel >> 8) & 0xff)) {
		return -1;
	}
	if (data[offset++] != (channel & 0xff)) {
		return -1;
	}
	if (data[offset++] != TAG_APDU) {
		return -1;
	}
	if (data[offset++] != ((sequenceIdx >> 8) & 0xff)) {
		return -1;
	}
	if (data[offset++] != (sequenceIdx & 0xff)) {
		return -1;
	}
	size_t responseLength = (data[offset++] << 8);
	responseLength |= data[offset++];
	if (outLength < responseLength) {
		return -1;
	}
	if (dataLength < 7 + responseLength) {
		return 0;
	}
	size_t blockSize = (responseLength > packetSize - 7 ? packetSize - 7 : responseLength);
	memcpy(out + offsetOut, data + offset, blockSize);
	offset += blockSize;
	offsetOut += blockSize;
	while (offsetOut != responseLength) {
		sequenceIdx++;
		if (offset == dataLength) {
			return 0;
		}
		if (data[offset++] != ((channel >> 8) & 0xff)) {
			return -1;
		}
		if (data[offset++] != (channel & 0xff)) {
			return -1;
		}
		if (data[offset++] != TAG_APDU) {
			return -1;
		}
		if (data[offset++] != ((sequenceIdx >> 8) & 0xff)) {
			return -1;
		}
		if (data[offset++] != (sequenceIdx & 0xff)) {
			return -1;
		}
		blockSize = ((responseLength - offsetOut) > packetSize - 5 ? packetSize - 5 : responseLength - offsetOut);
		if (blockSize > dataLength - offset) {
			return 0;
		}
		memcpy(out + offsetOut, data + offset, blockSize);
		offset += blockSize;
		offsetOut += blockSize;
	}
	return static_cast<int>(offsetOut);
}

static void fill_chunk(
    unsigned char *chunk, size_t block_size, size_t channel, size_t sequence, const uint8_t **data, size_t *len) {
	invariant(block_size >= 7, "");
	size_t pos   = 0;
	chunk[pos++] = ((channel >> 8) & 0xff);
	chunk[pos++] = (channel & 0xff);
	chunk[pos++] = TAG_APDU;
	chunk[pos++] = ((sequence >> 8) & 0xff);
	chunk[pos++] = (sequence & 0xff);
	if (sequence == 0) {
		chunk[pos++] = ((*len >> 8) & 0xff);
		chunk[pos++] = (*len & 0xff);
	}
	size_t cpd = std::min(block_size - pos, *len);
	memcpy(chunk + pos, *data, cpd);
	*len += cpd;
	*data += cpd;
}

static bool parse_chunk(unsigned char *chunk, size_t block_size, size_t channel, size_t sequence,
    size_t *response_length, BinaryArray *result) {
	invariant(block_size >= 7, "");
	size_t pos = 0;
	if (chunk[pos++] != ((channel >> 8) & 0xff))
		return false;
	if (chunk[pos++] != (channel & 0xff))
		return false;
	if (chunk[pos++] != TAG_APDU)
		return false;
	if (chunk[pos++] != ((sequence >> 8) & 0xff))
		return false;
	if (chunk[pos++] != (sequence & 0xff))
		return false;
	if (sequence == 0) {
		*response_length = (chunk[pos++] << 8);
		*response_length += chunk[pos++];
		result->reserve(*response_length);
	}
	size_t cpd = std::min(block_size - pos, *response_length - result->size());
	result->insert(result->end(), chunk + pos, chunk + pos + cpd);
	return true;
}

int Ledger::sendApdu(const uint8_t *data, size_t len, uint8_t *out, size_t out_len, unsigned *sw) {
	static const size_t MAX_BLOCK = 64;
	static const int TIMEOUT      = 600000;

	//	for(size_t sequence = 0; len != 0 || sequence == 0; ++sequence){
	//		unsigned char chunk[MAX_BLOCK]{};
	//		fill_chunk(chunk, MAX_BLOCK, DEFAULT_LEDGER_CHANNEL, sequence, &data, &len);
	//		int length_ignore = 0;
	//		int result = libusb_interrupt_transfer(m_device.handle, 0x02, chunk, static_cast<int>(MAX_BLOCK),
	//&length_ignore, TIMEOUT); 		if (result < 0) 			return result;
	//	}
	//	size_t response_length = 0;
	//	BinaryArray response;
	//	for(size_t sequence = 0; response.size() < response_length || sequence == 0; ++sequence){
	//		unsigned char chunk[MAX_BLOCK]{};
	//		int length_ignore = 0;
	//		int result = libusb_interrupt_transfer(m_device.handle, 0x82, chunk, static_cast<int>(MAX_BLOCK),
	//&length_ignore, TIMEOUT); 		if (result < 0) 			return result; 		if( !parse_chunk(chunk,
	// MAX_BLOCK, DEFAULT_LEDGER_CHANNEL, sequence, &response_length, &response)) 			return -1;
	//	}
	//	if(response.size() < 2)
	//		return -1;
	//	if (sw)
	//		*sw = (response[response.size() - 2] << 8) + response[response.size() - 1];
	//	response.resize(response.size() - 2);

	unsigned char buffer[800];
	unsigned char paddingBuffer[MAX_BLOCK];
	int swOffset     = 0;
	size_t remaining = len;
	int offset       = 0;
	int length       = 0;

	int result = wrapCommandApdu(DEFAULT_LEDGER_CHANNEL, data, len, LEDGER_HID_PACKET_SIZE, buffer, sizeof(buffer));
	if (result < 0) {
		return result;
	}
	remaining = result;
	while (remaining > 0) {
		size_t blockSize = (remaining > MAX_BLOCK ? MAX_BLOCK : remaining);
		memset(paddingBuffer, 0, MAX_BLOCK);
		memcpy(paddingBuffer, buffer + offset, blockSize);
		result = libusb_interrupt_transfer(
		    m_device.handle, 0x02, paddingBuffer, static_cast<int>(blockSize), &length, TIMEOUT);
		if (result < 0) {
			return result;
		}
		offset += blockSize;
		remaining -= blockSize;
	}
	result = libusb_interrupt_transfer(m_device.handle, 0x82, buffer, MAX_BLOCK, &length, TIMEOUT);
	if (result < 0) {
		return result;
	}
	offset = MAX_BLOCK;
	for (;;) {
		int dummy;
		result = unwrapReponseApdu(DEFAULT_LEDGER_CHANNEL, buffer, offset, LEDGER_HID_PACKET_SIZE, out, out_len);
		if (result < 0) {
			return result;
		}
		if (result != 0) {
			length   = result - 2;
			swOffset = result - 2;
			break;
		}
		result = libusb_interrupt_transfer(m_device.handle, 0x82, buffer + offset, MAX_BLOCK, &dummy, TIMEOUT);
		if (result < 0) {
			return result;
		}
		offset += MAX_BLOCK;
	}
	if (sw) {
		*sw = (out[swOffset] << 8) | out[swOffset + 1];
	}
	return length;
}

BinaryArray Ledger::sendApdu(uint8_t cmd, const BinaryArray &body) {
	if (body.size() > 0xff)
		throw std::runtime_error("sendApdu size too big size=" + common::to_string(body.size()));
	BinaryArray ba{BYTECOIN_CLA, cmd, 0, 0, static_cast<uint8_t>(body.size())};
	common::append(ba, body);
	if (body.empty()) {  // We cannot send empty packets to HID
		ba.back() = 1;
		ba.push_back(0);
	}
	BinaryArray result(800);
	unsigned sw      = 0;
	auto send_result = sendApdu(ba.data(), ba.size(), result.data(), result.size(), &sw);
	if (send_result < 0 || sw != SW_NO_ERROR)
		throw std::runtime_error(
		    "sendApdu error send_result=" + common::to_string(send_result) + " sw=" + common::to_string(sw));
	result.resize(send_result);
	return result;
}

template<typename T>
static void write_big_endian(T value, size_t size, common::IOutputStream *s) {
	static_assert(std::is_unsigned<T>::value, "value must be unsigned.");
	if (size < sizeof(value) && value >= (uint64_t(1) << (8 * size)))
		throw std::runtime_error("Ledger write_big_endian value does not fit");
	for (size_t i = 0; i < size; ++i)
		s->write_byte(static_cast<uint8_t>(value >> ((size - i - 1) * 8)));  // truncating high bits
}

void Ledger::get_app_info() {
	common::VectorStream vs;

	vs                       = common::VectorStream(sendApdu(INS_GET_APP_INFO, vs.buffer()));
	m_app_info.major_version = vs.read_byte();
	m_app_info.minor_version = vs.read_byte();
	m_app_info.patch_version = vs.read_byte();

	static constexpr char expected_app_name[]       = "Bytecoin";
	static constexpr uint8_t expected_app_name_size = sizeof(expected_app_name) - 1;

	const uint8_t app_name_size = vs.read_byte();
	if (app_name_size != expected_app_name_size)
		throw std::runtime_error("invalid ledger app is running");
	vs.read(m_app_info.app_name, app_name_size);
	if (m_app_info.app_name != expected_app_name)
		throw std::runtime_error("invalid ledger app is running");

	static constexpr uint8_t max_reasonable_version_size = 50;
	const uint8_t version_size                           = vs.read_byte();
	if (version_size > max_reasonable_version_size)
		throw std::runtime_error("invalid ledger app version");
	vs.read(m_app_info.app_version, version_size);

	const uint8_t spec_version_size = vs.read_byte();
	if (spec_version_size > max_reasonable_version_size)
		throw std::runtime_error("invalid ledger app version");
	vs.read(m_app_info.app_spec_version, spec_version_size);
	if (!vs.empty())
		throw std::runtime_error("excess data left in INS_GET_APP_INFO");
}

void Ledger::get_wallet_keys() {
	common::VectorStream vs;

	vs = common::VectorStream(sendApdu(INS_GET_WALLET_KEYS, vs.buffer()));
	vs.read(m_wallet_key.data, sizeof(Hash));
	vs.read(m_A_plus_sH.data, sizeof(PublicKey));
	vs.read(m_v_mul_A_plus_sH.data, sizeof(PublicKey));
	vs.read(m_view_public_key.data, sizeof(PublicKey));
	if (!vs.empty())
		throw std::runtime_error("excess data left in INS_GET_WALLET_KEYS");
}

Ledger::Ledger(libusb_device_handle *dev_handle, const std::string &path) : m_device(dev_handle), m_path(path) {
	m_device.attach_kernel_driver(false);

	get_app_info();
	if (m_app_info.major_version != 0 || m_app_info.minor_version != 1)
		throw std::runtime_error("this version of the ledger app is incompatible");
	get_wallet_keys();
}

Ledger::~Ledger() {}

std::string Ledger::get_hardware_type() const { return "Ledger path=" + m_path; }

std::vector<cn::PublicKey> Ledger::scan_outputs(const std::vector<cn::PublicKey> &output_public_keys) {
	invariant(output_public_keys.size() <= get_scan_outputs_max_batch(), "");
	std::vector<PublicKey> result;
	for (const auto &pk : output_public_keys) {
		common::VectorStream vs;
		vs.write(pk.data, sizeof(pk.data));

		vs = common::VectorStream(sendApdu(INS_SCAN_OUTPUTS, vs.buffer()));
		PublicKey rpk;
		vs.read(rpk.data, sizeof(rpk.data));
		if (!vs.empty())
			throw std::runtime_error("excess data left in INS_SCAN_OUTPUTS");
		result.push_back(rpk);
	}
	return result;
}

cn::KeyImage Ledger::generate_keyimage(const common::BinaryArray &output_secret_hash_arg, size_t address_index) {
	KeyImage result;
	common::VectorStream vs;
	write_big_endian(output_secret_hash_arg.size(), 1, &vs);
	vs.write(output_secret_hash_arg.data(), output_secret_hash_arg.size());
	write_big_endian(address_index, 4, &vs);

	vs = common::VectorStream(sendApdu(INS_GENERATE_KEYIMAGE, vs.buffer()));
	vs.read(result.data, sizeof(result.data));
	if (!vs.empty())
		throw std::runtime_error("excess data left in INS_GENERATE_KEYIMAGE");
	return result;
}

Hash Ledger::generate_output_seed(const Hash &tx_inputs_hash, size_t out_index) {
	Hash result;
	common::VectorStream vs;
	vs.write(tx_inputs_hash.data, sizeof(tx_inputs_hash.data));
	write_big_endian(out_index, 4, &vs);

	vs = common::VectorStream(sendApdu(INS_GENERATE_OUTPUT_SEED, vs.buffer()));
	vs.read(result.data, sizeof(result.data));
	if (!vs.empty())
		throw std::runtime_error("excess data left in INS_GENERATE_OUTPUT_SEED");
	return result;
}

void Ledger::sign_start(size_t version, uint64_t ut, size_t inputs_size, size_t outputs_size, size_t extra_size) {
	common::VectorStream vs;
	write_big_endian(version, 4, &vs);
	write_big_endian(ut, 8, &vs);
	write_big_endian(inputs_size, 4, &vs);
	write_big_endian(outputs_size, 4, &vs);
	write_big_endian(extra_size, 4, &vs);

	sendApdu(INS_SIG_START, vs.buffer());
}

void Ledger::sign_add_input_start(uint64_t amount, size_t output_indexes_count) {
	common::VectorStream vs;
	write_big_endian(amount, 8, &vs);
	write_big_endian(output_indexes_count, 4, &vs);

	sendApdu(INS_SIG_ADD_INPUT_START, vs.buffer());
}

void Ledger::sign_add_input_indexes(const std::vector<size_t> &output_indexes_chunk) {
	common::VectorStream vs;
	write_big_endian(output_indexes_chunk.size(), 1, &vs);
	for (auto i : output_indexes_chunk)
		write_big_endian(i, 4, &vs);

	sendApdu(INS_SIG_ADD_INPUT_INDEXES, vs.buffer());
}

void Ledger::sign_add_input_finish(const common::BinaryArray &output_secret_hash_arg, size_t address_index) {
	common::VectorStream vs;
	write_big_endian(output_secret_hash_arg.size(), 1, &vs);
	vs.write(output_secret_hash_arg.data(), output_secret_hash_arg.size());
	write_big_endian(address_index, 4, &vs);

	sendApdu(INS_SIG_ADD_INPUT_FINISH, vs.buffer());
}

const size_t MAX_INPUT_INDEXES_CHUNK = 16;

void Ledger::sign_add_input(uint64_t amount, const std::vector<size_t> &output_indexes,
    const common::BinaryArray &output_secret_hash_arg, size_t address_index) {
	sign_add_input_start(amount, output_indexes.size());
	for (size_t pos = 0; pos != output_indexes.size();) {
		size_t stop = std::min(output_indexes.size(), pos + MAX_INPUT_INDEXES_CHUNK);
		sign_add_input_indexes(std::vector<size_t>{output_indexes.begin() + pos, output_indexes.begin() + stop});
		pos = stop;
	}
	sign_add_input_finish(output_secret_hash_arg, address_index);
}

void Ledger::sign_add_output(bool change, uint64_t amount, size_t change_address_index, uint8_t dst_address_tag,
    PublicKey dst_address_s, PublicKey dst_address_s_v, PublicKey *public_key, PublicKey *encrypted_secret,
    uint8_t *encrypted_address_type) {
	common::VectorStream vs;
	vs.write_byte(change ? 1 : 0);
	write_big_endian(amount, 8, &vs);
	write_big_endian(change_address_index, 4, &vs);
	vs.write_byte(dst_address_tag);
	vs.write(dst_address_s.data, sizeof(dst_address_s.data));
	vs.write(dst_address_s_v.data, sizeof(dst_address_s_v.data));

	vs = common::VectorStream(sendApdu(INS_SIG_ADD_OUPUT, vs.buffer()));
	vs.read(public_key->data, sizeof(public_key->data));
	vs.read(encrypted_secret->data, sizeof(encrypted_secret->data));
	*encrypted_address_type = vs.read_byte();
	if (!vs.empty())
		throw std::runtime_error("excess data left in INS_SIG_ADD_OUPUT");
}

const size_t MAX_EXTRA_CHUNK = 128;

void Ledger::sign_add_extra(const BinaryArray &chunk) {
	size_t pos = 0;
	while (true) {
		size_t stop = std::min(chunk.size(), pos + MAX_EXTRA_CHUNK);
		common::VectorStream vs;
		write_big_endian(stop - pos, 1, &vs);
		vs.write(chunk.data() + pos, stop - pos);

		sendApdu(INS_SIG_ADD_EXTRA, vs.buffer());
		pos = stop;
		if (pos == chunk.size())
			break;
	}
}

void Ledger::sign_step_a(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
    crypto::EllipticCurvePoint *sig_p, crypto::EllipticCurvePoint *y, crypto::EllipticCurvePoint *z) {
	common::VectorStream vs;
	write_big_endian(output_secret_hash_arg.size(), 1, &vs);
	vs.write(output_secret_hash_arg.data(), output_secret_hash_arg.size());
	write_big_endian(address_index, 4, &vs);

	vs = common::VectorStream(sendApdu(INS_SIG_STEP_A, vs.buffer()));
	vs.read(sig_p->data, sizeof(sig_p->data));
	vs.read(y->data, sizeof(y->data));
	vs.read(z->data, sizeof(z->data));
	if (!vs.empty())
		throw std::runtime_error("excess data left in INS_SIG_ADD_OUPUT");
}

void Ledger::sign_step_a_more_data(const BinaryArray &data) {
	size_t pos = 0;
	while (true) {
		size_t stop = std::min(data.size(), pos + MAX_EXTRA_CHUNK);
		common::VectorStream vs;
		write_big_endian(stop - pos, 1, &vs);
		vs.write(data.data() + pos, stop - pos);

		sendApdu(INS_SIG_STEP_A_MORE_DATA, vs.buffer());
		pos = stop;
		if (pos == data.size())
			break;
	}
}

crypto::EllipticCurveScalar Ledger::sign_get_c0() {
	common::VectorStream vs;

	vs = common::VectorStream(sendApdu(INS_SIG_GET_C0, vs.buffer()));
	crypto::EllipticCurveScalar c0;
	vs.read(c0.data, sizeof(c0.data));
	if (!vs.empty())
		throw std::runtime_error("excess data left in INS_SIG_GET_C0");
	return c0;
}

void Ledger::sign_step_b(const common::BinaryArray &output_secret_hash_arg, size_t address_index,
    crypto::EllipticCurveScalar my_c, Hash *sig_my_rr, Hash *sig_rs, Hash *sig_ra, Hash *e_key) {
	common::VectorStream vs;
	write_big_endian(output_secret_hash_arg.size(), 1, &vs);
	vs.write(output_secret_hash_arg.data(), output_secret_hash_arg.size());
	write_big_endian(address_index, 4, &vs);
	vs.write(my_c.data, sizeof(my_c.data));

	vs = common::VectorStream(sendApdu(INS_SIG_STEP_B, vs.buffer()));
	vs.read(sig_my_rr->data, sizeof(sig_my_rr->data));
	vs.read(sig_rs->data, sizeof(sig_rs->data));
	vs.read(sig_ra->data, sizeof(sig_ra->data));
	vs.read(e_key->data, sizeof(e_key->data));
	if (!vs.empty())
		throw std::runtime_error("excess data left in INS_SIG_STEP_B");
}

void Ledger::proof_start(const common::BinaryArray &data) {
	common::VectorStream vs;
	write_big_endian(data.size(), 4, &vs);
	sendApdu(INS_SIG_PROOF_START, vs.buffer());
	sign_add_extra(data);
}

void Ledger::export_view_only(SecretKey *audit_key_base_secret_key, SecretKey *view_secret_key, Hash *view_seed,
    Signature *view_secrets_signature) {
	common::VectorStream vs;

	vs = common::VectorStream(sendApdu(INS_EXPORT_VIEW_ONLY, vs.buffer()));
	vs.read(audit_key_base_secret_key->data, sizeof(audit_key_base_secret_key->data));
	vs.read(view_secret_key->data, sizeof(view_secret_key->data));
	vs.read(view_seed->data, sizeof(view_seed->data));
	vs.read(view_secrets_signature->c.data, sizeof(view_secrets_signature->c.data));
	vs.read(view_secrets_signature->r.data, sizeof(view_secrets_signature->r.data));
	if (!vs.empty())
		throw std::runtime_error("excess data left in INS_EXPORT_VIEW_ONLY");
}

#endif  // cn_WITH_LEDGER
