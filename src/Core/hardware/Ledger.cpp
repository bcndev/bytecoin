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

using namespace cn::hardware;
using namespace crypto;

#define BTCHIP_VID 0x2c97
#define BTCHIP_PID 0x1001
#define DEFAULT_LEDGER_CHANNEL 0x0101
#define LEDGER_HID_PACKET_SIZE 64
#define TAG_APDU 0x05

void Ledger::add_connected(std::vector<std::unique_ptr<HardwareWallet>> *result) try {
	enumeration_handle_t enum_list{hid_enumerate(BTCHIP_VID, BTCHIP_PID), &hid_free_enumeration};
	if (!enum_list) {
		printf("No Ledger devices connected\n");
		return;
	}

	for (const hid_device_info *dev_info = enum_list.get(); dev_info != nullptr; dev_info = dev_info->next) {
		printf("Trying to open %s... ", dev_info->path);
		device_handle_t dev_handle{hid_open_path(dev_info->path), &hid_close};
		if (!dev_handle) {
			printf("Failed to open %s\n", dev_info->path);
			continue;
		}
		printf("Success.\n");
		try {
			result->push_back(std::make_unique<Ledger>(std::move(dev_handle), dev_info->path));
		} catch (const std::exception &) {
			// OK, this Ledger probably disconnected while we were communicating
		}
	}
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

size_t Ledger::get_scan_outputs_max_batch() const { return BYTECOIN_MAX_SCAN_OUTPUTS; }

static int hid_write_wrapper(hid_device *device, const uint8_t *data, size_t length) {
	std::unique_ptr<uint8_t[]> buffer{new uint8_t[length + 1]};
	memcpy(buffer.get() + 1, data, length);
	buffer[0]  = 0;  // hidapi requires report number
	int result = hid_write(device, buffer.get(), length + 1);
	if (result > 0)
		--result;  // hidapi returns number of bytes written including report number
	return result;
}

int Ledger::sendApdu(const uint8_t *data, size_t len, uint8_t *out, size_t out_len, unsigned *sw) {
	static const size_t MAX_BLOCK = 64;
	static const int TIMEOUT      = 600000;

	unsigned char buffer[800]{};
	unsigned char paddingBuffer[MAX_BLOCK]{};

	int send_size = wrapCommandApdu(DEFAULT_LEDGER_CHANNEL, data, len, LEDGER_HID_PACKET_SIZE, buffer, sizeof(buffer));
	if (send_size < 0) {
		return send_size;
	}
	size_t remaining = static_cast<size_t>(send_size);
	size_t offset    = 0;
	int result       = 0;
	while (remaining > 0) {
		size_t blockSize = (remaining > MAX_BLOCK ? MAX_BLOCK : remaining);
		memset(paddingBuffer, 0, MAX_BLOCK);
		memcpy(paddingBuffer, buffer + offset, blockSize);
		result = hid_write_wrapper(m_device_handle.get(), paddingBuffer, blockSize);
		if (result < 0) {
			return result;
		}
		offset += blockSize;
		remaining -= blockSize;
	}
	result = hid_read_timeout(m_device_handle.get(), buffer, MAX_BLOCK, TIMEOUT);
	if (result < 0) {
		return result;
	}
	if (result != MAX_BLOCK) {
		return result;
	}

	offset = MAX_BLOCK;
	while (true) {
		result = unwrapReponseApdu(DEFAULT_LEDGER_CHANNEL, buffer, offset, LEDGER_HID_PACKET_SIZE, out, out_len);
		if (result >= 2) {
			result -= 2;
			break;
		}
		if (result < 0 || result != 0)
			return -1;
		result = hid_read_timeout(m_device_handle.get(), buffer + offset, MAX_BLOCK, TIMEOUT);
		if (result < 0)
			return result;
		offset += MAX_BLOCK;
	}
	if (sw) {
		*sw = (out[result] << 8U) + out[result + 1];
	}
	return result;
}

BinaryArray Ledger::sendApdu(uint8_t cmd, const BinaryArray &body) {
	if (body.size() > 0xff)
		throw std::runtime_error("sendApdu size too big size=" + common::to_string(body.size()));
	BinaryArray ba{BYTECOIN_CLA, cmd, 0, 0, static_cast<uint8_t>(body.size())};
	common::append(ba, body);
	if (body.empty()) {  // According to smartcard protocol 0 means 256. We do not want this.
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

Ledger::Ledger(device_handle_t &&dev_handle, const std::string &path)
    : m_device_handle(std::move(dev_handle)), m_path(path) {
	//	m_device.attach_kernel_driver(false);

	get_app_info();
	if (m_app_info.major_version != 1 || m_app_info.minor_version != 0)
		throw std::runtime_error("this version of the ledger app is incompatible");
	get_wallet_keys();
}

Ledger::~Ledger() {}

std::string Ledger::get_hardware_type() const { return "Ledger path=" + m_path; }

std::vector<cn::PublicKey> Ledger::scan_outputs(const std::vector<cn::PublicKey> &output_public_keys) {
	invariant(output_public_keys.size() <= get_scan_outputs_max_batch(), "");
	std::vector<PublicKey> result;
	const size_t size = std::min(output_public_keys.size(), get_scan_outputs_max_batch());

	common::VectorStream vs;
	write_big_endian(size, 1, &vs);
	for (const auto &pk : output_public_keys)
		vs.write(pk.data, sizeof(pk.data));
	vs = common::VectorStream(sendApdu(INS_SCAN_OUTPUTS, vs.buffer()));
	for (size_t i = 0; i < size; ++i) {
		PublicKey rpk;
		vs.read(rpk.data, sizeof(rpk.data));
		result.push_back(std::move(rpk));
	}
	if (!vs.empty())
		throw std::runtime_error("excess data left in INS_SCAN_OUTPUTS");
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
