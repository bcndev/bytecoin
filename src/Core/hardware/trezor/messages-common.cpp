#include "messages-common.hpp"
#include "protobuf.hpp"

namespace protobuf {

void read(::hw::trezor::messages::common::Success &v, iterator s, iterator e) {
	while (s != e) {
		auto m            = read_varint(&s, e);
		auto field_type   = static_cast<unsigned>(m & 7);
		auto field_number = static_cast<unsigned>(m >> 3);
		if (field_number == 1 && field_type == 2)
			v.message = read_string(&s, e);
		else
			skip_by_type(field_type, &s, e);
	}
}

std::string write(const ::hw::trezor::messages::common::Success &v) {
	std::string s;
	if (!v.message.empty())
		write_field_string(1, v.message, s);
	return s;
}

void read(::hw::trezor::messages::common::Failure &v, iterator s, iterator e) {
	while (s != e) {
		auto m            = read_varint(&s, e);
		auto field_type   = static_cast<unsigned>(m & 7);
		auto field_number = static_cast<unsigned>(m >> 3);
		if (field_number == 1 && field_type == 0)
			v.code = read_varint_t<::hw::trezor::messages::common::Failure::FailureType>(&s, e);
		else if (field_number == 2 && field_type == 2)
			v.message = read_string(&s, e);
		else
			skip_by_type(field_type, &s, e);
	}
}

std::string write(const ::hw::trezor::messages::common::Failure &v) {
	std::string s;
	if (v.code != ::hw::trezor::messages::common::Failure::FailureType::Failure_UnexpectedMessage)
		write_field_varint(1, static_cast<uint64_t>(v.code), s);
	if (!v.message.empty())
		write_field_string(2, v.message, s);
	return s;
}

void read(::hw::trezor::messages::common::ButtonRequest &v, iterator s, iterator e) {
	while (s != e) {
		auto m            = read_varint(&s, e);
		auto field_type   = static_cast<unsigned>(m & 7);
		auto field_number = static_cast<unsigned>(m >> 3);
		if (field_number == 1 && field_type == 0)
			v.code = read_varint_t<::hw::trezor::messages::common::ButtonRequest::ButtonRequestType>(&s, e);
		else if (field_number == 2 && field_type == 2)
			v.data = read_string(&s, e);
		else
			skip_by_type(field_type, &s, e);
	}
}

std::string write(const ::hw::trezor::messages::common::ButtonRequest &v) {
	std::string s;
	if (v.code != ::hw::trezor::messages::common::ButtonRequest::ButtonRequestType::ButtonRequest_Other)
		write_field_varint(1, static_cast<uint64_t>(v.code), s);
	if (!v.data.empty())
		write_field_string(2, v.data, s);
	return s;
}

void read(::hw::trezor::messages::common::ButtonAck &v, iterator s, iterator e) {
	while (s != e) {
		auto m          = read_varint(&s, e);
		auto field_type = static_cast<unsigned>(m & 7);
		skip_by_type(field_type, &s, e);
	}
}

std::string write(const ::hw::trezor::messages::common::ButtonAck &v) {
	std::string s;
	return s;
}

void read(::hw::trezor::messages::common::PinMatrixRequest &v, iterator s, iterator e) {
	while (s != e) {
		auto m            = read_varint(&s, e);
		auto field_type   = static_cast<unsigned>(m & 7);
		auto field_number = static_cast<unsigned>(m >> 3);
		if (field_number == 1 && field_type == 0)
			v.type = read_varint_t<::hw::trezor::messages::common::PinMatrixRequest::PinMatrixRequestType>(&s, e);
		else
			skip_by_type(field_type, &s, e);
	}
}

std::string write(const ::hw::trezor::messages::common::PinMatrixRequest &v) {
	std::string s;
	if (v.type != ::hw::trezor::messages::common::PinMatrixRequest::PinMatrixRequestType::PinMatrixRequestType_Current)
		write_field_varint(1, static_cast<uint64_t>(v.type), s);
	return s;
}

void read(::hw::trezor::messages::common::PinMatrixAck &v, iterator s, iterator e) {
	while (s != e) {
		auto m            = read_varint(&s, e);
		auto field_type   = static_cast<unsigned>(m & 7);
		auto field_number = static_cast<unsigned>(m >> 3);
		if (field_number == 1 && field_type == 2)
			v.pin = read_string(&s, e);
		else
			skip_by_type(field_type, &s, e);
	}
}

std::string write(const ::hw::trezor::messages::common::PinMatrixAck &v) {
	std::string s;
	write_field_string(1, v.pin, s);
	return s;
}

void read(::hw::trezor::messages::common::PassphraseRequest &v, iterator s, iterator e) {
	while (s != e) {
		auto m            = read_varint(&s, e);
		auto field_type   = static_cast<unsigned>(m & 7);
		auto field_number = static_cast<unsigned>(m >> 3);
		if (field_number == 1 && field_type == 0)
			v.on_device = read_varint(&s, e) != 0;
		else
			skip_by_type(field_type, &s, e);
	}
}

std::string write(const ::hw::trezor::messages::common::PassphraseRequest &v) {
	std::string s;
	if (v.on_device)
		write_field_varint(1, v.on_device ? 1 : 0, s);
	return s;
}

void read(::hw::trezor::messages::common::PassphraseAck &v, iterator s, iterator e) {
	while (s != e) {
		auto m            = read_varint(&s, e);
		auto field_type   = static_cast<unsigned>(m & 7);
		auto field_number = static_cast<unsigned>(m >> 3);
		if (field_number == 1 && field_type == 2)
			v.passphrase = read_string(&s, e);
		else if (field_number == 2 && field_type == 2)
			v.state = read_string(&s, e);
		else
			skip_by_type(field_type, &s, e);
	}
}

std::string write(const ::hw::trezor::messages::common::PassphraseAck &v) {
	std::string s;
	if (!v.passphrase.empty())
		write_field_string(1, v.passphrase, s);
	if (!v.state.empty())
		write_field_string(2, v.state, s);
	return s;
}

void read(::hw::trezor::messages::common::PassphraseStateRequest &v, iterator s, iterator e) {
	while (s != e) {
		auto m            = read_varint(&s, e);
		auto field_type   = static_cast<unsigned>(m & 7);
		auto field_number = static_cast<unsigned>(m >> 3);
		if (field_number == 1 && field_type == 2)
			v.state = read_string(&s, e);
		else
			skip_by_type(field_type, &s, e);
	}
}

std::string write(const ::hw::trezor::messages::common::PassphraseStateRequest &v) {
	std::string s;
	if (!v.state.empty())
		write_field_string(1, v.state, s);
	return s;
}

void read(::hw::trezor::messages::common::PassphraseStateAck &v, iterator s, iterator e) {
	while (s != e) {
		auto m          = read_varint(&s, e);
		auto field_type = static_cast<unsigned>(m & 7);
		skip_by_type(field_type, &s, e);
	}
}

std::string write(const ::hw::trezor::messages::common::PassphraseStateAck &v) {
	std::string s;
	return s;
}

void read(::hw::trezor::messages::common::HDNodeType &v, iterator s, iterator e) {
	while (s != e) {
		auto m            = read_varint(&s, e);
		auto field_type   = static_cast<unsigned>(m & 7);
		auto field_number = static_cast<unsigned>(m >> 3);
		if (field_number == 1 && field_type == 0)
			v.depth = read_varint_t<uint32_t>(&s, e);
		else if (field_number == 2 && field_type == 0)
			v.fingerprint = read_varint_t<uint32_t>(&s, e);
		else if (field_number == 3 && field_type == 0)
			v.child_num = read_varint_t<uint32_t>(&s, e);
		else if (field_number == 4 && field_type == 2)
			v.chain_code = read_string(&s, e);
		else if (field_number == 5 && field_type == 2)
			v.private_key = read_string(&s, e);
		else if (field_number == 6 && field_type == 2)
			v.public_key = read_string(&s, e);
		else
			skip_by_type(field_type, &s, e);
	}
}

std::string write(const ::hw::trezor::messages::common::HDNodeType &v) {
	std::string s;
	write_field_varint(1, v.depth, s);
	write_field_varint(2, v.fingerprint, s);
	write_field_varint(3, v.child_num, s);
	write_field_string(4, v.chain_code, s);
	if (!v.private_key.empty())
		write_field_string(5, v.private_key, s);
	if (!v.public_key.empty())
		write_field_string(6, v.public_key, s);
	return s;
}

}  // namespace protobuf
