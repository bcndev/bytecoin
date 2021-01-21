#include <cstdint>
#include <string>
#include <vector>

namespace hw { namespace trezor { namespace messages { namespace common {

struct Success {
	std::string message;
};

struct Failure {
	enum FailureType {
		Failure_UnexpectedMessage = 1,
		Failure_ButtonExpected    = 2,
		Failure_DataError         = 3,
		Failure_ActionCancelled   = 4,
		Failure_PinExpected       = 5,
		Failure_PinCancelled      = 6,
		Failure_PinInvalid        = 7,
		Failure_InvalidSignature  = 8,
		Failure_ProcessError      = 9,
		Failure_NotEnoughFunds    = 10,
		Failure_NotInitialized    = 11,
		Failure_PinMismatch       = 12,
		Failure_FirmwareError     = 99
	};

	FailureType code = Failure_UnexpectedMessage;
	std::string message;
};

struct ButtonRequest {
	enum ButtonRequestType {
		ButtonRequest_Other                 = 1,
		ButtonRequest_FeeOverThreshold      = 2,
		ButtonRequest_ConfirmOutput         = 3,
		ButtonRequest_ResetDevice           = 4,
		ButtonRequest_ConfirmWord           = 5,
		ButtonRequest_WipeDevice            = 6,
		ButtonRequest_ProtectCall           = 7,
		ButtonRequest_SignTx                = 8,
		ButtonRequest_FirmwareCheck         = 9,
		ButtonRequest_Address               = 10,
		ButtonRequest_PublicKey             = 11,
		ButtonRequest_MnemonicWordCount     = 12,
		ButtonRequest_MnemonicInput         = 13,
		ButtonRequest_PassphraseType        = 14,
		ButtonRequest_UnknownDerivationPath = 15
	};

	ButtonRequestType code = ButtonRequest_Other;
	std::string data;
};

struct ButtonAck {};

struct PinMatrixRequest {
	enum PinMatrixRequestType {
		PinMatrixRequestType_Current   = 1,
		PinMatrixRequestType_NewFirst  = 2,
		PinMatrixRequestType_NewSecond = 3
	};

	PinMatrixRequestType type = PinMatrixRequestType_Current;
};

struct PinMatrixAck {
	std::string pin;
};

struct PassphraseRequest {
	bool on_device = false;
};

struct PassphraseAck {
	std::string passphrase;
	std::string state;
};

struct PassphraseStateRequest {
	std::string state;
};

struct PassphraseStateAck {};

struct HDNodeType {
	uint32_t depth       = 0;
	uint32_t fingerprint = 0;
	uint32_t child_num   = 0;
	std::string chain_code;
	std::string private_key;
	std::string public_key;
};

}}}}  // namespace hw::trezor::messages::common

namespace protobuf {

typedef std::string::const_iterator iterator;

void read(::hw::trezor::messages::common::ButtonAck &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::common::ButtonAck &v);

void read(::hw::trezor::messages::common::ButtonRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::common::ButtonRequest &v);

void read(::hw::trezor::messages::common::Failure &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::common::Failure &v);

void read(::hw::trezor::messages::common::HDNodeType &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::common::HDNodeType &v);

void read(::hw::trezor::messages::common::PassphraseAck &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::common::PassphraseAck &v);

void read(::hw::trezor::messages::common::PassphraseRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::common::PassphraseRequest &v);

void read(::hw::trezor::messages::common::PassphraseStateAck &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::common::PassphraseStateAck &v);

void read(::hw::trezor::messages::common::PassphraseStateRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::common::PassphraseStateRequest &v);

void read(::hw::trezor::messages::common::PinMatrixAck &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::common::PinMatrixAck &v);

void read(::hw::trezor::messages::common::PinMatrixRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::common::PinMatrixRequest &v);

void read(::hw::trezor::messages::common::Success &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::common::Success &v);

}  // namespace protobuf
