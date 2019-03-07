#include <cstdint>
#include <string>
#include <vector>

namespace hw { namespace trezor { namespace messages { namespace bytecoin {

struct BytecoinStartRequest {};

struct BytecoinStartResponse {
	std::string version;
	std::string wallet_key;
	std::string A_plus_sH;
	std::string v_mul_A_plus_sH;
	std::string view_public_key;
};

struct BytecoinScanOutputsRequest {
	std::vector<std::string> output_public_key;
};

struct BytecoinScanOutputsResponse {
	std::vector<std::string> Pv;
};

struct BytecoinGenerateKeyimageRequest {
	std::string output_secret_hash_arg;
	uint32_t address_index = 0;
};

struct BytecoinGenerateKeyimageResponse {
	std::string keyimage;
};

struct BytecoinGenerateOutputSeedRequest {
	std::string tx_inputs_hash;
	uint32_t out_index = 0;
};

struct BytecoinGenerateOutputSeedResponse {
	std::string output_seed;
};

struct BytecoinExportViewWalletRequest {};

struct BytecoinExportViewWalletResponse {
	std::string audit_key_base_secret_key;
	std::string view_secret_key;
	std::string view_seed;
	std::string view_secrets_signature;
};

struct BytecoinSignStartRequest {
	uint32_t version      = 0;
	uint64_t ut           = 0;
	uint32_t inputs_size  = 0;
	uint32_t outputs_size = 0;
	uint32_t extra_size   = 0;
};

struct BytecoinEmptyResponse {};

struct BytecoinSignAddInputRequest {
	uint64_t amount = 0;
	std::vector<uint32_t> output_indexes;
	std::string output_secret_hash_arg;
	uint32_t address_index = 0;
};

struct BytecoinSignAddOutputRequest {
	bool change              = false;
	uint64_t amount          = 0;
	uint32_t dst_address_tag = 0;
	std::string dst_address_S;
	std::string dst_address_Sv;
	uint32_t change_address_index = 0;
};

struct BytecoinSignAddOutputResponse {
	std::string public_key;
	std::string encrypted_secret;
	uint32_t encrypted_address_type = 0;
};

struct BytecoinSignAddExtraRequest {
	std::string extra_chunk;
};

struct BytecoinSignStepARequest {
	std::string output_secret_hash_arg;
	uint64_t address_index = 0;
};

struct BytecoinSignStepAResponse {
	std::string sig_p;
	std::string y;
	std::string z;
};

struct BytecoinSignStepAMoreDataRequest {
	std::string data_chunk;
};

struct BytecoinSignGetC0Request {};

struct BytecoinSignGetC0Response {
	std::string c0;
};

struct BytecoinSignStepBRequest {
	std::string output_secret_hash_arg;
	uint64_t address_index = 0;
	std::string my_c;
};

struct BytecoinSignStepBResponse {
	std::string my_rr;
	std::string rs;
	std::string ra;
	std::string encryption_key;
};

struct BytecoinStartProofRequest {
	uint32_t data_size = 0;
};

}}}}  // namespace hw::trezor::messages::bytecoin

namespace protobuf {

typedef std::string::const_iterator iterator;

void read(::hw::trezor::messages::bytecoin::BytecoinEmptyResponse &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinEmptyResponse &v);

void read(::hw::trezor::messages::bytecoin::BytecoinExportViewWalletRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinExportViewWalletRequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinExportViewWalletResponse &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinExportViewWalletResponse &v);

void read(::hw::trezor::messages::bytecoin::BytecoinGenerateKeyimageRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinGenerateKeyimageRequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinGenerateKeyimageResponse &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinGenerateKeyimageResponse &v);

void read(::hw::trezor::messages::bytecoin::BytecoinGenerateOutputSeedRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinGenerateOutputSeedRequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinGenerateOutputSeedResponse &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinGenerateOutputSeedResponse &v);

void read(::hw::trezor::messages::bytecoin::BytecoinScanOutputsRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinScanOutputsRequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinScanOutputsResponse &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinScanOutputsResponse &v);

void read(::hw::trezor::messages::bytecoin::BytecoinSignAddExtraRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinSignAddExtraRequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinSignAddInputRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinSignAddInputRequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinSignAddOutputRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinSignAddOutputRequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinSignAddOutputResponse &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinSignAddOutputResponse &v);

void read(::hw::trezor::messages::bytecoin::BytecoinSignGetC0Request &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinSignGetC0Request &v);

void read(::hw::trezor::messages::bytecoin::BytecoinSignGetC0Response &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinSignGetC0Response &v);

void read(::hw::trezor::messages::bytecoin::BytecoinSignStartRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinSignStartRequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinSignStepAMoreDataRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinSignStepAMoreDataRequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinSignStepARequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinSignStepARequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinSignStepAResponse &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinSignStepAResponse &v);

void read(::hw::trezor::messages::bytecoin::BytecoinSignStepBRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinSignStepBRequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinSignStepBResponse &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinSignStepBResponse &v);

void read(::hw::trezor::messages::bytecoin::BytecoinStartProofRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinStartProofRequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinStartRequest &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinStartRequest &v);

void read(::hw::trezor::messages::bytecoin::BytecoinStartResponse &v, iterator s, iterator e);
std::string write(const ::hw::trezor::messages::bytecoin::BytecoinStartResponse &v);

}  // namespace protobuf
