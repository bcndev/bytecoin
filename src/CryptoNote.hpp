// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <boost/variant.hpp>
#include <functional>
#include <vector>
#include "common/BinaryArray.hpp"
#include "common/Invariant.hpp"  // Promote using it systemwide
#include "crypto/types.hpp"

// We define here, as CryptoNoteConfig.h is never included anywhere anymore
#define bytecoin_ALLOW_DEBUG_COMMANDS 1

#define bytecoin_ALLOW_CM 0

#define bytecoin_NEWP2P 0

namespace bytecoin {

using crypto::Hash;
using crypto::PublicKey;
using crypto::SecretKey;
using crypto::KeyPair;
using crypto::KeyDerivation;
using crypto::KeyImage;
using crypto::Signature;

using common::BinaryArray;

using namespace std::placeholders;  // We enjoy standard bindings

typedef uint32_t Height;
typedef uint64_t Difficulty;
typedef uint64_t Amount;
typedef uint32_t Timestamp;
typedef uint64_t BlockOrTimestamp;
// Height or Timestamp, 32-bit is enough, but historically we already have several very large values in blockchain
typedef int64_t SignedAmount;

struct CoinbaseInput {
	Height height = 0;
};

struct KeyInput {
	Amount amount = 0;
	std::vector<uint32_t> output_indexes;
	KeyImage key_image;
};

struct KeyOutput {
	PublicKey public_key;
};

typedef boost::variant<CoinbaseInput, KeyInput> TransactionInput;

typedef boost::variant<KeyOutput> TransactionOutputTarget;

struct TransactionOutput {
	Amount amount = 0;
	// Freaking stupidity - why excess indirection with amount left outside variant part?
	// We cannot fix it easily. Will have to switch transaction version
	TransactionOutputTarget target;
};

struct TransactionPrefix {
	uint8_t version                            = 0;
	BlockOrTimestamp unlock_block_or_timestamp = 0;
	std::vector<TransactionInput> inputs;
	std::vector<TransactionOutput> outputs;
	BinaryArray extra;
};

typedef std::vector<std::vector<Signature>> TransactionSignatures;

struct Transaction : public TransactionPrefix {
	TransactionSignatures signatures;
};

struct BaseTransaction : public TransactionPrefix {};  // has 'ignored' field during seria

struct ParentBlock {  // or Merge Mining Root, not to be confused with previous block!
	uint8_t major_version = 0;
	uint8_t minor_version = 0;
	Timestamp timestamp   = 0;
	Hash previous_block_hash;
	uint32_t nonce             = 0;
	uint32_t transaction_count = 0;
	std::vector<Hash> base_transaction_branch;
	BaseTransaction base_transaction;
	std::vector<Hash> blockchain_branch;
};

struct BlockHeader {
	uint8_t major_version = 0;
	uint8_t minor_version = 0;  // Used for hard fork voting
	uint64_t nonce        = 0;  // only 32-bit is used in blocks without CM
	Timestamp timestamp   = 0;
	Hash previous_block_hash;
	ParentBlock parent_block;            // For block with MM (V2, V3)
	std::vector<Hash> cm_merkle_branch;  // For blocks with CM (V104)
};

struct BlockBodyProxy {
	Hash transactions_merkle_root;
	uint32_t transaction_count = 0;
};
// BlockHeader + (BlockBodyProxy | BlockBody) are enough to calc POW consensus
// BlockBody is std::vector<Transaction> where coinbase is the first one

struct BlockTemplate : public BlockHeader {
	Transaction base_transaction;
	std::vector<Hash> transaction_hashes;
};

enum BlockSeriaType { NORMAL, PREHASH, BLOCKHASH, LONG_BLOCKHASH };

struct AccountPublicAddress {
	PublicKey spend_public_key;
	PublicKey view_public_key;
};

struct SendProof {  // proofing that some tx actually sent amount to particular address
	Hash transaction_hash;
	AccountPublicAddress address;
	Amount amount = 0;
	std::string message;
	KeyDerivation derivation;
	Signature signature;
	// pair of derivation and signature form a proof of only fact that creator knows transaction private key and
	// he or she wished to include public view key of address into proof. To further check, look up tx_hash in
	// main chain and sum amounts of outputs which have spend keys corresponding to address public spend key
};

struct AccountKeys {
	AccountPublicAddress address;
	SecretKey spend_secret_key;
	SecretKey view_secret_key;
};

struct RawBlock {
	BinaryArray block;  // BlockTemplate
	std::vector<BinaryArray> transactions;
};

class Block {
public:
	BlockTemplate header;
	std::vector<Transaction> transactions;

	bool from_raw_block(const RawBlock &);
	bool to_raw_block(RawBlock &) const;
};

struct SWCheckpoint {
	Height height = 0;
	Hash hash;
};
struct Checkpoint {
	Height height = 0;
	Hash hash;
	uint32_t key_id  = 0;
	uint64_t counter = 0;
	Hash get_message_hash() const;
	bool is_enabled() const { return counter != std::numeric_limits<uint64_t>::max(); }
};
struct SignedCheckpoint : public Checkpoint {
	Signature signature;
};

// Predicates for using in maps, sets, etc
inline bool operator==(const AccountPublicAddress &a, const AccountPublicAddress &b) {
	return std::tie(a.view_public_key, a.spend_public_key) == std::tie(b.view_public_key, b.spend_public_key);
}
inline bool operator!=(const AccountPublicAddress &a, const AccountPublicAddress &b) { return !operator==(a, b); }
inline bool operator<(const AccountPublicAddress &a, const AccountPublicAddress &b) {
	return std::tie(a.view_public_key, a.spend_public_key) < std::tie(b.view_public_key, b.spend_public_key);
}

class Currency;  // For ser_members of bytecoin::SendProof
}  // namespace bytecoin

// Serialization is part of CryptoNote standard, not problem to put it here
namespace seria {
class ISeria;

void ser(bytecoin::Hash &v, ISeria &s);
void ser(bytecoin::KeyImage &v, ISeria &s);
void ser(bytecoin::PublicKey &v, ISeria &s);
void ser(bytecoin::SecretKey &v, ISeria &s);
void ser(bytecoin::KeyDerivation &v, ISeria &s);
void ser(bytecoin::Signature &v, ISeria &s);

void ser_members(bytecoin::AccountPublicAddress &v, ISeria &s);
void ser_members(bytecoin::SendProof &v, ISeria &s, const bytecoin::Currency &);
void ser_members(bytecoin::TransactionInput &v, ISeria &s);
void ser_members(bytecoin::TransactionOutput &v, ISeria &s);
void ser_members(bytecoin::TransactionOutputTarget &v, ISeria &s);

void ser_members(bytecoin::CoinbaseInput &v, ISeria &s);
void ser_members(bytecoin::KeyInput &v, ISeria &s);

void ser_members(bytecoin::KeyOutput &v, ISeria &s);

void ser_members(bytecoin::TransactionPrefix &v, ISeria &s);
void ser_members(bytecoin::BaseTransaction &v, ISeria &s);
void ser_members(bytecoin::Transaction &v, ISeria &s);

void ser_members(
    bytecoin::ParentBlock &v, ISeria &s, bytecoin::BlockSeriaType seria_type = bytecoin::BlockSeriaType::NORMAL);
void ser_members(bytecoin::BlockHeader &v, ISeria &s,
    bytecoin::BlockSeriaType seria_type = bytecoin::BlockSeriaType::NORMAL,
    bytecoin::BlockBodyProxy body_proxy = bytecoin::BlockBodyProxy{});
void ser_members(bytecoin::BlockBodyProxy &v, ISeria &s);
void ser_members(bytecoin::BlockTemplate &v, ISeria &s);

void ser_members(bytecoin::RawBlock &v, ISeria &s);
void ser_members(bytecoin::Block &v, ISeria &s);

void ser_members(bytecoin::SWCheckpoint &v, ISeria &s);
void ser_members(bytecoin::Checkpoint &v, ISeria &s);
void ser_members(bytecoin::SignedCheckpoint &v, ISeria &s);
}
