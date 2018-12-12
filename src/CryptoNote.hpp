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

#define bytecoin_ALLOW_CM 1

namespace cn {

using crypto::Hash;
using crypto::KeyDerivation;
using crypto::KeyImage;
using crypto::KeyPair;
using crypto::PublicKey;
using crypto::RingSignature;
using crypto::RingSignature3;
using crypto::SecretKey;
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

struct InputCoinbase {
	Height height = 0;
	enum { type_tag = 0xff };
	static std::string str_type_tag() { return "coinbase"; }
};

struct InputKey {
	Amount amount = 0;
	std::vector<size_t> output_indexes;
	KeyImage key_image;
	enum { type_tag = 2 };
	static std::string str_type_tag() { return "key"; }
};

struct OutputKey {
	Amount amount = 0;
	PublicKey public_key;
	Hash encrypted_secret;  // serialized only in amethyst
	bool is_auditable = false;
	enum { type_tag = 2, type_tag_auditable = 32 + 2 };  // we treat it similar to a flag
	// type_tag_auditable is only allowed in amethyst
	static std::string str_type_tag() { return "key"; }
	static std::string str_type_tag_auditable() { return "key_auditable"; }
};

typedef boost::variant<InputCoinbase, InputKey> TransactionInput;

typedef boost::variant<OutputKey> TransactionOutput;

// Beware - amount is serialized before variant tag. We cannot fix it easily without advancing transaction version
// We've broken compatibility in amethyst, bringing amount inside variant part

struct TransactionPrefix {
	uint8_t version                            = 0;
	BlockOrTimestamp unlock_block_or_timestamp = 0;
	std::vector<TransactionInput> inputs;
	std::vector<TransactionOutput> outputs;
	BinaryArray extra;
};

struct RingSignatures {
	std::vector<RingSignature> signatures;
};

typedef boost::variant<boost::blank, RingSignatures, RingSignature3> TransactionSignatures;

struct Transaction : public TransactionPrefix {
	TransactionSignatures signatures;
};

struct BaseTransaction : public TransactionPrefix {};  // has 'ignored' field during seria

struct RootBlock {  // when block is merge mined
	uint8_t major_version = 0;
	uint8_t minor_version = 0;
	Timestamp timestamp   = 0;
	Hash previous_block_hash;
	uint8_t nonce[4]{};  // 4 bytes is more convenient than uint32_t
	size_t transaction_count = 0;
	std::vector<Hash> base_transaction_branch;
	BaseTransaction base_transaction;
	std::vector<Hash> blockchain_branch;
};

struct BlockHeader {
	uint8_t major_version = 0;
	uint8_t minor_version = 0;  // Not version at all, used for hard fork voting
	Timestamp timestamp   = 0;
	Hash previous_block_hash;
	BinaryArray nonce;  // 4 bytes, except in blocks with is_cm_mined() (variable-length there)

	RootBlock root_block;                                   // For block with is_merge_mined() true
	std::vector<crypto::CMBranchElement> cm_merkle_branch;  // For blocks with is_cm_mined() true

	bool is_merge_mined() const { return major_version == 2 || major_version == 3 || major_version == 4; }
	bool is_cm_mined() const { return major_version == 5; }
};

struct BlockBodyProxy {
	Hash transactions_merkle_root;
	size_t transaction_count = 0;
};
// BlockHeader + (BlockBodyProxy | BlockBody) are enough to calc POW consensus
// BlockBody is std::vector<Transaction> where coinbase is the first one

struct BlockTemplate : public BlockHeader {
	Transaction base_transaction;
	std::vector<Hash> transaction_hashes;
};

enum BlockSeriaType { NORMAL, PREHASH, BLOCKHASH, LONG_BLOCKHASH };

struct AccountAddressSimple {
	PublicKey spend_public_key;
	PublicKey view_public_key;
	enum { type_tag = 0 };
	static std::string str_type_tag() { return "simple"; }
};

struct AccountAddressUnlinkable {
	PublicKey s;
	PublicKey sv;
	bool is_auditable = false;
	enum { type_tag = 1, type_tag_auditable = 2 };
	static std::string str_type_tag() { return "unlinkable"; }
	static std::string str_type_tag_auditable() { return "unlinkable_auditable"; }
};

typedef boost::variant<AccountAddressSimple, AccountAddressUnlinkable> AccountAddress;

struct SendproofKey {
	KeyDerivation derivation;
	Signature signature;
	// pair of derivation and signature form a proof of only fact that creator knows transaction private key and
	// he or she wished to include public view key of address into proof. To further check, look up tx_hash in
	// main chain and sum amounts of outputs which have spend keys corresponding to address public spend key
	// For unlinkable addresses
};
struct SendproofUnlinkable {
	struct Element {
		size_t out_index = 0;
		PublicKey q;
		Signature signature;
	};
	std::vector<Element> elements;
};

struct Sendproof {  // proofing that some tx actually sent amount to particular address
	Hash transaction_hash;
	AccountAddress address;
	Amount amount = 0;
	std::string message;
	boost::variant<SendproofKey, SendproofUnlinkable> proof;
};

struct RawBlock {
	BinaryArray block;  // BlockTemplate
	std::vector<BinaryArray> transactions;
};

class Block {
public:
	BlockTemplate header;
	std::vector<Transaction> transactions;

	Block() = default;
	explicit Block(const RawBlock &rb);
	//	bool from_raw_block(const RawBlock &);
	//	bool to_raw_block(RawBlock &) const;
};

struct HardCheckpoint {
	Height height = 0;
	Hash hash;
};
struct Checkpoint {
	Height height = 0;
	Hash hash;
	size_t key_id    = 0;
	uint64_t counter = 0;
	Hash get_message_hash() const;
	bool is_enabled() const { return counter != std::numeric_limits<uint64_t>::max(); }
};
struct SignedCheckpoint : public Checkpoint {
	Signature signature;
};

// Predicates for using in maps, sets, etc
inline bool operator==(const AccountAddressSimple &a, const AccountAddressSimple &b) {
	return std::tie(a.view_public_key, a.spend_public_key) == std::tie(b.view_public_key, b.spend_public_key);
}
inline bool operator!=(const AccountAddressSimple &a, const AccountAddressSimple &b) { return !operator==(a, b); }
inline bool operator<(const AccountAddressSimple &a, const AccountAddressSimple &b) {
	return std::tie(a.view_public_key, a.spend_public_key) < std::tie(b.view_public_key, b.spend_public_key);
}

inline bool operator==(const AccountAddressUnlinkable &a, const AccountAddressUnlinkable &b) {
	return std::tie(a.s, a.sv) == std::tie(b.s, b.sv);
}
inline bool operator!=(const AccountAddressUnlinkable &a, const AccountAddressUnlinkable &b) {
	return !operator==(a, b);
}
inline bool operator<(const AccountAddressUnlinkable &a, const AccountAddressUnlinkable &b) {
	return std::tie(a.s, a.sv) < std::tie(b.s, b.sv);
}

class Currency;  // For ser_members of cn::Sendproof
}  // namespace cn

// Serialization is part of CryptoNote standard, not problem to put it here
namespace seria {
class ISeria;

void ser(cn::Hash &v, ISeria &s);
void ser(cn::KeyImage &v, ISeria &s);
void ser(cn::PublicKey &v, ISeria &s);
void ser(cn::SecretKey &v, ISeria &s);
void ser(cn::KeyDerivation &v, ISeria &s);
void ser(cn::Signature &v, ISeria &s);
void ser(crypto::EllipticCurveScalar &v, ISeria &s);

void ser_members(cn::AccountAddressSimple &v, ISeria &s);
void ser_members(cn::AccountAddressUnlinkable &v, ISeria &s);
void ser_members(cn::AccountAddress &v, ISeria &s);
void ser_members(cn::SendproofKey &v, ISeria &s);
void ser_members(cn::SendproofUnlinkable::Element &v, ISeria &s);
void ser_members(cn::SendproofUnlinkable &v, ISeria &s);
void ser_members(cn::Sendproof &v, ISeria &s, const cn::Currency &);
void ser_members(cn::TransactionInput &v, ISeria &s);
void ser_members(cn::TransactionOutput &v, ISeria &s, bool is_tx_amethyst);

void ser_members(cn::InputCoinbase &v, ISeria &s);
void ser_members(cn::InputKey &v, ISeria &s);
void ser_members(cn::RingSignatures &v, ISeria &s);
void ser_members(cn::RingSignature3 &v, ISeria &s);
void ser_members(cn::TransactionSignatures &v, ISeria &s);
void ser_members(cn::TransactionSignatures &v, ISeria &s, const cn::TransactionPrefix &prefix);

void ser_members(cn::OutputKey &v, ISeria &s, bool is_tx_amethyst);

void ser_members(cn::TransactionPrefix &v, ISeria &s);
void ser_members(cn::BaseTransaction &v, ISeria &s);
void ser_members(cn::Transaction &v, ISeria &s);

void ser_members(cn::RootBlock &v, ISeria &s, cn::BlockSeriaType seria_type = cn::BlockSeriaType::NORMAL);
void ser_members(crypto::CMBranchElement &v, ISeria &s);

void ser_members(cn::BlockHeader &v, ISeria &s, cn::BlockSeriaType seria_type = cn::BlockSeriaType::NORMAL,
    cn::BlockBodyProxy body_proxy = cn::BlockBodyProxy{}, const crypto::Hash &cm_path = crypto::Hash{});
void ser_members(cn::BlockBodyProxy &v, ISeria &s);
void ser_members(cn::BlockTemplate &v, ISeria &s);

void ser_members(cn::RawBlock &v, ISeria &s);
void ser_members(cn::Block &v, ISeria &s);

void ser_members(cn::HardCheckpoint &v, ISeria &s);
void ser_members(cn::Checkpoint &v, ISeria &s);
void ser_members(cn::SignedCheckpoint &v, ISeria &s);
}  // namespace seria
