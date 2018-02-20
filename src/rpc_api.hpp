// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#pragma once

#include <boost/optional.hpp>
#include <limits>
#include <map>
#include <string>
#include <vector>
#include "CryptoNote.hpp"
#include "crypto/types.hpp"

// Common data structures used in all api calls.
// Basic data types are serialized to Json as follows
// bool - Bool
// Amount, SignedAmount, Height, Timestamp, UnlockMoment, Difficulty, (u)int - Number. bytecoin does not use fractional
// numbers, but uses numbers as large as 2^64-1 for amounts, which is larger than 2^53 exactly representable in double
// or JavaScript Number
//     amounts large than ~91 million BCN cannot be represented exactly in JavaScript and other platforms using IEEE
//     64-bit floating numbers, so you should use appropriate json/bigint library to handle large amounts
// std::string, Hash, PublicKey, SecretKey, KeyImage, BinaryArray - String (hex)
// std::vector - Array
// std::map, struct - Object
// bytecoin does not use Null, you should specify empty Array as [], empty string as "", empty Object as {}
namespace bytecoin {
namespace api {

struct EmptyStruct {};  // Used as a typedef for empty requests, which we have a lot

typedef int32_t HeightOrDepth;  // If >= 0 - interpret as Height, if < 0 interpret as Depth, e.g. -1 means
                                // top_block_height, -4 means 3 blocks back from topBlockHeight
constexpr HeightOrDepth DEFAULT_CONFIRMATIONS = 5;

struct Output {
	Amount amount = 0;
	PublicKey public_key;
	uint32_t global_index = 0;
	// Added from transaction
	UnlockMoment unlock_time      = 0;  // timestamp | blockIndex, see function isTransactionSpendTimeUnlocked below
	uint32_t index_in_transaction = 0;  // # of output, output keys depend on transaction_public_key and this index, so
	                                    // they are different for the same address
	// Added from block
	Height height = 0;
	// Added by wallet for recognized outputs
	KeyImage key_image;
	PublicKey transaction_public_key;
	std::string address;
	bool dust = false;
};

struct Transfer {
	std::string address;
	SignedAmount amount = 0;  // Will be negative if transfer is from that address
	bool ours = false;        // true for addresses in wallet, false for others. Other addresses are recognized only for
	                          // transactions which have proof data stored in <wallet_file>.history/
	bool locked = false;  // locked transfers should not be added to balance immediately. They will be unlocked later
	                      // and sent via GetTransfers.Response.unlocked_transfers
	std::vector<api::Output> outputs;  // Outputs corresponding to this transfer
};

struct Transaction {
	// Fields for new transactions.
	UnlockMoment unlock_time = 0;          // timestamp | blockIndex, see function isTransactionSpendTimeUnlocked below
	std::vector<api::Transfer> transfers;  // includes only transfers we can view
	Hash payment_id;         // omit or set to all zero-hash to indicate no payment id. Will be DEPRECATED in future
	uint32_t anonymity = 0;  // recommended to set to DEFAULT_ANONYMITY_LEVEL for new transactions, for existing
	                         // transactions min(input anonymity) will be returned
	// Filled after transaction is created
	Hash hash;
	SignedAmount fee = 0;
	PublicKey public_key;
	BinaryArray extra;  // payment_id and additional fields are packed here. see TransactionExtra.*pp for details
	bool coinbase = false;
	Amount amount = 0;  // Sum of amounts transferred

	// after transaction is included in block
	Height block_height = 0;
	Hash block_hash;          // For mempool transactions block_hash is all zeroes (or absent from Json)
	Timestamp timestamp = 0;  // Timestamp of block if transaction is in block. For mempool transactions this is the
	                          // time node first seen this transaction.
};

struct BlockHeader {
	uint8_t major_version = 0;
	uint8_t minor_version = 0;
	Timestamp timestamp   = 0;
	Hash previous_block_hash;
	uint32_t nonce = 0;
	Height height  = 0;
	Hash hash;
	Amount reward                           = 0;
	Difficulty cumulative_difficulty        = 0;
	Difficulty difficulty                   = 0;
	Amount base_reward                      = 0;
	uint32_t block_size                     = 0;  // Only sum of all transactions including coinbase.
	uint32_t transactions_cumulative_size   = 0;  // Sum of all transactions without coinbase.
	Amount already_generated_coins          = 0;
	uint64_t already_generated_transactions = 0;
	uint32_t size_median                    = 0;
	uint32_t effective_size_median =
	    0;  // max(100000, size_median) for block version 3, allows sudden peaks in network load.
	Timestamp timestamp_median = 0;
	Timestamp timestamp_unlock = 0;  // Can be used for guaranteed output unlocking, as 1. block.timestamp_unlock <
	                                 // block.timestamp and 2. nextBlock.timestamp_unlock >=
	                                 // currentBlock.timestamp_unlock
	Amount total_fee_amount = 0;

	double penalty() const {
		return base_reward == 0 ? 0 : double(base_reward - reward) / base_reward;
	}  // We do not need trivial fields in API. Instead we provide an algorithm to calc.
};

struct Block {
	api::BlockHeader header;
	std::vector<api::Transaction>
	    transactions;  // If got from walletd, will contain only transactions with transfers we can view.
};

struct Balance {
	Amount spendable             = 0;
	Amount spendable_dust        = 0;
	Amount locked_or_unconfirmed = 0;
	Amount total() const {
		return spendable + spendable_dust + locked_or_unconfirmed;
	}  // This fun serves as a documentation.
};
}
}

// These messages encoded in JSON can be sent via http to walletd rpc address:port
namespace bytecoin {
namespace api {

enum return_code {
	BYTECOIND_DATABASE_ERROR    = 101,  // We hope we are out of disk space, otherwise blockchain DB is corrupted.
	BYTECOIND_ALREADY_RUNNING   = 102,
	WALLETD_BIND_PORT_IN_USE    = 103,
	BYTECOIND_BIND_PORT_IN_USE  = 104,
	WALLET_FILE_READ_ERROR      = 205,
	WALLET_FILE_UNKNOWN_VERSION = 206,
	WALLET_FILE_DECRYPT_ERROR   = 207,
	WALLET_FILE_WRITE_ERROR     = 208,
	WALLET_FILE_EXISTS          = 209,  // Daemon never overwrites file during --generate-wallet.
	WALLET_WITH_THE_SAME_VIEWKEY_IN_USE =
	    210,  // Another walletd instance is using the same wallet file or another wallet file with the same view key.
	WALLETD_WRONG_ARGS = 211
};

namespace walletd {

inline std::string url() { return "/json_rpc"; }

const uint32_t DEFAULT_ANONYMITY_LEVEL = 6;

struct GetStatus {
	static std::string method() { return "get_status"; }  // get_status of node is shadowed by walletd.

	struct Request {
		Hash top_block_hash;
		uint32_t transaction_pool_version = 0;  // Pool version is reset to 1 on every new block. Pool version is
		                                        // incremented on every modification to pool.
		uint32_t outgoing_peer_count = 0;
		uint32_t incoming_peer_count = 0;
		// You get longpoll (no immediate reply) until any parameter changes.
		// You can just send previous response as a next request if you are interested in all changes visible to API.

		bool operator==(const Request &other) const {
			return top_block_hash == other.top_block_hash &&
			       transaction_pool_version == other.transaction_pool_version &&
			       outgoing_peer_count == other.outgoing_peer_count && incoming_peer_count == other.incoming_peer_count;
		}
		bool operator!=(const Request &other) const { return !operator==(other); }
	};
	struct Response : public Request {  // Response and Request have fields in common.
		// Last block analyzed and synched by wallet or node.
		Height top_block_height              = 0;
		Height top_known_block_height        = 0;  // Max of heights reported by p2p peers.
		Difficulty top_block_difficulty      = 0;
		Amount recommended_fee_per_byte      = 0;
		Timestamp top_block_timestamp        = 0;
		Timestamp top_block_timestamp_median = 0;  // This timestamp will be used in unlock calulations after hardfork.
		uint32_t next_block_effective_median_size =
		    0;  // If your tx size is larger, chance it will not be included in block for a long time (or never).
	};
};

struct GetAddresses {  // For simple GUI client, display addresses[0] as main one, show rest of the addresses in popup.
	static std::string method() { return "get_addresses"; }

	typedef EmptyStruct Request;

	struct Response {
		std::vector<std::string> addresses;
		bool view_only = false;
	};
};

struct GetViewKeyPair {
	static std::string method() { return "get_view_key_pair"; }

	typedef EmptyStruct Request;

	struct Response {
		SecretKey secret_view_key;
		PublicKey public_view_key;
	};
};

struct CreateAddresses {
	static std::string method() { return "create_addresses"; }
	struct Request {
		std::vector<SecretKey> secret_spend_keys;  // Leave corresponding key hex string empty to generate keypairs.
		                                           // ["", "", ""] will generate three fresh random addresses
		Timestamp creation_timestamp = 0;  // If you add addresses created in the past, specify an (oldest) timestamp.
		                                   // If any of those addresses not found in wallet cache file, wallet will
		                                   // resync starting from the creation timestamp and remember that timestamp
		                                   // for every added address. Zero means no timestamp, wallet will use now()
	};
	struct Response {
		std::vector<std::string> addresses;
		std::vector<SecretKey> secret_spend_keys;  // For backing up in your db.
	};
};

struct GetBalance {
	static std::string method() { return "get_balance"; }
	// Execution time is proportional to top_block_height - height, so keep height reasonably recent (3-30 confirmations
	// works for most usage cases)
	struct Request {
		std::string address;  // empty for all addresses
		HeightOrDepth height_or_depth = -DEFAULT_CONFIRMATIONS - 1;
	};
	typedef api::Balance Response;
};

struct GetUnspents {
	static std::string method() { return "get_unspents"; }
	// This method execution time is proportional to number of unspent coins
	// sum of outputs per address will be equal to what GetBalance returns
	struct Request {
		std::string address;  // empty for all addresses
		HeightOrDepth height_or_depth = -DEFAULT_CONFIRMATIONS - 1;
	};
	struct Response {
		std::vector<api::Output> spendable;              // Confirmed, unlocked. Dust is also returned here
		std::vector<api::Output> locked_or_unconfirmed;  // Unconfirmed or locked
	};
};

struct GetTransfers {  // Can be used incrementally by high-performace clients to monitor incoming transfers
	static std::string method() { return "get_transfers"; }

	struct Request {
		std::string address;                                        // empty for all addresses
		Height from_height = 0;                                     // From, but not including from_height
		Height to_height   = std::numeric_limits<uint32_t>::max();  // Up to, and including to_height. Will return
		                                                            // transfers in mempool if to_height >
		                                                            // top_block_height
		bool forward = true;  // determines order of blocks returned, additionally if desired_transactions_count set,
		                      // then this defines if call starts from from_height forward, or from to_height backwards
		uint32_t desired_transactions_count =
		    std::numeric_limits<uint32_t>::max();  // Will return this number of transactions or a bit more, It can
		                                           // return more, because this call always returns full blocks
	};
	struct Response {
		std::vector<api::Block> blocks;  // includes only blocks with transactions with transfers we can view
		std::vector<api::Transfer> unlocked_transfers;  // Previous transfers unlocked between from_height and to_height
		Height next_from_height = 0;  // When desired_transactions_count != max you can pass next* to corresponding
		                              // Request fields to continue iteration
		Height next_to_height = 0;
	};
};

struct CreateTransaction {
	static std::string method() { return "create_transaction"; }

	struct Request {
		api::Transaction transaction;  // You fill only basic info (anonymity, optional unlock_time, optional
		                               // payment_id) and transfers. All positive transfers (amount > 0) will be added
		                               // as outputs. For all negative transfers (amount < 0), spendable for requested
		                               // sum and address will be selected and added as inputs
		std::string spend_address;  // If this is not empty, will spend (and optimize) outputs for this address to get
		                            // neccessary funds. Otherwise will spend any output in the wallet
		bool any_spend_address = false;  // if you set spend_address to empty, you should set any_spend_address to true.
		                                 // This is protection against client bug when spend_address is forgotten or
		                                 // accidentally set to null, etc
		std::string change_address;      // Change will be returned to change_address.
		HeightOrDepth confirmed_height_or_depth =
		    -DEFAULT_CONFIRMATIONS - 1;  // Mix-ins will be selected from the [0..confirmed_height] window.
		                                 // Reorganizations larger than confirmations may change mix-in global indices,
		                                 // making transaction invalid.
		SignedAmount fee_per_byte = 0;   // Fee of created transaction will be close to the size of tx * fee_per_byte.
		                                 // You can check it in response.transaction.fee before sending, if you wish
		std::string optimization;  // Wallet outputs optimization (fusion). Leave empty to use normal optimization, good
		                           // for wallets with balanced sends to recieves count. You can save on a few percent
		                           // of fee (on average) by specifying "minimal" for wallet receiving far less
		                           // transactions than sending. You should use "aggressive" for wallet recieving far
		                           // more transactions than sending, this option will use every opportunity to reduce
		                           // number of outputs. For better optimization use as little anonymity as possible. If
		                           // anonymity is set to 0, wallet will prioritize optimizing out dust and crazy (large
		                           // but not round) denominations of outputs.
		bool save_history = true;  // If true, wallet will save encrypted transaction data (~100 bytes per used address)
		                           // in <wallet_file>.history/. With this data it is possible to generate
		                           // public-checkable proofs of sending funds to specific addresses.
	};
	struct Response {
		BinaryArray binary_transaction;   // Empty if error
		api::Transaction transaction;     // contains only fee, hash, blockIndex and anonymity for now...
		bool save_history_error = false;  // Read-only media
	};
};

struct SendTransaction {
	static std::string method() { return "send_transaction"; }

	struct Request {
		BinaryArray binary_transaction;
	};

	struct Response {
		std::string send_result;  // "broadcast" if added to pool. "increasefee" if not added to pool because it is full
		                          // and transaction fee is not enough to replace other transaction.
	};
};

struct CreateSendProof {
	static std::string method() { return "create_send_proof"; }

	struct Request {
		Hash transaction_hash;
		std::string message;  // Add any user message to proof. Changing message will invlidate proof (which works like
		                      // digital signature of message)
		std::vector<std::string> addresses;  // Leave empty to create proof for all "not ours" addresses
	};

	struct Response {
		std::vector<std::string> send_proofs;
	};
};

struct GetTransaction {
	static std::string method() { return "get_transaction"; }
	struct Request {
		Hash hash;
	};
	struct Response {
		api::Transaction
		    transaction;  // empty transaction no hash returned if this transaction contains no recognizable transfers
	};
};
}
}
}

// These messages encoded in JSON can be sent via http url /json_rpc3 to bytecoind rpc address:port
// or to binMethod() url encoded in unspecified binary format
namespace bytecoin {
namespace api {
namespace bytecoind {

inline std::string url() { return "/json_rpc"; }

struct GetStatus {
	static std::string method() { return "get_node_status"; }  // getNodeStatus works directly or through wallet tunnel
	static std::string method2() {
		return "get_status";
	}  // getStatus gets either status of node (if called on node) or wallet (if called on wallet)

	typedef walletd::GetStatus::Request Request;
	typedef walletd::GetStatus::Response Response;
};

// Signature of this method will stabilize to the end of beta
struct SyncBlocks {  // Used by walletd, block explorer, etc to sync to bytecoind
	static std::string method() { return "sync_blocks"; }
	static std::string binMethod() { return "/sync_blocks.bin"; }

	struct Request {
		static constexpr uint32_t MAX_COUNT = 1000;
		std::vector<Hash> sparse_chain;
		Timestamp first_block_timestamp = 0;
		uint32_t max_count              = MAX_COUNT / 10;
	};
	struct SyncBlock {  // Signatures are checked by bytecoind so usually they are of no interest
		api::BlockHeader header;
		bytecoin::BlockTemplate
		    bc_header;  // the only method returning actual BlockHeader from blockchain, not api::BlockHeader
		std::vector<bytecoin::TransactionPrefix>
		    bc_transactions;  // the only method returning actual Transaction from blockchain, not api::Transaction
		Hash base_transaction_hash;                         // BlockTemplate does not contain it
		std::vector<std::vector<uint32_t>> global_indices;  // for each transaction
	};
	struct Response {
		std::vector<SyncBlock> blocks;
		Height start_height = 0;
		GetStatus::Response status;  // We save roundtrip during sync by also sending status here
	};
};

// Signature of this method will stabilize to the end of beta
struct SyncMemPool {  // Used by walletd sync process
	static std::string method() { return "sync_mem_pool"; }
	static std::string binMethod() { return "/sync_mem_pool.bin"; }
	struct Request {
		std::vector<Hash> known_hashes;  // Should be sent sorted
	};
	struct Response {
		std::vector<Hash> removed_hashes;                    // Hashes no more in pool
		std::vector<BinaryArray> added_binary_transactions;  // New raw transactions in pool
		std::vector<api::Transaction>
		    added_transactions;      // binary version of this method returns only hash and timestamp here
		GetStatus::Response status;  // We save roundtrip during sync by also sending status here
	};
};

struct GetRandomOutputs {
	static std::string method() { return "get_random_outputs"; }
	struct Request {
		std::vector<Amount> amounts;  // Repeating the same amount will give you multiples of outs_count in result
		uint32_t outs_count = 0;
		HeightOrDepth confirmed_height_or_depth =
		    -DEFAULT_CONFIRMATIONS - 1;  // Mix-ins will be selected from the [0..confirmed_height] window.
		                                 // Reorganizations larger than confirmations may change mix-in global indices,
		                                 // making transaction invalid
	};
	struct Response {
		std::map<Amount, std::vector<api::Output>>
		    outputs;  // can have less outputs than asked for some amounts, if blockchain lacks enough
	};
};

typedef walletd::SendTransaction SendTransaction;

struct CheckSendProof {
	static std::string method() { return "check_send_proof"; }

	struct Request {
		std::string send_proof;
	};

	struct Response {
		std::string validation_error;  // empty when sucessfully validated
	};
};

// Methods below are used by miners
struct GetBlockTemplate {
	static std::string method_legacy() { return "getblocktemplate"; }  // This name is used by old miners
	static std::string method() { return "get_block_template"; }
	struct Request {
		uint32_t reserve_size = 0;  // max 255 bytes
		std::string wallet_address;
		Hash top_block_hash;                    // for longpoll in v3 - behaves like GetStatus
		uint32_t transaction_pool_version = 0;  // for longpoll in v3 - behaves like GetStatus
	};
	struct Response {
		Difficulty difficulty    = 0;
		Height height            = 0;
		uint32_t reserved_offset = 0;
		BinaryArray blocktemplate_blob;
		std::string status;
		Hash top_block_hash;                    // for longpoll in v3 - behaves like GetStatus
		uint32_t transaction_pool_version = 0;  // for longpoll in v3 - behaves like GetStatus
	};
};

struct GetCurrencyId {
	static std::string method_legacy() { return "getcurrencyid"; }  // This name is used by old miners
	static std::string method() { return "get_currency_id"; }
	typedef EmptyStruct Request;
	struct Response {
		Hash currency_id_blob;  // hash of genesis block
	};
};

struct SubmitBlockLegacy {
	static std::string method() { return "submitblock"; }  // This name is used by old miners
	typedef std::vector<std::string> Request;
	struct Response {
		std::string status;
	};
};

struct SubmitBlock {
	static std::string method() { return "submit_block"; }
	struct Request {
		BinaryArray blocktemplate_blob;
	};
	typedef SubmitBlockLegacy::Response Response;
};
}
}
}

namespace seria {

class ISeria;

void ser_members(bytecoin::api::EmptyStruct &v, ISeria &s);
void ser_members(bytecoin::api::Output &v, ISeria &s);
void ser_members(bytecoin::api::BlockHeader &v, ISeria &s);
void ser_members(bytecoin::api::Transfer &v, ISeria &s);
void ser_members(bytecoin::api::Transaction &v, ISeria &s);
void ser_members(bytecoin::api::Block &v, ISeria &s);
void ser_members(bytecoin::api::Balance &v, ISeria &s);

void ser_members(bytecoin::api::walletd::GetAddresses::Response &v, ISeria &s);
void ser_members(bytecoin::api::walletd::GetViewKeyPair::Response &v, ISeria &s);
void ser_members(bytecoin::api::walletd::CreateAddresses::Request &v, ISeria &s);
void ser_members(bytecoin::api::walletd::CreateAddresses::Response &v, ISeria &s);
void ser_members(bytecoin::api::walletd::GetBalance::Request &v, ISeria &s);
void ser_members(bytecoin::api::walletd::GetBalance::Response &v, ISeria &s);
void ser_members(bytecoin::api::walletd::GetUnspents::Request &v, ISeria &s);
void ser_members(bytecoin::api::walletd::GetUnspents::Response &v, ISeria &s);
void ser_members(bytecoin::api::walletd::GetTransfers::Request &v, ISeria &s);
void ser_members(bytecoin::api::walletd::GetTransfers::Response &v, ISeria &s);
void ser_members(bytecoin::api::walletd::CreateTransaction::Request &v, ISeria &s);
void ser_members(bytecoin::api::walletd::CreateTransaction::Response &v, ISeria &s);
void ser_members(bytecoin::api::walletd::CreateSendProof::Request &v, ISeria &s);
void ser_members(bytecoin::api::walletd::CreateSendProof::Response &v, ISeria &s);
void ser_members(bytecoin::api::walletd::GetTransaction::Request &v, ISeria &s);
void ser_members(bytecoin::api::walletd::GetTransaction::Response &v, ISeria &s);

void ser_members(bytecoin::api::bytecoind::GetStatus::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetStatus::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SyncBlocks::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SyncBlocks::SyncBlock &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SyncBlocks::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SyncMemPool::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SyncMemPool::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetRandomOutputs::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetRandomOutputs::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SendTransaction::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SendTransaction::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::CheckSendProof::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::CheckSendProof::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetBlockTemplate::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetBlockTemplate::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetCurrencyId::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SubmitBlock::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SubmitBlockLegacy::Response &v, ISeria &s);

}  // namespace seria
