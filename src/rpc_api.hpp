// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <boost/optional.hpp>
#include <limits>
#include <map>
#include <string>
#include <vector>
#include "Core/Difficulty.hpp"
#include "CryptoNote.hpp"
#include "common/Int128.hpp"
#include "crypto/types.hpp"
#include "http/JsonRpc.hpp"
#include "p2p/P2pProtocolNew.hpp"

// Common data structures used in all api calls.
// Basic data types are serialized to Json as follows
// bool - Bool
// Amount, SignedAmount, Height, Timestamp, BlockOrTimestamp, Difficulty, (u)int - Number. bytecoin does not use
// fractional
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
                                // top_block_height, -4 means 3 blocks back from top_block_height
constexpr HeightOrDepth DEFAULT_CONFIRMATIONS = 6;

struct Output {
	Amount amount = 0;
	PublicKey public_key;
	uint32_t index = 0;
	// Added from transaction
	BlockOrTimestamp unlock_block_or_timestamp =
	    0;                              // timestamp | height, see function isTransactionSpendTimeUnlocked below
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
	Hash transaction_hash; // TODO - requires changing DB format... For now will be available only on Json seria
};

struct Transaction {
	// Fields for new transactions.
	BlockOrTimestamp unlock_block_or_timestamp =
	    0;                                 // timestamp | height, see function isTransactionSpendTimeUnlocked below
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
	                          // Fields below are serialized only after V4 upgrade
	uint32_t size = 0;
};

struct BlockHeader {
	uint8_t major_version = 0;
	uint8_t minor_version = 0;
	Timestamp timestamp   = 0;
	Hash previous_block_hash;
	uint64_t nonce = 0;
	Height height  = 0;
	Hash hash;
	Amount reward = 0;
	// Low part is serialized as "cumulative_difficulty", Hi part will be serialized as cumulative_difficulty_hi
	CumulativeDifficulty cumulative_difficulty{};
	Difficulty difficulty          = 0;
	Amount base_reward             = 0;
	uint32_t block_size            = 0;  // in API True block size, in DB different value
	uint32_t transactions_size     = 0;  // in API Sum of all transactions including coinbase., in DB different value
	Amount already_generated_coins = 0;
	uint64_t already_generated_transactions = 0;
	uint32_t size_median                    = 0;  // median of transactions_size
	uint32_t effective_size_median          = 0;
	// max(100000, size_median) for block version 3, allows sudden peaks in network load.
	Timestamp timestamp_median = 0;
	Amount transactions_fee    = 0;

	Amount penalty() const {
		return base_reward + transactions_fee - reward;
	}  // We do not need trivial fields in API. Instead we provide an algorithm to calc.
};

struct Block {
	api::BlockHeader header;
	std::vector<api::Transaction> transactions;
	// If got from walletd, will contain only transactions with transfers we can view.
};

struct RawBlock {
	api::BlockHeader header;
	BlockTemplate raw_header;
	std::vector<TransactionPrefix> raw_transactions;
	std::vector<TransactionSignatures> signatures;  // empty unless request.signatures set
	std::vector<api::Transaction>
	    transactions;  // for each transaction + coinbase, contain only info known to bytecoind
	std::vector<std::vector<uint32_t>>
	    output_indexes;  // for each transaction + coinbase, not empty only if block in main chain
};

// In view-only wallets sum of incoming outputs can be arbitrary large
// Low part is serialized as "spendable", Hi part (if not 0) will be serialized as "spendable_hi"
struct Balance {
	common::Uint128 spendable              = 0;
	common::Uint128 spendable_dust         = 0;
	common::Uint128 locked_or_unconfirmed  = 0;
	uint64_t spendable_outputs             = 0;
	uint64_t spendable_dust_outputs        = 0;
	uint64_t locked_or_unconfirmed_outputs = 0;
	common::Uint128 total() const {
		return spendable + spendable_dust + locked_or_unconfirmed;
	}  // This fun serves as a documentation.
	uint64_t total_outputs() const {
		return spendable_outputs + spendable_dust_outputs + locked_or_unconfirmed_outputs;
	}
	bool operator==(const Balance &other) const {
		return std::tie(spendable, spendable_dust, locked_or_unconfirmed) ==
		       std::tie(other.spendable, other.spendable_dust, other.locked_or_unconfirmed);
	}
	bool operator!=(const Balance &other) const { return !(*this == other); }
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
	BYTECOIND_WRONG_ARGS        = 105,
	WALLET_FILE_READ_ERROR      = 205,
	WALLET_FILE_UNKNOWN_VERSION = 206,
	WALLET_FILE_DECRYPT_ERROR   = 207,
	WALLET_FILE_WRITE_ERROR     = 208,
	WALLET_FILE_EXISTS          = 209,  // Daemon never overwrites file during --generate-wallet.
	WALLET_WITH_SAME_KEYS_IN_USE =
	    210,  // Another walletd instance is using the same or another wallet file with the same keys.
	WALLETD_WRONG_ARGS             = 211,
	WALLETD_EXPORTKEYS_MORETHANONE = 212  // We can export keys only if wallet file contains exactly 1 spend keypair
};

// Returned from many methods
struct ErrorAddress : public json_rpc::Error {
	std::string address;
	ErrorAddress() {}
	ErrorAddress(int c, const std::string &msg, const std::string &address);
	void seria_data_members(seria::ISeria &s) override;
	enum { ADDRESS_FAILED_TO_PARSE = -4, ADDRESS_NOT_IN_WALLET = -1002 };
};

struct ErrorHashNotFound : public json_rpc::Error {
	Hash hash;
	ErrorHashNotFound() {}
	ErrorHashNotFound(const std::string &msg, const Hash &hash);
	void seria_data_members(seria::ISeria &s) override;
	enum {
		HASH_NOT_FOUND = -5  // Neither in main nor in side chain
	};
};

struct ErrorWrongHeight : public json_rpc::Error {
	HeightOrDepth request_height = 0;
	Height top_block_height      = 0;
	ErrorWrongHeight() {}
	ErrorWrongHeight(const std::string &msg, HeightOrDepth request_height, Height top_block_height);
	void seria_data_members(seria::ISeria &s) override;
	enum { INVALID_HEIGHT_OR_DEPTH = -2 };
	static Height fix_height_or_depth(api::HeightOrDepth ha, Height tip_height, bool throw_on_too_big_height,
									  bool throw_on_too_big_depth, Height max_depth = std::numeric_limits<Height>::max());
};

namespace walletd {

inline std::string url() { return "/json_rpc"; }

const uint32_t DEFAULT_ANONYMITY_LEVEL = 6;

struct GetStatus {
	static std::string method() { return "get_status"; }  // get_status of node is shadowed by walletd.

	struct Request {
		boost::optional<Hash> top_block_hash;
		boost::optional<uint32_t> transaction_pool_version;
		// Pool version is reset to 1 on every new block. Pool version is
		// incremented on every modification to pool.
		boost::optional<uint32_t> outgoing_peer_count;
		boost::optional<uint32_t> incoming_peer_count;
		// You get longpoll (no immediate reply) until any parameter changes.
		// You can just send previous response as a next request if you are interested in all changes visible to API.
		boost::optional<std::string> lower_level_error;
		// Problems on lower levels (like bytecoind errors in walletd status). Empty - no errors
	};
	struct Response {  // Response and Request have fields in common.
		Hash top_block_hash;
		uint32_t transaction_pool_version = 0;
		// Pool version is reset to 1 on every new block. Pool version is
		// incremented on every modification to pool.
		uint32_t outgoing_peer_count = 0;
		uint32_t incoming_peer_count = 0;
		// You get longpoll (no immediate reply) until any parameter changes.
		// You can just send previous response as a next request if you are interested in all changes visible to API.
		std::string lower_level_error;
		// Last block analyzed and synched by wallet or node.
		Height top_block_height                              = 0;
		Height top_known_block_height                        = 0;  // Max of heights reported by p2p peers.
		Difficulty top_block_difficulty                      = 0;
		CumulativeDifficulty top_block_cumulative_difficulty = 0;
		Amount recommended_fee_per_byte                      = 0;
		Timestamp top_block_timestamp                        = 0;
		Timestamp top_block_timestamp_median = 0;  // This timestamp will be used in unlock calulations after hardfork.
		uint32_t next_block_effective_median_size = 0;
		// If your tx size is larger, chance it will not be included in block for a long time (or never).
		bool ready_for_longpoll(const Request &other) const;
	};
};

struct GetAddresses {  // For simple GUI client, display addresses[0] as main one, show rest of the addresses in popup.
	static std::string method() { return "get_addresses"; }

	struct Request {
		bool need_secret_spend_keys  = false;
		uint32_t from_address        = 0;  // We can now iterate through addresses
		uint32_t max_count           = std::numeric_limits<uint32_t>::max();
	};
	struct Response {
		std::vector<std::string> addresses;        // starting from from_address up to max_count
		std::vector<SecretKey> secret_spend_keys;  // not empty only if need_secret_spend_keys specified
		uint32_t total_address_count = 0;  // Usefull when when iterating
	};
};

struct GetWalletInfo {
	static std::string method() { return "get_wallet_info"; }

	typedef EmptyStruct Request;

	struct Response {
		bool view_only                      = false;
		Timestamp wallet_creation_timestamp = 0;  // O if not known (restored form keys and did not sync yet)
		std::string first_address;
		uint32_t total_address_count        = 0;  // Usefull when when iterating
		std::string net; // Now - network walletd is launch on. Future - network for which the wallet is generated
		Hash mineproof_secret;                    // Highly experimental
	};
};

struct GetViewKeyPair { // Will be deprecated or heavily changed in Future
	static std::string method() { return "get_view_key_pair"; }

	typedef EmptyStruct Request;

	struct Response {
		SecretKey secret_view_key;
		PublicKey public_view_key;
		BinaryArray import_keys;
		// passing this value as --import-keys parameter to walletd would recreate wallet with
		// first address only, then you can call create_addresses passing other secret keys from your DB
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
		// height_or_depth is limited to arbitrary selected depth of 128 blocks before top block
	};
	typedef api::Balance Response;
	enum {
		ADDRESS_FAILED_TO_PARSE = -4,    // returns ErrorAddress
		INVALID_HEIGHT_OR_DEPTH = -2,    // height_or_depth too low or too high
		ADDRESS_NOT_IN_WALLET   = -1002  // returns ErrorAddress
	};
};

struct GetUnspents {
	static std::string method() { return "get_unspents"; }
	// This method execution time is proportional to number of unspent coins
	// sum of outputs per address will be equal to what GetBalance returns
	struct Request {
		std::string address;  // empty for all addresses
		HeightOrDepth height_or_depth = -DEFAULT_CONFIRMATIONS - 1;
		// height_or_depth is limited to arbitrary selected depth of 128 blocks before top block
	};
	struct Response {
		std::vector<api::Output> spendable;              // Confirmed, unlocked. Dust is also returned here
		std::vector<api::Output> locked_or_unconfirmed;  // Unconfirmed or locked
	};
	enum {
		ADDRESS_FAILED_TO_PARSE = -4,    // returns ErrorAddress
		INVALID_HEIGHT_OR_DEPTH = -2,    // height_or_depth too low or too high
		ADDRESS_NOT_IN_WALLET   = -1002  // returns ErrorAddress
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
		bool forward = true;  // determines order of blocks returned, additionally if desired_transaction_count set,
		                      // then this defines if call starts from from_height forward, or from to_height backwards
		uint32_t desired_transaction_count =
		    std::numeric_limits<uint32_t>::max();  // Will return this number of transactions or a bit more, It can
		                                           // return more, because this call always returns full blocks
	};
	struct Response {
		std::vector<api::Block> blocks;  // includes only blocks with transactions with transfers we can view
		std::vector<api::Transfer> unlocked_transfers;  // Previous transfers unlocked between from_height and to_height
		Height next_from_height = 0;  // When desired_transaction_count != max you can pass next* to corresponding
		                              // Request fields to continue iteration
		Height next_to_height = 0;
	};
	enum {
		ADDRESS_FAILED_TO_PARSE = -4,    // returns ErrorAddress
		ADDRESS_NOT_IN_WALLET   = -1002  // returns ErrorAddress
	};
};

struct CreateTransaction {
	static std::string method() { return "create_transaction"; }

	struct Request {
		api::Transaction
		    transaction;  // You fill only basic info (anonymity, optional unlock_block_or_timestamp, optional
		                  // payment_id) and transfers. All positive transfers (amount > 0) will be added
		                  // as outputs. For all negative transfers (amount < 0), spendable for requested
		                  // sum and address will be selected and added as inputs
		std::vector<std::string> spend_addresses;
		// If this is not empty, will spend (and optimize) outputs for this addresses to get
		// neccessary funds. Otherwise will spend any output in the wallet
		bool any_spend_address = false;  // if you set spend_address to empty, you should set any_spend_address to true.
		                                 // This is protection against client bug when spend_address is forgotten or
		                                 // accidentally set to null, etc
		std::string change_address;      // Change will be returned to change_address.
		HeightOrDepth confirmed_height_or_depth = -DEFAULT_CONFIRMATIONS - 1;
		// Mix-ins will be selected from the [0..confirmed_height] window.
		// Reorganizations larger than confirmations may change mix-in global indices, making transaction invalid.
		SignedAmount fee_per_byte = 0;  // Fee of created transaction will be close to the size of tx * fee_per_byte.
		                                // You can check it in response.transaction.fee before sending, if you wish
		std::string optimization;  // Wallet outputs optimization (fusion). Leave empty to use normal optimization, good
		                           // for wallets with balanced sends to receives count. You can save on a few percent
		                           // of fee (on average) by specifying "minimal" for wallet receiving far less
		                           // transactions than sending. You should use "aggressive" for wallet receiving far
		                           // more transactions than sending, this option will use every opportunity to reduce
		                           // number of outputs. For better optimization use as little anonymity as possible. If
		                           // anonymity is set to 0, wallet will prioritize optimizing out dust and crazy (large
		                           // but not round) denominations of outputs.
		bool save_history = true;  // If true, wallet will save encrypted transaction data (~100 bytes per used address)
		                           // in <wallet_file>.history/. With this data it is possible to generate
		                           // public-checkable proofs of sending funds to specific addresses.
		std::vector<Hash> prevent_conflict_with_transactions;
		// Experimental API for guaranteed payouts under any circumstances
	};
	struct Response {
		BinaryArray binary_transaction;  // Empty if error
		api::Transaction transaction;
		// block_hash will be empty, block_height set to current pool height (may change later)
		bool save_history_error = false;          // When wallet on read-only media. Most clients should ignore this
		std::vector<Hash> transactions_required;  // Works together with prevent_conflict_with_transactions
		// If not empty, you should resend those transactions before trying create_transaction again to prevent
		// conflicts
	};
	enum {
		NOT_ENOUGH_FUNDS                  = -301,
		TRANSACTION_DOES_NOT_FIT_IN_BLOCK = -302,  // Sender will have to split funds into several transactions
		NOT_ENOUGH_ANONYMITY              = -303,
		VIEW_ONLY_WALLET                  = -304,
		ADDRESS_FAILED_TO_PARSE           = -4,    // returns ErrorAddress
		INVALID_HEIGHT_OR_DEPTH           = -2,    // height_or_depth too low or too high
		ADDRESS_NOT_IN_WALLET             = -1002  // returns ErrorAddress
	};
};

struct SendTransaction {
	static std::string method() { return "send_transaction"; }

	struct Request {
		BinaryArray binary_transaction;
	};

	struct Response {
		std::string send_result;  // DEPRECATED, always contains "broadcast"
		// when this method returns, transactions is already added to payment queue and queue fsynced to disk.
	};
	enum {
		INVALID_TRANSACTION_BINARY_FORMAT = -101,
		WRONG_OUTPUT_REFERENCE = -102,  // wrong signature or referenced outputs changed during reorg. Bad output
		// height is reported in conflict_height. If output index > max current index, conflict_height will be set to
		// currency.max_block_number
		OUTPUT_ALREADY_SPENT = -103  // conflight height reported in error
	};
	struct Error : public json_rpc::Error {
		Height conflict_height = 0;
		Error() {}
		Error(int c, const std::string &msg, Height conflict_height)
		    : json_rpc::Error(c, msg), conflict_height(conflict_height) {}
		void seria_data_members(seria::ISeria &s) override;
	};
};

struct CreateSendProof {
	static std::string method() { return "create_sendproof"; }

	struct Request {
		Hash transaction_hash;
		std::string message;  // Add any user message to proof. Changing message will invlidate proof (which works like
		                      // digital signature of message)
		std::vector<std::string> addresses;  // Leave empty to create proof for all "not ours" addresses
	};

	struct Response {
		std::vector<std::string> sendproofs;
	};
	enum {
		ADDRESS_FAILED_TO_PARSE = -4,  // returns ErrorAddress
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
inline std::string binary_url() { return "/binary_rpc"; }

struct GetStatus {
	static std::string method() { return "get_node_status"; }  // getNodeStatus works directly or through wallet tunnel
	static std::string method2() { return "get_status"; }
	// getStatus gets either status of node (if called on node) or wallet (if called on wallet)

	typedef walletd::GetStatus::Request Request;
	typedef walletd::GetStatus::Response Response;
};

struct GetRawBlock {
	static std::string method() { return "get_raw_block"; }
	struct Request {
		Hash hash;
		HeightOrDepth height_or_depth = std::numeric_limits<HeightOrDepth>::max();
		bool need_signatures          = false;  // signatures are usually of no interest, they all are checked and valid
	};
	struct Response {
		api::RawBlock block;
		bool orphan_status  = false;
		HeightOrDepth depth = 0;  // new style, -1 is top block, -2 previous block, etc
	};
	enum {
		HASH_NOT_FOUND          = -5,  // Neither in main nor in side chain
		INVALID_HEIGHT_OR_DEPTH = -2   // height_or_depth too low or too high
	};
};

struct GetBlockHeader {
	static std::string method() { return "get_block_header"; }
	struct Request {
		Hash hash;
		HeightOrDepth height_or_depth = std::numeric_limits<HeightOrDepth>::max();
	};
	struct Response {
		BlockHeader block_header;
		bool orphan_status  = false;
		HeightOrDepth depth = 0;  // new style, -1 is top block, -2 previous block, etc
	};
	enum {
		HASH_NOT_FOUND          = -5,  // Neither in main nor in side chain
		INVALID_HEIGHT_OR_DEPTH = -2   // height_or_depth too low or too high
	};
};

struct SyncBlocks {  // Used by walletd, block explorer, etc to sync to bytecoind
	static std::string method() { return "sync_blocks"; }
	static std::string bin_method() { return "sync_blocks_v1"; }
	// we increment bin method version when binary format changes

	struct Request {
		static constexpr uint32_t MAX_COUNT = 1000;
		std::vector<Hash> sparse_chain;
		Timestamp first_block_timestamp = 0;
		uint32_t max_count              = MAX_COUNT / 10;
		bool need_signatures     = false;  // signatures are usually of no interest, they all are checked and valid
		bool need_redundant_data = true;   // walletd and smart clients can save traffic
	};
	struct Response {
		std::vector<RawBlock> blocks;
		Height start_height = 0;
		GetStatus::Response status;  // We save roundtrip during sync by also sending status here
	};
};

// TODO - return json error
struct GetRawTransaction {
	static std::string method() { return "get_raw_transaction"; }
	struct Request {
		Hash hash;
		bool need_signatures = false;  // signatures are usually of no interest, they all are checked and valid
	};
	struct Response {
		api::Transaction transaction;  // contain only info known to bytecoind
		TransactionPrefix raw_transaction;
		TransactionSignatures signatures;  // empty unless request.signatures set
	};
	enum {
		HASH_NOT_FOUND = -5  // Neither in main nor in side chain
	};
};

// Signature of this method will stabilize to the end of beta
struct SyncMemPool {  // Used by walletd sync process
	static std::string method() { return "sync_mem_pool"; }
	static std::string bin_method() { return "sync_mem_pool_v1"; }
	// we increment bin method version when binary format changes
	struct Request {
		std::vector<Hash> known_hashes;    // Should be sent sorted
		bool need_signatures     = false;  // signatures are usually of no interest, they all are checked and valid
		bool need_redundant_data = true;   // walletd and smart clients can save traffic
	};
	struct Response {
		std::vector<Hash> removed_hashes;                       // Hashes no more in pool
		std::vector<TransactionPrefix> added_raw_transactions;  // New raw transactions in pool
		std::vector<TransactionSignatures> added_signatures;    // empty unless request.signatures set
		std::vector<api::Transaction> added_transactions;       // contain only info known to bytecoind
		GetStatus::Response status;  // We save roundtrip during sync by also sending status here
	};
};

struct GetRandomOutputs {
	static std::string method() { return "get_random_outputs"; }
	struct Request {
		std::vector<Amount> amounts;  // Repeating the same amount will give you multiples of output_count in result
		uint32_t output_count                   = 0;
		HeightOrDepth confirmed_height_or_depth = -DEFAULT_CONFIRMATIONS - 1;
		// Mix-ins will be selected from the [0..confirmed_height] window.
		// Reorganizations larger than confirmations may change mix-in global indices,
		// making transaction invalid
	};
	struct Response {
		std::map<Amount, std::vector<api::Output>> outputs;
		// can have less outputs than asked for some amounts, if blockchain lacks enough
	};
	enum {
		INVALID_HEIGHT_OR_DEPTH = -2  // height_or_depth too low or too high
	};
};

typedef walletd::SendTransaction SendTransaction;

struct CheckSendproof {
	static std::string method() { return "check_sendproof"; }

	struct Request {
		std::string sendproof;
	};
	struct Response {
		Hash transaction_hash;
		std::string address;
		Amount amount = 0;
		std::string message;
	};  // All errors are reported as json rpc errors
	enum {
		FAILED_TO_PARSE            = -201,
		NOT_IN_MAIN_CHAIN          = -202,
		WRONG_SIGNATURE            = -203,
		ADDRESS_NOT_IN_TRANSACTION = -204,
		WRONG_AMOUNT               = -205
	};
	typedef json_rpc::Error Error;
};

struct GetStatistics {
	static std::string method() { return "get_statistics"; }

	typedef EmptyStruct Request;
	typedef np::GetPeerStatistics::Response Response;
};

// This method is highly experimental
struct GetArchive {
	static std::string method() { return "get_archive"; }
	struct Request {
		std::string archive_id;
		uint64_t from_record                = 0;
		uint64_t max_count                  = 100;
		static constexpr uint64_t MAX_COUNT = 10000;
		bool records_only                   = false;  // no objects
	};
	struct ArchiveRecord {
		Timestamp timestamp     = 0;
		uint32_t timestamp_usec = 0;
		std::string type;  // b(lock), t(ransaction), c(heckpoint)
		Hash hash;
		std::string source_address;
	};
	struct ArchiveBlock {  // TODO - use api::RawBlock
		BlockTemplate raw_header;
		// the only method returning actual BlockHeader from blockchain, not api::BlockHeader
		std::vector<TransactionPrefix> raw_transactions;
		// the only method returning actual Transaction from blockchain, not api::Transaction
		Hash base_transaction_hash;                      // BlockTemplate does not contain it
		std::vector<uint32_t> transaction_binary_sizes;  // for each transaction
	};
	struct Response {
		std::vector<ArchiveRecord> records;
		uint64_t from_record = 0;

		std::map<std::string, ArchiveBlock> blocks;
		std::map<std::string, TransactionPrefix> transactions;
		std::map<std::string, SignedCheckpoint> checkpoints;
	};
	enum {
		WRONG_ARCHIVE_ID    = -501,  // If archive id changed, it is returned in Error
		ARCHIVE_NOT_ENABLED = -502   // No archive on this node
	};
	struct Error : public json_rpc::Error {
		std::string archive_id;
		Error(int c, const std::string &msg, const std::string &archive_id)
		    : json_rpc::Error(c, msg), archive_id(archive_id) {}
		void seria_data_members(seria::ISeria &s) override;
	};
};

inline std::string legacy_status_ok() { return "OK"; }
// There is no point in always returning status="OK" from all methods

// Methods below are used by miners
struct GetBlockTemplate {
	static std::string method_legacy() { return "getblocktemplate"; }  // This name is used by old miners
	static std::string method() { return "get_block_template"; }
	struct Request {
		uint32_t reserve_size = 0;  // max 255 bytes
		std::string wallet_address;
		boost::optional<Hash> top_block_hash;                    // for longpoll in v3 - behaves like GetStatus
		boost::optional<uint32_t> transaction_pool_version = 0;  // for longpoll in v3 - behaves like GetStatus
	};
	struct Response {
		Difficulty difficulty    = 0;
		Height height            = 0;
		uint32_t reserved_offset = 0;
		BinaryArray blocktemplate_blob;
		std::string status = legacy_status_ok();
		Hash top_block_hash;                    // for longpoll in v3 - behaves like GetStatus
		uint32_t transaction_pool_version = 0;  // for longpoll in v3 - behaves like GetStatus
		Hash previous_block_hash;               // Deprecated, used by some legacy miners.
	};
	enum {
		ADDRESS_FAILED_TO_PARSE = -4,  // returns ErrorAddress
		TOO_BIG_RESERVE_SIZE    = -3
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

struct SubmitBlock {
	static std::string method() { return "submit_block"; }
	struct Request {
		BinaryArray blocktemplate_blob;
	};
	struct Response {
		BlockHeader block_header;  // contains detailed info about accepted block
		bool orphan_status  = false;
		HeightOrDepth depth = 0;  // new style, -1 is top block, -2 previous block, etc
	};
	enum { WRONG_BLOCKBLOB = -6, BLOCK_NOT_ACCEPTED = -7 };
};

// Legacy methods
struct BlockHeaderLegacy : public BlockHeader {
	bool orphan_status  = false;
	HeightOrDepth depth = 0;
	// Legacy methods return depth as number (usually >= 0), where 0 is top block
};

struct SubmitBlockLegacy {
	static std::string method() { return "submitblock"; }  // This name is used by old miners
	typedef std::vector<std::string> Request;
	struct Response {
		std::string status = legacy_status_ok();
	};
	// Same errors as SubmitBlock
};

struct GetLastBlockHeaderLegacy {  // Use GetStatus instead
	static std::string method() { return "getlastblockheader"; }
	typedef EmptyStruct Request;
	struct Response {
		std::string status = legacy_status_ok();
		BlockHeaderLegacy block_header;
	};
};

struct GetBlockHeaderByHashLegacy {
	static std::string method() { return "getblockheaderbyhash"; }
	struct Request {
		Hash hash;
	};
	typedef GetLastBlockHeaderLegacy::Response Response;
	enum {
		HASH_NOT_FOUND = -5  // Neither in main nor in side chain
	};
};

struct GetBlockHeaderByHeightLegacy {
	static std::string method() { return "getblockheaderbyheight"; }
	struct Request {
		Height height = 0;  // Beware, in this call height starts from 1, not 0, so height=1 returns genesis
	};
	typedef GetLastBlockHeaderLegacy::Response Response;
	enum {
		INVALID_HEIGHT_OR_DEPTH = -2  // height_or_depth too low or too high
	};
};
}
}
}

namespace seria {

class ISeria;

void ser_members(bytecoin::api::EmptyStruct &v, ISeria &s);
void ser_members(bytecoin::api::Output &v, ISeria &s);
void ser_members(bytecoin::api::BlockHeader &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::BlockHeaderLegacy &v, ISeria &s);
void ser_members(bytecoin::api::Transfer &v, ISeria &s);
void ser_members(bytecoin::api::Transaction &v, ISeria &s);
void ser_members(bytecoin::api::Block &v, ISeria &s);
void ser_members(bytecoin::api::RawBlock &v, ISeria &s);
void ser_members(bytecoin::api::Balance &v, ISeria &s);

void ser_members(bytecoin::api::walletd::GetAddresses::Request &v, ISeria &s);
void ser_members(bytecoin::api::walletd::GetAddresses::Response &v, ISeria &s);
void ser_members(bytecoin::api::walletd::GetWalletInfo::Response &v, ISeria &s);
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
void ser_members(bytecoin::api::bytecoind::GetBlockHeader::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetBlockHeader::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetRawBlock::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetRawBlock::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SyncBlocks::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SyncBlocks::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetRawTransaction::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetRawTransaction::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SyncMemPool::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SyncMemPool::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetRandomOutputs::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetRandomOutputs::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SendTransaction::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SendTransaction::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::CheckSendproof::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::CheckSendproof::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetArchive::ArchiveRecord &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetArchive::ArchiveBlock &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetArchive::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetArchive::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetBlockTemplate::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetBlockTemplate::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetCurrencyId::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SubmitBlock::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SubmitBlock::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::SubmitBlockLegacy::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetLastBlockHeaderLegacy::Response &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetBlockHeaderByHashLegacy::Request &v, ISeria &s);
void ser_members(bytecoin::api::bytecoind::GetBlockHeaderByHeightLegacy::Request &v, ISeria &s);

}  // namespace seria
