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
#include "p2p/P2pProtocolTypes.hpp"  // For CoreStatistics

// Common data structures used in all api calls.

// Basic data types are serialized to Json as follows
// bool - Bool

// Amount, SignedAmount, Height, Timestamp, BlockOrTimestamp, Difficulty, size_t, (u)int - Number.
// bytecoin does not use fractional numbers, but uses numbers as large as 2^64-1 for amounts,
// which is larger than 2^53 exactly representable in double or JavaScript Number
// amounts large than ~91 million BCN cannot be represented exactly in JavaScript and other platforms using IEEE
// 64-bit floating numbers, so you should use appropriate json/bigint library to handle large amounts

// std::string, Hash, PublicKey, SecretKey, KeyImage, BinaryArray - String (hex)

// std::vector - Array
// std::map, struct - Object

// bytecoin does not use Null, you should specify empty Array as [], empty string as "", empty Object as {}

namespace cn { namespace api {

struct EmptyStruct {};  // Used as a typedef for empty requests, which we have a lot

typedef int32_t HeightOrDepth;
// If >= 0 - interpret as Height, if < 0 interpret as Depth, e.g. -1 means
// top_block_height, -4 means 3 blocks back from top_block_height

constexpr HeightOrDepth DEFAULT_CONFIRMATIONS = 5;

struct Output {
	Amount amount = 0;
	PublicKey public_key;
	size_t stack_index  = 0;
	size_t global_index = 0;
	// Added from transaction
	Height height                              = 0;  // Added from block
	BlockOrTimestamp unlock_block_or_timestamp = 0;
	size_t index_in_transaction                = 0;
	// Added by wallet for recognized outputs
	Hash transaction_hash;
	KeyImage key_image;
	std::string address;
	bool dust = false;  // Dust is deprecated
};

struct Transfer {
	std::string address;
	SignedAmount amount = 0;  // Will be negative if transfer is from that address
	std::string message;      // Will be encrypted so that only receiver and sender can decrypt it
	bool ours = false;
	// addresses not in wallet are recognized only for transcations we sent, subject to some limitations
	bool locked = false;
	// locked transfers should not be added to balance immediately.
	// They will be unlocked later and sent via GetTransfers.Response.unlocked_transfers
	std::vector<api::Output> outputs;  // Outputs corresponding to this transfer
	Hash transaction_hash;
};

struct Transaction {
	// Fields for new transactions.
	BlockOrTimestamp unlock_block_or_timestamp = 0;
	std::vector<api::Transfer> transfers;
	// includes only transfers we can view
	// transfers are sorted, spends first, then sending, then change
	Hash payment_id;  // Will be DEPRECATED in future
	size_t anonymity = 0;

	// Filled after transaction is created
	Hash hash;
	Hash prefix_hash;
	Hash inputs_hash;
	Amount fee = 0;
	PublicKey public_key;
	BinaryArray extra;  // payment_id and additional fields are packed here. see TransactionExtra.*pp for details
	bool coinbase = false;
	Amount amount = 0;  // Sum of output amounts

	// after transaction is included in block
	Height block_height = 0;
	Hash block_hash;  // For mempool transactions block_hash is all zeroes (or absent from Json)
	Timestamp timestamp = 0;
	// Timestamp of block if transaction is in block.
	// For mempool transactions this is the time node first seen this transaction.
	size_t size = 0;
};

struct BlockHeader {
	uint8_t major_version = 0;
	uint8_t minor_version = 0;
	Timestamp timestamp   = 0;
	Hash previous_block_hash;
	BinaryArray binary_nonce;  // first 4 bytes are also serialized as "nonce"
	Height height = 0;
	Hash hash;
	Amount reward = 0;
	CumulativeDifficulty cumulative_difficulty{};
	Difficulty difficulty    = 0;
	Amount base_reward       = 0;
	size_t block_size        = 0;
	size_t transactions_size = 0;

	Amount already_generated_coins        = 0;
	size_t already_generated_transactions = 0;
	size_t already_generated_key_outputs  = 0;
	size_t size_median                    = 0;  // median of transactions_size, 0 in amethyst
	size_t effective_size_median          = 0;  // median of transactions_size, 0 in amethyst
	size_t block_capacity_vote            = 0;  // 0 before amethyst
	size_t block_capacity_vote_median     = 0;  // 0 before amethyst
	Timestamp timestamp_median            = 0;
	Amount transactions_fee               = 0;

	// before amethyst, penalty is (base_reward + transactions_fee - reward)/(base_reward + transactions_fee)
	// in amethyst there is no penalty
};

struct Block {
	api::BlockHeader header;
	std::vector<api::Transaction> transactions;
	std::vector<api::Transfer> unlocked_transfers;
	// If got from walletd, will contain only transactions with transfers we can view.
};

struct RawBlock {
	api::BlockHeader header;
	BlockTemplate raw_header;
	std::vector<TransactionPrefix> raw_transactions;
	std::vector<api::Transaction>
	    transactions;  // for each transaction + coinbase, contain only info known to bytecoind
	std::vector<std::vector<size_t>>
	    output_stack_indexes;  // for each transaction + coinbase, not empty only if block in main chain
};

// In legacy view-only wallets sum of incoming outputs can be arbitrary large and overflow
// New unlinkable wallets correctly reflect balance
struct Balance {
	Amount spendable                     = 0;
	Amount spendable_dust                = 0;  // Dust is deprecated and always 0
	Amount locked_or_unconfirmed         = 0;
	size_t spendable_outputs             = 0;
	size_t spendable_dust_outputs        = 0;  // Dust is deprecated and always 0
	size_t locked_or_unconfirmed_outputs = 0;
	Amount total() const {
		return spendable + spendable_dust + locked_or_unconfirmed;
	}  // This fun serves as a documentation.
	size_t total_outputs() const { return spendable_outputs + spendable_dust_outputs + locked_or_unconfirmed_outputs; }
	bool operator==(const Balance &other) const {
		return std::tie(spendable, spendable_dust, locked_or_unconfirmed) ==
		       std::tie(other.spendable, other.spendable_dust, other.locked_or_unconfirmed);
	}
	bool operator!=(const Balance &other) const { return !(*this == other); }
};

enum return_code {
	BYTECOIND_DATABASE_ERROR          = 101,  // We hope we are out of disk space, otherwise blockchain DB is corrupted.
	BYTECOIND_ALREADY_RUNNING         = 102,
	WALLETD_BIND_PORT_IN_USE          = 103,
	BYTECOIND_BIND_PORT_IN_USE        = 104,
	BYTECOIND_WRONG_ARGS              = 105,
	BYTECOIND_DATABASE_FORMAT_TOO_NEW = 106,
	BYTECOIND_DATAFOLDER_ERROR        = 107,  // Also returned from walletd
	WALLET_FILE_READ_ERROR            = 205,
	WALLET_FILE_UNKNOWN_VERSION       = 206,
	WALLET_FILE_DECRYPT_ERROR         = 207,
	WALLET_FILE_WRITE_ERROR           = 208,
	WALLET_FILE_EXISTS                = 209,  // Daemon never overwrites file during --generate-wallet.
	WALLET_WITH_SAME_KEYS_IN_USE =
	    210,  // Another walletd instance is using the same or another wallet file with the same keys.
	WALLETD_WRONG_ARGS             = 211,
	WALLETD_EXPORTKEYS_MORETHANONE = 212,  // We can export keys only if wallet file contains exactly 1 spend keypair
	WALLETD_MNEMONIC_CRC           = 213,  // Unknown version or wrong crc
	WALLET_FILE_HARDWARE_DECRYPT_ERROR =
	    214  // This wallet file is backed by hardware and no hardware could decrypt wallet file
};

// Returned from many methods
struct ErrorAddress : public json_rpc::Error {
	std::string address;
	ErrorAddress() = default;
	ErrorAddress(int c, const std::string &msg, const std::string &address);
	void seria_data_members(seria::ISeria &s) override;
	enum { ADDRESS_FAILED_TO_PARSE = -4, ADDRESS_NOT_IN_TRANSACTION = -204, ADDRESS_NOT_IN_WALLET = -1002 };
};

struct ErrorHash : public json_rpc::Error {
	Hash hash;
	ErrorHash() = default;
	ErrorHash(const std::string &msg, const Hash &hash) : ErrorHash(HASH_NOT_FOUND, msg, hash) {}
	ErrorHash(int c, const std::string &msg, const Hash &hash);
	void seria_data_members(seria::ISeria &s) override;
	enum {
		HASH_NOT_FOUND = -5,  // Neither in main nor in side chain
	};
};

struct ErrorWrongHeight : public json_rpc::Error {
	int64_t request_height  = 0;  // int64_t fits both Height and HeightOrDepth
	Height top_block_height = 0;
	ErrorWrongHeight()      = default;
	ErrorWrongHeight(const std::string &msg, int64_t request_height, Height top_block_height);
	void seria_data_members(seria::ISeria &s) override;
	enum { INVALID_HEIGHT_OR_DEPTH = -2 };
	static Height fix_height_or_depth(api::HeightOrDepth ha, Height tip_height, bool throw_on_too_big_height,
	    bool throw_on_too_big_depth, Height max_depth = std::numeric_limits<Height>::max());
};

// These messages encoded in JSON can be sent via http to walletd rpc address:port
namespace walletd {

inline std::string url() { return "/json_rpc"; }

const size_t DEFAULT_ANONYMITY_LEVEL = 6;

struct GetStatus {
	static std::string method() { return "get_status"; }  // get_status of node is shadowed by walletd.

	struct Request {
		boost::optional<Hash> top_block_hash;
		boost::optional<size_t> transaction_pool_version;
		boost::optional<size_t> outgoing_peer_count;
		boost::optional<size_t> incoming_peer_count;
		boost::optional<std::string> lower_level_error;
	};
	struct Response {  // Response and Request have fields in common.
		Hash top_block_hash;
		size_t transaction_pool_version = 0;
		// Pool version is reset to 1 on every new block. Pool version is
		// incremented on every modification to pool.
		size_t outgoing_peer_count = 0;
		size_t incoming_peer_count = 0;
		// You get longpoll (no immediate reply) until any parameter changes.
		// You can just send previous response as a next request if you are interested in all changes visible to API.
		std::string lower_level_error;
		// Problems on lower levels (like bytecoind errors in walletd status). Empty - no errors
		Height top_block_height                              = 0;
		Height top_known_block_height                        = 0;  // Max of heights reported by p2p peers.
		Difficulty top_block_difficulty                      = 0;
		CumulativeDifficulty top_block_cumulative_difficulty = 0;
		Amount recommended_fee_per_byte                      = 0;
		Timestamp top_block_timestamp                        = 0;
		Timestamp top_block_timestamp_median = 0;  // This timestamp will be used in unlock calulations after hardfork.
		size_t recommended_max_transaction_size = 0;  // max recommended transaction size. Amethyst ditches
		// effective median size concept, but if your tx size is larger, chance it will not be included in block for
		// a long time (or never).
		bool ready_for_longpoll(const Request &other) const;
	};
};

struct GetAddresses {  // Not recommended, use GetWalletRecords
	static std::string method() { return "get_addresses"; }

	struct Request {
		bool need_secret_spend_keys = false;
		size_t from_address         = 0;  // We can now iterate through addresses
		size_t max_count            = std::numeric_limits<size_t>::max();
	};
	struct Response {
		std::vector<std::string> addresses;        // starting from from_address up to max_count
		std::vector<SecretKey> secret_spend_keys;  // not empty only if need_secret_spend_keys specified
		size_t total_address_count = 0;            // Usefull when when iterating
	};
};

struct GetWalletInfo {
	static std::string method() { return "get_wallet_info"; }

	struct Request {
		bool need_secrets = false;
	};
	struct Response {
		bool view_only = false;
		std::string wallet_type;                      // can be legacy, amethyst, hardware
		bool can_view_outgoing_addresses    = false;  // can be false for some view-only wallets
		bool has_view_secret_key            = false;  // can be false for some hardware-backed wallets
		Timestamp wallet_creation_timestamp = 0;      // O if not known (restored from keys and did not sync yet)
		std::string first_address;
		size_t total_address_count = 0;  // Useful when iterating
		std::string net;                 // network walletd is currently operating on
		SecretKey secret_view_key;
		PublicKey public_view_key;
		std::string import_keys;  // for old wallets
		std::string mnemonic;     // for HD wallets
	};
};

struct GetWalletRecords {
	static std::string method() { return "get_wallet_records"; }

	struct Record {
		std::string address;
		std::string label;
		size_t index = 0;
		SecretKey secret_spend_key;
		PublicKey public_spend_key;
	};
	struct Request {
		bool need_secrets = false;
		bool create  = false;  // if true, will create all addresses up to from_address + max_count if they do not exist
		size_t index = 0;      // We can now iterate through addresses
		size_t count = std::numeric_limits<size_t>::max();
	};
	struct Response {
		std::vector<Record> records;  // starting from from_address up to max_count
		size_t total_count = 0;       // Useful when when iterating
	};
};

struct SetAddressLabel {
	static std::string method() { return "set_address_label"; }
	struct Request {
		std::string address;
		std::string label;
	};
	typedef EmptyStruct Response;
};

struct GetViewKeyPair {  // Deprecated
	static std::string method() { return "get_view_key_pair"; }

	typedef EmptyStruct Request;

	struct Response {
		SecretKey secret_view_key;
		PublicKey public_view_key;
		std::string import_keys;
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
		std::string address;     // empty for all addresses
		Height from_height = 0;  // From, but not including from_height
		Height to_height   = std::numeric_limits<Height>::max();
		// Up to, and including to_height. Will return transfers in mempool if from_height <= top_block_height &&
		// to_height > top_block_height
		bool forward = true;  // determines order of blocks returned, additionally if desired_transaction_count set,
		                      // then this defines if call starts from from_height forward, or from to_height backwards
		size_t desired_transaction_count =
		    std::numeric_limits<size_t>::max();  // Will return this number of transactions or a bit more, It can
		                                         // return more, because this call always returns full blocks
		bool need_outputs = false;  // Experimental, outputs are very rarely needed, so clients should ask explicitly
	};
	struct Response {
		std::vector<api::Block> blocks;  // includes only blocks with transactions with transfers we can view
		std::vector<api::Transfer> unlocked_transfers;  // deprecated, moved into blocks
		Height next_from_height = 0;  // When desired_transaction_count != max you can pass next* to corresponding
		                              // Request fields to continue iteration
		Height next_to_height = 0;
	};
	enum {
		INVALID_PARAMS          = -32602,  // from_height > to_height
		INVALID_HEIGHT_OR_DEPTH = -2,      // from_height too high
		ADDRESS_FAILED_TO_PARSE = -4,      // returns ErrorAddress
		ADDRESS_NOT_IN_WALLET   = -1002    // returns ErrorAddress
	};
};

struct CreateTransaction {
	static std::string method() { return "create_transaction"; }

	struct Request {
		api::Transaction transaction;  // You fill only basic info (anonymity, optional unlock_block_or_timestamp,
		                               // optional payment_id) and transfers. All positive transfers (amount > 0) will
		                               // be added as outputs. For all negative transfers (amount < 0), spendable for
		                               // requested sum and address will be selected and added as inputs
		std::vector<std::string> spend_addresses;
		// If this is not empty, will spend (and optimize) outputs for this addresses to get
		// neccessary funds. Otherwise will spend any output in the wallet
		bool any_spend_address = false;  // if you set spend_address to empty, you should set any_spend_address to true.
		                                 // This is protection against client bug when spend_address is forgotten or
		                                 // accidentally set to null, etc
		std::string change_address;      // Change will be returned to change_address.
		HeightOrDepth confirmed_height_or_depth = -DEFAULT_CONFIRMATIONS - 1;
		// Mix-ins will be selected from the [0..confirmed_height] window.
		// Reorganizations larger than confirmations may change mix-in global indexes, making transaction invalid.
		boost::optional<Amount> fee_per_byte;  // Fee of created transaction will be close to the
		                                       // size of tx * fee_per_byte.
		// You can check it in response.transaction.fee before sending, if you wish
		std::string optimization;  // Wallet outputs optimization (fusion). Leave empty to use normal optimization, good
		                           // for wallets with balanced sends to receives count. You can save on a few percent
		                           // of fee (on average) by specifying "minimal" for wallet receiving far less
		                           // transactions than sending. You should use "aggressive" for wallet receiving far
		                           // more transactions than sending, this option will use every opportunity to reduce
		                           // number of outputs. For better optimization use as little anonymity as possible. If
		                           // anonymity is set to 0, wallet will prioritize optimizing out dust and crazy (large
		                           // but not round) denominations of outputs.
		bool save_history = true;  // deprecated, history can now be restored from blockchain, if secrets are known
		bool subtract_fee_from_amount = false;
		// If true, fee wil be subtracted from transfers in their respective order
		std::vector<Hash> prevent_conflict_with_transactions;
		// Experimental API for guaranteed payouts under any circumstances
	};
	struct Response {
		BinaryArray binary_transaction;  // Empty if error
		api::Transaction transaction;
		// block_hash will be empty, block_height set to current pool height (may change later)
		bool save_history_error = false;          // Deprecated
		std::vector<Hash> transactions_required;  // Works together with prevent_conflict_with_transactions
		// If not empty, you should resend those transactions before trying create_transaction again to prevent
		// conflicts
	};
	enum {
		NOT_ENOUGH_FUNDS        = -301,
		NOT_ENOUGH_ANONYMITY    = -303,
		VIEW_ONLY_WALLET        = -304,
		TOO_MUCH_ANONYMITY      = -305,
		ADDRESS_FAILED_TO_PARSE = -4,     // returns ErrorAddress
		INVALID_HEIGHT_OR_DEPTH = -2,     // height_or_depth too low or too high
		ADDRESS_NOT_IN_WALLET   = -1002,  // returns ErrorAddress
		BYTECOIND_REQUEST_ERROR = -1003   // bytecoind returned error
	};
	struct ErrorTransactionTooBig : public json_rpc::Error {
		Amount max_amount               = 0;
		Amount max_min_anonymity_amount = 0;
		ErrorTransactionTooBig()        = default;
		ErrorTransactionTooBig(const std::string &msg, Amount a, Amount a_zero);
		void seria_data_members(seria::ISeria &s) override;
		enum {
			TRANSACTION_DOES_NOT_FIT_IN_BLOCK = -302  // Sender will have to split funds into several transactions
		};
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
		OUTPUT_ALREADY_SPENT    = -103,  // conflight height reported in error
		BYTECOIND_REQUEST_ERROR = -1003  // bytecoind returned error
	};
	struct Error : public json_rpc::Error {
		Height conflict_height = 0;
		Error()                = default;
		Error(int c, const std::string &msg, Height conflict_height)
		    : json_rpc::Error(c, msg), conflict_height(conflict_height) {}
		void seria_data_members(seria::ISeria &s) override;
	};
};

struct CreateSendproof {
	static std::string method() { return "create_sendproof"; }

	struct Request {
		Hash transaction_hash;
		std::string message;  // Add any user message to proof. Changing message will invlidate proof (which works like
		                      // digital signature of message)
		std::string address;
		std::vector<std::string> addresses;  // Deprecated, use address
		bool reveal_secret_message = false;  // Experimental
	};

	struct Response {
		std::string sendproof;
		std::vector<std::string> sendproofs;  // Deprecated, use sendproof
	};
	enum {
		ADDRESS_FAILED_TO_PARSE    = -4,    // returns ErrorAddress
		ADDRESS_NOT_IN_TRANSACTION = -204,  // returns ErrorAddress
		BYTECOIND_REQUEST_ERROR    = -1003  // bytecoind returned error
	};
};

struct GetTransaction {
	static std::string method() { return "get_transaction"; }
	struct Request {
		Hash hash;
		bool need_outputs = false;  // Experimental, outputs are very rarely needed, so clients should ask explicitly
	};
	struct Response {
		api::Transaction
		    transaction;  // empty transaction no hash returned if this transaction contains no recognizable transfers
	};
};

struct ExtCreateWallet {  // Experimental, undocumented
	static std::string method() { return "ext_create_wallet"; }
	struct Request {
		std::string wallet_file;
		std::string wallet_password;
		std::string wallet_type = "amethyst";
		std::string mnemonic;
		std::string mnemonic_password;
		std::string import_keys;
		size_t address_count         = 1;
		Timestamp creation_timestamp = 0;
		bool import_view_key         = false;
	};
	struct Response {  // On some platforms, wallet file name is chosen by walletd
		std::string wallet_file;
	};
	// json error codes correspond to walletd exit codes
};

struct ExtOpenWallet {  // Experimental, undocumented
	static std::string method() { return "ext_open_wallet"; }
	struct Request {
		std::string wallet_file;
		std::string wallet_password;
	};
	typedef EmptyStruct Response;
	// json error codes correspond to walletd exit codes
};

struct ExtSetPassword {  // Experimental, undocumented
	static std::string method() { return "ext_set_password"; }
	struct Request {
		std::string wallet_password;
	};
	typedef EmptyStruct Response;
	// json error codes correspond to walletd exit codes
};

struct ExtCloseWallet {  // Experimental, undocumented
	static std::string method() { return "ext_close_wallet"; }
	typedef EmptyStruct Request;
	typedef EmptyStruct Response;
};

}  // namespace walletd
}}  // namespace cn::api

// These messages encoded in JSON can be sent via http url /json_rpc3 to bytecoind rpc address:port
// or to binMethod() url encoded in unspecified binary format
namespace cn { namespace api { namespace cnd {  // cryptonoted is historically compiled to bytecoind, etc.

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
		boost::optional<Hash> hash;
		boost::optional<HeightOrDepth> height_or_depth;
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
		boost::optional<Hash> hash;
		boost::optional<HeightOrDepth> height_or_depth;
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
	static std::string bin_method() { return "sync_blocks_v3.4.3"; }
	// we increment bin method version when binary format changes
	static std::string url_prefix() { return "/sync_blocks/v3.4.3/"; }
	// /sync_blocks/ver/aaa/bbb/ccc, where aaabbbccc is dec height
	// we change url when binary format changes, so that we can set http to cache forever

	static std::string get_filename(Height ha, std::string *subfolder = nullptr);
	static bool parse_filename(const std::string &filename, Height *ha);
	static bool is_static_redirect(const std::string &body, Height *ha);

	struct Request {
		static constexpr size_t MAX_COUNT = 1000;
		static constexpr size_t MAX_SIZE  = 2 * 1024 * 1024;
		std::vector<Hash> sparse_chain;
		Timestamp first_block_timestamp = 0;
		size_t max_count                = MAX_COUNT / 2;
		size_t max_size                 = MAX_SIZE / 2;  // No more than ~1 megabytes of blocks + 1 block
		bool need_redundant_data        = true;          // smart clients can save traffic
	};
	struct Response {
		std::vector<RawBlock> blocks;
		Height start_height = 0;  // Redundant, deprecated. Use blocks[0].header.height (if blocks empty, sync finished)
		GetStatus::Response status;  // We save roundtrip during sync by also sending status here
	};
	struct RawBlockCompact {  // for binary method variant
		api::BlockHeader header;
		cn::Transaction base_transaction;
		std::vector<TransactionPrefix> raw_transactions;
		std::vector<Hash> transaction_hashes;                   // except coinbase
		std::vector<size_t> transaction_sizes;                  // except coinbase
		std::vector<std::vector<size_t>> output_stack_indexes;  // for each transaction + coinbase
	};
	struct ResponseCompact {
		std::vector<RawBlockCompact> blocks;
		GetStatus::Response status;  // in static responses, top_block_hash will be Hash{}
	};
};

struct GetRawTransaction {
	static std::string method() { return "get_raw_transaction"; }
	struct Request {
		Hash hash;
	};
	struct Response {
		api::Transaction transaction;  // contain only info known to bytecoind
		TransactionPrefix raw_transaction;
		std::vector<std::vector<PublicKey>> mixed_public_keys;  // deprecated
		std::vector<std::vector<api::Output>> mixed_outputs;    // TODO - document
		// TransactionPrefix contains only indexes, we need public keys to sign sendproof
		TransactionSignatures signatures;
	};
	enum {
		HASH_NOT_FOUND = -5  // Neither in main nor in side chain
	};
};

// Signature of this method will stabilize to the end of beta
struct SyncMemPool {  // Used by walletd sync process
	static std::string method() { return "sync_mem_pool"; }
	static std::string bin_method() { return "sync_mem_pool_v3.4.0"; }
	// we increment bin method version when binary format changes
	struct Request {
		std::vector<Hash> known_hashes;   // Should be sent sorted
		bool need_redundant_data = true;  // walletd and smart clients can save traffic
	};
	struct Response {
		std::vector<Hash> removed_hashes;                       // Hashes no more in pool
		std::vector<TransactionPrefix> added_raw_transactions;  // New raw transactions in pool
		std::vector<api::Transaction> added_transactions;       // contain only info known to bytecoind
		GetStatus::Response status;  // We save roundtrip during sync by also sending status here
	};
};

struct GetRandomOutputs {
	static std::string method() { return "get_random_outputs"; }
	struct Request {
		std::vector<Amount> amounts;  // Repeating the same amount will give you multiples of output_count in result
		size_t output_count                     = 0;
		HeightOrDepth confirmed_height_or_depth = -DEFAULT_CONFIRMATIONS - 1;
		// Mix-ins will be selected from the [0..confirmed_height] window.
		// Reorganizations larger than confirmations may change mix-in global indexes,
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
		std::vector<size_t> output_indexes;
		HeightOrDepth depth = 0;     // Experimental
		std::string secret_message;  // Experimental
	};
	// PROOF_FAILED_TO_PARSE is reported as json rpc error
	// all others return hash of transaction and destination address
	enum { PROOF_FAILED_TO_PARSE = -201, PROOF_NOT_IN_MAIN_CHAIN = -202, PROOF_WRONG_SIGNATURE = -203 };
	struct Error : public json_rpc::Error {
		Hash transaction_hash;
		Error() = default;
		Error(int c, const std::string &msg, const Hash &transaction_hash);
		void seria_data_members(seria::ISeria &s) override;
	};
};

struct GetStatistics {
	static std::string method() { return "get_statistics"; }

	struct Request {
		bool need_connected_peers = true;
		bool need_peer_lists      = false;
	};
	typedef CoreStatistics Response;
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
		Hash base_transaction_hash;                    // BlockTemplate does not contain it
		std::vector<size_t> transaction_binary_sizes;  // for each transaction
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
		size_t reserve_size = 0;  // max 127 bytes
		std::string wallet_address;
		Hash miner_secret;                                 // Used during testing for deterministic block generation
		boost::optional<Hash> top_block_hash;              // for longpoll in v3 - behaves like GetStatus
		boost::optional<size_t> transaction_pool_version;  // for longpoll in v3 - behaves like GetStatus
	};
	struct Response {
		Difficulty difficulty  = 0;
		Height height          = 0;
		size_t reserved_offset = 0;
		BinaryArray blocktemplate_blob;
		std::string status = legacy_status_ok();
		Hash top_block_hash;                  // for longpoll in v3 - behaves like GetStatus
		size_t transaction_pool_version = 0;  // for longpoll in v3 - behaves like GetStatus
		Hash previous_block_hash;             // Deprecated, used by some legacy miners.

		Hash cm_prehash;  // experimental stuff for CM
		Hash cm_path;     // experimental stuff for CM, usually equals to result of GetCurrencyId
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
		Hash currency_id_blob;
		// Usually hash of genesis block
		// If 2 currencies fork, one would have to change id so they can fit in the same MM tree
		// When currency id changes, miners will produce invalid blocks (similar to race condition)
		// So, currency_id must be field in GetBlockTemplate response, not separate method
	};
};

struct SubmitBlock {
	static std::string method() { return "submit_block"; }
	struct Request {
		BinaryArray blocktemplate_blob;
		BinaryArray cm_nonce;  // experimental stuff for CM. Will turn on CM if not empty
		std::vector<crypto::CMBranchElement> cm_merkle_branch;  // can be empty if solo cm-mining
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
}}}  // namespace cn::api::cnd

namespace seria {

class ISeria;

void ser_members(cn::api::EmptyStruct &v, ISeria &s);
void ser_members(cn::api::Output &v, ISeria &s, bool only_bytecoind_fields = false);
void ser_members(cn::api::BlockHeader &v, ISeria &s);
void ser_members(cn::api::cnd::BlockHeaderLegacy &v, ISeria &s);
void ser_members(cn::api::Transfer &v, ISeria &s, bool with_message = true);
void ser_members(cn::api::Transaction &v, ISeria &s, bool with_message = true);
void ser_members(cn::api::Block &v, ISeria &s);
void ser_members(cn::api::RawBlock &v, ISeria &s);
void ser_members(cn::api::Balance &v, ISeria &s);

void ser_members(cn::api::walletd::GetAddresses::Request &v, ISeria &s);
void ser_members(cn::api::walletd::GetAddresses::Response &v, ISeria &s);
void ser_members(cn::api::walletd::GetWalletRecords::Record &v, ISeria &s);
void ser_members(cn::api::walletd::GetWalletRecords::Request &v, ISeria &s);
void ser_members(cn::api::walletd::GetWalletRecords::Response &v, ISeria &s);
void ser_members(cn::api::walletd::GetWalletInfo::Request &v, ISeria &s);
void ser_members(cn::api::walletd::GetWalletInfo::Response &v, ISeria &s);
void ser_members(cn::api::walletd::SetAddressLabel::Request &v, ISeria &s);
void ser_members(cn::api::walletd::GetViewKeyPair::Response &v, ISeria &s);
void ser_members(cn::api::walletd::CreateAddresses::Request &v, ISeria &s);
void ser_members(cn::api::walletd::CreateAddresses::Response &v, ISeria &s);
void ser_members(cn::api::walletd::GetBalance::Request &v, ISeria &s);
void ser_members(cn::api::walletd::GetUnspents::Request &v, ISeria &s);
void ser_members(cn::api::walletd::GetUnspents::Response &v, ISeria &s);
void ser_members(cn::api::walletd::GetTransfers::Request &v, ISeria &s);
void ser_members(cn::api::walletd::GetTransfers::Response &v, ISeria &s);
void ser_members(cn::api::walletd::CreateTransaction::Request &v, ISeria &s);
void ser_members(cn::api::walletd::CreateTransaction::Response &v, ISeria &s);
void ser_members(cn::api::walletd::CreateSendproof::Request &v, ISeria &s);
void ser_members(cn::api::walletd::CreateSendproof::Response &v, ISeria &s);
void ser_members(cn::api::walletd::GetTransaction::Request &v, ISeria &s);
void ser_members(cn::api::walletd::GetTransaction::Response &v, ISeria &s);
void ser_members(cn::api::walletd::ExtCreateWallet::Request &v, ISeria &s);
void ser_members(cn::api::walletd::ExtCreateWallet::Response &v, ISeria &s);
void ser_members(cn::api::walletd::ExtOpenWallet::Request &v, ISeria &s);
void ser_members(cn::api::walletd::ExtSetPassword::Request &v, ISeria &s);

void ser_members(cn::api::cnd::GetStatus::Request &v, ISeria &s);
void ser_members(cn::api::cnd::GetStatus::Response &v, ISeria &s);
void ser_members(cn::api::cnd::GetBlockHeader::Request &v, ISeria &s);
void ser_members(cn::api::cnd::GetBlockHeader::Response &v, ISeria &s);
void ser_members(cn::api::cnd::GetRawBlock::Request &v, ISeria &s);
void ser_members(cn::api::cnd::GetRawBlock::Response &v, ISeria &s);
void ser_members(cn::api::cnd::SyncBlocks::Request &v, ISeria &s);
void ser_members(cn::api::cnd::SyncBlocks::Response &v, ISeria &s);
void ser_members(cn::api::cnd::SyncBlocks::RawBlockCompact &v, ISeria &s);
void ser_members(cn::api::cnd::SyncBlocks::ResponseCompact &v, ISeria &s);
void ser_members(cn::api::cnd::GetRawTransaction::Request &v, ISeria &s);
void ser_members(cn::api::cnd::GetRawTransaction::Response &v, ISeria &s);
void ser_members(cn::api::cnd::SyncMemPool::Request &v, ISeria &s);
void ser_members(cn::api::cnd::SyncMemPool::Response &v, ISeria &s);
void ser_members(cn::api::cnd::GetRandomOutputs::Request &v, ISeria &s);
void ser_members(cn::api::cnd::GetRandomOutputs::Response &v, ISeria &s);
void ser_members(cn::api::cnd::SendTransaction::Request &v, ISeria &s);
void ser_members(cn::api::cnd::SendTransaction::Response &v, ISeria &s);
void ser_members(cn::api::cnd::CheckSendproof::Request &v, ISeria &s);
void ser_members(cn::api::cnd::CheckSendproof::Response &v, ISeria &s);
void ser_members(cn::api::cnd::GetStatistics::Request &v, ISeria &s);
void ser_members(cn::api::cnd::GetArchive::ArchiveRecord &v, ISeria &s);
void ser_members(cn::api::cnd::GetArchive::ArchiveBlock &v, ISeria &s);
void ser_members(cn::api::cnd::GetArchive::Request &v, ISeria &s);
void ser_members(cn::api::cnd::GetArchive::Response &v, ISeria &s);
void ser_members(cn::api::cnd::GetBlockTemplate::Request &v, ISeria &s);
void ser_members(cn::api::cnd::GetBlockTemplate::Response &v, ISeria &s);
void ser_members(cn::api::cnd::GetCurrencyId::Response &v, ISeria &s);
void ser_members(cn::api::cnd::SubmitBlock::Request &v, ISeria &s);
void ser_members(cn::api::cnd::SubmitBlock::Response &v, ISeria &s);
void ser_members(cn::api::cnd::SubmitBlockLegacy::Response &v, ISeria &s);
void ser_members(cn::api::cnd::GetLastBlockHeaderLegacy::Response &v, ISeria &s);
void ser_members(cn::api::cnd::GetBlockHeaderByHashLegacy::Request &v, ISeria &s);
void ser_members(cn::api::cnd::GetBlockHeaderByHeightLegacy::Request &v, ISeria &s);

}  // namespace seria
