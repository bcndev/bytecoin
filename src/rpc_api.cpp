// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "rpc_api.hpp"
#include "Core/CryptoNoteTools.hpp"
#include "Core/TransactionExtra.hpp"
#include "common/StringTools.hpp"
#include "common/Varint.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/JsonOutputStream.hpp"

using namespace cn;

api::ErrorAddress::ErrorAddress(int c, const std::string &msg, const std::string &address)
    : json_rpc::Error(c, msg + " address=" + address), address(address) {}
api::ErrorWrongHeight::ErrorWrongHeight(const std::string &msg, int64_t request_height, Height top_block_height)
    : json_rpc::Error(INVALID_HEIGHT_OR_DEPTH,
          msg + "=" + common::to_string(request_height) + " while top block height is " +
              common::to_string(top_block_height))
    , request_height(request_height)
    , top_block_height(top_block_height) {}
Height api::ErrorWrongHeight::fix_height_or_depth(
    HeightOrDepth ha, Height tip_height, bool throw_on_too_big_height, bool throw_on_too_big_depth, Height max_depth) {
	if (ha < 0) {
		ha = static_cast<HeightOrDepth>(tip_height) + 1 + ha;
		if (ha < 0) {
			if (throw_on_too_big_depth)
				throw ErrorWrongHeight(
				    "height_or_depth cannot be deeper than genesis block, actual height_or_depth=", ha, tip_height);
			ha = 0;
		}
	}
	if (max_depth != std::numeric_limits<Height>::max() && ha + max_depth < tip_height)
		throw ErrorWrongHeight("height_or_depth cannot be deeper than " + common::to_string(max_depth) +
		                           " blocks from top block, actual height_or_depth=",
		    ha, tip_height);
	if (ha > static_cast<HeightOrDepth>(tip_height)) {
		if (throw_on_too_big_height)
			throw ErrorWrongHeight(
			    "height_or_depth cannot exceed top block height, actual height_or_depth=", ha, tip_height);
		return tip_height;
	}
	return static_cast<Height>(ha);
}
void api::ErrorWrongHeight::seria_data_members(seria::ISeria &s) {
	seria_kv("request_height", request_height, s);
	seria_kv("top_block_height", top_block_height, s);
}
api::ErrorHash::ErrorHash(int c, const std::string &msg, const Hash &hash)
    : json_rpc::Error(c, msg + " request_hash=" + common::pod_to_hex(hash)), hash(hash) {}
void api::ErrorHash::seria_data_members(seria::ISeria &s) { seria_kv("hash", hash, s); }

api::cnd::CheckSendproof::Error::Error(int c, const std::string &msg, const Hash &transaction_hash)
    : json_rpc::Error(c, msg + " transaction_hash=" + common::pod_to_hex(transaction_hash))
    , transaction_hash(transaction_hash) {}

void api::cnd::CheckSendproof::Error::seria_data_members(seria::ISeria &s) {
	seria_kv("transaction_hash", transaction_hash, s);
};

api::walletd::CreateTransaction::ErrorTransactionTooBig::ErrorTransactionTooBig(
    const std::string &msg, Amount a, Amount a_zero)
    : json_rpc::Error(TRANSACTION_DOES_NOT_FIT_IN_BLOCK, msg), max_amount(a), max_min_anonymity_amount(a_zero) {}

void api::walletd::CreateTransaction::ErrorTransactionTooBig::seria_data_members(seria::ISeria &s) {
	seria_kv("max_amount", max_amount, s);
	seria_kv("max_min_anonymity_amount", max_min_anonymity_amount, s);
}

void api::ErrorAddress::seria_data_members(seria::ISeria &s) { seria_kv("address", address, s); }
void api::walletd::SendTransaction::Error::seria_data_members(seria::ISeria &s) {
	seria_kv("conflict_height", conflict_height, s);
}
void api::cnd::GetArchive::Error::seria_data_members(seria::ISeria &s) { seria_kv("archive_id", archive_id, s); }

Hash Checkpoint::get_message_hash() const { return get_object_hash(*this, nullptr); }

bool api::walletd::GetStatus::Response::ready_for_longpoll(const Request &other) const {
	if (other.top_block_hash && top_block_hash != other.top_block_hash.get())
		return true;
	if (other.transaction_pool_version && transaction_pool_version != other.transaction_pool_version.get())
		return true;
	if (other.outgoing_peer_count && outgoing_peer_count != other.outgoing_peer_count.get())
		return true;
	if (other.incoming_peer_count && incoming_peer_count != other.incoming_peer_count.get())
		return true;
	if (other.lower_level_error && lower_level_error != other.lower_level_error.get())
		return true;
	return !other.top_block_hash && !other.transaction_pool_version && !other.outgoing_peer_count &&
	       !other.incoming_peer_count && !other.lower_level_error;
}

static std::string digit3(Height ha) {
	auto a = common::to_string(ha);
	return a.size() >= 3 ? a : std::string(3 - a.size(), '0') + a;
}

std::string api::cnd::SyncBlocks::get_filename(Height ha, std::string *subfolder) {
	Height rem            = ha;
	std::string file_name = digit3(rem % 1000);
	rem /= 1000;
	std::string sub_folder_name = digit3(rem % 1000);
	rem /= 1000;
	sub_folder_name = digit3(rem % 1000) + "/" + sub_folder_name;
	if (subfolder)
		*subfolder = sub_folder_name;
	return sub_folder_name + "/" + file_name;
}

bool api::cnd::SyncBlocks::parse_filename(const std::string &filename, Height *ha) {
	std::string aa[3];
	if (!common::split_string(filename, "/", aa[0], aa[1], aa[2]))
		return false;
	Height h = 0;
	try {
		for (size_t i = 0; i != 3; ++i) {
			Height part = common::integer_cast<Height>(aa[i]);
			if (digit3(part) != aa[i])
				return false;  // leading zeros, spaces, etc
			h = h * 1000 + part;
		}
		*ha = h;
		return true;
	} catch (const std::exception &) {
	}
	return false;
}

bool api::cnd::SyncBlocks::is_static_redirect(const std::string &body, Height *ha) {
	try {
		if (body.size() < 10) {
			*ha = common::integer_cast<Height>(body);
			return true;
		}
	} catch (const std::exception &) {
	}
	return false;
}

namespace seria {

void ser_members(api::Output &v, ISeria &s, bool only_bytecoind_fields) {
	seria_kv("amount", v.amount, s);
	seria_kv("public_key", v.public_key, s);
	seria_kv("stack_index", v.stack_index, s);
	seria_kv("global_index", v.global_index, s);
	seria_kv("height", v.height, s);
	seria_kv("unlock_block_or_timestamp", v.unlock_block_or_timestamp, s);
	if (dynamic_cast<seria::JsonOutputStream *>(&s))
		seria_kv("unlock_time", v.unlock_block_or_timestamp, s);  // deprecated
	if (dynamic_cast<seria::JsonInputStream *>(&s))
		seria_kv("unlock_time", v.unlock_block_or_timestamp, s);  // deprecated
	if (!only_bytecoind_fields)
		seria_kv("index_in_transaction", v.index_in_transaction, s);
	if (!only_bytecoind_fields) {
		seria_kv("transaction_hash", v.transaction_hash, s);
		seria_kv("key_image", v.key_image, s);
		seria_kv("address", v.address, s);
		seria_kv("dust", v.dust, s);
	}
}

void ser_members(api::BlockHeader &v, ISeria &s) {
	seria_kv("major_version", v.major_version, s);
	seria_kv("minor_version", v.minor_version, s);
	seria_kv("timestamp", v.timestamp, s);
	seria_kv("previous_block_hash", v.previous_block_hash, s);
	seria_kv("binary_nonce", v.binary_nonce, s);
	if (dynamic_cast<seria::JsonOutputStream *>(&s)) {
		auto nonce =
		    common::uint_le_from_bytes<uint32_t>(v.binary_nonce.data(), std::min<size_t>(4, v.binary_nonce.size()));
		seria_kv("nonce", nonce, s);
	}
	if (dynamic_cast<seria::JsonInputStream *>(&s)) {
		uint32_t nonce = 0;
		seria_kv("nonce", nonce, s);
	}
	seria_kv("height", v.height, s);
	seria_kv("hash", v.hash, s);
	seria_kv("reward", v.reward, s);
	seria_kv("cumulative_difficulty", v.cumulative_difficulty.lo, s);
	seria_kv_optional("cumulative_difficulty_hi", v.cumulative_difficulty.hi, s);
	seria_kv("difficulty", v.difficulty, s);
	seria_kv("base_reward", v.base_reward, s);
	seria_kv("block_size", v.block_size, s);
	seria_kv("transactions_size", v.transactions_size, s);
	seria_kv("already_generated_coins", v.already_generated_coins, s);
	seria_kv("already_generated_transactions", v.already_generated_transactions, s);
	seria_kv("already_generated_key_outputs", v.already_generated_key_outputs, s);
	seria_kv("block_capacity_vote", v.block_capacity_vote, s);
	seria_kv("block_capacity_vote_median", v.block_capacity_vote_median, s);
	seria_kv("size_median", v.size_median, s);
	seria_kv("effective_size_median", v.effective_size_median, s);
	seria_kv("timestamp_median", v.timestamp_median, s);
	seria_kv("transactions_fee", v.transactions_fee, s);
}

void ser_members(api::cnd::BlockHeaderLegacy &v, ISeria &s) {
	ser_members(static_cast<api::BlockHeader &>(v), s);
	seria_kv("prev_hash", v.previous_block_hash, s);
	seria_kv("depth", v.depth, s);
	seria_kv("orphan_status", v.orphan_status, s);
	seria_kv("transactions_cumulative_size", v.transactions_size, s);
	seria_kv("total_fee_amount", v.transactions_fee, s);
}

void ser_members(api::Transfer &v, ISeria &s, bool with_message) {
	seria_kv("address", v.address, s);
	seria_kv("amount", v.amount, s);
	seria_kv("ours", v.ours, s);
	seria_kv("locked", v.locked, s);
	seria_kv("outputs", v.outputs, s);
	seria_kv("transaction_hash", v.transaction_hash, s);
	if (with_message)  // TODO - remove on next WalletState db version upgrade
		seria_kv_optional("message", v.message, s);
}

void ser_members(api::Transaction &v, ISeria &s, bool with_message) {
	seria_kv("unlock_block_or_timestamp", v.unlock_block_or_timestamp, s);
	if (dynamic_cast<seria::JsonOutputStream *>(&s))
		seria_kv("unlock_time", v.unlock_block_or_timestamp, s);  // deprecated
	if (dynamic_cast<seria::JsonInputStream *>(&s))
		seria_kv("unlock_time", v.unlock_block_or_timestamp, s);  // deprecated
	seria_kv("amount", v.amount, s);
	seria_kv("fee", v.fee, s);
	seria_kv("public_key", v.public_key, s);
	seria_kv_optional("transfers", v.transfers, s, with_message);
	seria_kv_optional("payment_id", v.payment_id, s);
	seria_kv("anonymity", v.anonymity, s);
	seria_kv("extra", v.extra, s);
	seria_kv("hash", v.hash, s);
	seria_kv("prefix_hash", v.prefix_hash, s);
	seria_kv("inputs_hash", v.inputs_hash, s);
	seria_kv("coinbase", v.coinbase, s);
	seria_kv("block_height", v.block_height, s);
	seria_kv("block_hash", v.block_hash, s);
	seria_kv("timestamp", v.timestamp, s);
	seria_kv("size", v.size, s);
	if (dynamic_cast<seria::JsonOutputStream *>(&s))
		seria_kv("binary_size", v.size, s);  // deprecated
	if (dynamic_cast<seria::JsonInputStream *>(&s))
		seria_kv("binary_size", v.size, s);  // deprecated
}

void ser_members(api::Block &v, ISeria &s) {
	seria_kv("header", v.header, s);
	seria_kv("transactions", v.transactions, s);
	seria_kv("unlocked_transfers", v.unlocked_transfers, s);
}

void ser_members(api::RawBlock &v, ISeria &s) {
	seria_kv("header", v.header, s);
	seria_kv("raw_header", v.raw_header, s);
	seria_kv("raw_transactions", v.raw_transactions, s);
	seria_kv("transactions", v.transactions, s);
	seria_kv("output_stack_indexes", v.output_stack_indexes, s);
}

void ser_members(api::Balance &v, ISeria &s) {
	seria_kv("spendable", v.spendable, s);
	seria_kv("spendable_dust", v.spendable_dust, s);
	seria_kv("locked_or_unconfirmed", v.locked_or_unconfirmed, s);

	seria_kv("spendable_outputs", v.spendable_outputs, s);
	seria_kv("spendable_dust_outputs", v.spendable_dust_outputs, s);
	seria_kv("locked_or_unconfirmed_outputs", v.locked_or_unconfirmed_outputs, s);
}

void ser_members(api::EmptyStruct &, ISeria &) {}

void ser_members(api::walletd::GetAddresses::Request &v, ISeria &s) {
	seria_kv("need_secret_spend_keys", v.need_secret_spend_keys, s);
	seria_kv("from_address", v.from_address, s);
	seria_kv("max_count", v.max_count, s);
}

void ser_members(api::walletd::GetAddresses::Response &v, ISeria &s) {
	seria_kv("total_address_count", v.total_address_count, s);
	seria_kv("addresses", v.addresses, s);
	seria_kv_optional("secret_spend_keys", v.secret_spend_keys, s);
}

void ser_members(cn::api::walletd::GetWalletInfo::Request &v, ISeria &s) {
	seria_kv("need_secrets", v.need_secrets, s);
}

void ser_members(cn::api::walletd::GetWalletInfo::Response &v, ISeria &s) {
	seria_kv("view_only", v.view_only, s);
	seria_kv("wallet_type", v.wallet_type, s);
	seria_kv("can_view_outgoing_addresses", v.can_view_outgoing_addresses, s);
	seria_kv("has_view_secret_key", v.has_view_secret_key, s);
	seria_kv("wallet_creation_timestamp", v.wallet_creation_timestamp, s);
	seria_kv("total_address_count", v.total_address_count, s);
	seria_kv("first_address", v.first_address, s);
	seria_kv("net", v.net, s);
	seria_kv_optional("secret_view_key", v.secret_view_key, s);
	seria_kv_optional("public_view_key", v.public_view_key, s);
	seria_kv_optional("mnemonic", v.mnemonic, s);
	seria_kv_optional("import_keys", v.import_keys, s);
}

void ser_members(api::walletd::GetWalletRecords::Record &v, ISeria &s) {
	seria_kv("index", v.index, s);
	seria_kv("address", v.address, s);
	seria_kv("label", v.label, s);
	seria_kv_optional("secret_spend_key", v.secret_spend_key, s);
	seria_kv_optional("public_spend_key", v.public_spend_key, s);
}

void ser_members(api::walletd::GetWalletRecords::Request &v, ISeria &s) {
	seria_kv("need_secrets", v.need_secrets, s);
	seria_kv("create", v.create, s);
	seria_kv("index", v.index, s);
	seria_kv("count", v.count, s);
}

void ser_members(api::walletd::GetWalletRecords::Response &v, ISeria &s) {
	seria_kv("total_count", v.total_count, s);
	seria_kv("records", v.records, s);
}

void ser_members(cn::api::walletd::SetAddressLabel::Request &v, ISeria &s) {
	seria_kv_strict("address", v.address, s);
	seria_kv("label", v.label, s);
}

void ser_members(api::walletd::GetViewKeyPair::Response &v, ISeria &s) {
	seria_kv("secret_view_key", v.secret_view_key, s);
	seria_kv("public_view_key", v.public_view_key, s);
	seria_kv("import_keys", v.import_keys, s);
}

void ser_members(api::walletd::CreateAddresses::Request &v, ISeria &s) {
	seria_kv("secret_spend_keys", v.secret_spend_keys, s);
	seria_kv("creation_timestamp", v.creation_timestamp, s);
}

void ser_members(api::walletd::CreateAddresses::Response &v, ISeria &s) {
	seria_kv("addresses", v.addresses, s);
	seria_kv("secret_spend_keys", v.secret_spend_keys, s);
}

void ser_members(api::walletd::GetBalance::Request &v, ISeria &s) {
	seria_kv("address", v.address, s);
	seria_kv("height_or_depth", v.height_or_depth, s);
}

void ser_members(api::walletd::GetUnspents::Request &v, ISeria &s) {
	seria_kv("address", v.address, s);
	seria_kv("height_or_depth", v.height_or_depth, s);
}

void ser_members(api::walletd::GetUnspents::Response &v, ISeria &s) {
	seria_kv("spendable", v.spendable, s);
	seria_kv("locked_or_unconfirmed", v.locked_or_unconfirmed, s);
}

void ser_members(api::walletd::GetTransfers::Request &v, ISeria &s) {
	seria_kv("address", v.address, s);
	seria_kv("from_height", v.from_height, s);
	seria_kv("to_height", v.to_height, s);
	seria_kv("desired_transaction_count", v.desired_transaction_count, s);
	if (s.is_input())
		seria_kv("desired_transactions_count", v.desired_transaction_count, s);  // deprecated
	seria_kv("forward", v.forward, s);
}

void ser_members(api::walletd::GetTransfers::Response &v, ISeria &s) {
	seria_kv("blocks", v.blocks, s);
	seria_kv("unlocked_transfers", v.unlocked_transfers, s, true);
	seria_kv("next_from_height", v.next_from_height, s);
	seria_kv("next_to_height", v.next_to_height, s);
}

void ser_members(api::walletd::CreateTransaction::Request &v, ISeria &s) {
	seria_kv_strict("transaction", v.transaction, s);
	seria_kv("spend_addresses", v.spend_addresses, s);
	seria_kv("any_spend_address", v.any_spend_address, s);
	seria_kv("change_address", v.change_address, s);
	seria_kv("confirmed_height_or_depth", v.confirmed_height_or_depth, s);
	seria_kv("fee_per_byte", v.fee_per_byte, s);
	seria_kv("optimization", v.optimization, s);
	seria_kv("save_history", v.save_history, s);
	seria_kv("subtract_fee_from_amount", v.subtract_fee_from_amount, s);
	seria_kv("prevent_conflict_with_transactions", v.prevent_conflict_with_transactions, s);
}

void ser_members(api::walletd::CreateTransaction::Response &v, ISeria &s) {
	seria_kv("transaction", v.transaction, s);
	seria_kv("binary_transaction", v.binary_transaction, s);
	seria_kv("save_history_error", v.save_history_error, s);
	seria_kv("transactions_required", v.transactions_required, s);
}

void ser_members(api::walletd::CreateSendproof::Request &v, ISeria &s) {
	seria_kv_strict("transaction_hash", v.transaction_hash, s);
	seria_kv("message", v.message, s);
	seria_kv("addresses", v.addresses, s);
	seria_kv("reveal_secret_message", v.reveal_secret_message, s);
}

void ser_members(api::walletd::CreateSendproof::Response &v, ISeria &s) { seria_kv("sendproofs", v.sendproofs, s); }

void ser_members(api::cnd::GetStatus::Request &v, ISeria &s) {
	seria_kv("top_block_hash", v.top_block_hash, s);
	seria_kv("transaction_pool_version", v.transaction_pool_version, s);
	seria_kv("outgoing_peer_count", v.outgoing_peer_count, s);
	seria_kv("incoming_peer_count", v.incoming_peer_count, s);
	seria_kv("lower_level_error", v.lower_level_error, s);
}

void ser_members(api::cnd::GetStatus::Response &v, ISeria &s) {
	seria_kv("top_block_hash", v.top_block_hash, s);
	seria_kv("transaction_pool_version", v.transaction_pool_version, s);
	seria_kv("outgoing_peer_count", v.outgoing_peer_count, s);
	seria_kv("incoming_peer_count", v.incoming_peer_count, s);
	seria_kv("lower_level_error", v.lower_level_error, s);

	seria_kv("top_block_height", v.top_block_height, s);
	seria_kv("top_block_difficulty", v.top_block_difficulty, s);
	seria_kv("top_block_cumulative_difficulty", v.top_block_cumulative_difficulty.lo, s);
	seria_kv_optional("top_block_cumulative_difficulty_hi", v.top_block_cumulative_difficulty.hi, s);
	seria_kv("top_block_timestamp", v.top_block_timestamp, s);
	seria_kv("top_block_timestamp_median", v.top_block_timestamp_median, s);
	seria_kv("recommended_fee_per_byte", v.recommended_fee_per_byte, s);
	if (dynamic_cast<seria::JsonOutputStream *>(&s) || dynamic_cast<seria::JsonInputStream *>(&s))
		seria_kv("next_block_effective_median_size", v.recommended_max_transaction_size, s);
	seria_kv("recommended_max_transaction_size", v.recommended_max_transaction_size, s);
	seria_kv("top_known_block_height", v.top_known_block_height, s);
}

void ser_members(api::cnd::GetBlockHeader::Request &v, ISeria &s) {
	seria_kv("hash", v.hash, s);
	seria_kv("height_or_depth", v.height_or_depth, s);
}

void ser_members(api::cnd::GetBlockHeader::Response &v, ISeria &s) {
	seria_kv("block_header", v.block_header, s);
	seria_kv("orphan_status", v.orphan_status, s);
	seria_kv("depth", v.depth, s);
}

void ser_members(api::cnd::GetRawBlock::Request &v, ISeria &s) {
	seria_kv("hash", v.hash, s);
	seria_kv("height_or_depth", v.height_or_depth, s);
}

void ser_members(api::cnd::GetRawBlock::Response &v, ISeria &s) {
	seria_kv("block", v.block, s);
	seria_kv("orphan_status", v.orphan_status, s);
	seria_kv("depth", v.depth, s);
}

void ser_members(api::cnd::SyncBlocks::Request &v, ISeria &s) {
	seria_kv_strict("sparse_chain", v.sparse_chain, s);
	seria_kv("first_block_timestamp", v.first_block_timestamp, s);
	seria_kv("max_count", v.max_count, s);
	seria_kv("max_size", v.max_size, s);
	seria_kv("need_redundant_data", v.need_redundant_data, s);
}

void ser_members(api::cnd::SyncBlocks::Response &v, ISeria &s) {
	seria_kv("blocks", v.blocks, s);
	seria_kv("start_height", v.start_height, s);
	seria_kv("status", v.status, s);
}

void ser_members(cn::api::cnd::SyncBlocks::RawBlockCompact &v, ISeria &s) {
	seria_kv("header", v.header, s);
	seria_kv("base_transaction", v.base_transaction, s);
	seria_kv("raw_transactions", v.raw_transactions, s);
	seria_kv("transaction_hashes", v.transaction_hashes, s);
	seria_kv("transaction_sizes", v.transaction_sizes, s);
	seria_kv("output_stack_indexes", v.output_stack_indexes, s);
}

void ser_members(cn::api::cnd::SyncBlocks::ResponseCompact &v, ISeria &s) {
	seria_kv("blocks", v.blocks, s);
	seria_kv("status", v.status, s);
}

void ser_members(api::cnd::GetRawTransaction::Request &v, ISeria &s) { seria_kv_strict("hash", v.hash, s); }

void ser_members(api::cnd::GetRawTransaction::Response &v, ISeria &s) {
	seria_kv("transaction", v.transaction, s);
	seria_kv("raw_transaction", v.raw_transaction, s);
	seria_kv("mixed_public_keys", v.mixed_public_keys, s);
}

void ser_members(api::cnd::SyncMemPool::Request &v, ISeria &s) {
	if (!s.is_input())
		std::sort(v.known_hashes.begin(), v.known_hashes.end());
	seria_kv("known_hashes", v.known_hashes, s);
	if (s.is_input() && !std::is_sorted(v.known_hashes.begin(), v.known_hashes.end()))
		throw std::runtime_error(
		    "SyncMemPool::Request known_hashes must be sorted in increasing order (from [0000..] to [ffff..])");
	seria_kv("need_redundant_data", v.need_redundant_data, s);
}

void ser_members(api::cnd::SyncMemPool::Response &v, ISeria &s) {
	seria_kv("removed_hashes", v.removed_hashes, s);
	seria_kv("added_raw_transactions", v.added_raw_transactions, s);
	seria_kv("added_transactions", v.added_transactions, s);
	seria_kv("status", v.status, s);
}

void ser_members(api::cnd::GetRandomOutputs::Request &v, ISeria &s) {
	seria_kv_strict("amounts", v.amounts, s);
	seria_kv_strict("output_count", v.output_count, s);
	seria_kv("confirmed_height_or_depth", v.confirmed_height_or_depth, s);
}

void ser_members(api::cnd::GetRandomOutputs::Response &v, ISeria &s) { seria_kv("outputs", v.outputs, s, true); }

void ser_members(api::cnd::SendTransaction::Request &v, ISeria &s) {
	seria_kv_strict("binary_transaction", v.binary_transaction, s);
}

void ser_members(api::cnd::SendTransaction::Response &v, ISeria &s) { seria_kv("send_result", v.send_result, s); }

void ser_members(api::cnd::CheckSendproof::Request &v, ISeria &s) { seria_kv_strict("sendproof", v.sendproof, s); }

void ser_members(api::cnd::CheckSendproof::Response &v, ISeria &s) {
	seria_kv("transaction_hash", v.transaction_hash, s);
	seria_kv("address", v.address, s);
	seria_kv("amount", v.amount, s);
	seria_kv("message", v.message, s);
	seria_kv("output_indexes", v.output_indexes, s);
	seria_kv("depth", v.depth, s);
	seria_kv("secret_message", v.secret_message, s);
}

void ser_members(cn::api::cnd::GetStatistics::Request &v, ISeria &s) {
	seria_kv("need_connected_peers", v.need_connected_peers, s);
	seria_kv("need_peer_lists", v.need_peer_lists, s);
}

void ser_members(api::cnd::GetArchive::ArchiveRecord &v, ISeria &s) {
	seria_kv("timestamp", v.timestamp, s);
	seria_kv("timestamp_usec", v.timestamp_usec, s);
	seria_kv("type", v.type, s);
	seria_kv("hash", v.hash, s);
	seria_kv("source_address", v.source_address, s);
}

void ser_members(api::cnd::GetArchive::ArchiveBlock &v, ISeria &s) {
	seria_kv("raw_header", v.raw_header, s);
	seria_kv("raw_transactions", v.raw_transactions, s);
	seria_kv("base_transaction_hash", v.base_transaction_hash, s);
	seria_kv("transaction_binary_sizes", v.transaction_binary_sizes, s);
}

void ser_members(api::cnd::GetArchive::Request &v, ISeria &s) {
	seria_kv("archive_id", v.archive_id, s);
	seria_kv("from_record", v.from_record, s);
	seria_kv("max_count", v.max_count, s);
	seria_kv("records_only", v.records_only, s);
}

void ser_members(api::cnd::GetArchive::Response &v, ISeria &s) {
	seria_kv("records", v.records, s);
	seria_kv("from_record", v.from_record, s);
	seria_kv("blocks", v.blocks, s);
	seria_kv("transactions", v.transactions, s);
	seria_kv("checkpoints", v.checkpoints, s);
}

void ser_members(api::walletd::GetTransaction::Request &v, ISeria &s) { seria_kv_strict("hash", v.hash, s); }

void ser_members(api::walletd::GetTransaction::Response &v, ISeria &s) { seria_kv("transaction", v.transaction, s); }

void ser_members(api::cnd::GetBlockTemplate::Request &v, ISeria &s) {
	seria_kv("reserve_size", v.reserve_size, s);
	seria_kv_strict("wallet_address", v.wallet_address, s);
	seria_kv("miner_secret", v.miner_secret, s);
	seria_kv("top_block_hash", v.top_block_hash, s);
	seria_kv("transaction_pool_version", v.transaction_pool_version, s);
}

void ser_members(api::cnd::GetBlockTemplate::Response &v, ISeria &s) {
	seria_kv("difficulty", v.difficulty, s);
	seria_kv("height", v.height, s);
	seria_kv("reserved_offset", v.reserved_offset, s);
	seria_kv("blocktemplate_blob", v.blocktemplate_blob, s);
	seria_kv("status", v.status, s);
	seria_kv("top_block_hash", v.top_block_hash, s);
	seria_kv("transaction_pool_version", v.transaction_pool_version, s);
	seria_kv("previous_block_hash", v.previous_block_hash, s);
	seria_kv("cm_prehash", v.cm_prehash, s);
	seria_kv("cm_path", v.cm_path, s);
}

void ser_members(api::cnd::GetCurrencyId::Response &v, ISeria &s) {
	seria_kv("currency_id_blob", v.currency_id_blob, s);
}

void ser_members(api::cnd::SubmitBlock::Request &v, ISeria &s) {
	seria_kv_strict("blocktemplate_blob", v.blocktemplate_blob, s);
	seria_kv("cm_nonce", v.cm_nonce, s);
	seria_kv("cm_merkle_branch", v.cm_merkle_branch, s);
}

void ser_members(api::cnd::SubmitBlock::Response &v, ISeria &s) { seria_kv("block_header", v.block_header, s); }

void ser_members(api::cnd::SubmitBlockLegacy::Response &v, ISeria &s) { seria_kv("status", v.status, s); }

void ser_members(api::cnd::GetLastBlockHeaderLegacy::Response &v, ISeria &s) {
	seria_kv("status", v.status, s);
	seria_kv("block_header", v.block_header, s);
}

void ser_members(api::cnd::GetBlockHeaderByHashLegacy::Request &v, ISeria &s) { seria_kv_strict("hash", v.hash, s); }

void ser_members(api::cnd::GetBlockHeaderByHeightLegacy::Request &v, ISeria &s) {
	seria_kv_strict("height", v.height, s);
}

}  // namespace seria
