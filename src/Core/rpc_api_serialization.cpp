// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "CryptoNoteTools.hpp"
#include "TransactionExtra.hpp"
#include "rpc_api.hpp"
#include "seria/JsonOutputStream.hpp"
// includes below are for proof seria
#include <boost/lexical_cast.hpp>
#include "Currency.hpp"
#include "common/Base58.hpp"

using namespace bytecoin;

Hash CheckPoint::get_message_hash() const { return get_object_hash(*this); }

namespace seria {
enum class SerializationTag2 : uint8_t { Base = 0xff, Key = 0x2 };

void ser(Hash &v, ISeria &s) { s.binary(v.data, sizeof(v.data)); }
void ser(KeyImage &v, ISeria &s) { s.binary(v.data, sizeof(v.data)); }
void ser(PublicKey &v, ISeria &s) { s.binary(v.data, sizeof(v.data)); }
void ser(SecretKey &v, ISeria &s) { s.binary(v.data, sizeof(v.data)); }
void ser(KeyDerivation &v, ISeria &s) { s.binary(v.data, sizeof(v.data)); }
void ser(Signature &v, ISeria &s) { s.binary(reinterpret_cast<uint8_t *>(&v), sizeof(Signature)); }
void ser_members(AccountPublicAddress &v, ISeria &s) {
	seria_kv("spend", v.spend_public_key, s);
	seria_kv("view", v.view_public_key, s);
}
void ser_members(bytecoin::SendProof &v, ISeria &s) {
	const uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 6;  // TODO - hard to get reference to our currency here
	std::string addr;
	if (!s.is_input())
		addr = Currency::get_account_address_as_str(CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX, v.address);
	seria_kv("address", addr, s);
	uint64_t prefix = 0;
	if (s.is_input() && (!Currency::parse_account_address_string(&prefix, &v.address, addr) ||
	                        prefix != CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX))
		throw std::runtime_error("Wrong address format - " + addr);
	std::string proof;
	BinaryArray binary_proof;
	if (!s.is_input()) {
		common::append(binary_proof, std::begin(v.derivation.data), std::end(v.derivation.data));
		common::append(binary_proof, std::begin(v.signature.c.data), std::end(v.signature.c.data));
		common::append(binary_proof, std::begin(v.signature.r.data), std::end(v.signature.r.data));
		proof = common::base58::encode(binary_proof);
	}
	seria_kv("proof", proof, s);
	if (s.is_input()) {
		if (!common::base58::decode(proof, &binary_proof) ||
		    binary_proof.size() != sizeof(v.derivation.data) + sizeof(v.signature.c) + sizeof(v.signature.r))
			throw std::runtime_error("Wrong proof format - " + proof);
		memmove(v.derivation.data, binary_proof.data(), sizeof(v.derivation));
		memmove(v.signature.c.data, binary_proof.data() + sizeof(v.derivation), sizeof(v.signature.c));
		memmove(v.signature.r.data,
		    binary_proof.data() + sizeof(v.derivation) + sizeof(v.signature.c),
		    sizeof(v.signature.r));
	}
	seria_kv("transaction_hash", v.transaction_hash, s);
	seria_kv("message", v.message, s);
	//	std::string dam = Currency::format_amount(DECIMAL_PLACES, v.amount);
	seria_kv("amount", v.amount, s);
	//	if (s.is_input() && !Currency::parse_amount(DECIMAL_PLACES, dam,
	// v.amount) )
	//		throw std::runtime_error("Wrong proof amount - " + dam);
}
void ser_members(TransactionInput &v, ISeria &s) {
	if (s.is_input()) {
		uint8_t tag = 0;
		s.object_key("tag");
		s.binary(&tag, 1);
		switch ((SerializationTag2)tag) {
		case SerializationTag2::Base: {
			CoinbaseInput in{};
			ser_members(in, s);
			v = in;
			break;
		}
		case SerializationTag2::Key: {
			KeyInput in{};
			ser_members(in, s);
			v = in;
			break;
		}
		default:
			throw std::runtime_error("Deserialization error - unknown input tag");
		}
		return;
	}
	if (v.type() == typeid(CoinbaseInput)) {
		CoinbaseInput &in = boost::get<CoinbaseInput>(v);
		uint8_t tag       = (uint8_t)SerializationTag2::Base;
		s.object_key("tag");
		s.binary(&tag, 1);
		ser_members(in, s);
	} else if (v.type() == typeid(KeyInput)) {
		KeyInput &in = boost::get<KeyInput>(v);
		uint8_t tag  = (uint8_t)SerializationTag2::Key;
		s.object_key("tag");
		s.binary(&tag, 1);
		ser_members(in, s);
	}
}
void ser_members(TransactionOutputTarget &v, ISeria &s) {
	if (s.is_input()) {
		uint8_t tag = 0;
		s.object_key("tag");
		s.binary(&tag, 1);
		switch ((SerializationTag2)tag) {
		case SerializationTag2::Key: {
			KeyOutput in{};
			ser_members(in, s);
			v = in;
			break;
		}
		default:
			throw std::runtime_error("Deserialization error - unknown output tag");
		}
		return;
	}
	if (v.type() == typeid(KeyOutput)) {
		KeyOutput &in = boost::get<KeyOutput>(v);
		uint8_t tag   = (uint8_t)SerializationTag2::Key;
		s.object_key("tag");
		s.binary(&tag, 1);
		ser_members(in, s);
	}
}
void ser_members(TransactionOutput &v, ISeria &s) {
	seria_kv("amount", v.amount, s);
	seria_kv("target", v.target, s);
}
void ser_members(CoinbaseInput &v, ISeria &s) { seria_kv("block_index", v.block_index, s); }
void ser_members(KeyInput &v, ISeria &s) {
	seria_kv("amount", v.amount, s);
	seria_kv("output_indexes", v.output_indexes, s);
	seria_kv("key_image", v.key_image, s);
}

void ser_members(KeyOutput &v, ISeria &s) { seria_kv("key", v.key, s); }

void ser_members(TransactionPrefix &v, ISeria &s) {
	seria_kv("version", v.version, s);
	seria_kv("unlock_time", v.unlock_time, s);
	seria_kv("vin", v.inputs, s);
	seria_kv("vout", v.outputs, s);
	seria_kv("extra", v.extra, s);
}
void ser_members(BaseTransaction &v, ISeria &s) {
	ser_members(static_cast<TransactionPrefix &>(v), s);
	if (v.version >= 2) {
		size_t ignored = 0;
		seria_kv("ignored", ignored, s);
	}
}

static size_t get_signatures_count(const TransactionInput &input) {
	struct txin_signature_size_visitor : public boost::static_visitor<size_t> {
		size_t operator()(const CoinbaseInput &) const { return 0; }
		size_t operator()(const KeyInput &txin) const { return txin.output_indexes.size(); }
	};
	return boost::apply_visitor(txin_signature_size_visitor(), input);
}

void ser_members(Transaction &v, ISeria &s) {
	ser_members(static_cast<TransactionPrefix &>(v), s);

	//        seria_kv("signatures", v.signatures, s);

	bool is_base    = (v.inputs.size() == 1) && (v.inputs[0].type() == typeid(CoinbaseInput));
	size_t sig_size = is_base ? 0 : v.inputs.size();

	// ignore base transaction
	if (s.is_input()) {
		v.signatures.resize(sig_size);
	}
	// const bool signatures_expected = !v.signatures.empty();
	if (sig_size && v.inputs.size() != v.signatures.size())
		throw std::runtime_error("Serialization error: unexpected signatures size");

	s.object_key("signatures");
	s.begin_array(sig_size, true);
	for (size_t i = 0; i < sig_size; ++i) {
		size_t signature_size = get_signatures_count(v.inputs[i]);
		if (!s.is_input()) {
			if (signature_size != v.signatures[i].size())
				throw std::runtime_error("Serialization error: unexpected signatures size");
			s.begin_array(signature_size, true);
			for (crypto::Signature &sig : v.signatures[i]) {
				s(sig);
			}
			s.end_array();
		} else {
			std::vector<crypto::Signature> signatures(signature_size);
			s.begin_array(signature_size, true);
			for (crypto::Signature &sig : signatures) {
				s(sig);
			}
			s.end_array();
			v.signatures[i] = std::move(signatures);
		}
	}
	s.end_array();
}
void ser_members(ParentBlock &v, ISeria &s) {
	seria_kv("major_version", v.major_version, s);
	seria_kv("minor_version", v.minor_version, s);
	seria_kv("previous_block_hash", v.previous_block_hash, s);
	seria_kv("transaction_count", v.transaction_count, s);
	seria_kv("base_transaction_branch", v.base_transaction_branch, s);
	seria_kv("base_transaction", v.base_transaction, s);
	seria_kv("blockchain_branch", v.blockchain_branch, s);
}
void ser_members(BlockTemplate &v, ISeria &s) {
	ser_members(static_cast<BlockHeader &>(v), s);
	if (v.major_version >= 2) {
		auto parent_block_serializer = make_parent_block_serializer(v, false, false);
		seria_kv("parent_block", parent_block_serializer, s);
	}
	seria_kv("miner_tx", v.base_transaction, s);
	seria_kv("tx_hashes", v.transaction_hashes, s);
}
void ser_members(BlockHeader &v, ISeria &s) {
	seria_kv("major_version", v.major_version, s);
	seria_kv("minor_version", v.minor_version, s);
	if (v.major_version == 1) {
		seria_kv("timestamp", v.timestamp, s);
		seria_kv("previous_block_hash", v.previous_block_hash, s);
		s.object_key("nonce");
		s.binary(&v.nonce, sizeof(v.nonce));  // TODO - endianess
	} else if (v.major_version >= 2) {
		seria_kv("previous_block_hash", v.previous_block_hash, s);
	} else
		throw std::runtime_error("Wrong major version");
}
void ser_members(RawBlock &v, ISeria &s) {
	seria_kv("block", v.block, s);
	seria_kv("transactions", v.transactions, s);
}
void ser_members(Block &v, ISeria &s) {
	seria_kv("header", v.header, s);
	seria_kv("transactions", v.transactions, s);
}
void ser_members(CheckPoint &v, seria::ISeria &s) {
	seria_kv("height", v.height, s);
	seria_kv("hash", v.hash, s);
	seria_kv("key_id", v.key_id, s);
	seria_kv("counter", v.counter, s);
}
void ser_members(SignedCheckPoint &v, seria::ISeria &s) {
	ser_members(static_cast<CheckPoint &>(v), s);
	seria_kv("signature", v.signature, s);
}
void ser_members(api::Output &v, ISeria &s) {
	seria_kv("public_key", v.public_key, s);
	seria_kv("global_index", v.global_index, s);
	seria_kv("amount", v.amount, s);
	seria_kv("unlock_time", v.unlock_time, s);
	seria_kv("index_in_transaction", v.index_in_transaction, s);
	seria_kv("height", v.height, s);
	seria_kv("key_image", v.key_image, s);
	seria_kv("transaction_public_key", v.transaction_public_key, s);
	seria_kv("address", v.address, s);
	seria_kv("dust", v.dust, s);
}
void ser_members(api::BlockHeader &v, ISeria &s) {
	seria_kv("major_version", v.major_version, s);
	seria_kv("minor_version", v.minor_version, s);
	seria_kv("timestamp", v.timestamp, s);
	seria_kv("previous_block_hash", v.previous_block_hash, s);
	if (dynamic_cast<seria::JsonOutputStream *>(&s))
		seria_kv("prev_hash", v.previous_block_hash, s);
	seria_kv("nonce", v.nonce, s);

	// 	s(depth, "depth"); - Used by legacy methods, hope no one uses it
	//  s(orphan_status, "orphan_status"); - Used by legacy methods, hope no one uses it
	seria_kv("height", v.height, s);
	seria_kv("hash", v.hash, s);
	seria_kv("reward", v.reward, s);
	seria_kv("cumulative_difficulty", v.cumulative_difficulty.lo, s);
	seria_kv("cumulative_difficulty_hi", v.cumulative_difficulty.hi, s, true);
	seria_kv("difficulty", v.difficulty, s);
	seria_kv("base_reward", v.base_reward, s);
	seria_kv("block_size", v.block_size, s);
	seria_kv("transactions_cumulative_size", v.transactions_cumulative_size, s);
	seria_kv("already_generated_coins", v.already_generated_coins, s);
	seria_kv("already_generated_transactions", v.already_generated_transactions, s);
	seria_kv("size_median", v.size_median, s);
	seria_kv("effective_size_median", v.effective_size_median, s);
	seria_kv("timestamp_median", v.timestamp_median, s);
	seria_kv("total_fee_amount", v.total_fee_amount, s);
}
void ser_members(api::Transfer &v, ISeria &s) {
	seria_kv("address", v.address, s);
	seria_kv("amount", v.amount, s);
	seria_kv("ours", v.ours, s);
	seria_kv("locked", v.locked, s);
	seria_kv("outputs", v.outputs, s);
}
void ser_members(api::Transaction &v, ISeria &s) {
	seria_kv("unlock_time", v.unlock_time, s);
	seria_kv("amount", v.amount, s);
	seria_kv("fee", v.fee, s);
	seria_kv("public_key", v.public_key, s);
	seria_kv("transfers", v.transfers, s);
	seria_kv("payment_id", v.payment_id, s);
	seria_kv("anonymity", v.anonymity, s);
	seria_kv("extra", v.extra, s);
	seria_kv("hash", v.hash, s);
	seria_kv("coinbase", v.coinbase, s);
	seria_kv("block_height", v.block_height, s);
	seria_kv("block_hash", v.block_hash, s);
	seria_kv("timestamp", v.timestamp, s);
	seria_kv("binary_size", v.binary_size, s);
}
void ser_members(api::Block &v, ISeria &s) {
	seria_kv("header", v.header, s);
	seria_kv("transactions", v.transactions, s);
}
void ser_members(api::Balance &v, ISeria &s) {
	seria_kv("spendable", v.spendable.lo, s);
	seria_kv("spendable_hi", v.spendable.hi, s, true);

	seria_kv("spendable_dust", v.spendable_dust.lo, s);
	seria_kv("spendable_dust_hi", v.spendable_dust.hi, s, true);

	seria_kv("locked_or_unconfirmed", v.locked_or_unconfirmed.lo, s);
	seria_kv("locked_or_unconfirmed_hi", v.locked_or_unconfirmed.hi, s, true);

	seria_kv("spendable_outputs", v.spendable_outputs, s);
	seria_kv("spendable_dust_outputs", v.spendable_dust_outputs, s);
	seria_kv("locked_or_unconfirmed_outputs", v.locked_or_unconfirmed_outputs, s);
}
void ser_members(api::EmptyStruct &, ISeria &) {}

void ser_members(api::walletd::GetAddresses::Response &v, ISeria &s) {
	seria_kv("addresses", v.addresses, s);
	seria_kv("view_only", v.view_only, s);
}
void ser_members(api::walletd::GetViewKeyPair::Response &v, ISeria &s) {
	seria_kv("secret_view_key", v.secret_view_key, s);
	seria_kv("public_view_key", v.public_view_key, s);
}
void ser_members(bytecoin::api::walletd::CreateAddresses::Request &v, ISeria &s) {
	seria_kv("secret_spend_keys", v.secret_spend_keys, s);
	seria_kv("creation_timestamp", v.creation_timestamp, s);
}
void ser_members(bytecoin::api::walletd::CreateAddresses::Response &v, ISeria &s) {
	seria_kv("addresses", v.addresses, s);
	seria_kv("secret_spend_keys", v.secret_spend_keys, s);
}
void ser_members(bytecoin::api::walletd::GetBalance::Request &v, ISeria &s) {
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
	seria_kv("desired_transactions_count", v.desired_transactions_count, s);
	seria_kv("forward", v.forward, s);
}
void ser_members(api::walletd::GetTransfers::Response &v, ISeria &s) {
	seria_kv("blocks", v.blocks, s);
	seria_kv("unlocked_transfers", v.unlocked_transfers, s);
	seria_kv("next_from_height", v.next_from_height, s);
	seria_kv("next_to_height", v.next_to_height, s);
}
void ser_members(api::walletd::CreateTransaction::Request &v, ISeria &s) {
	seria_kv("transaction", v.transaction, s);
	seria_kv("spend_addresses", v.spend_addresses, s);
	seria_kv("any_spend_address", v.any_spend_address, s);
	seria_kv("change_address", v.change_address, s);
	seria_kv("confirmed_height_or_depth", v.confirmed_height_or_depth, s);
	seria_kv("fee_per_byte", v.fee_per_byte, s);
	seria_kv("optimization", v.optimization, s);
	seria_kv("save_history", v.save_history, s);
	seria_kv("prevent_conflict_with_transactions", v.prevent_conflict_with_transactions, s);
}
void ser_members(api::walletd::CreateTransaction::Response &v, ISeria &s) {
	seria_kv("transaction", v.transaction, s);
	seria_kv("binary_transaction", v.binary_transaction, s);
	seria_kv("save_history_error", v.save_history_error, s);
	seria_kv("transactions_required", v.transactions_required, s);
}
void ser_members(api::walletd::CreateSendProof::Request &v, ISeria &s) {
	seria_kv("transaction_hash", v.transaction_hash, s);
	seria_kv("message", v.message, s);
	seria_kv("addresses", v.addresses, s);
}
void ser_members(api::walletd::CreateSendProof::Response &v, ISeria &s) { seria_kv("sendproofs", v.sendproofs, s); }

void ser_members(api::bytecoind::GetStatus::Request &v, ISeria &s) {
	seria_kv("top_block_hash", v.top_block_hash, s);
	seria_kv("transaction_pool_version", v.transaction_pool_version, s);
	seria_kv("outgoing_peer_count", v.outgoing_peer_count, s);
	seria_kv("incoming_peer_count", v.incoming_peer_count, s);
	seria_kv("lower_level_error", v.lower_level_error, s);
}
void ser_members(api::bytecoind::GetStatus::Response &v, ISeria &s) {
	ser_members(static_cast<api::bytecoind::GetStatus::Request &>(v), s);
	seria_kv("top_block_height", v.top_block_height, s);
	seria_kv("top_block_difficulty", v.top_block_difficulty, s);
	seria_kv("top_block_cumulative_difficulty", v.top_block_cumulative_difficulty.lo, s);
	seria_kv("top_block_cumulative_difficulty_hi", v.top_block_cumulative_difficulty.hi, s, true);
	seria_kv("top_block_timestamp", v.top_block_timestamp, s);
	seria_kv("top_block_timestamp_median", v.top_block_timestamp_median, s);
	seria_kv("recommended_fee_per_byte", v.recommended_fee_per_byte, s);
	seria_kv("next_block_effective_median_size", v.next_block_effective_median_size, s);
	seria_kv("top_known_block_height", v.top_known_block_height, s);
}
void ser_members(api::bytecoind::SyncBlocks::Request &v, ISeria &s) {
	seria_kv("sparse_chain", v.sparse_chain, s);
	seria_kv("first_block_timestamp", v.first_block_timestamp, s);
	seria_kv("max_count", v.max_count, s);
	//	seria_kv("send_signatures", v.send_signatures, s);
}
void ser_members(bytecoin::api::bytecoind::SyncBlocks::SyncBlock &v, ISeria &s) {
	seria_kv("header", v.header, s);
	seria_kv("raw_header", v.raw_header, s);
	seria_kv("raw_transactions", v.raw_transactions, s);
	seria_kv("base_transaction_hash", v.base_transaction_hash, s);
	seria_kv("global_indices", v.global_indices, s);
	seria_kv("transaction_binary_sizes", v.transaction_binary_sizes, s);
}
void ser_members(api::bytecoind::SyncBlocks::Response &v, ISeria &s) {
	seria_kv("blocks", v.blocks, s);
	seria_kv("start_height", v.start_height, s);
	seria_kv("status", v.status, s);
}
void ser_members(api::bytecoind::GetRawTransaction::Request &v, ISeria &s) { seria_kv("hash", v.hash, s); }
void ser_members(api::bytecoind::GetRawTransaction::Response &v, ISeria &s) {
	seria_kv("transaction", v.transaction, s);
	seria_kv("raw_transaction", v.raw_transaction, s);
}

void ser_members(api::bytecoind::SyncMemPool::Request &v, ISeria &s) {
	if (!s.is_input())
		std::sort(v.known_hashes.begin(), v.known_hashes.end());
	seria_kv("known_hashes", v.known_hashes, s);
	if (s.is_input() && !std::is_sorted(v.known_hashes.begin(), v.known_hashes.end()))
		throw std::runtime_error("SyncMemPool::Request known_hashes must be sorted");
}
void ser_members(api::bytecoind::SyncMemPool::Response &v, ISeria &s) {
	seria_kv("removed_hashes", v.removed_hashes, s);
	seria_kv("added_raw_transactions", v.added_raw_transactions, s);
	seria_kv("added_transactions", v.added_transactions, s);
	seria_kv("status", v.status, s);
}
void ser_members(api::bytecoind::GetRandomOutputs::Request &v, ISeria &s) {
	seria_kv("amounts", v.amounts, s);
	seria_kv("outs_count", v.outs_count, s);
	seria_kv("confirmed_height_or_depth", v.confirmed_height_or_depth, s);
}
void ser_members(api::bytecoind::GetRandomOutputs::Response &v, ISeria &s) { seria_kv("outputs", v.outputs, s); }
void ser_members(api::bytecoind::SendTransaction::Request &v, ISeria &s) {
	seria_kv("binary_transaction", v.binary_transaction, s);
}
void ser_members(api::bytecoind::SendTransaction::Response &v, ISeria &s) { seria_kv("send_result", v.send_result, s); }
void ser_members(bytecoin::api::bytecoind::SendTransaction::Error &v, ISeria &s) {
	ser_members(static_cast<json_rpc::Error &>(v), s);
	seria_kv("conflict_height", v.conflict_height, s);
}
void ser_members(bytecoin::api::bytecoind::CheckSendProof::Request &v, ISeria &s) {
	seria_kv("sendproof", v.sendproof, s);
}
void ser_members(bytecoin::api::bytecoind::GetStatistics::Response &v, ISeria &s) {
	seria_kv("version", v.version, s);
	seria_kv("platform", v.platform, s);
	seria_kv("peer_id", v.peer_id, s);
	seria_kv("start_time", v.start_time, s);
	seria_kv("checkpoints", v.checkpoints, s);
}
void ser_members(bytecoin::api::bytecoind::GetArchive::ArchiveRecord &v, ISeria &s) {
	seria_kv("timestamp", v.timestamp, s);
	seria_kv("timestamp_usec", v.timestamp_usec, s);
	seria_kv("type", v.type, s);
	seria_kv("hash", v.hash, s);
	seria_kv("source_address", v.source_address, s);
}
void ser_members(bytecoin::api::bytecoind::GetArchive::ArchiveBlock &v, ISeria &s) {
	seria_kv("raw_header", v.raw_header, s);
	seria_kv("raw_transactions", v.raw_transactions, s);
	seria_kv("base_transaction_hash", v.base_transaction_hash, s);
	seria_kv("transaction_binary_sizes", v.transaction_binary_sizes, s);
}
void ser_members(bytecoin::api::bytecoind::GetArchive::Error &v, ISeria &s) {
	ser_members(static_cast<json_rpc::Error &>(v), s);
	seria_kv("archive_id", v.archive_id, s);
}
void ser_members(bytecoin::api::bytecoind::GetArchive::Request &v, ISeria &s) {
	seria_kv("archive_id", v.archive_id, s);
	seria_kv("from_record", v.from_record, s);
	seria_kv("max_count", v.max_count, s);
}
void ser_members(bytecoin::api::bytecoind::GetArchive::Response &v, ISeria &s) {
	seria_kv("records", v.records, s);
	seria_kv("from_record", v.from_record, s);
	seria_kv("blocks", v.blocks, s);
	seria_kv("transactions", v.transactions, s);
	seria_kv("checkpoints", v.checkpoints, s);
}

void ser_members(bytecoin::api::walletd::GetTransaction::Request &v, ISeria &s) { seria_kv("hash", v.hash, s); }
void ser_members(bytecoin::api::walletd::GetTransaction::Response &v, ISeria &s) {
	seria_kv("transaction", v.transaction, s);
}

void ser_members(bytecoin::api::bytecoind::GetBlockTemplate::Request &v, ISeria &s) {
	seria_kv("reserve_size", v.reserve_size, s);
	seria_kv("wallet_address", v.wallet_address, s);
	seria_kv("top_block_hash", v.top_block_hash, s);
	seria_kv("transaction_pool_version", v.transaction_pool_version, s);
}
void ser_members(bytecoin::api::bytecoind::GetBlockTemplate::Response &v, ISeria &s) {
	seria_kv("difficulty", v.difficulty, s);
	seria_kv("height", v.height, s);
	seria_kv("reserved_offset", v.reserved_offset, s);
	seria_kv("blocktemplate_blob", v.blocktemplate_blob, s);
	seria_kv("status", v.status, s);
	seria_kv("top_block_hash", v.top_block_hash, s);
	seria_kv("transaction_pool_version", v.transaction_pool_version, s);
}
void ser_members(bytecoin::api::bytecoind::GetCurrencyId::Response &v, ISeria &s) {
	seria_kv("currency_id_blob", v.currency_id_blob, s);
}
void ser_members(bytecoin::api::bytecoind::SubmitBlock::Response &v, ISeria &s) { seria_kv("status", v.status, s); }
void ser_members(bytecoin::api::bytecoind::SubmitBlock::Request &v, ISeria &s) {
	seria_kv("blocktemplate_blob", v.blocktemplate_blob, s);
}
void ser_members(bytecoin::api::bytecoind::BlockHeaderLegacy &v, ISeria &s) {
	ser_members(static_cast<bytecoin::api::BlockHeader &>(v), s);
	seria_kv("depth", v.depth, s);
	seria_kv("orphan_status", v.orphan_status, s);
}
void ser_members(bytecoin::api::bytecoind::GetLastBlockHeaderLegacy::Response &v, ISeria &s) {
	seria_kv("status", v.status, s);
	seria_kv("block_header", v.block_header, s);
}
void ser_members(bytecoin::api::bytecoind::GetBlockHeaderByHashLegacy::Request &v, ISeria &s) {
	seria_kv("hash", v.hash, s);
}
void ser_members(bytecoin::api::bytecoind::GetBlockHeaderByHeightLegacy::Request &v, ISeria &s) {
	seria_kv("height", v.height, s);
}

}  // namespace seria
