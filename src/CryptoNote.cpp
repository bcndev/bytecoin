// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "CryptoNote.hpp"
#include "Core/CryptoNoteTools.hpp"
#include "Core/TransactionExtra.hpp"
#include "rpc_api.hpp"
#include "seria/JsonOutputStream.hpp"
// includes below are for proof seria
#include "Core/Currency.hpp"
#include "common/Base58.hpp"
#include "common/Varint.hpp"

using namespace bytecoin;

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
void ser_members(SendProof &v, ISeria &s, const Currency &currency) {
	std::string addr;
	if (!s.is_input())
		addr = currency.account_address_as_string(v.address);
	seria_kv("address", addr, s);
	if (s.is_input() && (!currency.parse_account_address_string(addr, &v.address)))
		throw api::ErrorAddress(api::ErrorAddress::ADDRESS_FAILED_TO_PARSE, "Failed to parse wallet address", addr);
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
	seria_kv("amount", v.amount, s);
}
void ser_members(TransactionInput &v, ISeria &s) {
	if (s.is_input()) {
		uint8_t tag = 0;
		s.object_key("type");
		if (dynamic_cast<seria::JsonInputStream *>(&s)) {
			std::string str_tag;
			ser(str_tag, s);
			if (str_tag == "coinbase")
				tag = (uint8_t)SerializationTag2::Base;
			else if (str_tag == "key")
				tag = (uint8_t)SerializationTag2::Key;
		} else
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
		s.object_key("type");
		if (dynamic_cast<seria::JsonOutputStream *>(&s)) {
			std::string str_tag = "coinbase";
			ser(str_tag, s);
		} else
			s.binary(&tag, 1);
		ser_members(in, s);
	} else if (v.type() == typeid(KeyInput)) {
		KeyInput &in = boost::get<KeyInput>(v);
		uint8_t tag  = (uint8_t)SerializationTag2::Key;
		s.object_key("type");
		if (dynamic_cast<seria::JsonOutputStream *>(&s)) {
			std::string str_tag = "key";
			ser(str_tag, s);
		} else
			s.binary(&tag, 1);
		ser_members(in, s);
	}
}
void ser_members(TransactionOutputTarget &v, ISeria &s) {
	if (s.is_input()) {
		uint8_t tag = 0;
		s.object_key("type");
		if (dynamic_cast<seria::JsonInputStream *>(&s)) {
			std::string str_tag;
			ser(str_tag, s);
			if (str_tag == "key")
				tag = (uint8_t)SerializationTag2::Key;
		} else
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
		s.object_key("type");
		if (dynamic_cast<seria::JsonOutputStream *>(&s)) {
			std::string str_tag = "key";
			ser(str_tag, s);
		} else
			s.binary(&tag, 1);
		ser_members(in, s);
	}
}
void ser_members(TransactionOutput &v, ISeria &s) {
	seria_kv("amount", v.amount, s);
	ser_members(v.target, s);
	//	seria_kv("target", v.target, s);
}
void ser_members(CoinbaseInput &v, ISeria &s) { seria_kv("height", v.height, s); }
void ser_members(KeyInput &v, ISeria &s) {
	seria_kv("amount", v.amount, s);
	seria_kv("output_indexes", v.output_indexes, s);
	seria_kv("key_image", v.key_image, s);
}

void ser_members(KeyOutput &v, ISeria &s) { seria_kv("public_key", v.public_key, s); }

void ser_members(TransactionPrefix &v, ISeria &s) {
	seria_kv("version", v.version, s);
	seria_kv("unlock_block_or_timestamp", v.unlock_block_or_timestamp, s);
	seria_kv("inputs", v.inputs, s);
	seria_kv("outputs", v.outputs, s);
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

	bool is_base    = (v.inputs.size() == 1) && (v.inputs[0].type() == typeid(CoinbaseInput));
	size_t sig_size = is_base ? 0 : v.inputs.size();

	if (s.is_input())
		v.signatures.resize(sig_size);

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
				ser(sig, s);
			}
			s.end_array();
		} else {
			std::vector<crypto::Signature> signatures(signature_size);
			s.begin_array(signature_size, true);
			for (crypto::Signature &sig : signatures) {
				ser(sig, s);
			}
			s.end_array();
			v.signatures[i] = std::move(signatures);
		}
	}
	s.end_array();
}
void ser_members(ParentBlock &v, ISeria &s, BlockSeriaType seria_type) {
	seria_kv("major_version", v.major_version, s);

	seria_kv("minor_version", v.minor_version, s);
	seria_kv("timestamp", v.timestamp, s);
	seria_kv("previous_block_hash", v.previous_block_hash, s);
	unsigned char nonce_data[4];
	common::uint_le_to_bytes(nonce_data, 4, v.nonce);
	s.object_key("nonce");
	s.binary(nonce_data, 4);
	if (s.is_input())
		v.nonce = common::uint_le_from_bytes<uint32_t>(nonce_data, 4);

	if (seria_type == BlockSeriaType::BLOCKHASH || seria_type == BlockSeriaType::LONG_BLOCKHASH) {
		Hash miner_tx_hash = get_base_transaction_hash(v.base_transaction);
		Hash merkle_root   = crypto::tree_hash_from_branch(
		    v.base_transaction_branch.data(), v.base_transaction_branch.size(), miner_tx_hash, nullptr);

		seria_kv("merkle_root", merkle_root, s);
	}
	seria_kv("transaction_count", v.transaction_count, s);
	if (v.transaction_count < 1)
		throw std::runtime_error("Wrong transactions number");

	if (seria_type == BlockSeriaType::LONG_BLOCKHASH)
		return;

	size_t branch_size = crypto::coinbase_tree_depth(v.transaction_count);
	if (!s.is_input()) {
		if (v.base_transaction_branch.size() != branch_size)
			throw std::runtime_error("Wrong miner transaction branch size");
	} else {
		v.base_transaction_branch.resize(branch_size);
	}

	s.object_key("coinbase_transaction_branch");
	size_t btb_size = v.base_transaction_branch.size();
	s.begin_array(btb_size, true);
	for (Hash &hash : v.base_transaction_branch) {
		ser(hash, s);
	}
	s.end_array();

	seria_kv("coinbase_transaction", v.base_transaction, s);

	TransactionExtraMergeMiningTag mm_tag;
	if (!extra_get_merge_mining_tag(v.base_transaction.extra, mm_tag))
		throw std::runtime_error("Can't get extra merge mining tag");
	if (mm_tag.depth > 8 * sizeof(Hash))
		throw std::runtime_error("Wrong merge mining tag depth");

	if (!s.is_input()) {
		if (mm_tag.depth != v.blockchain_branch.size())
			throw std::runtime_error("Blockchain branch size must be equal to merge mining tag depth");
	} else {
		v.blockchain_branch.resize(mm_tag.depth);
	}

	s.object_key("blockchain_branch");
	btb_size = v.blockchain_branch.size();
	s.begin_array(btb_size, true);
	for (Hash &hash : v.blockchain_branch) {
		ser(hash, s);
	}
	s.end_array();
}
void ser_members(BlockHeader &v, ISeria &s, BlockSeriaType seria_type, BlockBodyProxy body_proxy) {
	if (v.major_version == 1 || seria_type != BlockSeriaType::LONG_BLOCKHASH) {
		seria_kv("major_version", v.major_version, s);
		seria_kv("minor_version", v.minor_version, s);
	}
#if bytecoin_ALLOW_CM
	if (v.major_version == 104) {  // CM, experimental
		seria_kv("timestamp", v.timestamp, s);
		seria_kv("previous_block_hash", v.previous_block_hash, s);
		unsigned char nonce_data[8];
		common::uint_le_to_bytes(nonce_data, 8, v.nonce);
		s.object_key("nonce");
		s.binary(nonce_data, 8);
		if (s.is_input())
			v.nonce = common::uint_le_from_bytes<uint64_t>(nonce_data, 4);
		if (seria_type != BlockSeriaType::NORMAL)
			seria_kv("body_proxy", body_proxy, s);
		if (seria_type != BlockSeriaType::PREHASH) {
			size_t length = v.cm_merkle_branch.size();
			seria_kv("cm_merkle_branch_length", length, s);
			std::vector<unsigned char> mask((length + 7) / 8);
			if (s.is_input()) {
				v.cm_merkle_branch.resize(length);
				s.object_key("cm_merkle_branch_mask");
				s.binary(mask.data(), mask.size());
				size_t non_zero_count = 0;
				for (size_t i = 0; i != length; ++i)
					if ((mask.at(i / 8) & (1 << (i % 8))) != 0)
						non_zero_count += 1;
				s.object_key("cm_merkle_branch");
				s.begin_array(non_zero_count, true);
				for (size_t i = 0; i != length; ++i) {
					if ((mask.at(i / 8) & (1 << (i % 8))) != 0)
						ser(v.cm_merkle_branch.at(i), s);
					else
						v.cm_merkle_branch.at(i) = Hash{};
				}
				s.end_array();
			} else {
				std::vector<Hash> non_zero_hashes;
				for (size_t i = 0; i != length; ++i)
					if (v.cm_merkle_branch.at(i) != Hash{}) {
						mask.at(i / 8) |= 1 << (i % 8);
						non_zero_hashes.push_back(v.cm_merkle_branch.at(i));
					}
				s.object_key("cm_merkle_branch_mask");
				s.binary(mask.data(), mask.size());
				s.object_key("cm_merkle_branch");
				size_t non_zero_count = non_zero_hashes.size();
				s.begin_array(non_zero_count, true);
				for (Hash &hash : non_zero_hashes) {
					ser(hash, s);
				}
				s.end_array();
			}
			//			seria_kv("cm_merkle_branch", v.cm_merkle_branch, s);
		}
		return;
	}
#endif
	if (v.major_version == 1) {
		seria_kv("timestamp", v.timestamp, s);
		seria_kv("previous_block_hash", v.previous_block_hash, s);
		unsigned char nonce_data[4];
		common::uint_le_to_bytes(nonce_data, 4, v.nonce);
		s.object_key("nonce");
		s.binary(nonce_data, 4);
		if (s.is_input())
			v.nonce = common::uint_le_from_bytes<uint64_t>(nonce_data, 4);
		if (seria_type != BlockSeriaType::NORMAL)
			seria_kv("body_proxy", body_proxy, s);
		return;
	}
	if (v.major_version == 2 || v.major_version == 3) {
		if (seria_type != BlockSeriaType::LONG_BLOCKHASH) {
			seria_kv("previous_block_hash", v.previous_block_hash, s);
			if (seria_type != BlockSeriaType::NORMAL)
				seria_kv("body_proxy", body_proxy, s);
		}
		//		auto parent_block_serializer = make_parent_block_serializer(v, false, false);
		if (seria_type != BlockSeriaType::PREHASH) {
			s.object_key("parent_block");
			s.begin_object();
			ser_members(v.parent_block, s, seria_type);
			s.end_object();
			if (s.is_input()) {
				v.nonce     = v.parent_block.nonce;
				v.timestamp = v.parent_block.timestamp;
			}
		}
		//		seria_kv("parent_block", parent_block_serializer, s);
		return;
	}
	throw std::runtime_error("Unknown block major version " + common::to_string(v.major_version));
}
void ser_members(BlockBodyProxy &v, ISeria &s) {
	seria_kv("transactions_merkle_root", v.transactions_merkle_root, s);
	seria_kv("transaction_count", v.transaction_count, s);
}
void ser_members(BlockTemplate &v, ISeria &s) {
	//	BlockBodyProxy body_proxy;
	//	if(seria_type != BlockSeriaType::NORMAL)
	//		body_proxy = get_body_proxy_from_template(v);
	ser_members(static_cast<BlockHeader &>(v), s);
	//	if(v.major_version == 104) { // CM, experimental
	//		seria_kv("transaction_hashes", v.transaction_hashes, s);
	//		return;
	//	}
	//	if(seria_type != BlockSeriaType::NORMAL)
	//		return;
	seria_kv("coinbase_transaction", v.base_transaction, s);
	seria_kv("transaction_hashes", v.transaction_hashes, s);
}
void ser_members(RawBlock &v, ISeria &s) {
	seria_kv("block", v.block, s);
	seria_kv("transactions", v.transactions, s);
}
void ser_members(Block &v, ISeria &s) {
	seria_kv("header", v.header, s);
	seria_kv("transactions", v.transactions, s);
}
void ser_members(SWCheckpoint &v, ISeria &s) {
	seria_kv("height", v.height, s);
	seria_kv("hash", v.hash, s);
}
void ser_members(Checkpoint &v, seria::ISeria &s) {
	seria_kv("height", v.height, s);
	seria_kv("hash", v.hash, s);
	seria_kv("key_id", v.key_id, s);
	seria_kv("counter", v.counter, s);
}
void ser_members(SignedCheckpoint &v, seria::ISeria &s) {
	ser_members(static_cast<Checkpoint &>(v), s);
	seria_kv("signature", v.signature, s);
}

}  // namespace seria
