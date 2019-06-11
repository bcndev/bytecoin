// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "CryptoNote.hpp"
#include "Core/CryptoNoteTools.hpp"
#include "Core/TransactionExtra.hpp"
#include "CryptoNoteConfig.hpp"  // We access TRANSACTION_VERSION_AMETHYST directly
#include "rpc_api.hpp"
#include "seria/JsonInputStream.hpp"
#include "seria/JsonOutputStream.hpp"

using namespace cn;

namespace seria {

bool ser(Hash &v, ISeria &s) { return s.binary(v.data, sizeof(v.data)); }
bool ser(KeyImage &v, ISeria &s) { return s.binary(v.data, sizeof(v.data)); }
bool ser(PublicKey &v, ISeria &s) { return s.binary(v.data, sizeof(v.data)); }
bool ser(SecretKey &v, ISeria &s) { return s.binary(v.data, sizeof(v.data)); }
bool ser(KeyDerivation &v, ISeria &s) { return s.binary(v.data, sizeof(v.data)); }
bool ser(Signature &v, ISeria &s) { return s.binary(reinterpret_cast<uint8_t *>(&v), sizeof(Signature)); }
bool ser(crypto::EllipticCurveScalar &v, ISeria &s) { return s.binary(v.data, sizeof(v.data)); }
bool ser(crypto::EllipticCurvePoint &v, ISeria &s) { return s.binary(v.data, sizeof(v.data)); }

void ser_members(cn::AccountAddressLegacy &v, ISeria &s) {
	seria_kv("spend", v.S, s);
	seria_kv("view", v.V, s);
}
void ser_members(cn::AccountAddressAmethyst &v, ISeria &s) {
	seria_kv("spend", v.S, s);
	seria_kv("spend_view", v.Sv, s);
}
void ser_members(cn::SendproofLegacy &v, ISeria &s) {
	Amount amount = 0;
	seria_kv("transaction_hash", v.transaction_hash, s);
	seria_kv("message", v.message, s);
	seria_kv("address", v.address, s);
	seria_kv("derivation", v.derivation, s);
	seria_kv("signature", v.signature, s);
	if (dynamic_cast<seria::JsonInputStream *>(&s))  // skip amount
		seria_kv("amount", amount, s);
}
void ser_members(cn::SendproofAmethyst::Element &v, ISeria &s) {
	seria_kv("output_index", v.out_index, s);
	seria_kv("output_seed", v.output_seed, s);
}
void ser_members(cn::SendproofAmethyst &v, ISeria &s) {
	uint8_t guard_byte = 0;
	seria_kv("guard_byte", guard_byte, s);
	if (s.is_input() && guard_byte != 0)  // forced binary incompatibility with transactions
		throw std::runtime_error("Sendproof disambiguition fails");
	seria_kv("version", v.version, s);
	seria_kv("transaction_hash", v.transaction_hash, s);
	if (v.version == 1) {
		seria_kv("address", v.address_simple, s);
		seria_kv("derivation", v.derivation, s);
		seria_kv("signature", v.signature, s);
	} else if (v.version == parameters::TRANSACTION_VERSION_AMETHYST) {
		seria_kv("elements", v.elements, s);
	} else
		throw std::runtime_error(
		    "Unknown version of amethyst sendproof, version = " + common::to_string(int(v.version)));
	seria_kv("message", v.message, s);
}

void ser_members(TransactionInput &v, ISeria &s) {
	if (s.is_input()) {
		uint8_t type = 0;
		s.object_key("type");
		if (dynamic_cast<seria::JsonInputStream *>(&s)) {
			std::string str_type_tag;
			ser(str_type_tag, s);
			if (str_type_tag == InputCoinbase::str_type_tag())
				type = InputCoinbase::type_tag;
			else if (str_type_tag == InputKey::str_type_tag())
				type = InputKey::type_tag;
			else
				throw std::runtime_error("Deserialization error - unknown input type " + str_type_tag);
		} else
			s.binary(&type, 1);
		switch (type) {
		case InputCoinbase::type_tag: {
			InputCoinbase in{};
			ser_members(in, s);
			v = in;
			break;
		}
		case InputKey::type_tag: {
			InputKey in{};
			ser_members(in, s);
			v = in;
			break;
		}
		default:
			throw std::runtime_error("Deserialization error - unknown input type " + common::to_string(type));
		}
		return;
	}
	if (v.type() == typeid(InputCoinbase)) {
		auto &in     = boost::get<InputCoinbase>(v);
		uint8_t type = InputCoinbase::type_tag;
		s.object_key("type");
		if (dynamic_cast<seria::JsonOutputStream *>(&s)) {
			std::string str_type_tag = InputCoinbase::str_type_tag();
			ser(str_type_tag, s);
		} else
			s.binary(&type, 1);
		ser_members(in, s);
	} else if (v.type() == typeid(InputKey)) {
		auto &in     = boost::get<InputKey>(v);
		uint8_t type = InputKey::type_tag;
		s.object_key("type");
		if (dynamic_cast<seria::JsonOutputStream *>(&s)) {
			std::string str_type_tag = InputKey::str_type_tag();
			ser(str_type_tag, s);
		} else
			s.binary(&type, 1);
		ser_members(in, s);
	}
}
void ser_members(TransactionOutput &v, ISeria &s, bool is_tx_amethyst) {
	if (s.is_input()) {
		Amount amount = 0;
		if (!is_tx_amethyst)
			seria_kv("amount", amount, s);
		uint8_t type = 0;
		s.object_key("type");
		if (dynamic_cast<seria::JsonInputStream *>(&s)) {
			std::string str_type_tag;
			ser(str_type_tag, s);
			if (str_type_tag == OutputKey::str_type_tag())
				type = OutputKey::type_tag;
			else
				throw std::runtime_error("Deserialization error - unknown output type " + str_type_tag);
		} else
			s.binary(&type, 1);
		switch (type) {
		case OutputKey::type_tag: {
			OutputKey out{};
			out.amount = amount;
			ser_members(out, s, is_tx_amethyst);
			v = out;
			break;
		}
		default:
			throw std::runtime_error("Deserialization error - unknown output type " + common::to_string(type));
		}
		return;
	}
	if (v.type() == typeid(OutputKey)) {
		auto &out = boost::get<OutputKey>(v);
		if (!is_tx_amethyst)
			seria_kv("amount", out.amount, s);
		s.object_key("type");
		if (dynamic_cast<seria::JsonOutputStream *>(&s)) {
			std::string str_type_tag = OutputKey::str_type_tag();
			ser(str_type_tag, s);
		} else {
			uint8_t type = OutputKey::type_tag;
			s.binary(&type, 1);
		}
		ser_members(out, s, is_tx_amethyst);
	}
}
void ser_members(InputCoinbase &v, ISeria &s) { seria_kv("height", v.height, s); }
void ser_members(InputKey &v, ISeria &s) {
	seria_kv("amount", v.amount, s);
	seria_kv("output_indexes", v.output_indexes, s);
	seria_kv("key_image", v.key_image, s);
}
void ser_members(cn::RingSignatures &v, ISeria &s) { seria_kv("signatures", v.signatures, s); }
void ser_members(cn::RingSignatureAmethyst &v, ISeria &s) {
	seria_kv("pp", v.pp, s);
	seria_kv("c0", v.c0, s);
	seria_kv("rr", v.rr, s);
	seria_kv("rs", v.rs, s);
	seria_kv("ra", v.ra, s);
}

// Serializing in the context of transaction - sizes and types are known from transaction prefix
void ser_members(cn::RingSignatureAmethyst &sigs, ISeria &s, const cn::TransactionPrefix &prefix) {
	size_t sig_size = prefix.inputs.size();
	if (s.is_input()) {
		sigs.pp.resize(sig_size);
		sigs.rr.resize(sig_size);
		sigs.rs.resize(sig_size);
		sigs.ra.resize(sig_size);
	}
	s.object_key("p");
	s.begin_array(sig_size, true);
	for (auto &sig : sigs.pp) {
		ser(sig, s);
	}
	s.end_array();
	s.object_key("c0");
	ser(sigs.c0, s);
	s.object_key("rr");
	s.begin_array(sig_size, true);
	for (size_t i = 0; i < sig_size; ++i) {
		invariant(prefix.inputs[i].type() == typeid(InputKey),
		    "Serialization error: input type wrong for transaction version");
		size_t signature_size = boost::get<InputKey>(prefix.inputs[i]).output_indexes.size();
		if (s.is_input()) {
			sigs.rr[i].resize(signature_size);
			s.begin_array(signature_size, true);
			for (crypto::EllipticCurveScalar &sig : sigs.rr[i]) {
				ser(sig, s);
			}
			s.end_array();
		} else {
			invariant(signature_size == sigs.rr[i].size(), "Serialization error: unexpected signatures size");
			s.begin_array(signature_size, true);
			for (crypto::EllipticCurveScalar &sig : sigs.rr[i]) {
				ser(sig, s);
			}
			s.end_array();
		}
	}
	s.end_array();
	s.object_key("rs");
	s.begin_array(sig_size, true);
	for (auto &sig : sigs.rs) {
		ser(sig, s);
	}
	s.end_array();
	s.object_key("ra");
	s.begin_array(sig_size, true);
	for (auto &sig : sigs.ra) {
		ser(sig, s);
	}
	s.end_array();
	s.end_object();
}

void ser_members(cn::TransactionSignatures &v, ISeria &s, const TransactionPrefix &prefix) {
	const bool is_base = (prefix.inputs.size() == 1) && (prefix.inputs[0].type() == typeid(InputCoinbase));
	if (is_base)
		return;  // No signatures in base transaction
	const bool is_tx_amethyst = (prefix.version >= parameters::TRANSACTION_VERSION_AMETHYST);

	s.object_key("signatures");
	if (is_tx_amethyst) {
		s.begin_object();
		if (s.is_input())
			v = RingSignatureAmethyst{};
		auto &sigs = boost::get<RingSignatureAmethyst>(v);
		ser_members(sigs, s, prefix);
	} else {
		size_t sig_size = prefix.inputs.size();
		s.begin_array(sig_size, true);
		if (s.is_input())
			v = RingSignatures{};
		auto &sigs = boost::get<RingSignatures>(v);
		if (s.is_input())
			sigs.signatures.resize(sig_size);
		for (size_t i = 0; i < sig_size; ++i) {
			invariant(prefix.inputs[i].type() == typeid(InputKey),
			    "Serialization error: input type wrong for transaction version");
			size_t signature_size = boost::get<InputKey>(prefix.inputs[i]).output_indexes.size();
			if (s.is_input()) {
				sigs.signatures[i].resize(signature_size);
				s.begin_array(signature_size, true);
				for (crypto::Signature &sig : sigs.signatures[i]) {
					ser(sig, s);
				}
				s.end_array();
			} else {
				invariant(
				    signature_size == sigs.signatures[i].size(), "Serialization error: unexpected signatures size");
				s.begin_array(signature_size, true);
				for (crypto::Signature &sig : sigs.signatures[i]) {
					ser(sig, s);
				}
				s.end_array();
			}
		}
		s.end_array();
	}
}

void ser_members(OutputKey &v, ISeria &s, bool is_tx_amethyst) {
	if (is_tx_amethyst)  // We moved amount inside variant part in amethyst
		seria_kv("amount", v.amount, s);
	seria_kv("public_key", v.public_key, s);
	if (is_tx_amethyst) {
		seria_kv("encrypted_secret", v.encrypted_secret, s);
		seria_kv_binary("encrypted_address_type", &v.encrypted_address_type, 1, s);
	}
}

void ser_members(TransactionPrefix &v, ISeria &s, bool is_root) {
	seria_kv("version", v.version, s);
	const bool is_tx_amethyst = (v.version == parameters::TRANSACTION_VERSION_AMETHYST);
	if (!is_root && v.version != 1 && !is_tx_amethyst)
		throw std::runtime_error("Unknown transaction version " + common::to_string(v.version));
	seria_kv("unlock_block_or_timestamp", v.unlock_block_or_timestamp, s);
	seria_kv("inputs", v.inputs, s);
	seria_kv("outputs", v.outputs, s, !is_root && is_tx_amethyst);
	seria_kv("extra", v.extra, s);
}
void ser_members(RootBaseTransaction &v, ISeria &s) {
	ser_members(static_cast<TransactionPrefix &>(v), s, true);
	if (v.version >= 2) {
		size_t ignored = 0;
		seria_kv("ignored", ignored, s);
	}
}

// static size_t get_signatures_count(const TransactionInput &input) {
//	struct txin_signature_size_visitor : public boost::static_visitor<size_t> {
//		size_t operator()(const InputCoinbase &) const { return 0; }
//		size_t operator()(const InputKey &txin) const { return txin.output_indexes.size(); }
//	};
//	return boost::apply_visitor(txin_signature_size_visitor(), input);
//}

void ser_members(Transaction &v, ISeria &s) {
	ser_members(static_cast<TransactionPrefix &>(v), s);
	ser_members(v.signatures, s, static_cast<TransactionPrefix &>(v));
}

void ser_members(RootBlock &v, ISeria &s, BlockSeriaType seria_type) {
	seria_kv("major_version", v.major_version, s);

	seria_kv("minor_version", v.minor_version, s);
	seria_kv("timestamp", v.timestamp, s);
	seria_kv("previous_block_hash", v.previous_block_hash, s);
	seria_kv_binary("nonce", v.nonce, 4, s);

	if (seria_type == BlockSeriaType::BLOCKHASH || seria_type == BlockSeriaType::LONG_BLOCKHASH) {
		Hash miner_tx_hash = get_root_block_base_transaction_hash(v.coinbase_transaction);
		Hash merkle_root   = crypto::tree_hash_from_branch(
            v.coinbase_transaction_branch.data(), v.coinbase_transaction_branch.size(), miner_tx_hash, nullptr);

		seria_kv("merkle_root", merkle_root, s);
	}
	seria_kv("transaction_count", v.transaction_count, s);
	if (v.transaction_count < 1)
		throw std::runtime_error("Wrong transactions number");

	if (seria_type == BlockSeriaType::LONG_BLOCKHASH)
		return;

	size_t branch_size = crypto_coinbase_tree_depth(v.transaction_count);
	if (s.is_input()) {
		v.coinbase_transaction_branch.resize(branch_size);
	} else {
		if (v.coinbase_transaction_branch.size() != branch_size)
			throw std::runtime_error("Wrong miner transaction branch size");
	}

	s.object_key("coinbase_transaction_branch");
	size_t btb_size = v.coinbase_transaction_branch.size();
	s.begin_array(btb_size, true);
	for (Hash &hash : v.coinbase_transaction_branch) {
		ser(hash, s);
	}
	s.end_array();

	seria_kv("coinbase_transaction", v.coinbase_transaction, s);

	extra::MergeMiningTag mm_tag;
	if (!extra::get_merge_mining_tag(v.coinbase_transaction.extra, mm_tag))
		throw std::runtime_error("Can't get extra merge mining tag");
	if (mm_tag.depth > 8 * sizeof(Hash))
		throw std::runtime_error("Wrong merge mining tag depth");

	if (s.is_input()) {
		v.blockchain_branch.resize(mm_tag.depth);
	} else {
		if (mm_tag.depth != v.blockchain_branch.size())
			throw std::runtime_error("Blockchain branch size must be equal to merge mining tag depth");
	}

	s.object_key("blockchain_branch");
	btb_size = v.blockchain_branch.size();
	s.begin_array(btb_size, true);
	for (Hash &hash : v.blockchain_branch) {
		ser(hash, s);
	}
	s.end_array();
}

void ser_members(crypto::CMBranchElement &v, ISeria &s) {
	seria_kv_binary("depth", &v.depth, 1, s);
	seria_kv("hash", v.hash, s);
}

void ser_members(BlockHeader &v,
    ISeria &s,
    BlockSeriaType seria_type,
    BlockBodyProxy body_proxy,
    const crypto::Hash &cm_path) {
	if (seria_type == BlockSeriaType::NORMAL) {
		seria_kv("major_version", v.major_version, s);
		seria_kv("minor_version", v.minor_version, s);
		if (v.major_version == 1) {
			seria_kv("timestamp", v.timestamp, s);
			seria_kv("previous_block_hash", v.previous_block_hash, s);
			v.nonce.resize(4);
			seria_kv_binary("nonce", v.nonce.data(), 4, s);
			return;
		}
		if (v.is_merge_mined()) {
			seria_kv("previous_block_hash", v.previous_block_hash, s);
			seria_kv("root_block", v.root_block, s);
			if (s.is_input()) {
				v.nonce.assign(std::begin(v.root_block.nonce), std::end(v.root_block.nonce));
				v.timestamp = v.root_block.timestamp;
			}
			return;
		}
#if bytecoin_ALLOW_CM
		if (v.is_cm_mined()) {
			seria_kv("timestamp", v.timestamp, s);
			seria_kv("previous_block_hash", v.previous_block_hash, s);
			seria_kv("nonce", v.nonce, s);
			seria_kv("cm_merkle_branch", v.cm_merkle_branch, s);
			return;
		}
#endif
		throw std::runtime_error("Unknown block major version " + common::to_string(v.major_version));
	}
	if (v.major_version == 1) {
		seria_kv("major_version", v.major_version, s);
		seria_kv("minor_version", v.minor_version, s);
		seria_kv("timestamp", v.timestamp, s);
		seria_kv("previous_block_hash", v.previous_block_hash, s);
		invariant(v.nonce.size() == 4, "");
		seria_kv_binary("nonce", v.nonce.data(), 4, s);
		seria_kv("body_proxy", body_proxy, s);
		return;
	}
	if (v.is_merge_mined()) {
		if (seria_type == BlockSeriaType::LONG_BLOCKHASH) {
			seria_kv("root_block", v.root_block, s, seria_type);
			return;
		}
		seria_kv("major_version", v.major_version, s);
		seria_kv("minor_version", v.minor_version, s);
		seria_kv("previous_block_hash", v.previous_block_hash, s);
		seria_kv("body_proxy", body_proxy, s);
		if (seria_type != BlockSeriaType::PREHASH) {  // BLOCKHASH
			seria_kv("root_block", v.root_block, s, seria_type);
		}
		return;
	}
#if bytecoin_ALLOW_CM
	if (v.is_cm_mined()) {
		if (seria_type == BlockSeriaType::LONG_BLOCKHASH) {
			Hash cm_merkle_root =
			    crypto::tree_hash_from_cm_branch(v.cm_merkle_branch, get_block_header_prehash(v, body_proxy), cm_path);
			// We should not allow adding merkle_root_hash twice to the pow_hashing_array, so more
			// flexible "pre_nonce" | root | "post_nonce" would be bad (allow mining of sidechains)
			// We select "nonce" to be first, because this would allow compatibility with some weird
			// ASICs which select algorithm based on block major version. Nonce could be made to contain
			// all required bytes and be of appropriate length (39+4+1 bytes for full binary compatibilty)
			seria_kv_binary("nonce", v.nonce.data(), v.nonce.size(), s);
			seria_kv("cm_merkle_root", cm_merkle_root, s);
			return;
		}
		// Any participating currency must have prehash taken from something with length != 65 bytes
		seria_kv("major_version", v.major_version, s);
		seria_kv("minor_version", v.minor_version, s);
		seria_kv("timestamp", v.timestamp, s);
		seria_kv("previous_block_hash", v.previous_block_hash, s);
		seria_kv("body_proxy", body_proxy, s);
		if (seria_type != BlockSeriaType::PREHASH) {  // BLOCKHASH
			seria_kv("nonce", v.nonce, s);
			seria_kv("cm_merkle_branch", v.cm_merkle_branch, s);
		}
		return;
	}
#endif
	throw std::runtime_error("Unknown block major version " + common::to_string(v.major_version));
}
void ser_members(BlockBodyProxy &v, ISeria &s) {
	seria_kv("transactions_merkle_root", v.transactions_merkle_root, s);
	seria_kv("transaction_count", v.transaction_count, s);
}
void ser_members(BlockTemplate &v, ISeria &s) {
	ser_members(static_cast<BlockHeader &>(v), s);
	seria_kv("coinbase_transaction", v.base_transaction, s);
	seria_kv("transaction_hashes", v.transaction_hashes, s);
}
void ser_members(RawBlock &v, ISeria &s) {
	seria_kv("block", v.block, s);
	seria_kv("txs", v.transactions, s);  // Name important for P2P kv-binary
}
void ser_members(Block &v, ISeria &s) {
	seria_kv("header", v.header, s);
	seria_kv("transactions", v.transactions, s);
}
void ser_members(HardCheckpoint &v, ISeria &s) {
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

Hash cn::get_transaction_inputs_hash(const TransactionPrefix &tx) {
	//	const bool is_tx_amethyst = (tx.version >= parameters::TRANSACTION_VERSION_AMETHYST);
	BinaryArray ba = seria::to_binary(tx.inputs);
	//	std::cout << "get_transaction_inputs_hash body=" << common::to_hex(ba) << std::endl;
	return crypto::cn_fast_hash(ba.data(), ba.size());
}

Hash cn::get_transaction_prefix_hash(const TransactionPrefix &tx) {
	BinaryArray ba = seria::to_binary(tx);
	//	std::cout << "get_transaction_prefix_hash body=" << common::to_hex(ba) << std::endl;
	return crypto::cn_fast_hash(ba.data(), ba.size());
}

Hash cn::get_transaction_hash(const Transaction &tx) {
	if (tx.version >= parameters::TRANSACTION_VERSION_AMETHYST) {
		std::pair<Hash, Hash> ha;
		ha.first                = get_transaction_prefix_hash(tx);
		BinaryArray binary_sigs = seria::to_binary(tx.signatures, static_cast<const TransactionPrefix &>(tx));
		ha.second               = crypto::cn_fast_hash(binary_sigs.data(), binary_sigs.size());
		BinaryArray ba          = seria::to_binary(ha);
		//		BinaryArray tx_body = seria::to_binary(static_cast<const TransactionPrefix&>(tx));
		//		common::append(tx_body, binary_sigs);
		//		invariant(tx_body == seria::to_binary(tx), "");
		return crypto::cn_fast_hash(ba.data(), ba.size());
	}
	BinaryArray ba = seria::to_binary(tx);
	return crypto::cn_fast_hash(ba.data(), ba.size());
}

Hash cn::get_block_hash(const BlockHeader &bh, const BlockBodyProxy &body_proxy) {
	// get_object_hash prepends array size before hashing.
	// this was a mistake of initial cryptonote developers
	Hash ha2 = get_object_hash(seria::to_binary(bh, BlockSeriaType::BLOCKHASH, body_proxy), nullptr);
	//	std::cout << "ha: " << ha2 << " ba: " << common::to_hex(seria::to_binary(bh, BlockSeriaType::BLOCKHASH,
	// body_proxy)) << std::endl;
	return ha2;
}

Hash cn::get_block_header_prehash(const BlockHeader &bh, const BlockBodyProxy &body_proxy) {
	// get_object_hash prepends array size before hashing.
	// this was a mistake of initial cryptonote developers
	Hash ha2 = get_object_hash(seria::to_binary(bh, BlockSeriaType::PREHASH, body_proxy), nullptr);
	//	std::cout << "ha: " << ha2 << " ba: " << common::to_hex(result.data(), result.size()) << std::endl;
	return ha2;
}

BinaryArray cn::get_block_pow_hashing_data(const BlockHeader &bh,
    const BlockBodyProxy &body_proxy,
    const Hash &genesis_block_hash) {
	common::BinaryArray result;
	common::VectorOutputStream stream(result);
	seria::BinaryOutputStream ba(stream);
	ba.begin_object();
	ser_members(const_cast<BlockHeader &>(bh), ba, BlockSeriaType::LONG_BLOCKHASH, body_proxy, genesis_block_hash);
	ba.end_object();
	return result;
}
