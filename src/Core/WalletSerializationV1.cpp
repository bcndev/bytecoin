// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#include <crypto/crypto.hpp>
#include "WalletSerializationV1.h"
#include "common/MemoryStreams.hpp"
#include "CryptoNoteTools.hpp"
#include "seria/BinaryInputStream.hpp"

using namespace common;
using namespace crypto;

namespace {

//const uint64_t ACCOUNT_CREATE_TIME_ACCURACY = 60 * 60 * 24;

// DO NOT CHANGE IT
struct WalletRecordDto {
	PublicKey spend_public_key{};
	SecretKey spend_secret_key{};
	uint64_t pending_balance    = 0;
	uint64_t actual_balance     = 0;
	uint64_t creation_timestamp = 0;
};

// DO NOT CHANGE IT
struct ObsoleteSpentOutputDto {
	uint64_t amount;
	Hash transaction_hash;
	uint32_t output_in_transaction;
	uint64_t wallet_index;
	crypto::Hash spending_transaction_hash;
};

// DO NOT CHANGE IT
struct ObsoleteChangeDto {
	Hash tx_hash;
	uint64_t amount;
};

// DO NOT CHANGE IT
struct UnlockTransactionJobDto {
	uint32_t block_height;
	Hash transaction_hash;
	uint64_t wallet_index;
};

// DO NOT CHANGE IT
/*struct WalletTransactionDto {
	WalletTransactionDto() {}

	WalletTransactionDto(const bytecoin::WalletTransaction &wallet) {
		state         = wallet.state;
		timestamp     = wallet.timestamp;
		block_height  = wallet.block_height;
		hash          = wallet.hash;
		total_amount  = wallet.total_amount;
		fee           = wallet.fee;
		creation_time = wallet.creation_time;
		unlock_time   = wallet.unlock_time;
		extra         = wallet.extra;
	}

	bytecoin::WalletTransactionState state;
	uint64_t timestamp;
	uint32_t block_height;
	Hash hash;
	int64_t total_amount;
	uint64_t fee;
	uint64_t creation_time;
	uint64_t unlock_time;
	std::string extra;
};

// DO NOT CHANGE IT
struct WalletTransferDto {
	explicit WalletTransferDto(uint32_t version) : amount(0), type(0), version(version) {}
	WalletTransferDto(const bytecoin::WalletTransfer &tr, uint32_t version) : WalletTransferDto(version) {
		address = tr.address;
		amount  = tr.amount;
		type    = static_cast<uint8_t>(tr.type);
	}

	std::string address;
	uint64_t amount;
	uint8_t type;

	uint32_t version;
};*/

/*void serialize(WalletRecordDto &v, bytecoin::ISerializer &s) {
	s(v.spend_public_key, "spend_public_key");
	s(v.spend_secret_key, "spend_secret_key");
	s(v.pending_balance, "pending_balance");
	s(v.actual_balance, "actual_balance");
	s(v.creation_timestamp, "creation_timestamp");
}*/
// This is DTO structure. Do not change it.
struct KeysStorage {
	uint64_t creation_timestamp;

	crypto::PublicKey spend_public_key;
	crypto::SecretKey spend_secret_key;

	crypto::PublicKey view_public_key;
	crypto::SecretKey view_secret_key;

/*	void serialize(bytecoin::ISerializer & s, const std::string &name) {
		s.beginObject(name);

		s(creation_timestamp, "creation_timestamp");

		s(spend_public_key, "spend_public_key");
		s(spend_secret_key, "spend_secret_key");

		s(view_public_key, "view_public_key");
		s(view_secret_key, "view_secret_key");

		s.endObject();
	}*/
};

/*void serialize(ObsoleteSpentOutputDto &v, bytecoin::ISerializer &s) {
	s(v.amount, "amount");
	s(v.transaction_hash, "transaction_hash");
	s(v.output_in_transaction, "output_in_transaction");
	s(v.wallet_index, "wallet_index");
	s(v.spending_transaction_hash, "spending_transaction_hash");
}

void serialize(ObsoleteChangeDto &v, bytecoin::ISerializer &s) {
	s(v.tx_hash, "transaction_hash");
	s(v.amount, "amount");
}

void serialize(UnlockTransactionJobDto &v, bytecoin::ISerializer &s) {
	s(v.block_height, "block_height");
	s(v.transaction_hash, "transaction_hash");
	s(v.wallet_index, "wallet_index");
}

void serialize(WalletTransactionDto &v, bytecoin::ISerializer &s) {
	typedef std::underlying_type<bytecoin::WalletTransactionState>::type StateType;

	StateType state = static_cast<StateType>(v.state);
	s(state, "state");
	v.state = static_cast<bytecoin::WalletTransactionState>(state);

	s(v.timestamp, "timestamp");
	bytecoin::serializeBlockHeight(s, v.block_height, "block_height");
	s(v.hash, "hash");
	s(v.total_amount, "total_amount");
	s(v.fee, "fee");
	s(v.creation_time, "creation_time");
	s(v.unlock_time, "unlock_time");
	s(v.extra, "extra");
}

void serialize(WalletTransferDto &v, bytecoin::ISerializer &s) {
	s(v.address, "address");
	s(v.amount, "amount");

	if (v.version > 2) {
		s(v.type, "type");
	}
}*/

std::string readCipher(common::IInputStream &source, const std::string &name) {
	std::string cipher;
//	bytecoin::BinaryInputStreamSerializer s(source);
	seria::BinaryInputStream s(source);
	s(cipher); // , name

	return cipher;
}

std::string decrypt(const std::string &cipher, bytecoin::WalletSerializerV1::CryptoContext &crypto_ctx) {
	std::string plain;
	plain.resize(cipher.size());

	crypto::chacha8(cipher.data(), cipher.size(), crypto_ctx.key, crypto_ctx.iv, &plain[0]);
	return plain;
}

template<typename Object>
void deserialize(Object &obj, const std::string &name, const std::string &plain) {
	MemoryInputStream stream(plain.data(), plain.size());
	seria::BinaryInputStream s(stream);
//	bytecoin::BinaryInputStreamSerializer s(stream);
	s(obj); // , common::StringView(name)
}

template<typename Object>
void deserializeEncrypted(Object &obj,
                          const std::string &name,
                          bytecoin::WalletSerializerV1::CryptoContext &crypto_ctx,
                          common::IInputStream &source) {
	std::string cipher = readCipher(source, name);
	std::string plain  = decrypt(cipher, crypto_ctx);

	deserialize(obj, name, plain);
}

/*bytecoin::WalletTransaction convert(const bytecoin::WalletLegacyTransaction &tx) {
	bytecoin::WalletTransaction mtx;

	mtx.state         = bytecoin::WalletTransactionState::SUCCEEDED;
	mtx.timestamp     = tx.timestamp;
	mtx.block_height  = tx.block_height;
	mtx.hash          = tx.hash;
	mtx.total_amount  = tx.total_amount;
	mtx.fee           = tx.fee;
	mtx.creation_time = tx.sent_time;
	mtx.unlock_time   = tx.unlock_time;
	mtx.extra         = tx.extra;
	mtx.coinbase       = tx.is_coinbase;

	return mtx;
}*/

/*bytecoin::WalletTransfer convert(const bytecoin::WalletLegacyTransfer &tr) {
	bytecoin::WalletTransfer mtr;

	mtr.address = tr.address;
	mtr.amount  = tr.amount;

	return mtr;
}*/

}  // anonymous namespace

namespace seria {
	void ser(crypto::chacha8_iv &v, ISeria &s) {
		s.binary(v.data, sizeof(v.data));
	}
	void serMembers(WalletRecordDto &v, ISeria &s){
		seria_kv("spend_public_key", v.spend_public_key, s);
		seria_kv("spend_secret_key", v.spend_secret_key, s);
		seria_kv("pending_balance", v.pending_balance, s);
		seria_kv("actual_balance", v.actual_balance, s);
		seria_kv("creation_timestamp", v.creation_timestamp, s);
	}
	void serMembers(KeysStorage &v, ISeria &s){
		seria_kv("creation_timestamp", v.creation_timestamp, s);
		seria_kv("spend_public_key", v.spend_public_key, s);
		seria_kv("spend_secret_key", v.spend_secret_key, s);
		seria_kv("view_public_key", v.view_public_key, s);
		seria_kv("view_secret_key", v.view_secret_key, s);
	}
}

namespace bytecoin {

const uint32_t WalletSerializerV1::SERIALIZATION_VERSION = 5;

void WalletSerializerV1::CryptoContext::incIv() {
	uint64_t *i = reinterpret_cast<uint64_t *>(&iv.data[0]);
	*i          = (*i == std::numeric_limits<uint64_t>::max()) ? 0 : (*i + 1);
}

WalletSerializerV1::WalletSerializerV1(
    //  ITransfersObserver& transfersObserver,
    crypto::PublicKey &view_public_key,
    crypto::SecretKey &view_secret_key,
//    uint64_t &actual_balance,
//    uint64_t &pending_palance,
    std::vector<WalletRecord> &wallets_container
    //  TransfersSyncronizer& synchronizer,
    //  UnlockTransactionJobs& unlockTransactions,
    //  WalletTransactions& transactions,
    //  WalletTransfers& transfers,
    //  UncommitedTransactions& uncommitedTransactions,
    //  uint32_t transactionSoftLockTime
    )
    :  //  m_transfersObserver(transfersObserver),
    m_view_public_key(view_public_key)
    , m_view_secret_key(view_secret_key)
//    , m_actual_balance(actual_balance)
//    , m_pending_balance(pending_palance)
    , m_wallets_container(wallets_container)
//  m_synchronizer(synchronizer),
//  m_unlockTransactions(unlockTransactions),
//  m_transactions(transactions),
//  m_transfers(transfers),
//  m_uncommitedTransactions(uncommitedTransactions),
//  m_transactionSoftLockTime(transactionSoftLockTime)
{}

void WalletSerializerV1::load(const crypto::chacha8_key &key, common::IInputStream &source) {
//	bytecoin::BinaryInputStreamSerializer s(source);
	seria::BinaryInputStream s(source);
	s.beginObject();

	uint32_t version = load_version(source);

	if (version > SERIALIZATION_VERSION) {
		throw std::runtime_error("WRONG_VERSION");
	} else if (version != 1) {
		load_wallet(source, key, version);
	} else {
		load_wallet_v1(source, key);
	}

	s.endObject();
}

void WalletSerializerV1::load_wallet(common::IInputStream &source, const crypto::chacha8_key &key, uint32_t version) {
	CryptoContext crypto_ctx;

//	bool details = false;
//	bool cache   = false;

	load_iv(source, crypto_ctx.iv);
	crypto_ctx.key = key;

	load_keys(source, crypto_ctx);
	check_keys();

	load_wallets(source, crypto_ctx);
	//  subscribeWallets();

	/*  loadFlags(details, cache, source, cryptoContext);

	  if (details) {
	    loadTransactions(source, cryptoContext);
	    loadTransfers(source, cryptoContext, version);
	  }

	  if (version < 5) {
	    updateTransfersSign();
	    cache = false;
	  }

	  if (cache) {
	    loadBalances(source, cryptoContext);
	    loadTransfersSynchronizer(source, cryptoContext);
	    if (version < 5) {
	      loadObsoleteSpentOutputs(source, cryptoContext);
	    }

	    loadUnlockTransactionsJobs(source, cryptoContext);

	    if (version < 5) {
	      loadObsoleteChange(source, cryptoContext);
	    }

	    if (version > 3) {
	      loadUncommitedTransactions(source, cryptoContext);
	    }
	  } else {
	    resetCachedBalance();
	  }

	  if (details && cache) {
	    updateTransactionsBaseStatus();
	  }*/
}

void WalletSerializerV1::load_wallet_v1(common::IInputStream &source, const crypto::chacha8_key &key) {
	CryptoContext crypto_ctx;

//	bytecoin::BinaryInputStreamSerializer encrypted(source);
	seria::BinaryInputStream encrypted(source);

	encrypted(crypto_ctx.iv); // , "iv"
	crypto_ctx.key = key;

	std::string cipher;
	encrypted(cipher); // , "data"

	std::string plain = decrypt(cipher, crypto_ctx);

	MemoryInputStream decrypted_stream(plain.data(), plain.size());
//	bytecoin::BinaryInputStreamSerializer serializer(decrypted_stream);
	seria::BinaryInputStream serializer(decrypted_stream);

	load_wallet_v1_keys(serializer);
	check_keys();

	//  subscribeWallets();

	bool details_saved;
	serializer(details_saved); // , "has_details"

	/*  if (detailsSaved) {
	    loadWalletV1Details(serializer);
	  }*/
}

void WalletSerializerV1::load_wallet_v1_keys(seria::ISeria &s) {
	KeysStorage keys;

	try {
		s(keys);
//		keys.serialize(s, "keys");
	} catch (const std::runtime_error &) {
		throw std::runtime_error("WRONG_PASSWORD");
	}

	m_view_public_key = keys.view_public_key;
	m_view_secret_key = keys.view_secret_key;

	WalletRecord wallet;
	wallet.spend_public_key = keys.spend_public_key;
	wallet.spend_secret_key = keys.spend_secret_key;
	//	wallet.actualBalance = 0;
	//	wallet.pendingBalance = 0;
	wallet.creation_timestamp = static_cast<Timestamp>(keys.creation_timestamp);

	m_wallets_container.push_back(wallet);
}

/*void WalletSerializerV1::loadWalletV1Details(bytecoin::BinaryInputStreamSerializer& serializer) {
  std::vector<WalletLegacyTransaction> txs;
  std::vector<WalletLegacyTransfer> trs;

  serializer(txs, "transactions");
  serializer(trs, "transfers");

  addWalletV1Details(txs, trs);
}*/

uint32_t WalletSerializerV1::load_version(common::IInputStream &source) {
//	bytecoin::BinaryInputStreamSerializer s(source);
	seria::BinaryInputStream s(source);

	uint32_t version = std::numeric_limits<uint32_t>::max();
	s(version); // , "version"

	return version;
}

void WalletSerializerV1::load_iv(common::IInputStream &source, crypto::chacha8_iv &iv) {
//	bytecoin::BinaryInputStreamSerializer s(source);
	seria::BinaryInputStream s(source);

	s.binary(static_cast<void *>(&iv.data), sizeof(iv.data)); // , "chacha_iv"
}

void WalletSerializerV1::load_keys(common::IInputStream &source, CryptoContext &crypto_ctx) {
	try {
		load_public_key(source, crypto_ctx);
		load_secret_key(source, crypto_ctx);
	} catch (const std::runtime_error &) {
		throw std::runtime_error("WRONG_PASSWORD");
	}
}

void WalletSerializerV1::load_public_key(common::IInputStream &source, CryptoContext &crypto_ctx) {
	deserializeEncrypted(m_view_public_key, "public_key", crypto_ctx, source);
	crypto_ctx.incIv();
}

void WalletSerializerV1::load_secret_key(common::IInputStream &source, CryptoContext &crypto_ctx) {
	deserializeEncrypted(m_view_secret_key, "secret_key", crypto_ctx, source);
	crypto_ctx.incIv();
}

void WalletSerializerV1::check_keys() {
	if( !keys_match(m_view_secret_key, m_view_public_key) )
		throw std::runtime_error("Keys do not match");
}

void WalletSerializerV1::load_flags(bool &details,
                                    bool &cache,
                                    common::IInputStream &source,
                                    CryptoContext &crypto_ctx) {
	deserializeEncrypted(details, "details", crypto_ctx, source);
	crypto_ctx.incIv();

	deserializeEncrypted(cache, "cache", crypto_ctx, source);
	crypto_ctx.incIv();
}

void WalletSerializerV1::load_wallets(common::IInputStream &source, CryptoContext &crypto_ctx) {
	auto &index = m_wallets_container;

	uint64_t count = 0;
	deserializeEncrypted(count, "wallets_count", crypto_ctx, source);
	crypto_ctx.incIv();

	bool is_tracking_mode = false;  // init not required, but prevents warning

	for (uint64_t i = 0; i < count; ++i) {
		WalletRecordDto dto;
		deserializeEncrypted(dto, "", crypto_ctx, source);
		crypto_ctx.incIv();

		if (i == 0) {
			is_tracking_mode = dto.spend_secret_key == SecretKey{};
		} else if ((is_tracking_mode && dto.spend_secret_key != SecretKey{}) ||
		           (!is_tracking_mode && dto.spend_secret_key == SecretKey{})) {
			throw std::runtime_error("BAD_ADDRESS - All addresses must be whether tracking or not");
		}

		if (dto.spend_secret_key != SecretKey{}) {
			if( !keys_match(dto.spend_secret_key, dto.spend_public_key) )
				throw std::runtime_error("Restored spend public key doesn't correspond to secret key");
		} else {
			if (!crypto::key_isvalid(dto.spend_public_key)) {
				throw std::runtime_error("WRONG_PASSWORD - Public spend key is incorrect");
			}
		}

		WalletRecord wallet;
		wallet.spend_public_key = dto.spend_public_key;
		wallet.spend_secret_key = dto.spend_secret_key;
		//		wallet.actualBalance = dto.actualBalance;
		//		wallet.pendingBalance = dto.pendingBalance;
		wallet.creation_timestamp = static_cast<Timestamp>(dto.creation_timestamp);
		//		wallet.container = nullptr;//reinterpret_cast<bytecoin::ITransfersContainer*>(i); //dirty hack.
		// container
		// field must be unique

		index.push_back(wallet);
	}
}

/*void WalletSerializerV1::subscribeWallets() {
  auto& index = m_walletsContainer.get<RandomAccessIndex>();

  for (auto it = index.begin(); it != index.end(); ++it) {
    const auto& wallet = *it;

    AccountSubscription sub;
    sub.keys.address.viewPublicKey = m_viewPublicKey;
    sub.keys.address.spendPublicKey = wallet.spendPublicKey;
    sub.keys.viewSecretKey = m_viewSecretKey;
    sub.keys.spendSecretKey = wallet.spendSecretKey;
    sub.transactionSpendableAge = m_transactionSoftLockTime;
    sub.syncStart.height = 0;
    sub.syncStart.timestamp = std::max(static_cast<uint64_t>(wallet.creationTimestamp), ACCOUNT_CREATE_TIME_ACCURACY) -
ACCOUNT_CREATE_TIME_ACCURACY;

    auto& subscription = m_synchronizer.addSubscription(sub);
    bool r = index.modify(it, [&subscription] (WalletRecord& rec) { rec.container = &subscription.getContainer(); });
    assert(r);

    subscription.addObserver(&m_transfersObserver);
  }
}*/

/*void WalletSerializerV1::load_balances(common::IInputStream &source, CryptoContext &crypto_ctx) {
	deserializeEncrypted(m_actual_balance, "actual_balance", crypto_ctx, source);
	crypto_ctx.incIv();

	deserializeEncrypted(m_pending_balance, "pending_balance", crypto_ctx, source);
	crypto_ctx.incIv();
}*/

/*void WalletSerializerV1::loadTransfersSynchronizer(common::IInputStream& source, CryptoContext& cryptoContext) {
  std::string deciphered;
  deserializeEncrypted(deciphered, "transfers_synchronizer", cryptoContext, source);
  cryptoContext.incIv();

  std::stringstream stream(deciphered);
  deciphered.clear();

  m_synchronizer.load(stream);
}

void WalletSerializerV1::loadObsoleteSpentOutputs(common::IInputStream& source, CryptoContext& cryptoContext) {
  uint64_t count = 0;
  deserializeEncrypted(count, "spent_outputs_count", cryptoContext, source);
  cryptoContext.incIv();

  for (uint64_t i = 0; i < count; ++i) {
    ObsoleteSpentOutputDto dto;
    deserializeEncrypted(dto, "", cryptoContext, source);
    cryptoContext.incIv();
  }
}

void WalletSerializerV1::loadUnlockTransactionsJobs(common::IInputStream& source, CryptoContext& cryptoContext) {
  auto& index = m_unlockTransactions.get<TransactionHashIndex>();
  auto& walletsIndex = m_walletsContainer.get<RandomAccessIndex>();
  const uint64_t walletsSize = walletsIndex.size();

  uint64_t jobsCount = 0;
  deserializeEncrypted(jobsCount, "unlock_transactions_jobs_count", cryptoContext, source);
  cryptoContext.incIv();

  for (uint64_t i = 0; i < jobsCount; ++i) {
    UnlockTransactionJobDto dto;
    deserializeEncrypted(dto, "", cryptoContext, source);
    cryptoContext.incIv();

    assert(dto.walletIndex < walletsSize);

    UnlockTransactionJob job;
    job.blockHeight = dto.blockHeight;
    job.transactionHash = dto.transactionHash;
    job.container = walletsIndex[dto.walletIndex].container;

    index.insert(std::move(job));
  }
}

void WalletSerializerV1::loadObsoleteChange(common::IInputStream& source, CryptoContext& cryptoContext) {
  uint64_t count = 0;
  deserializeEncrypted(count, "changes_count", cryptoContext, source);
  cryptoContext.incIv();

  for (uint64_t i = 0; i < count; i++) {
    ObsoleteChangeDto dto;
    deserializeEncrypted(dto, "", cryptoContext, source);
    cryptoContext.incIv();
  }
}

void WalletSerializerV1::loadUncommitedTransactions(common::IInputStream& source, CryptoContext& cryptoContext) {
  deserializeEncrypted(m_uncommitedTransactions, "uncommited_transactions", cryptoContext, source);
}

void WalletSerializerV1::resetCachedBalance() {
  for (auto it = m_walletsContainer.begin(); it != m_walletsContainer.end(); ++it) {
    m_walletsContainer.modify(it, [](WalletRecord& wallet) {
      wallet.actualBalance = 0;
      wallet.pendingBalance = 0;
    });
  }
}

// can't do it in loadTransactions, TransfersContainer is not yet loaded
void WalletSerializerV1::updateTransactionsBaseStatus() {
  auto& transactions = m_transactions.get<RandomAccessIndex>();
  auto begin = std::begin(transactions);
  auto end = std::end(transactions);
  for (; begin != end; ++begin) {
    transactions.modify(begin, [this](WalletTransaction& tx) {
      auto& wallets = m_walletsContainer.get<RandomAccessIndex>();
      TransactionInformation txInfo;
      auto it = std::find_if(std::begin(wallets), std::end(wallets), [&](const WalletRecord& rec) {
        assert(rec.container != nullptr);
        return rec.container->getTransactionInformation(tx.hash, txInfo);
      });

      tx.isBase = it != std::end(wallets) && txInfo.totalAmountIn == 0;
    });
  }
}

void WalletSerializerV1::updateTransfersSign() {
  auto it = m_transfers.begin();
  while (it != m_transfers.end()) {
    if (it->second.amount < 0) {
      it->second.amount = -it->second.amount;
      ++it;
    } else {
      it = m_transfers.erase(it);
    }
  }
}

void WalletSerializerV1::loadTransactions(common::IInputStream& source, CryptoContext& cryptoContext) {
  uint64_t count = 0;
  deserializeEncrypted(count, "transactions_count", cryptoContext, source);
  cryptoContext.incIv();

  m_transactions.get<RandomAccessIndex>().reserve(count);

  for (uint64_t i = 0; i < count; ++i) {
    WalletTransactionDto dto;
    deserializeEncrypted(dto, "", cryptoContext, source);
    cryptoContext.incIv();

    WalletTransaction tx;
    tx.state = dto.state;
    tx.timestamp = dto.timestamp;
    tx.blockHeight = dto.blockHeight;
    tx.hash = dto.hash;
    tx.totalAmount = dto.totalAmount;
    tx.fee = dto.fee;
    tx.creationTime = dto.creationTime;
    tx.unlockTime = dto.unlockTime;
    tx.extra = dto.extra;
    tx.isBase = false;

    m_transactions.get<RandomAccessIndex>().push_back(std::move(tx));
  }
}

void WalletSerializerV1::loadTransfers(common::IInputStream& source, CryptoContext& cryptoContext, uint32_t version) {
  uint64_t count = 0;
  deserializeEncrypted(count, "transfers_count", cryptoContext, source);
  cryptoContext.incIv();

  m_transfers.reserve(count);

  for (uint64_t i = 0; i < count; ++i) {
    uint64_t txId = 0;
    deserializeEncrypted(txId, "transaction_id", cryptoContext, source);
    cryptoContext.incIv();

    WalletTransferDto dto(version);
    deserializeEncrypted(dto, "transfer", cryptoContext, source);
    cryptoContext.incIv();

    WalletTransfer tr;
    tr.address = dto.address;
    tr.amount = dto.amount;

    if (version > 2) {
      tr.type = static_cast<WalletTransferType>(dto.type);
    } else {
      tr.type = WalletTransferType::USUAL;
    }

    m_transfers.push_back(std::make_pair(txId, tr));
  }
}

void WalletSerializerV1::addWalletV1Details(const std::vector<WalletLegacyTransaction>& txs, const
std::vector<WalletLegacyTransfer>& trs) {
  size_t txId = 0;
  m_transfers.reserve(trs.size());

  for (const auto& tx: txs) {
    WalletTransaction mtx = convert(tx);
    m_transactions.get<RandomAccessIndex>().push_back(std::move(mtx));

    if (tx.firstTransferId != WALLET_LEGACY_INVALID_TRANSFER_ID && tx.transferCount != 0) {
      size_t firstTr = tx.firstTransferId;
      size_t lastTr = firstTr + tx.transferCount;

      if (lastTr > trs.size()) {
        throw std::system_error(make_error_code(error::INTERNAL_WALLET_ERROR));
      }

      for (; firstTr < lastTr; firstTr++) {
        WalletTransfer tr = convert(trs[firstTr]);
        m_transfers.push_back(std::make_pair(txId, tr));
      }
    }

    txId++;
  }
}*/

}  // namespace bytecoin
