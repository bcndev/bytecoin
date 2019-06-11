// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "WalletStatePrepared.hpp"
#include "platform/DB.hpp"
#include "rpc_api.hpp"

namespace cn {

class IWalletState {
public:
	virtual ~IWalletState() = default;

	virtual bool add_incoming_output(const api::Output &)                       = 0;  // added amount may be lower
	virtual Amount add_incoming_keyimage(Height block_height, const KeyImage &) = 0;
	virtual void add_transaction(
	    Height block_height, const Hash &tid, const PreparedWalletTransaction &pwtx, const api::Transaction &ptx) = 0;
};

class WalletStateBasic : protected IWalletState {
public:
	typedef platform::DB DB;

	explicit WalletStateBasic(
	    logging::ILogger &, const Config &, const Currency &, DB &db, const std::string &cache_name);
	const Currency &get_currency() const { return m_currency; };

	//	bool is_version_compact()const { return m_version_compact; }
	Hash get_tip_bid() const { return m_tip.hash; }
	Height get_tip_height() const { return m_tip.height; }
	bool db_empty() const { return m_chain_height == Height(-1); }
	const api::BlockHeader &get_tip() const { return m_tip; }
	bool read_chain(Height, api::BlockHeader *) const;

	std::vector<Hash> get_sparse_chain() const;

	// methods used by API
	bool api_add_unspent(std::vector<api::Output> *result, Amount *total_amount, const std::string &address,
	    Height confirmed_height, Amount max_amount = std::numeric_limits<Amount>::max()) const;
	std::vector<api::Block> api_get_transfers_legacy(const std::string &address, Height *from_height, Height *to_height,
	    bool forward,
	    size_t desired_tx_count = std::numeric_limits<size_t>::max()) const;  // TODO - remove after testing
	std::vector<api::Block> api_get_transfers(const std::string &address, Height *from_height, Height *to_height,
	    bool forward, size_t desired_tx_count = std::numeric_limits<size_t>::max()) const;
	virtual std::vector<api::Output> api_get_locked_or_unconfirmed_unspent(
	    const std::string &address, Height height) const;
	virtual api::Balance get_balance(const std::string &address, Height height) const;
	std::vector<api::Transfer> api_get_unlocked_transfers_legacy(
	    const std::string &address, Height from_height, Height to_height = std::numeric_limits<Height>::max()) const;
	bool get_transaction(Hash tid, TransactionPrefix *tx, api::Transaction *ptx) const;
	bool has_transaction(Hash tid) const;

	struct UndoValue {
		bool exists = false;
		common::BinaryArray value;
	};
	struct HeightGi {
		Height height       = 0;
		size_t global_index = 0;
		Hash transaction_hash;  // So we can look up spent coins by keyimage
		size_t index_in_transaction = 0;
	};
	struct GiHeightPk {
		size_t global_index = 0;
		Height height       = 0;
		PublicKey public_key;
	};

	void db_commit();
	void test_undo_blocks();
	void test_print_everything(const std::string &str);
	static void combine_balance(api::Balance &balance, const api::Output &output, int locked_op, int spendable_op);

	const Config &get_config() const { return m_config; }

protected:
	const Hash m_genesis_bid;
	const Config &m_config;
	const Currency &m_currency;
	logging::LoggerRef m_log;

	DB &m_db;

	void push_chain(const api::BlockHeader &);
	bool pop_chain();
	void clear_db(bool everything);
	api::BlockHeader read_chain(Height) const;

	bool is_memory_spent(const api::Output &output) const {
		return get_mempool_keyimages().count(output.key_image) != 0;
	}
	virtual const std::map<KeyImage, std::vector<Hash>> &get_mempool_keyimages() const;
	virtual void on_first_transaction_found(Timestamp ts) {}
	void unlock(Height now_height, Timestamp now);

	bool read_from_unspent_index(const HeightGi &value, api::Output *) const;
	bool read_by_keyimage(const KeyImage &ki, HeightGi *value) const;

	bool try_add_incoming_output(const api::Output &) const;
	bool try_adding_incoming_keyimage(const KeyImage &, api::Output *spending_output) const;
	// returns true if our keyimage

	// methods to add incoming tx
	bool add_incoming_output(const api::Output &) override;  // added amount may be lower
	Amount add_incoming_keyimage(Height block_height, const KeyImage &) override;
	void add_transaction(
	    Height, const Hash &tid, const PreparedWalletTransaction &pwtx, const api::Transaction &ptx) override;

	std::string format_output(const api::Output &output);

private:
	Height m_chain_height = -1;
	api::BlockHeader m_tip;

	//	void put_am_gi_he(const api::Output &output);
	//	bool get_gi_he(size_t gi, Height *he, PublicKey *pk) const;
	//	bool get_am_si_he(Amount am, size_t si, size_t *gi, Height *he, PublicKey *pk) const;
	// DB generic undo machinery
	typedef std::map<std::string, UndoValue> UndoMap;
	UndoMap current_undo_map;
	UndoMap::iterator record_undo(UndoMap &undo_map, const std::string &key);
	void put_with_undo(const std::string &key, const common::BinaryArray &value, bool nooverwrite);
	void del_with_undo(const std::string &key, bool mustexist);
	void save_db_state(Height height, const UndoMap &undo_map);
	bool undo_db_state(Height height);
	static api::BlockHeader fill_genesis(Hash genesis_bid, const BlockTemplate &g);

	// indices implemenation
	bool add_incoming_output(const api::Output &, bool just_unlocked);
	void modify_balance(const api::Output &output, int locked_op, int spendable_op);
	// lock/unlock
	void add_to_lock_index(const api::Output &);
	void remove_from_lock_index(const api::Output &);

	void unlock(Height now_height, api::Output &&output);
	void read_unlock_index(std::map<size_t, api::Output> *add, const std::string &index_prefix,
	    const std::string &address, BlockOrTimestamp begin, BlockOrTimestamp end) const;
	std::map<size_t, api::Output> get_unlocked_outputs(
	    const std::string &address, Height from_height, Height to_height) const;

	// add coin/spend coin
	void add_to_unspent_index(const api::Output &);
	void remove_from_unspent_index(const api::Output &);
	bool for_each_in_unspent_index(
	    const std::string &address, Height from, Height to, std::function<bool(api::Output &&)> fun) const;
	void add_keyimage(const KeyImage &m, const HeightGi &value);
};

}  // namespace cn

namespace seria {
void ser_members(cn::WalletStateBasic::HeightGi &v, ISeria &s);
void ser_members(cn::WalletStateBasic::GiHeightPk &v, ISeria &s);
void ser_members(cn::WalletStateBasic::UndoValue &v, seria::ISeria &s);
}  // namespace seria
