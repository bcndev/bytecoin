// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "WalletStateBasic.hpp"
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "TransactionExtra.hpp"
#include "common/Math.hpp"
#include "common/Varint.hpp"
#include "common/string.hpp"
#include "crypto/crypto.hpp"
#include "platform/PathTools.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"

static const auto LEVEL = logging::TRACE;

static const std::string version_current = "11";

static const std::string INDEX_UID_to_STATE = "X";  // We do not store it for empty blocks

static const std::string INDEX_HEIGHT_to_HEADER = "c";

// (tid) -> tx                  <- find tx by tid
static const std::string INDEX_TID_to_TRANSACTIONS = "tx";  // for get_transations

// (   _, he, tid) -> ()        <- find transfers
// (addr, he, tid) -> ()        <- find transfers by addr
static const std::string INDEX_ADDRESS_HEIGHT_TID = "th";  // for get_transfers

// (   _) -> (balance)          <- find total balance
// (addr) -> (balance)          <- find balance by addr
static const std::string INDEX_ADDRESS_to_BALANCE = "ba";  // for get_balance

// (ki) -> (he, gi, tid, iit) <- find largest coin from same ki group (can be spent or not)
static const std::string INDEX_KEYIMAGE_to_HE_GI = "ki";  // ki->output_key, if !view_only

// (gi) -> (he, pk)          <- find coin by  gi (can be spent or not)
// static const std::string INDEX_GI_to_HE_PK = "g";
// (am, si) -> (gi, he, pk)          <- find coin by  am, si (can be spent or not)
// static const std::string INDEX_AM_SI_to_HE_PK = "s";

// (he, gi) -> output       <- find available unspents         (never locked or already unlocked)
// (addr, he, gi) -> ()     <- find available unspents by addr (never locked or already unlocked)
static const std::string INDEX_HE_GI_to_OUTPUT = "un";
static const std::string INDEX_ADDRESS_HE_GI   = "uh";

// (real_he, gi) -> (output) <- find unlocked transfers by height (only those originally locked) Balance here is
// adjusted, might become "crazy"
static const std::string UNLOCKED_INDEX_REALHE_GI_to_OUTPUT =
    "ul";  // Amount here can be adjusted if not first in the ki group

// (ki, gi) -> (unl_mom)    <- find in locked by key_image
static const std::string LOCKED_INDEX_KI_GI = "li";

// (unl_he, gi) -> (output)         <- find yet locked by height/timestamp
static const std::string LOCKED_INDEX_B_OR_T_GI_to_OUTPUT = "lh";  // key contain unlock_block_or_timestamp

using namespace cn;
using namespace platform;

void seria::ser_members(WalletStateBasic::HeightGi &v, ISeria &s) {
	seria_kv("height", v.height, s);
	seria_kv("global_index", v.global_index, s);
	seria_kv("transaction_hash", v.transaction_hash, s);
	seria_kv("index_in_transaction", v.index_in_transaction, s);
}

void seria::ser_members(WalletStateBasic::GiHeightPk &v, ISeria &s) {
	seria_kv("global_index", v.global_index, s);
	seria_kv("height", v.height, s);
	seria_kv("public_key", v.public_key, s);
}
void seria::ser_members(WalletStateBasic::UndoValue &v, seria::ISeria &s) {
	seria_kv("exists", v.exists, s);
	seria_kv("value", v.value, s);
}

WalletStateBasic::WalletStateBasic(
    logging::ILogger &log, const Config &config, const Currency &currency, const std::string &cache_name)
    : m_genesis_bid(currency.genesis_block_hash)
    , m_config(config)
    , m_currency(currency)
    , m_log(log, "WalletState")
    , m_db(platform::O_OPEN_ALWAYS, config.get_data_folder("wallet_cache") + "/" + cache_name, 0x2000000000)  // 128 gb
{
	std::string version;
	std::string other_genesis_bid;
	std::string other_cache_name;
	m_db.get("$version", version);
	m_db.get("$genesis_bid", other_genesis_bid);
	m_db.get("$cache_name", other_cache_name);
	if (version != version_current || other_genesis_bid != common::pod_to_hex(m_genesis_bid) ||
	    other_cache_name != cache_name) {
		if (!version.empty())
			m_log(logging::INFO) << "Data format, wallet seed or genesis bid different, old version=" << version
			                     << " current version=" << version_current << ", clearing wallet cache..." << std::endl;
		size_t total_items = m_db.get_approximate_items_count();
		size_t erased      = 0;
		for (DB::Cursor cur = m_db.rbegin(std::string()); !cur.end(); cur.erase()) {
			if (erased % 1000000 == 0)
				m_log(logging::INFO) << "Processing " << erased / 1000000 << "/" << (total_items + 999999) / 1000000
				                     << " million DB records" << std::endl;
			erased += 1;
		}
		version = version_current;
		m_db.put("$version", version, true);
		m_db.put("$cache_name", cache_name, true);
		m_db.put("$genesis_bid", common::pod_to_hex(m_genesis_bid), true);
	}
	{  // must close cursors before possible commit in wallet_addresses_updated
		DB::Cursor cur1 = m_db.begin(INDEX_HEIGHT_to_HEADER);
		DB::Cursor cur2 = m_db.rbegin(INDEX_HEIGHT_to_HEADER);
		if (!cur1.end() && !cur2.end()) {
			m_tip_height = common::integer_cast<Height>(common::read_varint_sqlite4(cur2.get_suffix()));
			;
			m_tail_height = common::integer_cast<Height>(common::read_varint_sqlite4(cur1.get_suffix()));
			m_tip         = (m_tip_height + 1 == m_tail_height) ? api::BlockHeader{} : read_chain(m_tip_height);
		}
		fix_empty_chain();
	}
}

/*void WalletStateBasic::put_am_gi_he(const api::Output &output) {
    std::string unkey = INDEX_GI_to_HE_PK + common::write_varint_sqlite4(output.global_index);
    BinaryArray ba    = seria::to_binary(std::make_pair(output.height, output.public_key));
    put_with_undo(unkey, ba, true);
    unkey = INDEX_AM_SI_to_HE_PK + common::write_varint_sqlite4(output.amount) +
            common::write_varint_sqlite4(output.stack_index);
    ba = seria::to_binary(GiHeightPk{output.global_index, output.height, output.public_key});
    put_with_undo(unkey, ba, true);
}
bool WalletStateBasic::get_gi_he(size_t gi, Height *he, PublicKey *pk) const {
    std::string unkey = INDEX_GI_to_HE_PK + common::write_varint_sqlite4(gi);
    BinaryArray ba;
    if (!m_db.get(unkey, ba))
        return false;
    std::pair<Height, PublicKey> pa;
    seria::from_binary(pa, ba);
    *he = pa.first;
    *pk = pa.second;
    return true;
}
bool WalletStateBasic::get_am_si_he(Amount am, size_t si, size_t *gi, Height *he, PublicKey *pk) const {
    std::string unkey = INDEX_AM_SI_to_HE_PK + common::write_varint_sqlite4(am) + common::write_varint_sqlite4(si);
    BinaryArray ba;
    if (!m_db.get(unkey, ba))
        return false;
    GiHeightPk pa;
    seria::from_binary(pa, ba);
    *gi = pa.global_index;
    *he = pa.height;
    *pk = pa.public_key;
    return true;
}*/

void WalletStateBasic::combine_balance(
    api::Balance &balance, const api::Output &output, int locked_op, int spendable_op) {
	auto &mod       = output.dust ? balance.spendable_dust : balance.spendable;
	auto &mod_coins = output.dust ? balance.spendable_dust_outputs : balance.spendable_outputs;
	if (locked_op > 0)
		balance.locked_or_unconfirmed += output.amount;
	if (locked_op < 0)
		balance.locked_or_unconfirmed -= output.amount;
	balance.locked_or_unconfirmed_outputs += locked_op;
	if (spendable_op > 0)
		mod += output.amount;
	if (spendable_op < 0)
		mod -= output.amount;
	mod_coins += spendable_op;
}

void WalletStateBasic::db_commit() {
	m_log(logging::INFO) << "WalletState::db_commit started... tip_height=" << m_tip_height << std::endl;
	m_db.commit_db_txn();
	m_log(logging::TRACE) << "WalletState::db_commit finished..." << std::endl;
}

std::string WalletStateBasic::format_output(const api::Output &v) {
	std::stringstream str;
	str << " he=" << v.height << " gi=" << v.global_index << " am=" << m_currency.format_amount(v.amount)
	    << " si=" << v.stack_index << " ki=" << v.key_image << " addr=" << v.address
	    << (v.unlock_block_or_timestamp == 0 ? "" : " unl=" + common::to_string(v.unlock_block_or_timestamp));
	return str.str();
}

void WalletStateBasic::push_chain(const api::BlockHeader &header) {
	m_tip_height += 1;
	BinaryArray ba = seria::to_binary(header);
	m_db.put(INDEX_HEIGHT_to_HEADER + common::write_varint_sqlite4(m_tip_height), ba, true);
	m_tip = header;
	save_db_state(m_tip_height, current_undo_map);
	current_undo_map.clear();
}

void WalletStateBasic::pop_chain() {
	invariant(m_tip_height + 1 != m_tail_height, "pop_chain tip_height == -1");
	undo_db_state(m_tip_height);
	m_db.del(INDEX_HEIGHT_to_HEADER + common::write_varint_sqlite4(m_tip_height), true);
	m_tip_height -= 1;
	m_tip = (m_tip_height + 1 == m_tail_height) ? api::BlockHeader{} : read_chain(m_tip_height);
}

void WalletStateBasic::fix_empty_chain() {
	if (m_tip_height + 1 == m_tail_height) {
		m_tail_height = 0;
		m_tip_height  = -1;
		push_chain(BlockChainState::fill_genesis(m_genesis_bid, m_currency.genesis_block_template));
	}
}
void WalletStateBasic::reset_chain(Height new_tail_height) {
	invariant(empty_chain(), "reset_chain chain should be empty");
	m_tail_height = new_tail_height;
	m_tip_height  = m_tail_height - 1;
}

bool WalletStateBasic::read_chain(Height height, api::BlockHeader &header) const {
	BinaryArray rb;
	if (!m_db.get(INDEX_HEIGHT_to_HEADER + common::write_varint_sqlite4(height), rb))
		return false;
	seria::from_binary(header, rb);
	return true;
}

api::BlockHeader WalletStateBasic::read_chain(Height height) const {
	api::BlockHeader ha;
	invariant(read_chain(height, ha), "read_header_chain failed");
	return ha;
}

std::vector<Hash> WalletStateBasic::get_sparse_chain() const {
	std::vector<Hash> tip_path;

	Height jump = 0;
	if (m_tip_height + 1 > m_tail_height)
		while (m_tip_height >= jump + m_tail_height) {
			tip_path.push_back(read_chain(m_tip_height - jump).hash);
			if (tip_path.size() <= 10)
				jump += 1;
			else
				jump += (1 << (tip_path.size() - 10));
		}
	if (tip_path.empty() || tip_path.back() != m_genesis_bid)
		tip_path.push_back(m_genesis_bid);
	return tip_path;
}

WalletStateBasic::UndoMap::iterator WalletStateBasic::record_undo(UndoMap &undo_map, const std::string &key) {
	UndoMap::iterator kit = undo_map.find(key);
	if (kit == undo_map.end()) {
		kit = undo_map.insert(std::make_pair(key, UndoValue{})).first;
		common::BinaryArray was_value;
		if (m_db.get(key, was_value)) {
			kit->second.exists = true;
			kit->second.value  = std::move(was_value);
		}
	}
	return kit;
}

void WalletStateBasic::put_with_undo(const std::string &key, const common::BinaryArray &value, bool nooverwrite) {
	//	UndoMap::iterator kit =
	record_undo(current_undo_map, key);
	m_db.put(key, value, nooverwrite);
	//	if(kit->second.exists && kit->second.value == value) - TODO - test before next release
	//		current_undo_map.erase(kit);
}

void WalletStateBasic::del_with_undo(const std::string &key, bool mustexist) {
	//	UndoMap::iterator kit =
	record_undo(current_undo_map, key);
	m_db.del(key, mustexist);
	//	if(!kit->second.exists) - TODO - test before next release
	//		current_undo_map.erase(kit);
}

void WalletStateBasic::save_db_state(Height state, const UndoMap &undo_map) {
	if (undo_map.empty())
		return;
	const auto key            = INDEX_UID_to_STATE + common::write_varint_sqlite4(state);
	common::BinaryArray value = seria::to_binary(undo_map);
	m_db.put(key, value, true);
}

void WalletStateBasic::undo_db_state(Height state) {
	const auto key = INDEX_UID_to_STATE + common::write_varint_sqlite4(state);
	common::BinaryArray value;
	if (!m_db.get(key, value))
		return;
	UndoMap undo_map;
	seria::from_binary(undo_map, value);
	m_db.del(key, true);
	for (auto &&uv : undo_map) {
		if (uv.second.exists)
			m_db.put(uv.first, uv.second.value, false);
		else
			m_db.del(uv.first, false);
	}
}

bool WalletStateBasic::try_add_incoming_output(const api::Output &output) const {
	HeightGi heamgi;
	bool ki_exists = read_by_keyimage(output.key_image, &heamgi);
	api::Output existing_output;
	bool is_existing_unspent = ki_exists && read_from_unspent_index(heamgi, &existing_output);
	if (ki_exists && !is_existing_unspent)
		return false;
	if (output.unlock_block_or_timestamp != 0) {
		return true;
	}
	return !ki_exists;  // We fixed problem on crypto level, but retain code to keep indexes invariants
}

bool WalletStateBasic::add_incoming_output(const api::Output &output, bool just_unlocked) {
	HeightGi heamgi;
	bool ki_exists = read_by_keyimage(output.key_image, &heamgi);
	api::Output existing_output;
	bool is_existing_unspent = ki_exists && read_from_unspent_index(heamgi, &existing_output);
	if (ki_exists && !is_existing_unspent) {
		m_log(logging::WARNING) << "  Duplicate key_output attack, ignoring output because already spent" << std::endl;
		return false;
	}
	if (output.unlock_block_or_timestamp != 0 && !just_unlocked) {  // incoming
		                                                            //		if (is_det_viewonly)
		                                                            //			put_am_gi_he(output);
		add_to_lock_index(output);
		return true;
	}
	if (ki_exists) {
		// We fixed problem on crypto level, but retain code to keep indexes invariants
		m_log(logging::WARNING)
		    << "  Duplicate key_output attack, ignoring output because have another one unspent with same or larger amount or different address, "
		    << format_output(existing_output) << std::endl;
		return false;
	}
	add_to_unspent_index(output);
	heamgi.height               = output.height;
	heamgi.global_index         = output.global_index;
	heamgi.transaction_hash     = output.transaction_hash;
	heamgi.index_in_transaction = output.index_in_transaction;
	update_keyimage(output.key_image, heamgi);
	//	if (is_det_viewonly)
	//		put_am_gi_he(output);
	return true;
}

bool WalletStateBasic::add_incoming_output(const api::Output &output) {
	m_log(LEVEL) << "Incoming output " << format_output(output) << std::endl;
	return add_incoming_output(output, false);
}

Amount WalletStateBasic::add_incoming_keyimage(Height block_height, const KeyImage &key_image) {
	m_log(LEVEL) << "Incoming ki_or_pk " << key_image << std::endl;
	std::string prefix = LOCKED_INDEX_KI_GI + DB::to_binary_key(key_image.data, sizeof(key_image.data));
	// find and remove in locked
	std::vector<api::Output> found_in_locked;
	for (DB::Cursor cur = m_db.begin(prefix); !cur.end(); cur.next()) {
		size_t gi            = common::integer_cast<size_t>(common::read_varint_sqlite4(cur.get_suffix()));
		BlockOrTimestamp unl = 0;
		seria::from_binary(unl, cur.get_value_array());
		std::string unkey =
		    LOCKED_INDEX_B_OR_T_GI_to_OUTPUT + common::write_varint_sqlite4(unl) + common::write_varint_sqlite4(gi);
		BinaryArray output_ba;
		invariant(m_db.get(unkey, output_ba), "");
		api::Output output;
		seria::from_binary(output, output_ba);
		found_in_locked.push_back(output);
	}
	for (auto &&lo : found_in_locked) {
		unlock(block_height, std::move(lo));
	}
	Amount removed_amount = 0;
	HeightGi heamgi;
	bool ki_exists = read_by_keyimage(key_image, &heamgi);
	api::Output existing_output;
	if (ki_exists && read_from_unspent_index(heamgi, &existing_output)) {
		removed_amount = existing_output.amount;
		remove_from_unspent_index(existing_output);
	}
	return removed_amount;
}

bool WalletStateBasic::try_adding_incoming_keyimage(const KeyImage &key_image, api::Output *spending_output) const {
	bool candidate_found = false;
	HeightGi heamgi;
	bool ki_exists = read_by_keyimage(key_image, &heamgi);
	if (ki_exists && read_from_unspent_index(heamgi, spending_output)) {
		candidate_found = true;
	}
	std::string prefix = LOCKED_INDEX_KI_GI + DB::to_binary_key(key_image.data, sizeof(key_image.data));
	for (DB::Cursor cur = m_db.begin(prefix); !cur.end(); cur.next()) {
		size_t gi = common::integer_cast<size_t>(common::read_varint_sqlite4(cur.get_suffix()));
		if (candidate_found)
			continue;
		BlockOrTimestamp unl = 0;
		seria::from_binary(unl, cur.get_value_array());
		std::string unkey =
		    LOCKED_INDEX_B_OR_T_GI_to_OUTPUT + common::write_varint_sqlite4(unl) + common::write_varint_sqlite4(gi);
		BinaryArray output_ba;
		invariant(m_db.get(unkey, output_ba), "");
		api::Output output;
		seria::from_binary(output, output_ba);
		invariant(output.global_index == gi, "");
		if (candidate_found && output.address != spending_output->address)
			continue;
		*spending_output = output;
		candidate_found  = true;
	}
	return candidate_found;
}

void WalletStateBasic::add_transaction(
    Height height, const Hash &tid, const TransactionPrefix &tx, const api::Transaction &ptx) {
	auto cur = m_db.begin(INDEX_TID_to_TRANSACTIONS);
	if (cur.end())
		on_first_transaction_found(ptx.timestamp);
	auto trkey         = INDEX_TID_to_TRANSACTIONS + DB::to_binary_key(tid.data, sizeof(tid.data));
	BinaryArray str_pa = seria::to_binary(std::make_pair(tx, ptx));
	put_with_undo(trkey, str_pa, true);
	std::set<std::string> addresses;
	addresses.insert(std::string());
	for (auto &&transfer : ptx.transfers) {
		addresses.insert(transfer.address);
	}
	for (auto &&addr : addresses) {
		auto adtrkey = INDEX_ADDRESS_HEIGHT_TID + addr + "/" + common::write_varint_sqlite4(height) +
		               DB::to_binary_key(tid.data, sizeof(tid.data));
		put_with_undo(adtrkey, BinaryArray(), true);
	}
}

bool WalletStateBasic::api_add_unspent(std::vector<api::Output> *result, Amount *total_amount,
    const std::string &address, Height confirmed_height, Amount max_amount) const {
	auto recently_unlocked = get_unlocked_outputs(address, confirmed_height + 1, std::numeric_limits<Height>::max());
	const size_t min_count = 10000;  // We return up to 10k outputs after we find requested sum
	return for_each_in_unspent_index(address, 0, confirmed_height + 1, [&](api::Output &&output) -> bool {
		if (!is_memory_spent(output) && recently_unlocked.count(output.global_index) == 0) {
			//			if (!output.dust)  // We ensure total can be spent with non-zero anonymity
			//				*total_amount += output.amount;
			result->push_back(std::move(output));
			if (*total_amount >= max_amount && result->size() >= min_count)
				return false;  // Stop looking for
		}
		return true;
	});
}

std::vector<api::Block> WalletStateBasic::api_get_transfers(
    const std::string &address, Height *from_height, Height *to_height, bool forward, size_t desired_tx_count) const {
	std::vector<api::Block> result;
	if (*from_height >= *to_height)
		return result;
	auto prefix = INDEX_ADDRESS_HEIGHT_TID + address + "/";
	std::string middle =
	    common::write_varint_sqlite4(forward ? *from_height : *to_height - 1);  // to_height != 0 checked in if above
	api::Block current_block;
	size_t total_transactions_found = 0;
	for (DB::Cursor cur = forward ? m_db.begin(prefix, middle) : m_db.rbegin(prefix, middle); !cur.end(); cur.next()) {
		const std::string &suf = cur.get_suffix();
		const char *be         = suf.data();
		const char *en         = be + suf.size();
		Height height          = common::integer_cast<Height>(common::read_varint_sqlite4(be, en));
		Hash tid;
		invariant(en - be == sizeof(tid.data), "CD_TIPS_PREFIX corrupted");
		DB::from_binary_key(cur.get_suffix(), cur.get_suffix().size() - sizeof(tid.data), tid.data, sizeof(tid.data));
		if (forward && height >= *to_height)
			break;
		if (!forward && height < *from_height)
			break;
		TransactionPrefix ptx;
		api::Transaction tx;
		get_transaction(tid, &ptx, &tx);
		if (!address.empty()) {
			for (auto tit = tx.transfers.begin(); tit != tx.transfers.end();)
				if (tit->address == address)
					++tit;
				else
					tit = tx.transfers.erase(tit);
			if (tx.transfers.empty())
				continue;
		}
		if (current_block.header.height != height && !current_block.transactions.empty()) {
			result.push_back(std::move(current_block));
			current_block = api::Block();
			if (total_transactions_found >= desired_tx_count) {
				if (forward)
					*to_height = height;
				else
					*from_height = height + 1;
				break;
			}
		}
		if (current_block.transactions.empty()) {
			read_chain(height, current_block.header);
		}
		current_block.transactions.push_back(std::move(tx));
		total_transactions_found += 1;
	}
	if (!current_block.transactions.empty()) {
		result.push_back(std::move(current_block));
	}
	return result;
}

std::vector<api::Output> WalletStateBasic::api_get_locked_or_unconfirmed_unspent(const std::string &address,
    Height confirmed_height) const {
	std::vector<api::Output> result;
	for_each_in_unspent_index(
	    address, confirmed_height + 1, std::numeric_limits<Height>::max(), [&](api::Output &&output) -> bool {
		    if (!is_memory_spent(output))
			    result.push_back(std::move(output));
		    return true;
	    });
	auto recently_unlocked = get_unlocked_outputs(address, confirmed_height + 1, std::numeric_limits<Height>::max());
	for (auto &&lou : recently_unlocked) {
		HeightGi heamgi{lou.second.height, lou.second.global_index, {}, 0};
		api::Output existing_output;
		bool is_existing_unspent = read_from_unspent_index(heamgi, &existing_output);
		if (!is_existing_unspent || is_memory_spent(lou.second))
			continue;
		if (lou.second.height <= confirmed_height)
			result.push_back(lou.second);
	}
	std::map<size_t, api::Output> still_locked;
	read_unlock_index(
	    &still_locked, LOCKED_INDEX_B_OR_T_GI_to_OUTPUT, address, 0, std::numeric_limits<BlockOrTimestamp>::max());
	for (auto &&lou : still_locked)
		if (!is_memory_spent(lou.second))
			result.push_back(std::move(lou.second));
	return result;
}

// spendable: unspent [0..conf] && !recently unlocked && !spent
// unconfirmed: unspent (conf..inf] || recently_unlocked

api::Balance WalletStateBasic::get_balance(const std::string &address, Height confirmed_height) const {
	auto bakey = INDEX_ADDRESS_to_BALANCE + address;
	BinaryArray ba;
	api::Balance balance;
	if (m_db.get(bakey, ba))
		seria::from_binary(balance, ba);

	for_each_in_unspent_index(
	    address, confirmed_height + 1, std::numeric_limits<Height>::max(), [&](api::Output &&output) -> bool {
		    if (is_memory_spent(output))
			    combine_balance(balance, output, 0, -1);
		    else
			    combine_balance(balance, output, 1, -1);
		    return true;
	    });

	auto recently_unlocked = get_unlocked_outputs(address, confirmed_height + 1, std::numeric_limits<Height>::max());
	for (auto &&lou : recently_unlocked) {
		HeightGi heamgi{lou.second.height, lou.first, {}, 0};
		api::Output existing_output;
		bool is_existing_unspent = read_from_unspent_index(heamgi, &existing_output);
		if (!is_existing_unspent || is_memory_spent(lou.second))
			continue;
		if (lou.second.height <= confirmed_height)
			combine_balance(balance, existing_output, 1, -1);
	}
	for (auto &&kit : get_mempool_keyimages()) {
		HeightGi heamgi;
		bool ki_exists = read_by_keyimage(kit.first, &heamgi);
		api::Output existing_output;
		bool is_existing_unspent = ki_exists && read_from_unspent_index(heamgi, &existing_output);
		if (is_existing_unspent && existing_output.height <= confirmed_height &&
		    (address.empty() || existing_output.address == address))
			combine_balance(balance, existing_output, 0, -1);
	}

	//	We commented code below because it requires either iterating all locked index ot all used keyimages
	//  So, we do not account for memory spent locked outputs in unconfirmed balance
	//	std::map<size_t, api::Output> still_locked;
	//	read_unlock_index(&still_locked, LOCKED_INDEX_B_OR_T_GI_to_OUTPUT, address, 0,
	// std::numeric_limits<BlockOrTimestamp>::max());
	//	for(auto && lou : still_locked)
	//		if (is_memory_spent(lou.second))
	//			combine_balance(balance, lou.second, -1, 0);

	return balance;
}

bool WalletStateBasic::has_transaction(Hash tid) const {
	auto trkey = INDEX_TID_to_TRANSACTIONS + DB::to_binary_key(tid.data, sizeof(tid.data));
	BinaryArray data;
	return m_db.get(trkey, data);
}

bool WalletStateBasic::get_transaction(Hash tid, TransactionPrefix *tx, api::Transaction *ptx) const {
	auto trkey = INDEX_TID_to_TRANSACTIONS + DB::to_binary_key(tid.data, sizeof(tid.data));
	BinaryArray data;
	if (!m_db.get(trkey, data))
		return false;
	std::pair<TransactionPrefix, api::Transaction> pa;
	seria::from_binary(pa, data);
	*tx  = std::move(pa.first);
	*ptx = std::move(pa.second);
	return true;
}

static void parse_lock_key(const std::string &suffix, BlockOrTimestamp *unl, size_t *global_index) {
	const char *be = suffix.data();
	const char *en = be + suffix.size();
	*unl           = common::integer_cast<BlockOrTimestamp>(common::read_varint_sqlite4(be, en));
	*global_index  = common::integer_cast<size_t>(common::read_varint_sqlite4(be, en));
	invariant(en - be == 0, "");
}

void WalletStateBasic::read_unlock_index(std::map<size_t, api::Output> *add, const std::string &index_prefix,
    const std::string &address, BlockOrTimestamp begin, BlockOrTimestamp end) const {
	if (begin >= end)  // optimization
		return;
	auto middle = common::write_varint_sqlite4(begin);
	for (DB::Cursor cur = m_db.begin(index_prefix, middle); !cur.end(); cur.next()) {
		BlockOrTimestamp unl = 0;
		size_t global_index  = 0;
		parse_lock_key(cur.get_suffix(), &unl, &global_index);
		if (unl >= end)
			break;
		api::Output output;
		seria::from_binary(output, cur.get_value_array());
		// amount can be different to output.amount, if added from te same ki group
		// original amount is in unlocked index key, use it as a key because it is unambigous
		invariant(output.global_index == global_index, "Index corrupted");
		if (address.empty() || output.address == address)
			invariant(add->insert(std::make_pair(output.global_index, output)).second,
			    "Invariant dead read_unlock_index adding output twice");
	}
}

std::map<size_t, api::Output> WalletStateBasic::get_unlocked_outputs(const std::string &address,
    Height from_height,
    Height to_height) const {
	std::map<size_t, api::Output> unlocked;
	read_unlock_index(&unlocked, UNLOCKED_INDEX_REALHE_GI_to_OUTPUT, address, from_height, to_height);
	return unlocked;
}

std::vector<api::Transfer> WalletStateBasic::api_get_unlocked_transfers(
    const std::string &address, Height from_height, Height to_height) const {
	auto unlocked = get_unlocked_outputs(address, from_height, to_height);
	std::map<std::pair<Hash, std::string>, api::Transfer> transfers;
	for (auto &unl : unlocked) {
		api::Transfer &tr = transfers[std::make_pair(unl.second.transaction_hash, unl.second.address)];
		tr.ours           = true;
		tr.amount += unl.second.amount;
		tr.address          = unl.second.address;
		tr.transaction_hash = unl.second.transaction_hash;
		tr.outputs.push_back(std::move(unl.second));
	}
	std::vector<api::Transfer> result;
	result.reserve(transfers.size());
	for (auto &tra : transfers) {
		result.push_back(std::move(tra.second));
	}
	return result;
}

void WalletStateBasic::modify_balance(const api::Output &output, int locked_op, int spendable_op) {
	auto bakey  = INDEX_ADDRESS_to_BALANCE + output.address;
	auto bakey2 = INDEX_ADDRESS_to_BALANCE;
	BinaryArray ba;
	api::Balance balance;
	api::Balance balance2;
	if (m_db.get(bakey, ba))
		seria::from_binary(balance, ba);
	if (m_db.get(bakey2, ba))
		seria::from_binary(balance2, ba);
	//	std::cout << "modify_balance " << output.amount << " locked_op=" <<
	// locked_op << " spendable_op=" << spendable_op << std::endl;
	combine_balance(balance, output, locked_op, spendable_op);
	combine_balance(balance2, output, locked_op, spendable_op);
	if (balance.total() == 0 && balance.total_outputs() == 0)
		del_with_undo(bakey, false);
	else
		put_with_undo(bakey, seria::to_binary(balance), false);
	if (balance2.total() == 0 && balance2.total_outputs() == 0)
		del_with_undo(bakey2, false);
	else
		put_with_undo(bakey2, seria::to_binary(balance2), false);
}

static const std::map<KeyImage, int> empty_kis_or_pks;
const std::map<KeyImage, int> &WalletStateBasic::get_mempool_keyimages() const { return empty_kis_or_pks; }

void WalletStateBasic::unlock(Height now_height, api::Output &&output) {
	remove_from_lock_index(output);
	bool add = add_incoming_output(output, true);  // TODO - check before 3.5
	//		if( adjusted_amount == 0) // Unlocked and have coin with the same ki and amount
	//			continue; // We decided to put in DB anyway, so that we know we did not miss unlock
	// We add into index with original amount as a key because otherwise there could be ambiguity in index
	auto unkey = UNLOCKED_INDEX_REALHE_GI_to_OUTPUT + common::write_varint_sqlite4(now_height) +
	             common::write_varint_sqlite4(output.global_index);
	//	output.amount  = adjusted_amount;
	BinaryArray ba = seria::to_binary(output);
	put_with_undo(unkey, ba, true);
}

void WalletStateBasic::add_to_lock_index(const api::Output &output) {
	m_log(LEVEL) << "  Adding output to lock index, " << format_output(output) << std::endl;
	//	put_am_gi_tid(output.amount, output.index, tid);

	modify_balance(output, 1, 0);
	std::string unkey = LOCKED_INDEX_B_OR_T_GI_to_OUTPUT +
	                    common::write_varint_sqlite4(output.unlock_block_or_timestamp) +
	                    common::write_varint_sqlite4(output.global_index);
	put_with_undo(unkey, seria::to_binary(output), true);
	if (output.key_image != KeyImage{}) {
		unkey = LOCKED_INDEX_KI_GI + DB::to_binary_key(output.key_image.data, sizeof(output.key_image.data)) +
		        common::write_varint_sqlite4(output.global_index);
		BinaryArray ba = seria::to_binary(output.unlock_block_or_timestamp);
		put_with_undo(unkey, ba, true);
	}
}

void WalletStateBasic::remove_from_lock_index(const api::Output &output) {
	m_log(LEVEL) << "  Removing output from lock index, " << format_output(output) << std::endl;
	std::string unkey = LOCKED_INDEX_B_OR_T_GI_to_OUTPUT +
	                    common::write_varint_sqlite4(output.unlock_block_or_timestamp) +
	                    common::write_varint_sqlite4(output.global_index);
	modify_balance(output, -1, 0);
	del_with_undo(unkey, true);
	if (output.key_image != KeyImage{}) {
		unkey = LOCKED_INDEX_KI_GI + DB::to_binary_key(output.key_image.data, sizeof(output.key_image.data)) +
		        common::write_varint_sqlite4(output.global_index);
		del_with_undo(unkey, true);
	}
}

void WalletStateBasic::unlock(Height now_height, Timestamp now) {
	std::map<size_t, api::Output> to_unlock;
	read_unlock_index(&to_unlock, LOCKED_INDEX_B_OR_T_GI_to_OUTPUT, std::string(), 0, now_height + 1);
	read_unlock_index(
	    &to_unlock, LOCKED_INDEX_B_OR_T_GI_to_OUTPUT, std::string(), m_currency.max_block_height, now + 1);
	if (!to_unlock.empty())
		m_log(LEVEL) << "Unlocking for height=" << now_height << ", now=" << now << std::endl;
	for (auto &&unl : to_unlock) {
		unlock(now_height, std::move(unl.second));
	}
}

bool WalletStateBasic::read_from_unspent_index(const HeightGi &value, api::Output *output) const {
	auto keyun = INDEX_HE_GI_to_OUTPUT + common::write_varint_sqlite4(value.height) +
	             common::write_varint_sqlite4(value.global_index);
	BinaryArray ba;
	if (!m_db.get(keyun, ba))
		return false;
	seria::from_binary(*output, ba);
	return true;
}
bool WalletStateBasic::for_each_in_unspent_index(
    const std::string &address, Height from, Height to, std::function<bool(api::Output &&)> fun) const {
	auto prefix        = address.empty() ? INDEX_HE_GI_to_OUTPUT : INDEX_ADDRESS_HE_GI + address + "/";
	std::string middle = common::write_varint_sqlite4(from);
	for (DB::Cursor cur = m_db.begin(prefix, middle); !cur.end(); cur.next()) {
		const std::string &suf = cur.get_suffix();
		const char *be         = suf.data();
		const char *en         = be + suf.size();
		Height he              = common::integer_cast<Height>(common::read_varint_sqlite4(be, en));
		size_t gi              = common::integer_cast<size_t>(common::read_varint_sqlite4(be, en));
		invariant(en - be == 0, "");
		if (he >= to)
			break;
		api::Output output;
		if (!address.empty()) {
			HeightGi heamgi{he, gi, {}, 0};
			invariant(read_from_unspent_index(heamgi, &output), "unspent indexes do not match");
			invariant(output.address == address, "output is in wrong index by address");
		} else
			seria::from_binary(output, cur.get_value_array());
		if (!fun(std::move(output)))
			return false;
	}
	return true;
}

void WalletStateBasic::add_to_unspent_index(const api::Output &output) {
	m_log(LEVEL) << "  Adding to unspent, " << format_output(output) << std::endl;
	modify_balance(output, 0, 1);
	auto keyun = INDEX_HE_GI_to_OUTPUT + common::write_varint_sqlite4(output.height) +
	             common::write_varint_sqlite4(output.global_index);
	put_with_undo(keyun, seria::to_binary(output), true);

	keyun = INDEX_ADDRESS_HE_GI + output.address + "/" + common::write_varint_sqlite4(output.height) +
	        common::write_varint_sqlite4(output.global_index);
	put_with_undo(keyun, BinaryArray{}, true);
}

void WalletStateBasic::remove_from_unspent_index(const api::Output &output) {
	m_log(LEVEL) << "  Removing from unspent, " << format_output(output) << std::endl;
	modify_balance(output, 0, -1);
	auto keyun = INDEX_HE_GI_to_OUTPUT + common::write_varint_sqlite4(output.height) +
	             common::write_varint_sqlite4(output.global_index);
	del_with_undo(keyun, true);

	keyun = INDEX_ADDRESS_HE_GI + output.address + "/" + common::write_varint_sqlite4(output.height) +
	        common::write_varint_sqlite4(output.global_index);
	del_with_undo(keyun, true);
}

bool WalletStateBasic::read_by_keyimage(const KeyImage &ki, HeightGi *value) const {
	auto keyun = INDEX_KEYIMAGE_to_HE_GI + DB::to_binary_key(ki.data, sizeof(ki.data));
	BinaryArray ba;
	if (!m_db.get(keyun, ba))
		return false;
	seria::from_binary(*value, ba);
	return true;
}
void WalletStateBasic::update_keyimage(const KeyImage &ki, const HeightGi &value) {
	if (ki == KeyImage{})  // linkable view-only wallet cannot calculate keyimages
		return;
	auto keyun = INDEX_KEYIMAGE_to_HE_GI + DB::to_binary_key(ki.data, sizeof(ki.data));
	put_with_undo(keyun, seria::to_binary(value), true);
}

void WalletStateBasic::test_undo_blocks() {
	int counter = 0;
	while (!empty_chain()) {
		pop_chain();
	}
	std::cout << "---- After undo everything ---- " << std::endl;
	counter = 0;
	for (DB::Cursor cur = m_db.begin(std::string()); !cur.end(); cur.next()) {
		if (cur.get_suffix().find("a") == 0)
			continue;
		std::cout << DB::clean_key(cur.get_suffix()) << std::endl;
		if (counter++ > 2000)
			break;
	}
}

void WalletStateBasic::test_print_everything(const std::string &str) {
	std::cout << str << " tail:tip_height=" << get_tail_height() << ":" << get_tip_height() << std::endl;
	for (DB::Cursor cur = m_db.begin(std::string()); !cur.end(); cur.next()) {
		if (cur.get_suffix().find(INDEX_HEIGHT_to_HEADER) == 0)
			continue;
		if (cur.get_suffix().find(INDEX_UID_to_STATE) == 0)
			continue;
		std::cout << DB::clean_key(cur.get_suffix()) << std::endl;
	}
}
