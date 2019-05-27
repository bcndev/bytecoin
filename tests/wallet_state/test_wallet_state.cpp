// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for
// details.

#include "../Random.hpp"
#include "Core/BlockChain.hpp"
#include "Core/Config.hpp"
#include "Core/WalletState.hpp"
#include "logging/ConsoleLogger.hpp"
#include "platform/PathTools.hpp"

#include "test_wallet_state.hpp"

using namespace cn;

class WalletStateTest : public WalletStateBasic {
public:
	std::map<KeyImage, std::vector<Hash>> memory_spent;
	explicit WalletStateTest(logging::ILogger &log, const Config &config, const Currency &currency, DB &db)
	    : WalletStateBasic(log, config, currency, db, "test") {}
	bool add_incoming_output(const api::Output &output) override {
		return WalletStateBasic::add_incoming_output(output);
	}
	Amount add_incoming_keyimage(Height block_height, const KeyImage &ki) override {
		return WalletStateBasic::add_incoming_keyimage(block_height, ki);
	}
	bool try_add_incoming_output(const api::Output &output) const {
		return WalletStateBasic::try_add_incoming_output(output);
	}
	bool try_adding_incoming_keyimage(const KeyImage &ki, api::Output *spending_output) const {
		return WalletStateBasic::try_adding_incoming_keyimage(ki, spending_output);
	}
	void add_transaction(
	    Height height, const Hash &tid, const PreparedWalletTransaction &pwtx, const api::Transaction &ptx) override {
		WalletStateBasic::add_transaction(height, tid, pwtx, ptx);
	}
	void unlock(Height height, Timestamp ts) { WalletStateBasic::unlock(height, ts); }
	const std::map<KeyImage, std::vector<Hash>> &get_mempool_keyimages() const override { return memory_spent; }
};

static bool less_output(const api::Output &a, const api::Output &b) {
	return std::tie(a.height, a.global_index) < std::tie(b.height, b.global_index);
}
static bool eq_output(const api::Output &a, const api::Output &b) {
	return std::tie(a.height, a.global_index) == std::tie(b.height, b.global_index);
}

// We will check that WalletStateBasic and model have the same behaviour

// Wallet State cannot remember all key images, so sending key image before
// corresponding output is also NOP in model
// They will both incorrectly show corresponding unspent as available, creating
// invalid transactions
// We might add "conflicting keyimage" to bytecoind CreateTransaction reply, so
// that they can somehow update their
// balances
class WalletStateModel : public IWalletState {
public:
	const Currency &m_currency;

	explicit WalletStateModel(const Currency &currency) : m_currency(currency) {}
	std::map<KeyImage, size_t> all_keyimages;
	std::map<size_t, api::Output> outputs;
	//	std::map<Height, std::vector<api::Transaction>> transactions;
	std::map<Height, api::Block> transfers;

	std::vector<api::Output> locked_outputs;
	std::map<size_t, std::pair<Height, Amount>> unlocked_outputs;  // height of unlock and adjusted amount

	bool add_incoming_output(Height block_height, const api::Output &output, bool just_unlocked) {
		bool ki_exists      = all_keyimages.count(output.key_image) != 0;
		bool unspent_exists = ki_exists && outputs.count(all_keyimages.at(output.key_image)) != 0;
		if (ki_exists && !unspent_exists)
			return false;                                               // second unspent after first spent
		if (output.unlock_block_or_timestamp != 0 && !just_unlocked) {  // incoming
			locked_outputs.push_back(output);
			return true;
		}
		if (ki_exists) {
			return false;
			//			auto existing_output = outputs.at(all_keyimages.at(output.key_image));
			//			if (output.amount <= existing_output.amount || output.address != existing_output.address)
			//				return 0;
			//			added_amount = output.amount - existing_output.amount;
			//			invariant(outputs.erase(all_keyimages.at(output.key_image)) == 1, "");
		}
		invariant(outputs.insert(std::make_pair(output.global_index, output)).second, "");
		if (output.key_image != KeyImage{})
			all_keyimages[output.key_image] = output.global_index;
		//		if(!just_unlocked) {
		if (transfers.count(block_height) == 0) {
			transfers[block_height].header.height = block_height;
			transfers[block_height].transactions.push_back(api::Transaction{});
		}
		api::Transfer transfer;
		transfer.outputs.push_back(output);
		transfer.amount  = output.amount;
		transfer.address = output.address;
		transfer.ours    = true;
		transfers[block_height].transactions.back().transfers.push_back(transfer);
		//		}
		return true;
	}
	void unlock(Height block_height, const api::Output &output) {
		for (size_t i = 0; i != locked_outputs.size(); ++i) {
			if (locked_outputs.at(i).amount == output.amount &&
			    locked_outputs.at(i).global_index == output.global_index) {
				locked_outputs.erase(locked_outputs.begin() + i);
				--i;
			}
		}
		if (!add_incoming_output(block_height, output, true))
			return;
		invariant(
		    unlocked_outputs.insert(std::make_pair(output.global_index, std::make_pair(block_height, output.amount)))
		        .second,
		    "");
	}

public:
	virtual bool add_incoming_output(const api::Output &output) override {
		return add_incoming_output(output.height, output, false);
	}
	std::map<KeyImage, std::vector<Hash>> memory_spent;
	bool is_memory_spent(const api::Output &output) const { return memory_spent.count(output.key_image) != 0; }
	void unlock(Height height, Timestamp timestamp) {
		std::vector<api::Output> to_unlock;
		for (size_t i = 0; i != locked_outputs.size(); ++i)
			if (m_currency.is_block_or_timestamp_block(locked_outputs.at(i).unlock_block_or_timestamp)) {
				if (locked_outputs.at(i).unlock_block_or_timestamp <= height)
					to_unlock.push_back(locked_outputs.at(i));
			} else {
				if (locked_outputs.at(i).unlock_block_or_timestamp <= timestamp)
					to_unlock.push_back(locked_outputs.at(i));
			}
		for (auto &&unl : to_unlock)
			unlock(height, unl);
	}
	Amount add_incoming_keyimage(Height block_height, const KeyImage &ki) override {
		if (ki == KeyImage{})
			return 0;
		std::vector<api::Output> to_unlock;
		for (size_t i = 0; i != locked_outputs.size(); ++i)
			if (locked_outputs.at(i).key_image == ki)
				to_unlock.push_back(locked_outputs.at(i));
		for (auto &&unl : to_unlock)
			unlock(block_height, unl);
		bool ki_exists      = all_keyimages.count(ki) != 0;
		bool unspent_exists = ki_exists && outputs.count(all_keyimages.at(ki)) != 0;
		if (!unspent_exists)
			return 0;
		auto existing_output = outputs.at(all_keyimages.at(ki));
		invariant(outputs.erase(all_keyimages.at(ki)) == 1, "");

		if (transfers.count(block_height) == 0) {
			transfers[block_height].header.height = block_height;
			transfers[block_height].transactions.push_back(api::Transaction{});
		}
		api::Transfer transfer;
		transfer.outputs.push_back(existing_output);
		transfer.amount  = -static_cast<SignedAmount>(existing_output.amount);
		transfer.address = existing_output.address;
		transfer.ours    = true;
		transfers[block_height].transactions.back().transfers.push_back(transfer);
		return existing_output.amount;
	}
	void add_transaction(
	    Height height, const Hash &tid, const PreparedWalletTransaction &pwtx, const api::Transaction &ptx) override {
		//		transactions[height].push_back(ptx);
	}

	bool api_add_unspent(std::vector<api::Output> *result, Amount *total_amount, const std::string &address,
	    Height height, Amount max_amount = std::numeric_limits<Amount>::max()) const {
		for (auto &&la : outputs) {
			if (!is_memory_spent(la.second) && la.second.height <= height &&
			    (address.empty() || la.second.address == address)) {
				result->push_back(la.second);
				*total_amount += la.second.amount;
				if (*total_amount > max_amount)
					return false;
			}
		}
		return true;
	}
	std::vector<api::Output> api_get_locked_or_unconfirmed_unspent(const std::string &address, Height height) const {
		std::vector<api::Output> result;
		for (auto &&la : outputs) {
			if (!is_memory_spent(la.second) && la.second.height > height &&
			    (address.empty() || la.second.address == address))
				result.push_back(la.second);
		}
		for (const auto &la : locked_outputs)
			if (!is_memory_spent(la) && (address.empty() || la.address == address))
				result.push_back(la);
		return result;
	}

	std::vector<api::Block> api_get_transfers(const std::string &address, Height *from_height, Height *to_height,
	    bool forward, size_t desired_tx_count = std::numeric_limits<size_t>::max()) const {
		std::vector<api::Block> result;
		for (auto mit = transfers.lower_bound(*from_height); mit != transfers.lower_bound(*to_height); ++mit) {
			//			api::Block block;
			//			block.header.height = mit->second.header.height;
			//			block.transactions.push_back(api::Transaction{});
			//			for(auto && tr : mit->second.transactions)
			//				for(auto && t : tr.transfers)
			//					if(address.empty() || t.address
			//== address)
			//						block.transactions.back().transfers.push_back(t);
			//			result.push_back(block);
			result.push_back(mit->second);
		}
		return result;
	}
	// virtual std::vector<api::Output>
	// api_get_locked_or_unconfirmed_unspent(const std::string &address, Height
	// height)
	// const;
	api::Balance get_balance(const std::string &address, Height height) const {
		api::Balance balance;
		for (auto &&la : outputs)
			if (!is_memory_spent(la.second) && (address.empty() || la.second.address == address)) {
				if (la.second.height <= height) {
					auto uit = unlocked_outputs.find(la.first);
					if (uit != unlocked_outputs.end() &&
					    uit->second.first > height)  // recently unlocked, so unconfirmed
						WalletStateBasic::combine_balance(balance, la.second, 1, 0);
					else
						WalletStateBasic::combine_balance(balance, la.second, 0, 1);
				} else
					WalletStateBasic::combine_balance(balance, la.second, 1, 0);
			}
		for (auto &&la : locked_outputs)
			//			if(!is_memory_spent(la)) // WalletStateBasic
			// does not perform this check, because it requires
			// iterating either all used keyimages or all lock index
			if (address.empty() || la.address == address)
				WalletStateBasic::combine_balance(balance, la, 1, 0);
		return balance;
	}
};

void test_wallet_state(common::CommandLine &cmd) {
	common::Random random{};
	logging::ConsoleLogger logger;
	Currency currency("main");
	Config config(cmd);
	config.data_folder = "../tests/scratchpad";
	const auto db_name = config.get_data_folder("wallet_cache") + "/test_wallet_state";
	WalletStateTest::DB::delete_db(db_name);
	WalletState::DB wallet_state_db(platform::O_OPEN_ALWAYS, db_name);
	WalletStateTest ws(logger, config, currency, wallet_state_db);
	WalletStateModel wm(currency);

	std::map<Amount, size_t> next_si;
	size_t next_gi = 0;
	std::set<KeyImage> used_keyimages;
	std::set<KeyImage> output_keyimages;

	std::vector<std::string> addresses{"address1", "address2", "address3", ""};

	bool VIEW_ONLY           = false;
	const Height TEST_HEIGHT = 2000;

	if (!VIEW_ONLY)
		for (size_t i = 0; i != 1024; ++i) {
			KeyImage ki;
			ki.data[0] = random() % 256;
			ki.data[1] = random() % 16;
			ki.data[2] = 1;
			Hash ha;
			ha.data[0] = ki.data[0];
			ha.data[1] = ki.data[1];
			ha.data[2] = ki.data[2];
			if (ki != KeyImage{})
				wm.memory_spent[ki].push_back(ha);
		}
	ws.memory_spent = wm.memory_spent;
	//	for(auto && ki : wm.memory_spent)
	//		std::cout << "spent " << ki.first << std::endl;

	std::map<std::string, SignedAmount> global_transfer_balances;

	const Timestamp TEST_TIMESTAMP = currency.max_block_height * 2;

	for (Height ha = 1; ha != TEST_HEIGHT; ++ha) {
		api::Transaction ptx;
		size_t spend_outputs = (random() % 16);
		if (spend_outputs < 10 && ha != TEST_HEIGHT - 1) {
			for (size_t j = 0; j != spend_outputs; ++j) {
				KeyImage ki;
				if (random() % 4 == 0 || output_keyimages.empty()) {
					ki.data[0] = random() % 256;
					ki.data[1] = random() % 16;
					ki.data[2] = 1;
				} else {
					auto num = random() % output_keyimages.size();
					auto oit = output_keyimages.begin();
					for (; num-- > 0;)
						++oit;
					ki = *oit;
				}
				if (used_keyimages.insert(ki).second) {  // We never get same ki from blockchain
					api::Output spending_output;
					if (ws.try_adding_incoming_keyimage(ki, &spending_output)) {
						api::Transfer transfer;
						transfer.amount -= static_cast<SignedAmount>(spending_output.amount);
						transfer.address = spending_output.address;
						transfer.ours    = true;
						transfer.outputs.push_back(spending_output);
						ptx.transfers.push_back(transfer);
					}
					invariant(ws.add_incoming_keyimage(ha, ki) == wm.add_incoming_keyimage(ha, ki), "");
				}
			}
		}
		size_t add_outputs = (random() % 8);
		if (add_outputs < 3 && ha != TEST_HEIGHT - 1) {
			for (size_t j = 0; j != add_outputs; ++j) {
				api::Output output;
				size_t dc     = 5 + (random() % 5);
				size_t am     = 1 + (random() % 9);
				output.height = ha;
				output.amount = am * Currency::DECIMAL_PLACES.at(dc);
				//				output.dust    = currency.is_dust(output.amount);
				output.stack_index  = next_si[output.amount];
				output.global_index = next_gi;
				next_si[output.amount] += 1;
				next_gi += 1;
				output.address = addresses.at(random() % (addresses.size() - 1));  // last one is empty
				if (random() % 20 == 0)
					output.unlock_block_or_timestamp = (3 * ha / 4) + random() % (TEST_HEIGHT / 2);
				else if (random() % 20 == 1)
					output.unlock_block_or_timestamp =
					    TEST_TIMESTAMP + currency.difficulty_target * ((3 * ha / 4) + random() % (TEST_HEIGHT / 2));
				if (!VIEW_ONLY) {
					output.key_image.data[0] = random() % 256;
					output.key_image.data[1] = random() % 16;
					output.key_image.data[2] = 1;
					output_keyimages.insert(output.key_image);
				}
				if (ws.try_add_incoming_output(output)) {
					api::Transfer transfer;
					transfer.amount += output.amount;
					transfer.address = output.address;
					transfer.ours    = true;
					transfer.locked  = output.unlock_block_or_timestamp != 0;
					transfer.outputs.push_back(output);
					ptx.transfers.push_back(transfer);
				}
				auto inc1 = wm.add_incoming_output(output);
				auto inc2 = ws.add_incoming_output(output);
				invariant(inc1 == inc2, "");
			}
		}
		if (ha == TEST_HEIGHT - 1) {
			auto ba = wm.get_balance(std::string(), TEST_HEIGHT - 1);
			std::cout << "Total coins remains before final spend"
			          << (ba.locked_or_unconfirmed_outputs + ba.spendable_outputs + ba.spendable_dust_outputs)
			          << " spent " << wm.all_keyimages.size() << std::endl;
			for (const auto &ki : output_keyimages) {
				//				if (used_keyimages.insert(ki).second) {  // We
				// never get same ki from blockchain
				api::Output spending_output;
				if (ws.try_adding_incoming_keyimage(ki, &spending_output)) {
					api::Transfer transfer;
					transfer.amount -= static_cast<SignedAmount>(spending_output.amount);
					transfer.address = spending_output.address;
					transfer.ours    = true;
					transfer.outputs.push_back(spending_output);
					ptx.transfers.push_back(transfer);
				}
				invariant(ws.add_incoming_keyimage(ha, ki) == wm.add_incoming_keyimage(ha, ki), "");
				//				}
			}
		}
		ws.add_transaction(ha, crypto::cn_fast_hash(&ha, sizeof(ha)), PreparedWalletTransaction{}, ptx);
		const Timestamp uti =
		    TEST_TIMESTAMP + ha * currency.difficulty_target + random() % currency.block_future_time_limit;
		wm.unlock(ha, uti);
		ws.unlock(ha, uti);
		for (Height wi = 0; wi != 25; ++wi) {  // [-20..5) range around tip
			if (ha + wi < 20)
				continue;
			for (const auto &addr : addresses) {
				auto ba1 = wm.get_balance(addr, ha + wi - 20);
				auto ba2 = ws.get_balance(addr, ha + wi - 20);
				if (ba1 != ba2 || ha == TEST_HEIGHT - 1) {
					std::vector<api::Output> a1;
					Amount total_amount1 = 0;
					std::vector<api::Output> a2;
					Amount total_amount2 = 0;
					bool res1            = wm.api_add_unspent(&a1, &total_amount1, addr, ha + wi - 10);
					bool res2            = ws.api_add_unspent(&a2, &total_amount2, addr, ha + wi - 10);
					std::sort(a1.begin(), a1.end(), &less_output);
					std::sort(a2.begin(), a2.end(), &less_output);
					std::vector<api::Output> la1 = wm.api_get_locked_or_unconfirmed_unspent(addr, ha + wi - 10);
					std::vector<api::Output> la2 = ws.api_get_locked_or_unconfirmed_unspent(addr, ha + wi - 10);

					ba1 = wm.get_balance(addr, ha + wi - 20);
					ba2 = ws.get_balance(addr, ha + wi - 20);
					invariant(res1 == res2 && total_amount1 == total_amount2 &&
					              std::equal(a1.begin(), a1.end(), a2.begin(), a2.end(), eq_output),
					    "");
				}
				invariant(ba1 == ba2, "");
			}
		}
		for (const auto &addr : addresses) {
			std::map<std::string, SignedAmount> transfer_balances1;
			std::map<std::string, SignedAmount> transfer_balances2;
			Height from_height = ha;
			Height to_height   = ha + 1;
			auto tra1          = wm.api_get_transfers(addr, &from_height, &to_height, true);
			for (auto &&b1 : tra1)
				for (auto &&tr1 : b1.transactions)
					for (auto &&t1 : tr1.transfers)
						if (t1.ours && !t1.locked && (addr.empty() || t1.address == addr)) {
							invariant(!t1.address.empty(), "");
							transfer_balances1[addr] += t1.amount;
							//							invariant(transfer_balances1[addr]
							//>= 0, "");
							if (transfer_balances1[addr] == 0)
								transfer_balances1.erase(addr);
						}
			from_height = ha;
			to_height   = ha + 1;
			auto unl2   = ws.api_get_unlocked_transfers(addr, from_height, to_height);
			for (auto &&u : unl2)
				if (addr.empty() || u.address == addr) {
					invariant(!u.address.empty(), "");
					transfer_balances2[addr] += u.amount;
					//					invariant(transfer_balances2[addr] >= 0,
					//"");
					if (transfer_balances2[addr] == 0)
						transfer_balances2.erase(addr);
				}
			auto tra2 = ws.api_get_transfers(addr, &from_height, &to_height, true);
			for (auto &&b1 : tra2)
				for (auto &&tr1 : b1.transactions)
					for (auto &&t1 : tr1.transfers)
						if (t1.ours && !t1.locked && (addr.empty() || t1.address == addr)) {
							invariant(!t1.address.empty(), "");
							transfer_balances2[addr] += t1.amount;
							//							invariant(transfer_balances2[addr]
							//>= 0, "");
							if (transfer_balances2[addr] == 0)
								transfer_balances2.erase(addr);
						}
			invariant(transfer_balances1 == transfer_balances2, "");
			if (transfer_balances1.count(addr) != 0) {
				global_transfer_balances[addr] += transfer_balances1[addr];
				invariant(global_transfer_balances[addr] >= 0, "");
				if (global_transfer_balances[addr] == 0)
					global_transfer_balances.erase(addr);
			}
		}
		Amount sum1 = 0;
		Amount sum2 = 0;
		for (auto &&bit : global_transfer_balances)
			if (bit.first.empty())
				sum1 += bit.second;
			else
				sum2 += bit.second;
		invariant(sum1 == sum2, "");
	}
	//	for (auto uk : output_keyimages) {
	//		invariant(ws.add_incoming_keyimage(TEST_HEIGHT, uk) ==
	// wm.add_incoming_keyimage(TEST_HEIGHT, uk), "");
	//	}
	for (auto addr : addresses) {
		auto ba1 = wm.get_balance(addr, TEST_HEIGHT + 10);
		auto ba2 = ws.get_balance(addr, TEST_HEIGHT + 10);
		api::Balance zero;
		if (!VIEW_ONLY)  // we cannot spend to zero
			invariant(ba1 == zero && ba2 == zero, "");
	}
	invariant(global_transfer_balances.empty(), "");
	std::cout << "Testing wallet state finished" << std::endl;
}
