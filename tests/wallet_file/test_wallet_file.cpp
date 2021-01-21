// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for
// details.

#include "Core/Config.hpp"
#include "Core/Wallet.hpp"
#include "Core/WalletHD.hpp"
#include "Core/WalletLegacy.hpp"
#include "common/BIPs.hpp"
#include "common/CommandLine.hpp"
#include "crypto/crypto.hpp"
#include "logging/ConsoleLogger.hpp"
#include "platform/DBmemory.hpp"
#include "platform/PathTools.hpp"

#include "test_wallet_file.hpp"

using namespace cn;

// test01.simplewallet.wallet
// format - simplewallet with cache
// no password
// created by simplewallet from bytecoin-2.1.2, several tx received and sent
// 24xTx43fFtNBUn5f6Fj1wC7y8JsbD4N1XS2s3Q8HzWxtfvERccTPX6e5ua1mf55Wm7Z4MiaWT7LPeiBxPtD8kU9V7z3kuex

// test02.wallet
// format - legacy walletd with cache (file truncated to 1000000 bytes due to
// git limitations)
// no password
// created by rpc-wallet-2.1.2, several tx received and sent
// 25HYsSBvERcePEb7LWrECYiPw4vpeG3MWCBxB3LbNC43issv7LEDp8gat9CRkq1ZusM85yZA6y2gTBfdUpJwyJKdDb8W8dk
// 29gEx3NRgooBHLdzQUGicXBtMdAtHaaDtf6aGZjbsgJrCSFVaRCT9SYat9CRkq1ZusM85yZA6y2gTBfdUpJwyJKdDZriJ8Y
// 23acTzmNBWFSDK12QNVucEdjRjTwPmXHsPwyXaYtc1yP9FviK5e5bMiat9CRkq1ZusM85yZA6y2gTBfdUpJwyJKdDaQapEx

// test03.wallet
// format - legacy walletd with cache (file truncated to 1000000 bytes due to
// git limitations)
// password - test03
// created by rpc-wallet-2.1.2, several tx received and sent
// 21vbqHu4mDLGyo7Q959fbggLU4Z6cXMfaDpUJuHQSY9b4bRfYGbv9hF4zcz3DBpH1y4kUop2HPKPsNb9WLBYE6U16w1V12t

// test04.wallet
// format - legacy walletd with cache and contacts (file truncated to 1000000
// bytes due to git limitations)
// password - test04
// created by GUI wallet 1.1.9.3, several tx received and sent
// 27TfAw84qKYEktQW9QvV94VkjNnRJuQ9JTrirjbQC5ASdRS233RAtENBNEZrGCSjPAFBNBReUsaQ8Jo82GTHLU4xQ28tTWU

// test05.wallet
// format - new walletd
// password - test05
// created by walletd 3.0.0
// 23ryfTTpryt8q3h5NFoMGs4BjM6jGmdQqUrtSuU4nM3oP8CKmXXwu6CcEYrwtUm2rx43LvihFEhKEfDagjQxWoLwDTX6XpC

// test05v.wallet - view-only version of test05.wallet

// test06.wallet
// format - new walletd
// no password
// created by walletd 3.0.0
// 27j6TP7du1SWKk4fVQa138VNhy339xa76jEBRajhHYnVeLaLs5HmSkEZ4FiLuLy87hgWYkSinGntREBMq3dvui11NkhsuUJ
// 23kJeyCgzH6JkTJqq1NNjrhXFYrfsUYvw2a9HhiEqVtRXK86HAu3uWWZ4FiLuLy87hgWYkSinGntREBMq3dvui11NiUKftd
// 28acio4hR2cjQPSBj8oYbjSYkFvVaPdQTH44HsigJQiSgr6S5BaAZkzZ4FiLuLy87hgWYkSinGntREBMq3dvui11Ng9YMtq

// test06v.wallet - view-only version of test06.wallet

const std::string tmp_name("../tests/scratchpad/test_wallet_file.tmp");

static void test_body(const Currency &currency, const std::string &path, const std::string &password,
    const std::vector<std::string> &addresses, bool view_only, bool test_create_addresses) {
	logging::ConsoleLogger logger;
	WalletLegacy wallet(currency, logger, tmp_name, password);
	if (wallet.is_view_only() != view_only)
		throw std::runtime_error("view_only test failed for " + path);
	auto records = wallet.test_get_records();
	if (!crypto::keys_match(wallet.get_view_secret_key(), wallet.get_view_public_key()))
		throw std::runtime_error("view keys do not match for " + path);
	WalletRecord first_record = records.at(0);
	for (auto &&a : addresses) {
		AccountAddress v_address;
		if (!currency.parse_account_address_string(a, &v_address))
			throw std::runtime_error("failed to parse address " + a);
		invariant(v_address.type() == typeid(AccountAddressLegacy), "");
		auto &address = boost::get<AccountAddressLegacy>(v_address);
		if (address.V != wallet.get_view_public_key())
			throw std::runtime_error("view_public_key test failed for " + path);
		size_t pos = 0;
		for (; pos != records.size(); ++pos)
			if (records.at(pos).spend_public_key == address.S)
				break;
		if (pos == records.size())
			throw std::runtime_error("spend_public_key not found for " + path);
		if (view_only && records.at(pos).spend_secret_key != crypto::SecretKey{})
			throw std::runtime_error("non empty secret spend key for " + path);
		if (!view_only && !crypto::keys_match(records.at(pos).spend_secret_key, records.at(pos).spend_public_key))
			throw std::runtime_error("spend keys do not match for " + path);
		if (address.S != records.at(pos).spend_public_key)
			throw std::runtime_error("spend_public_key test failed for " + path);
		records.erase(records.begin() + pos);
	}
	if (!records.empty())
		throw std::runtime_error("excess wallet records for " + path);
	if (!test_create_addresses)
		return;
	const auto initial_oldest_timestamp = wallet.get_oldest_timestamp();
	bool rescan_from_ct                 = false;
	std::vector<AccountAddress> new_addresses;
	try {
		wallet.generate_new_addresses({first_record.spend_secret_key}, first_record.creation_timestamp + 1,
		    first_record.creation_timestamp + 1, &new_addresses, &rescan_from_ct);
	} catch (const Wallet::Exception &) {
		if (!view_only)
			throw;
		return;
	}
	if (view_only)
		throw std::runtime_error("View-only wallet created addresses " + path);
	std::cout << "Oldest timestamp is " << wallet.get_oldest_timestamp() << std::endl;
	if (rescan_from_ct || initial_oldest_timestamp != wallet.get_oldest_timestamp())
		throw std::runtime_error("Increasing timestamp of exising address should not lead to rescan " + path);
	wallet.generate_new_addresses({crypto::SecretKey{}}, 0, 1600000000, &new_addresses, &rescan_from_ct);
	std::cout << "Oldest timestamp is " << wallet.get_oldest_timestamp() << std::endl;
	if (rescan_from_ct || initial_oldest_timestamp != wallet.get_oldest_timestamp())
		throw std::runtime_error("Adding new secret key should not lead to rescan " + path);
	wallet.generate_new_addresses({first_record.spend_secret_key}, first_record.creation_timestamp - 1,
	    first_record.creation_timestamp + 1, &new_addresses, &rescan_from_ct);
	std::cout << "Oldest timestamp is " << wallet.get_oldest_timestamp() << std::endl;
	if (!rescan_from_ct || initial_oldest_timestamp == wallet.get_oldest_timestamp())
		throw std::runtime_error("Reducing timestamp of exising address should lead to rescan " + path);
}

static void test_single_file(const Currency &currency, const std::string &path, const std::string &password,
    const std::vector<std::string> &addresses, bool view_only) {
	platform::copy_file(path, tmp_name);
	test_body(currency, tmp_name, password, addresses, view_only, false);
	{
		platform::FileStream fs(tmp_name, platform::O_READ_EXISTING);
		auto si = fs.seek(0, SEEK_END);
		if (si != WalletLegacy::wallet_file_size(addresses.size()))
			throw std::runtime_error("truncated/overwritten wallet size wrong " + path);
	}
	test_body(currency, tmp_name, password, addresses, view_only, true);
	platform::remove_file(tmp_name);
}

void test_wallet_file(const std::string &path_prefix) {
	platform::DBmemory::run_tests();

	common::CommandLine cmd;
	Config config(cmd);
	Currency currency(config);

	logging::ConsoleLogger logger;
	WalletHDJson wa(currency, logger, cn::Bip32Key::create_random_bip39_mnemonic(128), 0, std::string{});
	const auto da = wa.save_json_data();
	WalletHDJson wa2(currency, logger, da);
	invariant(wa.get_first_address() == wa2.get_first_address(), "");

	test_single_file(currency, path_prefix + "/test01.simplewallet.wallet", "",
	    {"24xTx43fFtNBUn5f6Fj1wC7y8JsbD4N1XS2s3Q8HzWxtfvERccTPX6e5ua"
	     "1mf55Wm7Z4MiaWT7LPeiBxPtD8kU9V7z3kuex"},
	    false);
	test_single_file(currency, path_prefix + "/test02.wallet", "",
	    {"25HYsSBvERcePEb7LWrECYiPw4vpeG3MWCBxB3LbNC43issv7LEDp8gat9"
	     "CRkq1ZusM85yZA6y2gTBfdUpJwyJKdDb8W8dk",
	        "29gEx3NRgooBHLdzQUGicXBtMdAtHaaDtf6aGZjbsgJrCSFVaRCT9SYat9"
	        "CRkq1ZusM85yZA6y2gTBfdUpJwyJKdDZriJ8Y",
	        "23acTzmNBWFSDK12QNVucEdjRjTwPmXHsPwyXaYtc1yP9FviK5e5bMiat9"
	        "CRkq1ZusM85yZA6y2gTBfdUpJwyJKdDaQapEx"},
	    false);
	test_single_file(currency, path_prefix + "/test03.wallet", "test03",
	    {"21vbqHu4mDLGyo7Q959fbggLU4Z6cXMfaDpUJuHQSY9b4bRfYGbv9hF4zc"
	     "z3DBpH1y4kUop2HPKPsNb9WLBYE6U16w1V12t"},
	    false);
	test_single_file(currency, path_prefix + "/test04.wallet", "test04",
	    {"27TfAw84qKYEktQW9QvV94VkjNnRJuQ9JTrirjbQC5ASdRS233RAtENBNE"
	     "ZrGCSjPAFBNBReUsaQ8Jo82GTHLU4xQ28tTWU"},
	    false);
	test_single_file(currency, path_prefix + "/test05.wallet", "test05",
	    {"23ryfTTpryt8q3h5NFoMGs4BjM6jGmdQqUrtSuU4nM3oP8CKmXXwu6CcEY"
	     "rwtUm2rx43LvihFEhKEfDagjQxWoLwDTX6XpC"},
	    false);
	test_single_file(currency, path_prefix + "/test05v.wallet", "test05",
	    {"23ryfTTpryt8q3h5NFoMGs4BjM6jGmdQqUrtSuU4nM3oP8CKmXXwu6CcEY"
	     "rwtUm2rx43LvihFEhKEfDagjQxWoLwDTX6XpC"},
	    true);
	test_single_file(currency, path_prefix + "/test06.wallet", "",
	    {"27j6TP7du1SWKk4fVQa138VNhy339xa76jEBRajhHYnVeLaLs5HmSkEZ4F"
	     "iLuLy87hgWYkSinGntREBMq3dvui11NkhsuUJ",
	        "23kJeyCgzH6JkTJqq1NNjrhXFYrfsUYvw2a9HhiEqVtRXK86HAu3uWWZ4F"
	        "iLuLy87hgWYkSinGntREBMq3dvui11NiUKftd",
	        "28acio4hR2cjQPSBj8oYbjSYkFvVaPdQTH44HsigJQiSgr6S5BaAZkzZ4F"
	        "iLuLy87hgWYkSinGntREBMq3dvui11Ng9YMtq"},
	    false);
	test_single_file(currency, path_prefix + "/test06v.wallet", "",
	    {"27j6TP7du1SWKk4fVQa138VNhy339xa76jEBRajhHYnVeLaLs5HmSkEZ4F"
	     "iLuLy87hgWYkSinGntREBMq3dvui11NkhsuUJ",
	        "23kJeyCgzH6JkTJqq1NNjrhXFYrfsUYvw2a9HhiEqVtRXK86HAu3uWWZ4F"
	        "iLuLy87hgWYkSinGntREBMq3dvui11NiUKftd",
	        "28acio4hR2cjQPSBj8oYbjSYkFvVaPdQTH44HsigJQiSgr6S5BaAZkzZ4F"
	        "iLuLy87hgWYkSinGntREBMq3dvui11Ng9YMtq"},
	    true);
}
