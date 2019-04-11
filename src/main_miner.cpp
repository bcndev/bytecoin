// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <thread>
#include "Core/Config.hpp"
#include "Core/CryptoNoteTools.hpp"
#include "Core/Currency.hpp"
#include "Core/Difficulty.hpp"
#include "Core/TransactionExtra.hpp"
#include "CryptoNoteConfig.hpp"
#include "common/CommandLine.hpp"
#include "common/ConsoleTools.hpp"
#include "common/Varint.hpp"
#include "crypto/crypto.hpp"
#include "http/Agent.hpp"
#include "http/JsonRpc.hpp"
#include "rpc_api.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "version.hpp"

// Single-threaded, as this is enough for testNet.

static const char USAGE[] =
    R"(minerd. single-threaded to be light on cpu while running in background

Usage:
  minerd [options]

Options:
  -h --help                      Show this screen.
  -v --version                   Show version.
  --wallet-address=<address>     Address to receive mined coins (required).
  --bytecoind-address=<ip:port>  Single option for both daemon address and port.
  --limit=<N>                    Mine and submit specified number of blocks, then exit, 0 means no limit [Default: 0].
  --threads=<N>                  Not implemented yet - just start several copies of minerd.
  --boast=<text>                 Text to insert into coinbase transaction's extra nonce.
  --miner-secret=<hash_hex>      Turn on deterministic mining.
  --cm                           EXPERIMENTAL. Use CM with random virtual coins.
)";

using namespace cn;

struct MiningConfig {
	explicit MiningConfig(common::CommandLine &cmd)
	    : bytecoind_ip("127.0.0.1")
	    , bytecoind_port(parameters::RPC_DEFAULT_PORT)
	    , thread_count(std::thread::hardware_concurrency()) {
		if (const char *pa = cmd.get("--address", "Use --wallet-address instead"))
			mining_address = pa;
		if (const char *pa = cmd.get("--wallet-address"))
			mining_address = pa;
		if (const char *pa = cmd.get("--" CRYPTONOTE_NAME "d-address")) {
			ewrap(common::parse_ip_address_and_port(pa, &bytecoind_ip, &bytecoind_port),
			    std::runtime_error("Command line option --" CRYPTONOTE_NAME "d-address has wrong format"));
		} else
			throw std::runtime_error("--" CRYPTONOTE_NAME "d-address=ip:port argument is mandatory");
		if (const char *pa = cmd.get("--threads"))
			thread_count = common::integer_cast<size_t>(pa);
		if (const char *pa = cmd.get("--limit"))
			blocks_limit = common::integer_cast<size_t>(pa);
		if (const char *pa = cmd.get("--boast"))
			boast = pa;
		if (const char *pa = cmd.get("--miner-secret")) {
			if (!common::pod_from_hex(pa, &miner_secret))
				throw std::runtime_error("Miner Secret must be hash in hex");
			if (miner_secret == Hash{})
				throw std::runtime_error("Miner Secret must not be all zeroes");
		}
		cm = cmd.get_bool("--cm");
	}

	std::string mining_address;
	std::string bytecoind_ip;
	std::string boast;
	uint16_t bytecoind_port = 0;
	size_t thread_count     = 0;
	size_t blocks_limit     = 0;
	// Mine specified number of blocks, then exit, 0 == indefinetely
	Hash miner_secret;
	bool cm = false;
};

class HTTPMiner {
public:
	const MiningConfig &mining_config;

	http::Agent getwork_agent;
	std::unique_ptr<http::Request> getwork_request;
	http::Agent submit_agent;
	std::unique_ptr<http::Request> submit_request;
	platform::Timer getwork_retry;
	platform::Timer submit_retry;

	Currency currency;  // Need genesis_bid, will be changed to API method get_currency_id later
	crypto::CryptoNightContext crypto_context;
	BlockTemplate block{};
	api::cnd::GetBlockTemplate::Response block_response;
	uint64_t nonce        = 0;  // we use lower 4 bytes as a nonce.
	Difficulty difficulty = 0;  // used as a flag to mine/not mine

	struct FoundBlock {
		BlockTemplate block;
		common::BinaryArray cm_nonce;  // cm, if not empty
		std::vector<crypto::CMBranchElement> cm_merkle_branch;
	};
	std::deque<FoundBlock> found_blocks;
	size_t blocks_submitted = 0;
	// In MM boast is included into reserved space in block
	// In CM boast is included into cm_nonce

	explicit HTTPMiner(const MiningConfig &mining_config)
	    : mining_config(mining_config)
	    , getwork_agent(mining_config.bytecoind_ip, mining_config.bytecoind_port)
	    , submit_agent(mining_config.bytecoind_ip, mining_config.bytecoind_port)
	    , getwork_retry(std::bind(&HTTPMiner::send_getwork, this))
	    , submit_retry(std::bind(&HTTPMiner::send_submit, this))
	    , currency("main") {
		send_getwork();
	}
	bool on_idle() {
		if (difficulty == 0)
			return false;
		nonce++;
		BinaryArray long_hashing_data;
		BinaryArray cm_nonce;
		std::vector<crypto::CMBranchElement> cm_merkle_branch;
		Hash cm_merkle_root;
		if (mining_config.cm) {
			cm_nonce.resize(cm_nonce.size() + 7);
			common::uint_le_to_bytes(cm_nonce.data() + 3, 7, nonce);
			cm_nonce.push_back(0);  // So that next symbol is UTF-8 rune start
			common::append(cm_nonce,
			    BinaryArray{mining_config.boast.data(), mining_config.boast.data() + mining_config.boast.size()});
			if (crypto::rand<uint32_t>() % 2) {
				cm_merkle_branch.push_back(
				    crypto::CMBranchElement{static_cast<uint8_t>(crypto::rand<uint32_t>() % 4), crypto::rand<Hash>()});
				const size_t count = crypto::rand<uint32_t>() % 4;
				for (size_t i = 0; i != count; ++i) {
					const size_t depth = cm_merkle_branch.back().depth + 1 + crypto::rand<uint32_t>() % 4;
					cm_merkle_branch.push_back(
					    crypto::CMBranchElement{static_cast<uint8_t>(depth), crypto::rand<Hash>()});
				}
			}
			cm_merkle_root =
			    crypto::tree_hash_from_cm_branch(cm_merkle_branch, block_response.cm_prehash, block_response.cm_path);
			common::append(long_hashing_data, cm_nonce);
			common::append(long_hashing_data, std::begin(cm_merkle_root.data), std::end(cm_merkle_root.data));
		} else {
			common::uint_le_to_bytes(block.root_block.nonce, 4, nonce);
			auto body_proxy   = get_body_proxy_from_template(block);
			long_hashing_data = currency.get_block_long_hashing_data(block, body_proxy);
		}
		Hash hash = crypto_context.cn_slow_hash(long_hashing_data.data(), long_hashing_data.size());
		if (check_hash(hash, difficulty)) {
			common::console::set_text_color(common::console::BrightGreen);
			std::cout << "Miner found block !!!, will send ASAP" << std::endl;
			if (mining_config.cm) {
				std::cout << "    cm_nonce=" << common::to_hex(cm_nonce) << std::endl;
				std::cout << "    cm_merkle_root=" << cm_merkle_root << std::endl;
				for (const auto &cb : cm_merkle_branch)
					std::cout << "    cm_merkle_branch d=" << cb.depth << " h=" << cb.hash << std::endl;
			}
			common::console::set_text_color(common::console::Default);
			found_blocks.push_back(FoundBlock{block, cm_nonce, cm_merkle_branch});
			difficulty = 0;
			send_submit();
			return false;
		}
		return true;
	}
	void send_submit() {
		if (found_blocks.empty() || submit_request)
			return;
		api::cnd::SubmitBlock::Request req;
		req.blocktemplate_blob       = seria::to_binary(found_blocks.front().block);
		req.cm_nonce                 = found_blocks.front().cm_nonce;
		req.cm_merkle_branch         = found_blocks.front().cm_merkle_branch;
		http::RequestBody req_header = json_rpc::create_request("/json_rpc", api::cnd::SubmitBlock::method(), req);
		submit_request               = std::make_unique<http::Request>(submit_agent, std::move(req_header),
            [&](http::ResponseBody &&response) {
                submit_request.reset();
                api::cnd::SubmitBlock::Response resp;
                json_rpc::Response json_resp(response.body);
                json_rpc::Error err_resp;
                if (json_resp.get_error(err_resp)) {
                    common::console::set_text_color(common::console::BrightRed);
                    std::cout << "Json Error submitting block code=" << err_resp.code << " msg=" << err_resp.message
                              << std::endl;
                    common::console::set_text_color(common::console::Default);
                    if (!found_blocks.empty())  // Should not be empty, but...
                        found_blocks.pop_front();
                    send_submit();
                } else {
                    json_resp.get_result(resp);
                    common::console::set_text_color(common::console::BrightGreen);
                    std::cout << "Block submitted " << resp.block_header.hash << " orphan_status=" << resp.orphan_status
                              << std::endl;
                    common::console::set_text_color(common::console::Default);
                    if (!found_blocks.empty()) {  // Should not be empty, but...
                        found_blocks.pop_front();
                        blocks_submitted += 1;
                    }
                    if (mining_config.blocks_limit != 0 && blocks_submitted >= mining_config.blocks_limit) {
                        platform::EventLoop::cancel_current();
                    } else {
                        send_submit();
                    }
                }
            },
            [&](std::string err) { submit_retry.once(5); });
	}
	void send_getwork() {
		api::cnd::GetBlockTemplate::Request req{};
		req.wallet_address = mining_config.mining_address;
		req.miner_secret   = mining_config.miner_secret;
		if (!mining_config.cm)
			req.reserve_size = mining_config.boast.size();
		req.top_block_hash           = block_response.top_block_hash;
		req.transaction_pool_version = block_response.transaction_pool_version;
		http::RequestBody req_header = json_rpc::create_request("/json_rpc", "getblocktemplate", req);
		std::cout << "Miner send getblocktemplate top_block_hash=" << block_response.top_block_hash << std::endl;
		getwork_request = std::make_unique<http::Request>(getwork_agent, std::move(req_header),
		    [&](http::ResponseBody &&response) {
			    getwork_request.reset();
			    api::cnd::GetBlockTemplate::Response resp;
			    json_rpc::Error err_resp;
			    if (json_rpc::parse_response(response.body, resp, err_resp)) {
				    if (!mining_config.cm)
					    for (size_t i = 0; i != mining_config.boast.size(); ++i)
						    resp.blocktemplate_blob.at(resp.reserved_offset + i) = mining_config.boast[i];
				    block_response = resp;
				    seria::from_binary(block, resp.blocktemplate_blob);
				    set_root_extra_to_solo_mining_tag(block);
				    difficulty = resp.difficulty;
				    nonce      = crypto::rand<uint32_t>();
				    if (mining_config.miner_secret != Hash{}) {
					    block.timestamp = block.root_block.timestamp =
					        1550000000 + resp.height * currency.difficulty_target;
					    nonce = 0;
				    }
				    std::cout << "Miner received getblocktemplate difficulty=" << difficulty
				              << " top_block_hash=" << resp.top_block_hash << " #tx=" << block.transaction_hashes.size()
				              << std::endl;
				    for (const auto &ha : block.transaction_hashes)
					    std::cout << "tx=" << ha << std::endl;
				    getwork_retry.once(0.1f);
			    } else {
				    getwork_retry.once(10);
				    std::cout << "Json Error getting blocktemplate (will retry in 10 sec) code=" << err_resp.code
				              << " msg=" << err_resp.message << std::endl;
			    }
		    },
		    [&](std::string err) {
			    getwork_retry.once(5);
			    std::cout << "Network Error getting blocktemplate (will retry in 5 sec) err=" << err << std::endl;
		    });
	}
	static int main(int argc, const char *argv[]) try {
		common::console::UnicodeConsoleSetup console_setup;
		common::console::set_text_color(common::console::BrightRed);
		std::cout << "This miner is VERY INEFFICIENT and should be only used by team only for testnet" << std::endl;
		common::console::set_text_color(common::console::Default);

		common::CommandLine cmd(argc, argv);
		if (cmd.show_help(Config::prepare_usage(USAGE).c_str(), cn::app_version()))
			return 0;
		MiningConfig mining_config(cmd);
		if (cmd.show_errors())
			return 1;
		if (mining_config.mining_address.empty()) {
			std::cout << "--wallet-address=<addr> option is mandatory" << std::endl;
			return 1;
		}

		boost::asio::io_service io;
		platform::EventLoop run_loop(io);

		HTTPMiner miner(mining_config);
		while (!io.stopped()) {
			io.poll();
			if (!miner.on_idle())
				io.run_one();
		}
		return 0;
	} catch (const std::exception &ex) {
		std::cout << common::what(ex) << std::endl;
		return 1;
	}
};

int main(int argc, const char *argv[]) { return HTTPMiner::main(argc, argv); }
