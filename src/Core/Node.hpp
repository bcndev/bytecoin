// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <condition_variable>
#include <functional>
#include <iostream>
#include <mutex>
#include <thread>
#include "BlockChainFileFormat.hpp"
#include "BlockChainState.hpp"
#include "http/BinaryRpc.hpp"
#include "http/JsonRpc.hpp"
#include "http/Server.hpp"
#include "p2p/P2P.hpp"
#include "p2p/P2PClientBasic.hpp"
#include "p2p/P2PClientNew.hpp"
#include "platform/PreventSleep.hpp"
#include "rpc_api.hpp"

namespace bytecoin {

// a bit different commit periods to make most commits not simultaneous
static const float SYNC_TIMEOUT           = 20;  // If sync does not return, select different sync node after
static const int DOWNLOAD_CONCURRENCY     = 4;
static const int DOWNLOAD_QUEUE           = 10;  // number of block requests sent before receiving reply
static const int DOWNLOAD_BLOCK_WINDOW    = DOWNLOAD_CONCURRENCY * DOWNLOAD_QUEUE * 2;
static const float RETRY_DOWNLOAD_SECONDS = 10;

class Node {
public:
	typedef std::function<bool(Node *, http::Client *, http::RequestData &&, json_rpc::Request &&, std::string &)>
	    JSONRPCHandlerFunction;
	typedef std::function<bool(Node *, http::Client *, common::IInputStream &, json_rpc::Request &&, std::string &)>
	    BINARYRPCHandlerFunction;

	explicit Node(logging::ILogger &, const Config &, BlockChainState &);
	bool on_idle();

	// binary method
	bool on_sync_blocks(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::SyncBlocks::Request &&, api::bytecoind::SyncBlocks::Response &);
	bool on_sync_mempool(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::SyncMemPool::Request &&, api::bytecoind::SyncMemPool::Response &);

	bool on_get_raw_transaction(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::GetRawTransaction::Request &&, api::bytecoind::GetRawTransaction::Response &);
	bool on_get_raw_block(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::GetRawBlock::Request &&, api::bytecoind::GetRawBlock::Response &);
	bool on_get_block_header(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::GetBlockHeader::Request &&, api::bytecoind::GetBlockHeader::Response &);

	api::bytecoind::GetStatus::Response create_status_response() const;
	api::bytecoind::GetStatistics::Response create_statistics_response() const;
	// json_rpc_node
	bool on_get_status(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::GetStatus::Request &&, api::bytecoind::GetStatus::Response &);
	bool on_get_statistics(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::GetStatistics::Request &&, api::bytecoind::GetStatistics::Response &);
	bool on_get_archive(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::GetArchive::Request &&, api::bytecoind::GetArchive::Response &);
	bool on_get_random_outputs(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::GetRandomOutputs::Request &&, api::bytecoind::GetRandomOutputs::Response &);
	bool handle_send_transaction(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::SendTransaction::Request &&, api::bytecoind::SendTransaction::Response &);
	bool handle_check_sendproof(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::CheckSendproof::Request &&, api::bytecoind::CheckSendproof::Response &);
	bool on_getblocktemplate(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::GetBlockTemplate::Request &&r, api::bytecoind::GetBlockTemplate::Response &);
	void getblocktemplate(
	    const api::bytecoind::GetBlockTemplate::Request &, api::bytecoind::GetBlockTemplate::Response &);
	bool on_get_currency_id(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::GetCurrencyId::Request &&, api::bytecoind::GetCurrencyId::Response &);
	void submit_block(const BinaryArray &blockblob, api::BlockHeader *info);
	bool on_submitblock(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::SubmitBlock::Request &&, api::bytecoind::SubmitBlock::Response &);
	bool on_submitblock_legacy(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::SubmitBlockLegacy::Request &&, api::bytecoind::SubmitBlockLegacy::Response &);
	bool on_get_last_block_header(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::GetLastBlockHeaderLegacy::Request &&, api::bytecoind::GetLastBlockHeaderLegacy::Response &);
	bool on_get_block_header_by_hash(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::GetBlockHeaderByHashLegacy::Request &&, api::bytecoind::GetBlockHeaderByHashLegacy::Response &);
	bool on_get_block_header_by_height(http::Client *, http::RequestData &&, json_rpc::Request &&,
	    api::bytecoind::GetBlockHeaderByHeightLegacy::Request &&,
	    api::bytecoind::GetBlockHeaderByHeightLegacy::Response &);

	bool on_json_rpc(http::Client *, http::RequestData &&, http::ResponseData &);
	bool on_binary_rpc(http::Client *, http::RequestData &&, http::ResponseData &);

	BlockChainState &m_block_chain;
	const Config &m_config;

protected:
	// We read from both because any could be truncated/corrupted
	std::unique_ptr<LegacyBlockChainReader> m_block_chain_reader1;
	std::unique_ptr<LegacyBlockChainReader> m_block_chain_reader2;
	std::unique_ptr<http::Server> m_api;
	std::unique_ptr<platform::PreventSleep> m_prevent_sleep;
	struct LongPollClient {
		http::Client *original_who = nullptr;
		http::RequestData original_request;
		json_rpc::Request original_json_request;
		api::bytecoind::GetStatus::Request original_get_status;
	};
	std::list<LongPollClient> m_long_poll_http_clients;
	void advance_long_poll();

	bool m_block_chain_was_far_behind;
	logging::LoggerRef m_log;
	PeerDB m_peer_db;
	P2P m_p2p;
	platform::UDPMulticast multicast;
	platform::Timer m_multicast_timer;
	void send_multicast();
	void on_multicast(const std::string &addr, const unsigned char *data, size_t size);

	const Timestamp m_start_time;
	platform::Timer m_commit_timer;
	std::unique_ptr<platform::PreventSleep> prevent_sleep;
	void db_commit();

	bool check_trust(const np::ProofOfTrust &);
	bool check_trust(const ProofOfTrustLegacy &);
	uint64_t m_last_stat_request_time = 0;  // TODO - Timestamp type after getting rid of old p2p
	// Prevent replay attacks by only trusting requests with timestamp > than previous request

	class P2PProtocolBytecoin : public P2PProtocolBasic {
		Node *const m_node;
		void after_handshake();

	protected:
		virtual void on_disconnect(const std::string &ban_reason) override;

		virtual void on_msg_bytes(size_t downloaded, size_t uploaded) override;
		virtual CORE_SYNC_DATA get_sync_data() const override;
		virtual std::vector<PeerlistEntryLegacy> get_peers_to_share() const override;

		virtual void on_immediate_protocol_switch(unsigned char first_byte) override;
		virtual void on_first_message_after_handshake() override;
		virtual void on_msg_handshake(COMMAND_HANDSHAKE::request &&) override;
		virtual void on_msg_handshake(COMMAND_HANDSHAKE::response &&) override;
		virtual void on_msg_notify_request_chain(NOTIFY_REQUEST_CHAIN::request &&) override;
		virtual void on_msg_notify_request_chain(NOTIFY_RESPONSE_CHAIN_ENTRY::request &&) override;
		virtual void on_msg_notify_request_objects(NOTIFY_REQUEST_GET_OBJECTS::request &&) override;
		virtual void on_msg_notify_request_objects(NOTIFY_RESPONSE_GET_OBJECTS::request &&) override;
		virtual void on_msg_notify_request_tx_pool(NOTIFY_REQUEST_TX_POOL::request &&) override;
		virtual void on_msg_timed_sync(COMMAND_TIMED_SYNC::request &&) override;
		virtual void on_msg_timed_sync(COMMAND_TIMED_SYNC::response &&) override;
		virtual void on_msg_notify_new_block(NOTIFY_NEW_BLOCK::request &&) override;
		virtual void on_msg_notify_new_transactions(NOTIFY_NEW_TRANSACTIONS::request &&) override;
		virtual void on_msg_notify_checkpoint(NOTIFY_CHECKPOINT::request &&) override;
#if bytecoin_ALLOW_DEBUG_COMMANDS
		virtual void on_msg_network_state(COMMAND_REQUEST_NETWORK_STATE::request &&) override;
		virtual void on_msg_stat_info(COMMAND_REQUEST_STAT_INFO::request &&) override;
#endif
	public:
		explicit P2PProtocolBytecoin(Node *node, P2PClient *client)
		    : P2PProtocolBasic(node->m_config, node->m_p2p.get_unique_number(), client), m_node(node) {}
		~P2PProtocolBytecoin();
		Node *get_node() const { return m_node; }
	};
	std::unique_ptr<P2PProtocol> client_factory(P2PClient *client) {
		return std::make_unique<P2PProtocolBytecoin>(this, client);
	}
	class DownloaderV11 {  // torrent-style sync&download from legacy v1 clients
		Node *const m_node;
		BlockChainState &m_block_chain;

		std::map<P2PProtocolBytecoin *, size_t> m_good_clients;  // -> # of downloading blocks
		size_t total_downloading_blocks = 0;
		std::list<P2PProtocolBytecoin *> m_who_downloaded_block;
		P2PProtocolBytecoin *m_chain_client = nullptr;
		bool m_chain_request_sent           = false;
		platform::Timer m_chain_timer;  // If m_chain_client does not respond for long, disconnect it

		struct DownloadCell {
			Hash bid;
			Height expected_height = 0;
			NetworkAddress bid_source;    // for banning culprit in case of a problem
			NetworkAddress block_source;  // for banning culprit in case of a problem
			P2PProtocolBytecoin *downloading_client = nullptr;
			std::chrono::steady_clock::time_point request_time;
			RawBlock rb;
			enum Status { DOWNLOADING, DOWNLOADED, PREPARING, PREPARED } status = DOWNLOADING;
			bool protect_from_disconnect = false;
			PreparedBlock pb;
		};
		std::deque<DownloadCell>
		    m_download_chain;  // ~20-1000 of blocks we wish to have downloading (depending on current median size)
		                       //		Height m_protected_start = 0;
		Height m_chain_start_height = 0;
		std::deque<Hash> m_chain;     // 10k-20k of hashes of the next wanted blocks
		NetworkAddress chain_source;  // for banning culprit in case of a problem
		platform::Timer m_download_timer;
		std::chrono::steady_clock::time_point log_request_timestamp;
		std::chrono::steady_clock::time_point log_response_timestamp;

		// multicore preparator
		std::vector<std::thread> threads;
		std::mutex mu;
		std::map<Hash, PreparedBlock> prepared_blocks;
		std::deque<std::tuple<Hash, bool, RawBlock>> work;
		std::condition_variable have_work;
		platform::EventLoop *main_loop = nullptr;
		bool quit                      = false;
		void add_work(std::tuple<Hash, bool, RawBlock> &&wo);
		void thread_run();

		void start_download(DownloadCell &dc, P2PProtocolBytecoin *who);
		void stop_download(DownloadCell &dc, bool success);
		void on_chain_timer();
		void on_download_timer();
		void advance_chain();

	public:
		DownloaderV11(Node *node, BlockChainState &block_chain);
		~DownloaderV11();

		void advance_download();
		bool on_idle();

		uint32_t get_known_block_count(uint32_t my) const;
		void on_connect(P2PProtocolBytecoin *);
		void on_disconnect(P2PProtocolBytecoin *);
		const std::map<P2PProtocolBytecoin *, size_t> &get_good_clients() const { return m_good_clients; }
		void on_msg_notify_request_chain(P2PProtocolBytecoin *, const NOTIFY_RESPONSE_CHAIN_ENTRY::request &);
		void on_msg_notify_request_objects(P2PProtocolBytecoin *, const NOTIFY_RESPONSE_GET_OBJECTS::request &);
		void on_msg_timed_sync(const CORE_SYNC_DATA &payload_data);
	};
	class P2PProtocolBytecoinNew : public P2PProtocolNew {
		Node *const m_node;
		void after_handshake();

		void on_download_timer();

	protected:
		void on_disconnect(const std::string &ban_reason) override;

		void on_msg_bytes(size_t, size_t) override;

		void on_msg_handshake(np::Handshake::Request &&req) override;
		void on_msg_handshake(np::Handshake::Response &&req) override;
		void on_msg_find_diff(np::FindDiff::Request &&) override;
		void on_msg_find_diff(np::FindDiff::Response &&) override;
		void on_msg_sync_headers(np::SyncHeaders::Request &&) override;
		void on_msg_sync_headers(np::SyncHeaders::Response &&) override;
		void on_msg_get_transactions(np::GetTransactions::Request &&) override;
		void on_msg_get_transactions(np::GetTransactions::Response &&) override;
		void on_msg_get_pool_hashes(np::GetPoolHashes::Request &&) override;
		void on_msg_get_pool_hashes(np::GetPoolHashes::Response &&) override;
		void on_msg_relay_block_header(np::RelayBlockHeader &&) override;
		void on_msg_relay_transaction_desc(np::RelayTransactionDescs &&) override;
#if bytecoin_ALLOW_DEBUG_COMMANDS
		void on_msg_get_peer_statistics(np::GetPeerStatistics::Request &&) override;
#endif
		void on_first_message_after_handshake() override;
		np::TopBlockDesc get_top_block_desc() const override;
		std::vector<NetworkAddress> get_peers_to_share() const override;

	public:
		explicit P2PProtocolBytecoinNew(Node *node, P2PClient *client)
		    : P2PProtocolNew(
		          node->m_config, node->m_block_chain.get_currency(), node->m_p2p.get_unique_number(), client)
		    , m_node(node)
		    , m_download_timer(std::bind(&P2PProtocolBytecoinNew::on_download_timer, this)) {}
		Node *get_node() const { return m_node; }

		std::set<std::pair<Height, Hash>> can_download_blocks;
		std::set<Hash> downloading_blocks;
		platform::Timer m_download_timer;  // Reset when start download or receive block
	};
	class DownloaderV3 {  // torrent-style sync&download from new v3 clients
		Node *const m_node;
		BlockChainState &m_block_chain;

		//		std::set<std::pair<Height, Hash>> fill_can_download(Hash hash)const;

		std::map<P2PProtocolBytecoinNew *, size_t> m_good_clients;  // -> # of downloading blocks
		size_t total_downloading_blocks = 0;
		std::list<P2PProtocolBytecoinNew *> m_who_downloaded_block;
		P2PProtocolBytecoinNew *m_find_diff_client = nullptr;
		int m_find_diff_iteration                  = 0;
		Hash m_find_diff_bid;
		P2PProtocolBytecoinNew *m_sync_headers_client = nullptr;
		Hash m_sync_headers_previous_block_hash;
		platform::Timer m_chain_timer;  // If m_chain_client does not respond for long, disconnect it

		struct DownloadCell {
			Hash bid;
			Height expected_height = 0;
			NetworkAddress block_source;  // for banning culprit in case of a problem
			P2PProtocolBytecoinNew *downloading_client = nullptr;
			std::chrono::steady_clock::time_point request_time;
			RawBlock rb;
			enum Status { DOWNLOADING, DOWNLOADED, PREPARING, PREPARED } status = DOWNLOADING;
			bool protect_from_disconnect = false;
			PreparedBlock pb;
		};
		std::deque<DownloadCell>
		    m_download_chain;  // ~20-1000 of blocks we wish to have downloading (depending on current median size)
		platform::Timer m_download_timer;
		std::chrono::steady_clock::time_point log_request_timestamp;
		std::chrono::steady_clock::time_point log_response_timestamp;

		// multicore preparator
		std::vector<std::thread> threads;
		std::mutex mu;
		std::map<Hash, PreparedBlock> prepared_blocks;
		std::deque<std::tuple<Hash, bool, RawBlock>> work;
		std::condition_variable have_work;
		platform::EventLoop *main_loop = nullptr;
		bool quit                      = false;
		void add_work(std::tuple<Hash, bool, RawBlock> &&wo);
		void thread_run();

		void start_download(DownloadCell &dc, P2PProtocolBytecoinNew *who);
		void stop_download(DownloadCell &dc, bool success);
		void on_chain_timer();
		void on_download_timer();
		void advance_chain();

	public:
		DownloaderV3(Node *node, BlockChainState &block_chain);
		~DownloaderV3();

		void advance_download();
		bool on_idle();

		uint32_t get_known_block_count(uint32_t my) const;
		void on_connect(P2PProtocolBytecoinNew *);
		void on_disconnect(P2PProtocolBytecoinNew *);
		const std::map<P2PProtocolBytecoinNew *, size_t> &get_good_clients() const { return m_good_clients; }

		void on_msg_find_diff(P2PProtocolBytecoinNew *, np::FindDiff::Response &&resp);
		void on_msg_sync_headers(P2PProtocolBytecoinNew *, np::SyncHeaders::Response &&resp);
		void on_msg_get_transactions(P2PProtocolBytecoinNew *, np::GetTransactions::Response &&resp);
	};

	std::set<P2PProtocolBytecoin *> broadcast_protocols;
	void broadcast(P2PProtocolBytecoin *exclude, const BinaryArray &data);
	std::set<P2PProtocolBytecoinNew *> broadcast_protocols_new;
	void broadcast_new(P2PProtocolBytecoinNew *exclude, const BinaryArray &binary_header);
	void broadcast_new(P2PProtocolBytecoinNew *exclude, const std::vector<np::TransactionDesc> &transaction_descs);
	DownloaderV11 m_downloader;
	DownloaderV3 m_downloader_v3;

	bool on_api_http_request(http::Client *, http::RequestData &&, http::ResponseData &);
	void on_api_http_disconnect(http::Client *);

	void sync_transactions(P2PProtocolBytecoin *);
	void sync_transactions(P2PProtocolBytecoinNew *) {}

	static std::unordered_map<std::string, JSONRPCHandlerFunction> m_jsonrpc_handlers;
	static const std::unordered_map<std::string, BINARYRPCHandlerFunction> m_binaryrpc_handlers;
};

}  // namespace bytecoin
