## Release Notes

### v3.3.0

*Consensus update (hard fork)*

- Voting starts immediately, once 90% of mined blocks contain votes for update, the update height will be automatically selected so that consensus update will happen approximately 2 weeks after that.
- Market fees - any transaction fee including 0 is now legal for all transactions. Miners will increase block size only if it is profitable for them in a short run.

*General improvements*

- Better priority and exclusive nodes logic.
- Seed nodes are now contacted approximately once per day (greatly helps to catch up after `bytecoind` is started for users who run it after delay of several weeks or more).
- Binary methods now share single access point `/binary_rpc`.
- Code for consensus upgrade voting correctly counts votes on both main chain and each side chain.
- Limited on incoming connections (default is 100).
- Fixed ignored external port on peer handshake (made connects through exposed non-standard ports to nodes behind NAT impossible).
- Groestl hash function is updated from the official source.
- Keccak permutation function is updated from the official source.
- `bytecoind` never searches for `blocks.bin` and `blockindex.bin` outside the data folder.
- now when you specify `--p2p-bind-address`, but not `--p2p-external-port`, p2p external port will be set to p2p bind port. When you wish NAT tunneling, good practice is to specify both.

*Command line changes/additions*

- Paranoid mode to check every byte of blockchain when downloading (usually checks only blocks beyond the last checkpoint).
- *Warning:* Now `walletd` exits by default after `--create-wallet` and `--set-password` operations. This change can break your scripts. If you need the wallet running after those commands, you can add `--launch-after-command` parameter
- Now you can use `--set-password` with `--export-view-only` and `--backup-wallet-data`, to encrypt result wallet with a different password.
- Fixed bug with `walletd` not returning `api::WALLETD_BIND_PORT_IN_USE` error code when the JSON API port is in use and using inproc `bytecoind`.
- Fixed bug with `bytecoind` not returning `api::BYTECOIND_BIND_PORT_IN_USE` error code when the JSON API port is in use.
- `walletd` now prints address after creation of wallet.
- `walletd` now prints deprecation warning when using inproc `bytecoind`.
- `walletd` now binds to port `9070` on testnet and `10070` on stagenet resp. by default.

*General API improvements*

- Optimisation of JSON RPC calls (2x speed up on very large responses).
- Made the `jsonrpc` argument mandatory with value "2.0" in all JSON RPC calls according to the spec.
- JSON RPC `id` is required now according to spec.
- JSON RPC error's additional data moved into `data` object inside the `error` object according to spec.
- Now any field in requests that daemons do not understand will be reported as a error.
- Much better error handling, more specific error codes.

*Specific API improvements*

- New `get_block_header` method for blockchain structure inspection (to replace `getblockheaderbyhash`, `getblockheaderbyheight`, and `getlastblockheader` legacy methods).
- New `get_wallet_info` method.
- New `VIEW_ONLY_WALLET` (`-304`) error code, returned from `create_transaction`.
- In methods supporting longpoll (`get_statu`s and `get_block_template`) all longpoll arguments are now optional. So, for example, if you are interested in `outgoing_peer_count` only, you can specify only `outgoing_peer_count` in request and get response when `outgoing_peer_count` changes. Changes to other fields will not trigger response to longpoll.
- New `ADDRESS_FAILED_TO_PARSE` (`-4`) and `ADDRESS_NOT_IN_WALLET` (`-1002`) error codes, returned from lots of methods
- New fields in get_addresses request/response to iterate through list of addresses
- Now `top_block_timestamp_median` returned correctly from get_status JSON RPC methods.
- New `need_signatures` fields in APIs returning raw transactions.
- `check_sendproof` now returns values from sendproof in response if proof is valid.
- All methods return new correct values for `block_size` and `transactions_cumulative_size`.
- `get_raw_block` and `get_block_header` now return `orphan_status` and `depth` (consistent with `height_or_depth` fields where top block is `-1`).
- `get_random_amounts` has no more depth limit of 128 block (distribution would be skewed a bit for very large depths).
- `get_statistics` response now includes much more information.
- `submit_block` now returns `block_header` in result.
- All `transfer` objects now have `transaction_hash` field - especially useful when processing `unlocked_transfers` in result of `get_transfers` method.

*API deprecations (will be removed in version 3.4.0)*

- In all `output` and `transaction` objects `unlock_time` is deprecated (renamed to `unlock_block_or_timestamp`).
- In all `output` objects `global_index` deprecated (renamed to `index`).
- In `get_random_outputs` request `outs_count` is deprecated (renamed to `output_count`).
- In `get_transfers` request `desired_transactions_count` is deprecated (renamed to `desired_transaction_count`).
- In all `transaction` objects 'binary_size' is deprecated (renamed to `size`).

*Incompatible API changes*

- `get_raw_transaction` method now returns json error `-5` if transaction not found.
- Deprecated `prev_hash` field remains only in result of legacy methods (`getblockheaderbyhash`, `getblockheaderbyheight`, and `getlastblockheader` legacy methods), use 'previous_block_hash' instead.
- Deprecated `total_fee_amount` field remains only in result of legacy methods (`getblockheaderbyhash`, `getblockheaderbyheight`, and `getlastblockheader`), use `transactions_fee` instead.
- Deprecated `transactions_cumulative_size` field remains only in result of legacy methods (`getblockheaderbyhash`, `getblockheaderbyheight`, and `getlastblockheader`), use `transactions_size` instead.

*Incompatible API changes (likely to affect only developers of block explorers)*

- In all raw block objects `global_indices` renamed to `output_indexes`.
- In all raw transaction objects `vin`, `vout` renamed to `inputs`, `outputs` resp. 
- In all raw output objects `key` renamed to `public_key`.
- In all raw output objects `target` object removed and all its fields moved into raw output object.
- In all raw coinbase input objects `block_index` renamed to `height`.
- In all raw header objects (including `parent_block`) `miner_tx`, `base_transaction_branch` renamed to `coinbase_transaction`, `coinbase_transaction_branch` resp.
- In all raw input and raw output objects, `tag`:`ff` renamed to `type`:`coinbase` and `tag`:`02` renamed to `type`:`key`.

*Testnet/Stagenet related*

- New command line parameter `--net=test|stage|main` configures daemons for testnet, stagenet, or mainnet resp.
- For testnet time multiplier can now be set to speed up all processes 10x, 100x or even more.
- When participating in testnet or stagenet, `bytecoind` now uses UDP Multicast to announce/discover other bytecoind nodes in local network. Thus in most local networks testnet will self-assemble without seed nodes. In mainnet multicasts are disabled due to anonymity concerns.
- Testnet/Stagenet now have fixed 1MB max block size limit.

### v3.2.4

- Added the testnet functionality.
- Fixed `WRONG_BLOCKCHAIN` problem when walletd ends up in a state where it could not sync with `bytecoind`.
- Put a stop to infinite attempts to download blockchain from nodes lagging behind.

### v3.2.3

- Fixed issues in SQLite logic in x86-32 daemons.
- Fixed a bug in the downloader, which hinders normal downloading blocks.

### v3.2.2

- Fixed an output bufferization issue in the `bytecoind` daemon.
- Fixed a rare downloader's crash on Windows.

### v3.2.1

- Fixed a severe bug in the downloader.

### v3.2.0

- *Warning:* This version uses different format of `bytecoind` database and `walletd` caches, they will be upgraded to the new format on a first start of daemons. Prepare for downtime of up to 2 hours depending on your wallet size and computer performance.
- __API change:__ Renamed methods `create_send_proof` and `check_send_proof` to `create_sendproof` and `check_sendproof` respectively (along with input parameter `send_proof` that became `sendproof`).
- Fixed minor bugs found in the beta release.

### v3.2.0-beta-20180723

- *Warning:* This version uses different format of `bytecoind` database and `walletd` caches, they will be upgraded to the new format on a first start of daemons. Prepare for downtime of up to 2 hours depending on your wallet size and computer performance.
- Reworked the wallet cache storage to use 3x less space and run 2x faster.
- Intoduced the 'payment queue' which stores and resends all sent transactions until they are successfully confirmed. This fixes issues with sent transactions lost due to chain reorganizations under high loads.
- Changed the logic of the `send_transaction` method: It never returns an error, its result is always `broadcast` because all transactions are first stored in the payment queue and later sent for sure.
- Improved the downloader to reduce sync times.
- Made the `params` argument optional in all JSON RPC calls according to the spec.
- Improved error handling in the `create_transaction` and `send_transaction` methods (distinct error codes for common errors).
- Fixed issue when requests to `walletd` with address is not in the wallet (it now fails with an appopriate error).
- Changed the mechanism of the memory pool size adjustment to give miners more freedom in selecting transactions for including in blocks.
- The `walletd` command line parameter `--backup-wallet` is renamed to `--backup-wallet-data` and now it makes a hot backup of the wallet cache, wallet history, and payment queue in bulk (backward compatibility is maintained).
- Extended the number of bits of the cumulative difficulty parameter (it is now 128 bits).
- Made entering passwords in terminals/consoles invisible on all major platforms.
- Allowed entered passwords to contain Unicode characters on Windows (not recommended though).
- Changed the logic of the `create_addresses` method when called with at least one existing spend key and without setting `creation_timestamp` (or setting it to `0`). `walletd` will perform rescan of the whole blockchain in this case.
- Added a better error message when `walletd` fails to be authenticated at `bytecoind`.
- Started versioning binary API methods for better detection of changes.

### v3.1.1

- Added `--backup-blockchain` `--backup-wallet` command-line flags to `bytecoind` and `walletd` resp. to hot-copy blockchain and wallet data (wallet file and wallet cache).
- Fixed behavior of the `walletd`'s methods such as `get_balance`, which until now returned zero balance for addresses not belonging to the opened wallet file.

### v3.1.0

- Updated `README` in the part of linking with `boost` libraries to prevent using inappropriate versions.
- __API change:__ Renamed field `added_bc_transactions` to `added_raw_transactions` in response of the `sync_mem_pool` method.
- __API change:__ Renamed fields `bc_header` to `raw_header`, `bc_transactions` to `raw_transactions` in response of the `sync_blocks` method.
- __API addition:__ Added the `get_raw_transaction` method to the `bytecoind` API to get a transaction by its hash.
- __API addition:__ Added the `prevent_conflict_with_transactions` field to the `create_transaction` `walletd`'s method to be used by resilient payout queues.
- Speeded up memory pool to handle large transaction load.
- Fixed rare bug in `bytecoind` when less than possible transactions were included in block for mining during large transaction load.
- Fixed rare bug in `bytecoind` when cumulative difficulty of the block was calculated incorrectly, leading to increased orphan block percentage. (`bytecoind` will now perform quickcheck on start once for all exisitng blockchain database, fixing all differences.)
- Fixed rare bug in `bytecoind` when it stopped accepting new P2P connections or stopped answering API calls under high transaction load.

### v3.0.4

- Made early fixes to downloader to prevent long lagging behind.

### v3.0.3

- Fixed consensus bug.

### v3.0.2

- __API change:__ In `create_transaction`, `spend_address` parameter of type `string` is changed to `spend_addresses` of type `[]string`. This change is likely to affect only Web wallets developers.
- __API change:__ In `sync_mem_pool`, `added_binary_transactions` of type `string` is changed to `added_bc_transactions` of type `bytecoin::TransactionPrefix`. This change breaks compatilibilty between new and old `walletd` and `bytecoind`, so make sure they are both the same version.

### v3.0.1

- Added `walletd` option `--export-keys` to export keys in legacy format (for example, to print on paper and put in a vault).
- Changed logic of how `walletd` truncates cache in old wallet files: On writable media, it now tries to do that right after opening.
- Fixed wallet state undo logic, which rarely lead to sync crashes/stucks in version 3.0.0.
- Added test wallets for import/export testing.

### v3.0.0

- Added HTTPS support between walletd and bytecoind.
- Added generating and checking send proofs.
- Added SQLite database support as an alternative to LMDB.
- Added several legacy bytecoind RPC API methods for miners.

### v3.0.0-beta-20180219

- Reworked creating transactions with 100,000+ unspent outputs to make it much faster.
- Fixed rare crashes of `bytecoind` while downloading blockchain.
- Fixed stuck dowloading from misbehaving nodes.
- Added early support of JSON-RPC API basic authentification that prevents CSRF attacks.
- Added (experimental) support of 32-bit platforms.

### v3.0.0-beta-20180206

- Project is moved to the new public GitHub repository.
- Added `walletd` option `--export-keys` to export keys in legacy format (for example, to print on paper and put in a vault).
- Changed logic of how `walletd` truncates cache in old wallet files: On writable media, it now tries to do that right after opening.
- Fixed wallet state undo logic, which rarely lead to sync crashes/stucks in version 3.0.0.
- Added test wallets for import/export testing.
