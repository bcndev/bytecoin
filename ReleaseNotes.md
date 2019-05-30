## Release Notes

### v3.4.4 (Amethyst)

- `walletd` can now sync most of the blockchain from static files (tremendously increasing efficiency for public nodes), reverting to RPC only for the (small) part of blockchain after last hard checkpoint.
- Fixed bug when during wallet sync some transactions from memory pool were requested and processed more than once

### v3.4.3 (Amethyst)

- In `get_transfers` `walletd`'s method error is returned if `from_height` is larger than `to_height` or top block height.
- `WALLET_FILE_EXISTS (209)` is correctly returned when `walletd` is instructed to overwrite an existing wallet.
- Fixed a bug when wrong error message was displayed when passing some invalid addresses to `walletd`'s `create_transaction` RPC method.
- LMDB virtual memory usage by `bytecoind` and `walletd` reduced from fixed 512Gb to approx. actual blockchain database/wallet cache size.
- `walletd` will not undo sync progress, if connected node is behind wallet state and behind latest hard checkpoint. It will wait for a node to advance to a checkpoint.
- Wallet cache now takes much less space, especially for wallets with small number of transactions.
- For all TCP sockets `keep_alive` option is now set after they are created (with default timeouts for each system, common value is 2 hours), solving very rare bug when there would be no reply to long poll ever for external services (like block explorers) calling from remote machines.
- All paths now subject to substitution of `~` (Mac & Linux) and `%appdata%` (Windows). Also, on Linux and Max backslash is no more considered path separator.

*API tweaks*
- JSON numbers are interpreted according to spec throughout API, for example 10.01E2 is now good value for height (1001). This helps integration with some weird languages.
- Better error messages throughout API when required parameters are not specified.
- More strict JSON RPC - excess fields on top level are no more allowed in requests.
- `bytecoind`'s binary version of `sync_blocks` now uses separate zero overhead response to save traffic during sync.

*Incompatible API changes*
- `bytecoind`'s `getblocktemplate`, `submitblock` and JSON versions of `sync_blocks` and `sync_mempool` now require private authorization. This helps with preventing excess load on public nodes.
- deprecated field `outs_count` in `bytecoind.get_random_outputs` removed.

### v3.4.2 (Amethyst)

- Fixed merge mining related bug affecting blocks version 4 (amethyst). All miners not upgraded to 3.4.2 at the moment of consensus update will produce broken blocks.
- Fixed crash when disconnecting Ledger while scanning blockchain.
- Fixed behavior of the `get_transfers` `walletd`'s method when transactions from a memory pool are wrongly returned for some `from_height` and `to_height` values.

*Incompatible API changes*
- In response to the `get_wallet_info` `walletd`'s method, boolean field `amethyst` changed to string `wallet_type`

### v3.4.2-beta-20190412

- Fixed a stagenet voting bug.

### v3.4.2-beta-20190411

- Fixed problem when `bytecoind` stops responding via JSON RPC API.
- Tweaked random output distribution for mixins.
- The `walletd` daemon now better utilizes CPU during sync (cores use 100%, if available).
- During mining, the `bytecoind` daemon now prefers blocks received via `submit_block` API to other blocks, if difficulty are equal. This will slightly increase mining profitability for lucky miners.
- Added back `create_transaction` optimization for large wallets which was accidentally removed in version 3.4.1.
- Fixed bug when transaction size is `0` in all `walletd` API calls.
- Fixed bug when transaction timestamp is `0` in `get_transaction` of `bytecoind` API call for transaction, if it has been already included in the blockchain.
- Transaction fields `prefix_hash` and `inputs_hash` are now correctly set in various `bytecoind` API calls, if `need_redundant_data` is set.
- Improved command line processing in `walletd`, especially if wrong combination of options specified.
- Trezor and Ledger early support in `walletd`.

*Incompatible API changes*
- Deprecated `binary_size` field removed from transaction in all contexts. Please use the `size` field.

### v3.4.1 (Amethyst)

- New cryptography reviewed, some important tweaks added - thanks for all feedback to those who contributed.
- Derivation paths of wallet secrets modified. Now dishonest modification of any secret in view-only wallet is immediately clear to auditor.
- Output seed generation simplified.
- Proof of sH ~ H contained in view-only wallet is simplified.

*API additions*

- Added `has_view_secret_key` field in the `get_wallet_info` method of `walletd`.

### hardware-wallets-alpha-20190214

- Added an early support for hardware wallets.
- Fully working Trezor Model T prototype.
- Partial support for Ledger Nano.

*Current Limitations*
- If you disconnect a hardware wallet while `walletd` is running, it will immediately crash.
- Works in the stagenet only.

### v3.4.0 (Amethyst)

- Sendproofs are now in base58 format, which eases copying and sharing.
- New addresses now start from `bcnZ` prefix.

*Command line changes/additions*

- New walletd command-line parameter `--wallet-type` to create legacy wallets (`--create-wallet` by default creates new HD wallet).

*API removal*

- Removed `amethyst_only` flag in the `get_random_outputs` bytecoind method.


### v3.4.0-beta-20190123

*Strong support for audit-compatible wallets*

- All new unlinkable addresses are now auditable, so separate auditable address type removed from system.
- View-only HD wallet is now guaranteed to have the same balance as original wallet. So owner of HD wallet cannot spend any funds in a way that view-only version of the same wallet does not see the fact.
- If view-only HD wallet was exported with --view-outgoing-addresses, it can also see all destination addresses in transactions that spend funds. If spender is sending to some address, he cannot make auditor see different destination address for this transaction. If spender is using sophisticated "out-of-blockchain shared secret" fraud, auditor will see random address, and spender will not be able to provide valid sendproof for this transaction.

*Consensus update (hard fork)*
- New crypto for legacy addresses (unlinkable-inspired), which prevents "burning bug" attacks on crypto level. This is important because such attacks cannot be reliably fixed on operational level.

*API additions*
- `amethyst_only` flag in `get_random_outputs` bytecoind method.

*Incompatible API changes (likely to affect only developers of block explorers)*

- In all raw block objects `output_indexes` renamed to `stack_indexes`.

### v3.4.0-beta-20181218

- Signatures are now fully prunable (but not yet pruned) via modification to transaction hash calculations.
- A view-only wallet now shows address balance even for non-auditable unlinkable addresses, but only if sender follows the protocol. If in doubt about sender's fair play, auditable addresses should be used instead.
- A view-only wallet can now be exported with or without ability to view transaction destination addresses.
- `bytecoind` will not automatically look for `blocks.bin` anywhere. If you need to import blocks from file, use `--import-blocks=<folder>` command line parameter.
- `bytecoind` command line parameters  `--ssl-certificate-pem-file`, `--ssl-certificate-password` removed, use ngnx in https proxy mode!

### v3.4.0-beta-20181212

*Consensus update (hard fork)*
- The release starts immediate voting in the stagenet. Voting in the mainnet will start when v3.4.0 is released.
- Introduce new unlinkable addresses, stored in new HD wallet. Single mnemonic is enough to restore all wallet addresses.
- Destination addresses can now be derived from blockchain with wallet secrets, so saving history is now unnecessary.
- Greatly simplified maximum block size calculations. Miners will now explicitly vote for maximum block size (up to hard limit of 2 MB), depending on how many expensive transactions are in memory pool. Reward penalties are removed and most other unnecessary checks on block/transactions sizes are also removed from consensus.
- New HD wallet is encrypted with chacha20 with salt (major improvement to previous wallet format)
- New auditable addresses, guaranteed to always have balance exactly equal to what view-only version of the same wallet shows (useful for public deposits).
- Signatures are now half size.
- The requirement that coinbase transactions are locked for 10 blocks is removed from consensus.
- Creating 6-digit dust (or other not round output amounts) are now prohibited by consensus rules.
- Minimum anonymity is now 3 (4 output references per input). This does not apply to dust or not round outputs.
- `bytecoind` now calculates output obfuscation value, and does not use less-than-ideal outputs for mix-in

*Command line changes/additions*
- New walletd command-line parameter to set creation time when importing keys or mnemonic (which have no inherent timestamp)
- New walletd command-line parameter to generate mnemonics
- New walletd command-line parameter to create unlinkable wallet from mnemonics
- New walletd command-line parameter to enable getting secrets bia JSON RPC API

*Specific API improvements*
- By default, getting secrets via JSON RPC API is disabled. 
- New walletd method 'get_wallet_records' with optional 'create' parameter can be used to get (creating if needed) wallet records from linkable wallet
- New walletd method `set_address_label` to set labels for addresses (labels are returned by `get_wallet_records`)
- New error code `TOO_MUCH_ANONYMITY` (`-305`) can be returned from `create_transaction`.

*API deprecations (will be removed in version 3.5.0)*
- `walletd` method `get_addresses` is marked as deprecated, use `get_wallet_records` instead.
- `walletd` method `get_view_key_pair` is marked as deprecated, use `get_wallet_info` with `need_secrets` set to true instead.
- `walletd` method 'create_transaction' has 'save_history' and 'save_history_error' deprecated, because history is now always implicitly saved to blockchain.
- `next_block_effective_median_size` renamed to `recommended_max_transaction_size` with `next_block_effective_median_size` deprecated.

*Incompatible API changes*
- `parent_block` is renamed to `root_block` in all contexts without deprecation, due to widespread confusion.

*Improvements to P2P protocol to handle large network load*
- Header relay instead of block body relay. In most cases receiver will reasemble block from memory pool. In rare case when this is not possible, the block body will be requested.
- Transaction description relay instead of transactions body relay. Only new transactions will be requested. Transaction descriptions contain most recent referenced block hash, so that receiver can easily distinguish between "wrong signatures due to malicious intent" and "wrong signatures due to chain reorganisations"
- Incremental memory pool sync with cut-off limit by fee/byte. Allows pools with huge assymetry in size to quickly get into stable state. 

*Other changes*
- Memory pool size increased to 4 MB.
- `walletd` will automatically rebuild wallet cache after upgrade to this version. This can take long time for large wallets.

### v3.3.3

- Fixed bug when `walletd` fails to create transactions for certain coins.

### v3.3.2

- Now all folders we get from user/system are normalized by removing excess slashes from the tail

### v3.3.1

- The `create_transaction` method can now create transactions with fee < 0.01 BCN iff both `fee_per_byte` and transaction size are small enough.
- In the `create_transaction` method, if `any_spend_address` is set to true, leaving `change_address` empty now sets it to first wallet address.
- Added amounts to the message of the `TRANSACTION_TOO_BIG` error so that you see how much you can actually send (with desired or zero anonymity).
- Added a new new flag `subtract_fee_from_amount` to the `create_transaction` method to indicate subtracting fee from receivers.
- Tweaked the distribution of mix-in outputs returned by the `get_random_outputs` method to make it .
- Fixed error in the `getblocktemplate` and `get_block_template` methods which returned wrong reserved_offset.

### v3.3.0

*Consensus update (hard fork)*

- Voting starts immediately, once 90% of mined blocks contain votes for update, the update height will be automatically selected so that consensus update will happen approximately 2 weeks after that.
- Market fees - any transaction fee including `0` is now legal for all transactions. Miners will increase block size only if it is profitable for them in a short run.

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
