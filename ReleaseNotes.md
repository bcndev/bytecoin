## Release Notes

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
