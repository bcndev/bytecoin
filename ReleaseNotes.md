## Release Notes

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
- Fixed rare `bytecoind` crashes while downloading blockchain.
- Fixed stuck dowloading from misbehaving nodes.
- Added early support of JSON-RPC API basic authentification that prevents CSRF attacks.
- Added (experimental) support of 32-bit platforms.


### v3.0.0-beta-20180206

- Project is moved to the new public GitHub repository.
