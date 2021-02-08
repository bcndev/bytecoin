## Introduction

The Armor Wallet Daemon (`walletd`, Armor RPC Wallet) is designed to manage a user's account while operating together with a Armor Node Daemon. To start the `walletd` you must pass a path to a wallet file as a command-line parameter which identifies the context the service will work within.

## Service Location

By default, the Armor Wallet Daemon is only bound to `127.0.0.1` (`localhost`) interface, so it can only be reached from the same computer it runs on. To bind it to all interfaces, use `--walletd-bind-address=0.0.0.0:58082` command line argument (note that specifying port is mandatory).

To make a JSON PRC request to the `walletd` you should make an HTTP POST request to an entry point:
```
http://<ip>:<port>/json_rpc
```
where:
* `<ip>` is the IPv4 address of the `walletd` service. If the service is on a local machine, use `127.0.0.1` instead of `localhost`.
* `<port>` is TCP port of `walletd`. By default the service is bound to `58082`.

## Curl Template

```
curl -s -u <user>:<pass> -X POST http://<ip>:<port>/json_rpc -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "id": "<id>", "method": "<method>", "params": {<params>}}'
```

## Methods

### Address and key management

| #   | Method               | Description                                                 |
|-----|----------------------|-------------------------------------------------------------|
| 1.  | `create_addresses`   | Adds addresses into the wallet file.                        |
| 2.  | `get_addresses`      | Returns a list of addresses extracted from the wallet file. |
| 3.  | `get_view_key_pair`  | Returns a view key pair shared by addresses.                |
| 4.  | `get_wallet_info`    | Returns basic information about the wallet.                 |
| 5.  | `get_wallet_records` | Returns records found in the wallet.                        |
| 6.  | `set_address_label`  | Sets a label to an address in the wallet.                   |

### Balance and history of transfers

| #   | Method              | Description                                                                   |
|-----|---------------------|-------------------------------------------------------------------------------|
| 7.  | `create_sendproof`  | Creates sendproof that money has been sent to an address.                     |
| 8.  | `get_balance`       | Returns balance for a single address or all addresses.                        |
| 9.  | `get_status`        | Returns combined status of `walletd` and `armord`.                         |
| 10. | `get_transaction`   | Returns transaction (only if it has transfer(s) to/from any address) by hash. |
| 11. | `get_transfers`     | Allows iterating through history of transfers to/from addresses.              |
| 12. | `get_unspents`      | Returns balance split into outputs.                                           |

### Sending money

| #   | Method               | Description                                                                                  |
|-----|----------------------|----------------------------------------------------------------------------------------------|
| 13. | `create_transaction` | Builds a transaction by specifying transfers you want to make and returns it for inspection. |
| 14. |`send_transaction`    | Sends previously created transaction to the network.                                         |

-----------------------------------------------------------------------------------------------------------------------

### 1. `create_addresses`

#### About

Either adds new or imports existing addresses (with corresponding spend keys) into a wallet file. To generate a new random key pair (and address, of course), you append an empty string to a `secret_spend_keys` array. To import an existing address, you append its secret spend key to a `secret_spend_keys` array.

If you import existing addresses created some time ago, specify `creation_timestamp` so the `walletd` can rescan the blockchain starting from that point of time, looking for transactions to/from those addresses. If no `creation_timestamp` is included, or if it is set to `0`, `walletd` will rescan the whole blockchain from the beginning.

Adding an existing secret spend key is not an error, it will just return a corresponding address together with that key.

This method returns arrays of both addresses and secret spend keys, where each address corresponds to each secret key.

Before this method returns, it performs `fdatasync` on the wallet file, so if you add lots of addresses, it makes sense to batch them instead of calling this method individually per address.

#### Input (params)

| Field                | Type       | Mandatory | Default value | Description                               |
|----------------------|------------|-----------|---------------|-------------------------------------------|
| `secret_spend_keys`  | `[]string` | Yes       | -             | Array of secret spend keys.               |
| `creation_timestamp` | `uint32`   | No        | `0`           | Min of creation timestamps of spend keys. |

#### Output

| Field                | Type       | Description                         |
|----------------------|------------|-------------------------------------|
| `secret_spend_keys`  | `[]string` | Array of created secret spend keys. |
| `addresses`          | `[]string` | Array of created addresses.         |

#### Example 1

Let's create two new addresses.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "create_addresses",
  "params": { "secret_spend_keys": ["", ""] }
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "addresses": [
      "232A9qxGyKLanKmP7Q9TBA6Jv1tPx5AxM3ExRFhSijaVYVY4FtboZDSfortdXLzEqZQkan6xqXb73XiJND3tqnQY6yJMXXL",
      "275e2yS1sD6bpNCAbfZa5HH1C3FU8SZnLCSnEE2VLmdi5u373YQNsgCfortdXLzEqZQkan6xqXb73XiJND3tqnQY6stvysa"
    ],
    "secret_spend_keys": [
      "5506af58782aaae7603d80bcca0785affa2289e70242624eb3af28f8ca03bb02",
      "50b3e1b926ca731b634c6084532daf1796775ed54a91cd89371363bb43b4d907"
    ]
  }
}
```

### 2. `get_addresses`

#### About

Returns an array of all addresses stored in a wallet file. If `view_only` flag is `true`, there are no
secret spend keys in the file, so the `walletd` is not allowed to spend money from any address.

#### Input (params)

| Field                    | Type            | Mandatory | Default value | Description                                         |
|--------------------------|-----------------|-----------|---------------|-----------------------------------------------------|
| `need_secret_spend_keys` | `bool`          | No        | `false`       | Send true if need secret spend keys.                |
| `from_address`           | `uint32`        | No        | `0`           | Position of address in the wallet starting from `0`.|
| `max_count`              | `uint32`        | No        | `2^32-1`      | Max number of addresses to show.                    |

#### Output

| Field                 | Type       | Description          |
|-----------------------|------------|----------------------|
| `addresses`           | `[]string` | Array of addresses.  |
| `total_address_count` | `uint32`   | Number of addresses. |

#### Example 1

Let's request all the addresses in the current wallet file.

__Input:__

```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_addresses"
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "total_address_count": 3,
    "addresses": [
      "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
      "26T3ixqCLeRDF5J7j6W5VrifKxLmafkDX4wariwdze3yMUgx6BKLNTMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6hoLkAr",
      "25kdF3s7Yp64Zuw5JAnPQGFouFjDuTT7BFYPKBh3MiUvSq8UY1X7q1uZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6iL4SKW"
    ]
  }
}
```

#### Example 2

Let's request `2` addresses, starting from position `1` in the file (count starts from `0`).

__Input:__

```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_addresses",
  "params": {
  	"from_address": 1,
  	"max_count": 2
  }
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "total_address_count": 3,
    "addresses": [
      "26T3ixqCLeRDF5J7j6W5VrifKxLmafkDX4wariwdze3yMUgx6BKLNTMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6hoLkAr",
      "25kdF3s7Yp64Zuw5JAnPQGFouFjDuTT7BFYPKBh3MiUvSq8UY1X7q1uZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6iL4SKW"
    ]
  }
}
```



### 3. `get_view_key_pair`

#### About

THIS IS A DEPRECATED METHOD, DO NOT USE IT.</br>
Returns a view key pair common for all addresses in a wallet file.

#### Input (params)

Empty

#### Output

| Field             | Type     | Description      |
|-------------------|----------|------------------|
| `public_view_key` | `string` | Public view key. |
| `secret_view_key` | `string` | Secret view key. |
| `import_keys`     | `string` |                  |

#### Example 1

Let's receive a pair of view keys from the current wallet file.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_view_key_pair"
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "secret_view_key": "e7ceaac5db5a6ddfeac377425bed8021e5405a450b8596d2505b204b8fc0cf0a",
    "public_view_key": "6d242ce8a98404c272612b8ddf7fb6f81474b9bfe8e7fb76da03ae80a3edce32",
    "import_keys": "329e20ee1852027d455059b0c64434050706b18b7cac0619704bbe64d64756d16d242ce8a98404c272612b8ddf7fb6f81474b9bfe8e7fb76da03ae80a3edce3276d6acf14c24f3869ff010426627fe41724e7f6458202694c82ed32ac602f00de7ceaac5db5a6ddfeac377425bed8021e5405a450b8596d2505b204b8fc0cf0a"
  }
}
```



### 4. `get_wallet_info`

#### About

Returns basic information about the wallet.

#### Input (params)

| Field                    | Type            | Mandatory | Default value | Description                                                        |
|--------------------------|-----------------|-----------|---------------|--------------------------------------------------------------------|
| `need_secrets`           | `bool`          | No        | `false`       | Secret keys and/or mnemonic will be returned if set to true.       |

#### Output

| Field                         | Type        | Description                                                                                             |
|-------------------------------|-------------|---------------------------------------------------------------------------------------------------------|
| `view_only`                   | `bool`      | Shows whether a wallet is view-only or not.                                                             |
| `wallet_type`                 | `string`    | Shows the type of a wallet: `legacy`, `amethyst`, `hardware`.                                           |
| `can_view_outgoing_addresses` | `bool`      | Indicates that a view wallet is able to detect outgoing transfers.                                      |
| `has_view_secret_key`         | `bool`      | Indicates whether a wallet has a view secret key.                                                       |
| `wallet_creation_timestamp`   | `timestamp` | Returns a timestamp of the wallet creation. `0` if not known (restored form keys and did not sync yet). |
| `total_address_count`         | `uint32`    | Total number of addresses in a wallet.                                                                  |
| `first_address`               | `string`    | First address in the wallet.                                                                            |
| `net`                         | `string`    | Shows the network `walletd` is launched on (`main`, `stage` or `test`).                                 |
| `secret_view_key`             | `string`    | Secret view key                                                                                         |
| `public_view_key`             | `string`    | Public view key                                                                                         |
| `import_keys`                 | `string`    | Value for --import-keys (for legacy wallet)                                                             |
| `mnemonic`                    | `string`    | BIP39 mnemonic (for amethyst wallet)                                                                    |

#### Example 1

Let's receive a pair of view keys from the current wallet file.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_wallet_info"
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "view_only": false,
    "amethyst": false,
    "can_view_outgoing_addresses": true,
    "has_view_secret_key": true,
    "wallet_creation_timestamp": 1554216254,
    "total_address_count": 3,
    "first_address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
    "net": "main"
  }
}
```
### 5. `get_wallet_records`

Gets (first creating if desired) wallet records (addresses). `index` and `count` define range, `create` determines if not yet existing addresses in the range will be created.


#### Input (params)

| Field                    | Type            | Mandatory | Default value | Description                                         |
|--------------------------|-----------------|-----------|---------------|-----------------------------------------------------|
| `index`                  | `uint32`        | No        | `0`           | Start of address range to return/create.            |
| `count`                  | `uint32`        | No        | `2^32-1`      | End of address range to return/create               |
| `create`                 | `bool`          | No        | `false`       | Create addresses in range if set to true.           |
| `need_secrets`           | `bool`          | No        | `false`       | Also returns spend secret keys for addresses.       |

#### Output

| Field                         | Type        | Description                                                                     |
|-------------------------------|-------------|---------------------------------------------------------------------------------|
| `records`                     | `[]Record`  | Address records.                                                                |
| `total_count`                 | `uint32`    | Total number of addresses in wallet.                                            |

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_wallet_records"
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "total_count": 3,
    "records": [
      {
        "index": 0,
        "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
        "label": ""
      },
      {
        "index": 1,
        "address": "26T3ixqCLeRDF5J7j6W5VrifKxLmafkDX4wariwdze3yMUgx6BKLNTMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6hoLkAr",
        "label": ""
      },
      {
        "index": 2,
        "address": "25kdF3s7Yp64Zuw5JAnPQGFouFjDuTT7BFYPKBh3MiUvSq8UY1X7q1uZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6iL4SKW",
        "label": ""
      }
    ]
  }
}
```
### 6. `set_address_label`

#### Input (params)

| Field                        | Type     | Mandatory | Default value | Description                         |
|------------------------------|----------|-----------|---------------|-------------------------------------|
| `address`                    | `string` | Yes       | -             | Address to label.                   |
| `label`                      | `string` | Yes       | -             | User label to attach to an address. |

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "set_address_label",
  "params": {
    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
    "label": "red"
  }
}'
```
__Output:__
```
{"id":"0","jsonrpc":"2.0","result":{}}
```




### 7. `create_sendproof`

#### About

Creates a sendproof certifying that the money has actually been sent by the caller in a specified transaction to an address.
If you leave the field `addresses` empty, you get a proof for every address used in the transaction, which is not stored in a wallet file (so no proofs for change). This works only if there is a `<wallet-file>.history` folder with the corresponding transaction history.
If you set an array of addresses, you get a proof for every address actually used in a transaction. The GUI client can use the address book in an attempt to guess addresses in case there is no history stored for a particular transaction.

The field `message` is any user text. It will be included in the proof and become part of it so that changing the `message` would be impossible without destroying the proof validity. So a user can include personal info or some challenge there to prove that they have really created the proof.

Returns an array of generated proofs or empty array if no proofs has been generated (this usually happens if no money has been actually sent to specified addresses in specified transaction)

#### Input (params)

| Field              | Type       | Mandatory | Default value | Description         |
|--------------------|----------- |-----------|---------------|---------------------|
| `addresses`        | `[]string` | No        | Empty         | Array of addresses. |
| `transaction_hash` | `string`   | Yes       | -             | Transaction hash.   |
| `message`          | `string`   | No        | Empty         | User message.       |

#### Output

| Field             | Type       | Description              |
|-------------------|------------|--------------------------|
| `sendproofs`      | `[]string` | Array of created proofs. |

#### Example 1

Let's create a send proof for a transaction sent from the current wallet.

__Input:__
```
curl -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "create_sendproof",
  "params": {
    "transaction_hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5",
    "message":"Luke I’m your father!"
}
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "sendproofs": [
      "bcn1PRoof1R1qSQZb2f7qU4j9dPWkRhaK19GsNhUQxJPiEk2W5fjLdEZxBiKf8FsT67T1M2qk9zx33eEKMAtqLPLRzGtLyVhtMvbVAoTcLJmgn6QEvKH16XRAKeHobfr2piBHy9neyNe1WcTk5cPNhvaJjcNPhyzdQW4s3pfLxuj11htCn4ggDwsT1rBFqJeTQoQbSS3aNiUbpq2Raa1pydVWxHZN7Hz2Kt6ZGgcYZ6MiVLWrnXeVAAtGVuvJE3tU6J3JKr1aoZjtg2bPH5DimtTUhPwj1SwTwGGijYuv8rXQLSs7SuaiAJh3WbYyvhSCidQPPz44wMvMsS5eWtWK9DkYniUfzPoJr9zDkyS5z8A2V3BTjboHyeiHW6bSRyGWDy9gShFN6ExGzVdW2ZiF9GfP3M9GT2UXzZ4LP7jNK5opHmQcu3uAVbg53zXHy7AFKqAtvzns3n3mNY67AgGxxRfUQ99Fak77UMCGWqCoheGbSoJV7PFwjexNcEdBctQAVn931ik7MoawSdtdtExQafc2Tc6GqsLL1Pm5UcWugy1uBqVuYPjKXnzKJfX7L8h794bzBiXQUP5pNyrcEGYgZQ9Mfu6dGZuWksPBYMo9JrdsARPaL"
    ]
  }
}
```

### 8. `get_balance`

#### About

Gets balance of specified address (or all addresses) taking in account specified confirmation blocks count.
Clients, which regard some block height as 'final', should specify that height as `height_or_depth`. Simple clients may omit `height_or_depth` altogether, or use negative value equal to desired confirmations.

Returns balanced split into 3 categories - `spendable` is the sum of all unlocked unspent non-dust outputs created prior to specified height_or_depth. `spendable_dust` is the same for dust outputs. It can be spent only by specifying anonymity `0` in `create_tranasaction` call. `locked_or_unconfirmed` is sum of all locked or unconfirmed unspent outputs.

If you need introspection into actual outputs, call `get_unspents`.

#### Input (params)

| Field                | Type     | Mandatory | Default value | Description        |
|--------------------- |----------|-----------|---------------|--------------------|
| `address`            | `string` | No        | Empty         | Address.           |
| `height_or_depth`    | `int32`  | No        | `-6`          | Point of finality. |

#### Output

| Field                          | Type     | Description                                                |
|--------------------------------|----------|------------------------------------------------------------|
| `spendable`                    | `uint64` | Amount that can be spent with anonymity >= 0.              |
| `spendable_dust`               | `uint64` | Amount that can be spend with anonymity = 0.               |
| `locked_or_unconfirmed`        | `uint64` | Amount that will be available at some point in the future. |
| `spendable_outputs`            | `uint32` | Corresponding spendable outputs.                           |
| `spendable_dust_outputs`       | `uint32` | Corresponding spendable dust outputs.                      |
| `locked_or_unconfirmed_outputs`| `uint32` | Corresponding locked or unconfirmed outputs.               |

#### Example 1

Let's get balance for all addresses under a depth of 6 blocks.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_balance",
  "params": {
    "height_or_depth": -6
  }
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "spendable": 0,
    "spendable_dust": 0,
    "locked_or_unconfirmed": 123000000000000,
    "spendable_outputs": 0,
    "spendable_dust_outputs": 0,
    "locked_or_unconfirmed_outputs": 3
  }
}
```

### Example 2

Let's get balance for address `2AGmhxRPbK3BtiyUz7vc4hHTj4n2cPdiWTHXgfHmPow5gr83GAkEsKLTE8muA6umGAEU78k7L4LmyAi7Efk4EwKoShnPYwR` over a height of 1526550.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_balance",
  "params": {
    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
    "height_or_depth": 1526550
  }
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "spendable": 123000000000000,
    "spendable_dust": 0,
    "locked_or_unconfirmed": 0,
    "spendable_outputs": 3,
    "spendable_dust_outputs": 0,
    "locked_or_unconfirmed_outputs": 0
  }
}
```

### 9. `get_status`

#### About

Get status about state of walletd and armord. If you specify all input parameters, and they are equal to the current state of the `walletd`, you will get response only when some of them change. Most simple way to accomplish this is just sending previous response as the next request.

`get_status` supports longpoll. All longpoll arguments are optional. For example, if you are interested in `outgoing_peer_count` only, you can specify only `outgoing_peer_count` in the request and get the response when `outgoing_peer_count` changes. Changes to other fields will not trigger response to longpoll.

#### Input (params)

| Field                      | Type     | Mandatory | Default value | Description                                       |
|----------------------------|----------|-----------|---------------|---------------------------------------------------|
| `top_block_hash`           | `string` | No        | Empty         | Value received in previous `get_status` response. |
| `transaction_pool_version` | `uint32` | No        | `0`           | Value received in previous `get_status` response. |
| `incoming_peer_count`      | `uint32` | No        | `0`           | Value received in previous `get_status` response. |
| `outgoing_peer_count`      | `uint32` | No        | `0`           | Value received in previous `get_status` response. |
| `lower_level_error`        | `string` | No        | Empty         | Value received in previous `get_status` response. |

#### Output

| Field                              | Type     | Description                                                                              |
|------------------------------------|----------|------------------------------------------------------------------------------------------|
| `top_known_block_height`           | `uint32` | Largest block height known to walletd or armord.                                      |
| `top_block_height`                 | `uint32` | All transaction prior to that height have been processed by walletd.                     |
| `top_block_difficulty`             | `uint64` | Difficulty of top block.                                                                 |
| `top_block_timestamp`              | `uint32` | Timestamp of top block.                                                                  |
| `top_block_hash`                   | `string` | Hash of top block.                                                                       |
| `top_block_timestamp_median`       | `uint32` | Median timestamp of top block.                                                           |
| `recommended_fee_per_byte`         | `uint64` | Value of fee recommended.                                                                |
| `transaction_pool_version`         | `uint32` | Adding or removing transaction from pool increments version.                             |
| `incoming_peer_count`              | `uint32` | Incoming peers to armord.                                                             |
| `outgoing_peer_count`              | `uint32` | Outgoing peers from armord.                                                           |
| `lower_level_error`                | `string` | Error on lower level (armord for walletd, etc).                                       |
| `next_block_effective_median_size` | `uint32` | Created transaction raw size should be less this value, otherwise will not fit in block. |

#### Example 1

Let's do a regular status request.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_status"
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "top_block_hash": "111e76d64e57ca1b1c0d5c1c2d992eac8e4b7768b4aa932daded61d04529d1d7",
    "transaction_pool_version": 0,
    "outgoing_peer_count": 1,
    "incoming_peer_count": 0,
    "lower_level_error": "",
    "top_block_height": 74304,
    "top_block_difficulty": 4749998,
    "top_block_cumulative_difficulty": 366860193939,
    "top_block_timestamp": 1555432176,
    "top_block_timestamp_median": 1555429315,
    "recommended_fee_per_byte": 100,
    "next_block_effective_median_size": 98958,
    "recommended_max_transaction_size": 98958,
    "top_known_block_height": 74304
  }
}
```

### 10. `get_transaction`

#### About

Returns transaction by hash (only if it contains at least one transfer to/from any of wallet addresses).

If transaction is not found, will return a transaction with default fields (check for empty `hash` field)

#### Input (params)

| Field  | Type     | Mandatory | Default value | Description        |
|--------|----------|-----------|---------------|--------------------|
| `hash` | `string` | Yes       | -             | Hex of hash bytes. |

#### Output

| Field         | Type          | Description            |
|---------------|---------------|------------------------|
| `transaction` | `Transaction` | Resultant transaction. |

#### Example 1

Let's request the transaction info by its hash.

__Input:__
```
curl -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_transaction",
  "params": {
    "hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722"
  }
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "transaction": {
      "unlock_block_or_timestamp": 0,
      "unlock_time": 0,
      "amount": 140100000633000,
      "fee": 2589000,
      "public_key": "",
      "transfers": [
        {
          "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
          "amount": 123000000000000,
          "ours": true,
          "locked": false,
          "outputs": [
            {
              "amount": 3000000000000,
              "public_key": "44830abc360bd57598932f130bf24b7d5129ee81dd3e7f200839229423b45997",
              "stack_index": 9021,
              "global_index": 693444,
              "height": 74296,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 2,
              "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
              "key_image": "2df813d5217698f3bd1c2edb01dd0f7a12be48de1f97a7630d3b18ac86810528",
              "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
              "dust": false
            },
            {
              "amount": 20000000000000,
              "public_key": "b84b752301ea7127802b4c0f6cb98b6ad27b88f7f215021bb736eb6e80786b6b",
              "stack_index": 6,
              "global_index": 693447,
              "height": 74296,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 5,
              "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
              "key_image": "70171f597d1ceda0e2331a9910005060f7057155ca636044177acd78ffa4beba",
              "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
              "dust": false
            },
            {
              "amount": 100000000000000,
              "public_key": "c42ae196ef1812f3ef4f6067d3b5ffe4e9af1e33417946817f60f38e505427de",
              "stack_index": 61,
              "global_index": 693448,
              "height": 74296,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 6,
              "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
              "key_image": "b76b72fbcbb3f8bcf93c60305eebe87b5e8df21216a15e7412fa6d6736e729a7",
              "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
              "dust": false
            }
          ],
          "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722"
        }
      ],
      "anonymity": 6,
      "extra": "",
      "hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
      "prefix_hash": "1dccf48ad8e017b5a49a76f93d3e09dcf9608ea4feb2addc0f4e895da7fb9f93",
      "inputs_hash": "5f677959f06ac055de250f6498070b11c1efc4e0ecd376480940ab86b92f453b",
      "coinbase": false,
      "block_height": 74296,
      "block_hash": "ee27c49b5530596ae0fc381837417d698d3f8fef93fb9845d76ae4330baa9380",
      "timestamp": 1555431672,
      "size": 15163,
      "binary_size": 15163
    }
  }
}
```

### 11. `get_transfers`

#### About

This is how you iterate through the history of transfers to/from wallet addresses. If you specify address, it will filter transfers with that address (anyway you should compare address of transfer to desired address yourself, because this filter is not exact and will return excess transfers). If you set address to empty, you will get all transfers to/from any address stored in wallet file.

You specify window (`from_height` .. `to_height`), direction (`forward`) flag, and approximate chunk size (`desired_transactions_count`) to iterate through the transfer history. A bit more or less than `desired_transactions_count` can be returned, as this call always returns whole blocks. Window for the next iteration is returned as (`next_from_height` .. `next_to_height`). When this window becomes empty, iteration is finished.

If you specify window that includes `top_block + 1`, you will get transfers residing in transaction memory pool.

This method returns block only if it contains transaction we are interested into. Also transaction will be included in block only if it contains transfer we are interested into. So we get filtered view of blockchain, omitting parts which walletd cannot parse using keys stored in wallet file.

### Twists with locked outputs

Some transactions are locked until specific block height or block timestamp. When parsing returned transfers you should look into `locked` field, and if it is true, you should avoid counting incoming balance from that transfer.

In addition to blocks with transfers, this method also returns transfers from prior blocks, unlocked by block height or timestamp of blocks in window you specified. So for locked transfers, you will get them in `unlocked_transfers` as soon as they are unlocked. This is the point you should count their incoming balances.


#### Input (params)

| Field                       | Type     | Mandatory | Default value | Description                               |
|-----------------------------|----------|-----------|---------------|-------------------------------------------|
| `address`                   | `string` | No        | Empty         | Filter by address.                        |
| `desired_transaction_count` | `uint32` | No        | `2^32-1`      | Approx. number of transactions to return. |
| `forward`                   | `bool`   | No        | `false`       | Direction of iteration through window.    |
| `from_height`               | `uint32` | No        | `0`           | Start of window (not included).           |
| `to_height`                 | `uint32` | No        | `2^32-1`      | End of window (included).                 |

#### Output

| Field                | Type         | Description                       |
|----------------------|--------------|-----------------------------------|
| `blocks`             | `[]Block`    | Blocks from window.               |
| `unlocked_transfers` | `[]Transfer` | Transfers unlocked within window. |
| `next_from_height`   | `uint32`     | Window for next iteration.        |
| `next_to_height`     | `uint32`     | Window for next iteration.        |

#### Example 1

Let's get transfers for address `2AGmhxRPbK3BtiyUz7vc4hHTj4n2cPdiWTHXgfHmPow5gr83GAkEsKLTE8muA6umGAEU78k7L4LmyAi7Efk4EwKoShnPYwR`, from height `1525800` to `1525900` with `100` TX count:

__Input:__
```
curl -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_transfers",
  "params": {
  	"address":"238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
    "desired_transaction_count": 100
  }
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "blocks": [
      {
        "header": {
          "major_version": 4,
          "minor_version": 7,
          "timestamp": 1555431672,
          "previous_block_hash": "ab729dd72d060d27d8f7c4d83f2bb4a8c42e45de2ab508b21554715c8c162325",
          "binary_nonce": "a04025af",
          "nonce": 2938454176,
          "height": 74296,
          "hash": "ee27c49b5530596ae0fc381837417d698d3f8fef93fb9845d76ae4330baa9380",
          "reward": 53002121977037,
          "cumulative_difficulty": 366822090940,
          "difficulty": 4797930,
          "base_reward": 53002119388037,
          "block_size": 15871,
          "transactions_size": 15738,
          "already_generated_coins": 4552609490971250700,
          "already_generated_transactions": 74536,
          "already_generated_key_outputs": 693449,
          "block_capacity_vote": 100000,
          "block_capacity_vote_median": 100000,
          "size_median": 0,
          "effective_size_median": 0,
          "timestamp_median": 1555428574,
          "transactions_fee": 2589000
        },
        "transactions": [
          {
            "unlock_block_or_timestamp": 0,
            "unlock_time": 0,
            "amount": 140100000633000,
            "fee": 2589000,
            "public_key": "",
            "transfers": [
              {
                "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                "amount": 123000000000000,
                "ours": true,
                "locked": false,
                "outputs": [
                  {
                    "amount": 3000000000000,
                    "public_key": "44830abc360bd57598932f130bf24b7d5129ee81dd3e7f200839229423b45997",
                    "stack_index": 9021,
                    "global_index": 693444,
                    "height": 74296,
                    "unlock_block_or_timestamp": 0,
                    "unlock_time": 0,
                    "index_in_transaction": 2,
                    "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
                    "key_image": "2df813d5217698f3bd1c2edb01dd0f7a12be48de1f97a7630d3b18ac86810528",
                    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                    "dust": false
                  },
                  {
                    "amount": 20000000000000,
                    "public_key": "b84b752301ea7127802b4c0f6cb98b6ad27b88f7f215021bb736eb6e80786b6b",
                    "stack_index": 6,
                    "global_index": 693447,
                    "height": 74296,
                    "unlock_block_or_timestamp": 0,
                    "unlock_time": 0,
                    "index_in_transaction": 5,
                    "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
                    "key_image": "70171f597d1ceda0e2331a9910005060f7057155ca636044177acd78ffa4beba",
                    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                    "dust": false
                  },
                  {
                    "amount": 100000000000000,
                    "public_key": "c42ae196ef1812f3ef4f6067d3b5ffe4e9af1e33417946817f60f38e505427de",
                    "stack_index": 61,
                    "global_index": 693448,
                    "height": 74296,
                    "unlock_block_or_timestamp": 0,
                    "unlock_time": 0,
                    "index_in_transaction": 6,
                    "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
                    "key_image": "b76b72fbcbb3f8bcf93c60305eebe87b5e8df21216a15e7412fa6d6736e729a7",
                    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                    "dust": false
                  }
                ],
                "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722"
              }
            ],
            "anonymity": 6,
            "extra": "",
            "hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
            "prefix_hash": "1dccf48ad8e017b5a49a76f93d3e09dcf9608ea4feb2addc0f4e895da7fb9f93",
            "inputs_hash": "5f677959f06ac055de250f6498070b11c1efc4e0ecd376480940ab86b92f453b",
            "coinbase": false,
            "block_height": 74296,
            "block_hash": "ee27c49b5530596ae0fc381837417d698d3f8fef93fb9845d76ae4330baa9380",
            "timestamp": 1555431672,
            "size": 15163,
            "binary_size": 15163
          }
        ]
      },
      {
        "header": {
          "major_version": 4,
          "minor_version": 7,
          "timestamp": 1555495771,
          "previous_block_hash": "8dbef7d21fd21046248d04d0746737995f407d216c0aa28855b67daa28a86050",
          "binary_nonce": "54001772",
          "nonce": 1914110036,
          "height": 74976,
          "hash": "d46ee2591266fb4d9d0780188092c1a43607bbdf7ba38214f85e4eeea47add19",
          "reward": 52864810123738,
          "cumulative_difficulty": 370361794014,
          "difficulty": 6498933,
          "base_reward": 52864810105738,
          "block_size": 1829,
          "transactions_size": 1696,
          "already_generated_coins": 4588604158160997000,
          "already_generated_transactions": 75217,
          "already_generated_key_outputs": 699901,
          "block_capacity_vote": 100000,
          "block_capacity_vote_median": 100000,
          "size_median": 0,
          "effective_size_median": 0,
          "timestamp_median": 1555492786,
          "transactions_fee": 18000
        },
        "transactions": [
          {
            "unlock_block_or_timestamp": 0,
            "unlock_time": 0,
            "amount": 2999999982000,
            "fee": 18000,
            "public_key": "",
            "transfers": [
              {
                "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                "amount": -3000000000000,
                "ours": true,
                "locked": false,
                "outputs": [
                  {
                    "amount": 3000000000000,
                    "public_key": "44830abc360bd57598932f130bf24b7d5129ee81dd3e7f200839229423b45997",
                    "stack_index": 9021,
                    "global_index": 693444,
                    "height": 74296,
                    "unlock_block_or_timestamp": 0,
                    "unlock_time": 0,
                    "index_in_transaction": 2,
                    "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
                    "key_image": "2df813d5217698f3bd1c2edb01dd0f7a12be48de1f97a7630d3b18ac86810528",
                    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                    "dust": false
                  }
                ],
                "transaction_hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5"
              },
              {
                "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                "amount": 2999999972000,
                "ours": true,
                "locked": false,
                "outputs": [
                  {
                    "amount": 972000,
                    "public_key": "b2584e3614844e55831753e3856c70925132a77704ce70734f4ad6c65d9f27c2",
                    "stack_index": 79,
                    "global_index": 699893,
                    "height": 74976,
                    "unlock_block_or_timestamp": 0,
                    "unlock_time": 0,
                    "index_in_transaction": 1,
                    "transaction_hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5",
                    "key_image": "5656488e9e94de00c308bdc04a06f30d1201887fb3803dccd75998481f9015ce",
                    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                    "dust": false
                  },
                  {
                    "amount": 9000000,
                    "public_key": "845c24dad76383b88b675318ee7afeb3d4830f0d48c61ce64c9bd587bb76882b",
                    "stack_index": 7718,
                    "global_index": 699894,
                    "height": 74976,
                    "unlock_block_or_timestamp": 0,
                    "unlock_time": 0,
                    "index_in_transaction": 2,
                    "transaction_hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5",
                    "key_image": "b9313739533cbab3e14016e3074df886b1ac845730a682e7c11c3ab151021c25",
                    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                    "dust": false
                  },
                  {
                    "amount": 90000000,
                    "public_key": "177b3611f280c1f77a6819cdf6d56adfa90e04bc2a13caf9bae6844c2b2c0e7d",
                    "stack_index": 7420,
                    "global_index": 699895,
                    "height": 74976,
                    "unlock_block_or_timestamp": 0,
                    "unlock_time": 0,
                    "index_in_transaction": 3,
                    "transaction_hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5",
                    "key_image": "4edd33531643226b3a371f858ec292f7f4097fef57a21c432fb3de5f1f2bdbf7",
                    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                    "dust": false
                  },
                  {
                    "amount": 900000000,
                    "public_key": "e2ec9ea1236333ed3af540fb326f304f4f2be5c52b51f8fd272a7e91107e6e36",
                    "stack_index": 7450,
                    "global_index": 699896,
                    "height": 74976,
                    "unlock_block_or_timestamp": 0,
                    "unlock_time": 0,
                    "index_in_transaction": 4,
                    "transaction_hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5",
                    "key_image": "24a3519edb4cfcf6189d455bc9a036e99e56cc8fd66c61df03c7d98890ec6607",
                    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                    "dust": false
                  },
                  {
                    "amount": 9000000000,
                    "public_key": "6f24e7975b6d784005d72507bd7bb364bd76fb476797a94a5cd61d0d753c1e9d",
                    "stack_index": 7508,
                    "global_index": 699897,
                    "height": 74976,
                    "unlock_block_or_timestamp": 0,
                    "unlock_time": 0,
                    "index_in_transaction": 5,
                    "transaction_hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5",
                    "key_image": "f156047e504cd7e9a0c5c8f19f8c077ade19a4b373456510e18379138b998afe",
                    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                    "dust": false
                  },
                  {
                    "amount": 90000000000,
                    "public_key": "41faa145b6f83ea1e0f94617d88fba780e0cbc8f33e3b6e398d82f2f8b1831f3",
                    "stack_index": 7503,
                    "global_index": 699898,
                    "height": 74976,
                    "unlock_block_or_timestamp": 0,
                    "unlock_time": 0,
                    "index_in_transaction": 6,
                    "transaction_hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5",
                    "key_image": "6c5b7b248b85c15d9971d73ab7e7456067e2a3fcb32e3a073adb1d4203fbcc0e",
                    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                    "dust": false
                  },
                  {
                    "amount": 900000000000,
                    "public_key": "dd834e2d1e99e8a41390dcdfe069e78355c784475580a8739acb6c71ce8c89c2",
                    "stack_index": 7801,
                    "global_index": 699899,
                    "height": 74976,
                    "unlock_block_or_timestamp": 0,
                    "unlock_time": 0,
                    "index_in_transaction": 7,
                    "transaction_hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5",
                    "key_image": "098be094229c2b95f3e4c1c5e4c10df05a34a9cd7397ac2e1cb7a78d31022037",
                    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                    "dust": false
                  },
                  {
                    "amount": 2000000000000,
                    "public_key": "2ca928bb25975356236f2d66b739093d74beb4147a103c58075ea3f71a406f00",
                    "stack_index": 4874,
                    "global_index": 699900,
                    "height": 74976,
                    "unlock_block_or_timestamp": 0,
                    "unlock_time": 0,
                    "index_in_transaction": 8,
                    "transaction_hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5",
                    "key_image": "00bbd295a6639159ec79244fdbfa733fd9acb4b2bc28661e334ccafc50c8cf7b",
                    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
                    "dust": false
                  }
                ],
                "transaction_hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5"
              }
            ],
            "anonymity": 6,
            "extra": "",
            "hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5",
            "prefix_hash": "d8b1acad59e0f04add895727d7173f1e77867f98a6914d662a29b6a68377137a",
            "inputs_hash": "496174c3ef22dd313564747a31c1ee6c7f1ca67a60e947b4914e38e11ac048f3",
            "coinbase": false,
            "block_height": 74976,
            "block_hash": "d46ee2591266fb4d9d0780188092c1a43607bbdf7ba38214f85e4eeea47add19",
            "timestamp": 1555495771,
            "size": 1044,
            "binary_size": 1044
          }
        ]
      }
    ],
    "unlocked_transfers": [],
    "next_from_height": 4294967295,
    "next_to_height": 4294967295
  }
}
```

### 12. `get_unspents`

#### About

This method returns the same information as `get_balance`, but split into individual outputs. Sum of those outputs is always the result of `get_balance` call (if no changes to `walletd` state happened between those 2 calls).

Outputs corresponding to `spendable` and `spendable_dust` balance will be returned in `spendable` array, to distinguish them you should look into `output.is_dust` field.

#### Input (params)

| Field                | Type     | Mandatory | Default value | Description        |
|----------------------|----------|-----------|---------------|--------------------|
| `address`            | `string` | No        | Empty         | Address.           |
| `height_or_depth`    | `int32`  | No        | `-6`          | Point of finality. |

#### Output

| Field                   | Type       | Description                                                 |
|-------------------------|------------|-------------------------------------------------------------|
| `spendable`             | `[]Output` | Outputs that can be spent.                                  |
| `locked_or_unconfirmed` | `[]Output` | Outputs that will be available at some point in the future. |

#### Example 1

Let's view unpsents for address `2AGmhxRPbK3BtiyUz7vc4hHTj4n2cPdiWTHXgfHmPow5gr83GAkEsKLTE8muA6umGAEU78k7L4LmyAi7Efk4EwKoShnPYwR` under a depth of 10 blocks.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_unspents",
  "params": {
    "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
    "height_or_depth": -6
  }
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "spendable": [
      {
        "amount": 3000000000000,
        "public_key": "44830abc360bd57598932f130bf24b7d5129ee81dd3e7f200839229423b45997",
        "stack_index": 9021,
        "global_index": 693444,
        "height": 74296,
        "unlock_block_or_timestamp": 0,
        "unlock_time": 0,
        "index_in_transaction": 2,
        "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
        "key_image": "2df813d5217698f3bd1c2edb01dd0f7a12be48de1f97a7630d3b18ac86810528",
        "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
        "dust": false
      },
      {
        "amount": 20000000000000,
        "public_key": "b84b752301ea7127802b4c0f6cb98b6ad27b88f7f215021bb736eb6e80786b6b",
        "stack_index": 6,
        "global_index": 693447,
        "height": 74296,
        "unlock_block_or_timestamp": 0,
        "unlock_time": 0,
        "index_in_transaction": 5,
        "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
        "key_image": "70171f597d1ceda0e2331a9910005060f7057155ca636044177acd78ffa4beba",
        "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
        "dust": false
      },
      {
        "amount": 100000000000000,
        "public_key": "c42ae196ef1812f3ef4f6067d3b5ffe4e9af1e33417946817f60f38e505427de",
        "stack_index": 61,
        "global_index": 693448,
        "height": 74296,
        "unlock_block_or_timestamp": 0,
        "unlock_time": 0,
        "index_in_transaction": 6,
        "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
        "key_image": "b76b72fbcbb3f8bcf93c60305eebe87b5e8df21216a15e7412fa6d6736e729a7",
        "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
        "dust": false
      }
    ],
    "locked_or_unconfirmed": []
  }
}
```

### 13. `create_transaction`

#### About

Create and sign transaction by specifying transfers to make.

If you set `spend_addresses`, the call is limited to the balance of that addresses.
If you leave `spend_addresses` empty, you should also set `any_spend_address` to true, as a protection against bug in your code accidentally leaving spend_address empty. In this case the call can spend all balance of all addresses in a wallet.

Usually it is impossible to find set of outputs to transfer exact sum you specify, so `change_address` is required.

`confirmed_height_or_depth` should be set to the same value you use for your `get_balance` and `get_transfers` call. walletd selects random outputs to mix in with your outputs, and should select them from the same finality window, otherwise you risk either losing anonymity (if you set it to low) or making transaction invalid (if you set it too high and blockchain reorganization happens).

Setting `fee_per_byte` to 0 is the same as setting it to the value returned by `get_status`. You can use larger or smaller value to increase or decrease chance of speedy inclusion in the blockchain.

You should fill in the following fields of transaction: `anonymity`, (optional) `unlock_time`, (optional) `payment_id` and `transfer`s to make. For each transfer you should fill `address` and (positive) `amount` fields.

If you leave `optimization` field empty, walletd will use normal optimization of output denominations (fusion) when creating transaction. This works well when ratio of transactions sent to received is around 1. You can use `minimal` setting for wallets receiving far less transactions than sending, saving a bit of fees. You should use `aggressive` for wallets recieving far more transactions than sending, this setting will use every opportunity to fuse larger number of identical outputs together. As maximum transaction size is limited by block median size, you can give more room for optimization by setting anonymity to as low value as possible. Moreover, if anonymity is set to 0, wallet will prioritize optimizing out dust and crazy (large but not round) denominations of outputs.

You can set `save_history` to false if you save transfers you make in your own database. In case you need to generate send proof later, you will use transfer information from your database as an input to `create_sendproof` call.

You get `binary_transaction` field to later pass to `send_transaction`, and `transaction` field for inspecting fee and size before sending. `save_history_error` is reported, usually as a result of storing wallet on read-only media.

#### Input (params)

| Field                       | Type          | Mandatory | Default value | Description                                |
|-----------------------------|---------------|-----------|---------------|--------------------------------------------|
| `transaction`               | `Transaction` | Yes       |  -            | Partly filled transaction.                 |
| `spend_addresses`           | `[]string`    | No        |  Empty        | Addresses money will be withdrawn from.    |
| `any_spend_address`         | `bool`        | No        |  `false`      | Required if `spend_address` empty.         |
| `change_address`            | `string`      | Yes       |  -            | Address where the change will be sent to.  |
| `confirmed_height_or_depth` | `int32`       | No        |  `-6`         | Confirmed point of finality.               |
| `fee_per_byte`              | `int64`       | No        |  `0`          | 0 to use recommended value.                |
| `optimization`              | `string`      | No        |  Empty        | Optimization (fusion) level.               |
| `save_history`              | `bool`        | No        |  `true`       | Flag to indicate storing transfer history. |

#### Output

| Field                   | Type          | Description                                       |
|-------------------------|---------------|---------------------------------------------------|
| `binary_transaction`    | `string`      |  Hex of binary transaction bytes.                 |
| `transaction`           | `Transaction` |  Transaction for inspecting.                      |
| `transactions_required` | `[]Hash`      |  Works with `prevent_conflict_with_transactions`. |



#### Error codes

Error codes are as follows or self explanatory.

|  Code   | Message                                     | Description                                                                        |
|---------|---------------------------------------------|------------------------------------------------------------------------------------|
| `-301`  | `NOT_ENOUGH_FUNDS`                          |                                                                                    |
| `-302`  | `TRANSACTION_DOES_NOT_FIT_IN_BLOCK`         | Sender will have to split funds into several transactions.                         |
| `-303`  | `NOT_ENOUGH_ANONYMITY`                      | Not enough similar outputs found to provide anonymity or anonymity number is >100. |
| `-304`  | `VIEW_ONLY_WALLET`                          |                                                                                    |
| `-4`    | `ADDRESS_FAILED_TO_PARSE`                   | Returns Error Address                                                              |
| `-2`    | `INVALID_HEIGHT_OR_DEPTH`                   | `height_or_depth` too low or too high                                              |
| `-1002` | `ADDRESS_NOT_IN_WALLET`                     |                                                                                    |

#### Example 1

Let's create a transaction, which transfers `10000` AU to address `2AREy1c2nBj7NVWB3SNnVDhLEN8Jve1UQ6FQYJdn9BLsQeDaUdAoGTr5tD9zn7XouYErdGafrHzfQfNEGt9XyDPB9jdzoc5` from address `238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv` and returns change to address `238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv`.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "create_transaction",
  "params": {
    "transaction": {
      "anonymity": 6,
      "payment_id": "",
      "transfers": [
        {
          "address": "2AREy1c2nBj7NVWB3SNnVDhLEN8Jve1UQ6FQYJdn9BLsQeDaUdAoGTr5tD9zn7XouYErdGafrHzfQfNEGt9XyDPB9jdzoc5",
          "amount": 10000
        }
      ]
    },
    "spend_addresses": [
      "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv"
    ],
    "change_address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
    "optimization": "minimal",
    "confirmed_height_or_depth": -6,
    "fee_per_byte": 10
  }
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "transaction": {
      "unlock_block_or_timestamp": 0,
      "unlock_time": 0,
      "amount": 2999999982000,
      "fee": 18000,
      "public_key": "",
      "transfers": [
        {
          "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
          "amount": -3000000000000,
          "ours": true,
          "locked": false,
          "outputs": [
            {
              "amount": 3000000000000,
              "public_key": "44830abc360bd57598932f130bf24b7d5129ee81dd3e7f200839229423b45997",
              "stack_index": 9021,
              "global_index": 693444,
              "height": 74296,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 2,
              "transaction_hash": "fc9718bbebb2a266ab75da951ed801aaeedaf3e0f6d1c026d150dc70758fc722",
              "key_image": "2df813d5217698f3bd1c2edb01dd0f7a12be48de1f97a7630d3b18ac86810528",
              "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
              "dust": false
            }
          ],
          "transaction_hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5"
        },
        {
          "address": "2AREy1c2nBj7NVWB3SNnVDhLEN8Jve1UQ6FQYJdn9BLsQeDaUdAoGTr5tD9zn7XouYErdGafrHzfQfNEGt9XyDPB9jdzoc5",
          "amount": 10000,
          "ours": false,
          "locked": false,
          "outputs": [
            {
              "amount": 10000,
              "public_key": "56ee544a32b3452077bf94d03904275aa6d3c91af26156ea9a092153cea49b49",
              "stack_index": 0,
              "global_index": 0,
              "height": 74960,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 0,
              "transaction_hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5",
              "key_image": "",
              "address": "2AREy1c2nBj7NVWB3SNnVDhLEN8Jve1UQ6FQYJdn9BLsQeDaUdAoGTr5tD9zn7XouYErdGafrHzfQfNEGt9XyDPB9jdzoc5",
              "dust": false
            }
          ],
          "transaction_hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5"
        },
        {
          "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
          "amount": 2999999972000,
          "ours": true,
          "locked": false,
          "outputs": [
            {
              "amount": 972000,
              "public_key": "228ae143770a0a17c2c3d43fe00b4b30a25a545de4e738394e2087cbadec8b41",
              "stack_index": 0,
              "global_index": 1,
              "height": 74960,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 1,
              "transaction_hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5",
              "key_image": "a10707144e398b1dc958b27691ca353ec264aa974bcc9d585884c3d95eb1fdc6",
              "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
              "dust": false
            },
            {
              "amount": 9000000,
              "public_key": "08cb71d57731216f37dde20320c1be218ff93feec522f1514e828af1b7a792ad",
              "stack_index": 0,
              "global_index": 2,
              "height": 74960,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 2,
              "transaction_hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5",
              "key_image": "fc5e4a69aa939e01fd3a09892daa5c5cc78f35de0eca57f4fbe20d6838ea7a25",
              "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
              "dust": false
            },
            {
              "amount": 90000000,
              "public_key": "64aef1e08cff65a1feb36dd2a45cf364c6ebee7da1357a5d10a90920323b78aa",
              "stack_index": 0,
              "global_index": 3,
              "height": 74960,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 3,
              "transaction_hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5",
              "key_image": "b3d1b830f334f24cb929b4fad9a043e195585729a602a3c1fb57e11958ef824c",
              "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
              "dust": false
            },
            {
              "amount": 900000000,
              "public_key": "15634fcfa8df437f36f19479b28435a661b85128c13e04522c846491d9c92fbf",
              "stack_index": 0,
              "global_index": 4,
              "height": 74960,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 4,
              "transaction_hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5",
              "key_image": "e44b90f3d48781c4046c9a051a31f91b409cc577ac998d81d64ea2158d99dcbe",
              "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
              "dust": false
            },
            {
              "amount": 9000000000,
              "public_key": "c8fb9a8cc1034dcc1a97a663dc789cf5b393693a5d1134d6933cbe7a4f42b46b",
              "stack_index": 0,
              "global_index": 5,
              "height": 74960,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 5,
              "transaction_hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5",
              "key_image": "42edc859832d9544195c5379baf7f5f25786e4b49e9cda177bb744e3eae3cb75",
              "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
              "dust": false
            },
            {
              "amount": 90000000000,
              "public_key": "746d92142854f4ff7c663dd781d9946334f116a298477376f52a753ae6ae02ce",
              "stack_index": 0,
              "global_index": 6,
              "height": 74960,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 6,
              "transaction_hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5",
              "key_image": "997d4cc709db5071c6a750d946fbb187c93cd59879fa23f9a423568af771ca83",
              "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
              "dust": false
            },
            {
              "amount": 900000000000,
              "public_key": "75f7f96ca19218aef811c8fd35fccff0805cb3bb48028a62b96bc36ab6639256",
              "stack_index": 0,
              "global_index": 7,
              "height": 74960,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 7,
              "transaction_hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5",
              "key_image": "854d5921ac9746a216ed1ffc99472f057ec157f41ba3ce165f3d9cdcce365ae1",
              "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
              "dust": false
            },
            {
              "amount": 2000000000000,
              "public_key": "e1ec3c62fb3278429b2278b4f61b9020a5cd11120d4b429607f7e023dd3cfa84",
              "stack_index": 0,
              "global_index": 8,
              "height": 74960,
              "unlock_block_or_timestamp": 0,
              "unlock_time": 0,
              "index_in_transaction": 8,
              "transaction_hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5",
              "key_image": "cc244b303f3768e33fd466587d9945558e6ca18567441fa1dbe84fa518286823",
              "address": "238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv",
              "dust": false
            }
          ],
          "transaction_hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5"
        }
      ],
      "anonymity": 6,
      "extra": "",
      "hash": "77e1ff8482e859a4bbcc5717e787fb072236b67cc826871bbcba6f305e1a64c5",
      "prefix_hash": "fd6a1461963aca88290ce0cfd89ff93ed6e9c49915d6cdddbb52067ede42db1c",
      "inputs_hash": "2d153242083d0f981eefe16c265060d9c4ee3c5323055b715275e90b85d84dd4",
      "coinbase": false,
      "block_height": 74960,
      "block_hash": "",
      "timestamp": 0,
      "size": 1043,
      "binary_size": 1043
    },
    "binary_transaction": "0400010280e0bcefa75707f109a229bf10eb013906412df813d5217698f3bd1c2edb01dd0f7a12be48de1f97a7630d3b18ac868105280902904e56ee544a32b3452077bf94d03904275aa6d3c91af26156ea9a092153cea49b498a1cafbcd40ae59d21980b083457d37e98f4227122147a7e0123532f9fb7f99bfb02e0a93b228ae143770a0a17c2c3d43fe00b4b30a25a545de4e738394e2087cbadec8b41f807735eb40bf6be21a49e374f6acb5fcad9a7aeb598ee9cabdfb1a9d944000cb702c0a8a50408cb71d57731216f37dde20320c1be218ff93feec522f1514e828af1b7a792adee35dbcfdd3d86b54be8224d3bae7c6b5dfc11005a0076ec2c06db030bcf1b316a028095f52a64aef1e08cff65a1feb36dd2a45cf364c6ebee7da1357a5d10a90920323b78aa6c32004017bb5e404dde314b3e9f30d5b79a3349567d9be91d312f14a7bf1a704b0280d293ad0315634fcfa8df437f36f19479b28435a661b85128c13e04522c846491d9c92fbf9209d355d06e8e3e0b023303aa8dc1835779dc9278ada7bf2f78838b88fdd924040280b4c4c321c8fb9a8cc1034dcc1a97a663dc789cf5b393693a5d1134d6933cbe7a4f42b46b0adc0fda8ef32067da4846b569e4fa9d96bb2cce4130f5abea94425cadf941171c028088aca3cf02746d92142854f4ff7c663dd781d9946334f116a298477376f52a753ae6ae02ce80c816a91caed34988a8c5bf565e69149c8fff8f0f10863a50aa4664b7b1faaad90280d0b8e1981a75f7f96ca19218aef811c8fd35fccff0805cb3bb48028a62b96bc36ab663925689fe54a4365db78f9e10c4200c05ff1aa7949e4a3ef6a29331fed5815554342d190280c0a8ca9a3ae1ec3c62fb3278429b2278b4f61b9020a5cd11120d4b429607f7e023dd3cfa840e643b94e56f9c4164ed52be70f07b9130b442dac9e2ebf3fa2536d563eefe7ee60012ae5f938d9fe26b95fdd23390d374d3780bb7846c10debee7b0dbc5a34668eaacd8766e8093b682796b83e016f351d968a91f3c3711ed1226e1bd5d73646f0a3a5d6d2e57f27b85f08866b5dd986076f8b8d02804911d46c23bdfaedc15d7015c5c4ab0869c5dd13871aea3999dc305f1052e9956d015cb5994e938aa90cc0cba0831e57345ca205d3b8ea9b799607d87a8624fa55948bb40020e16d646d608f44792f108bb8f8242744dcdb2d1b021402c0e856bae126743f6cc4c0f13ae0710625fa55af40cc865ff4b075cf2aee2457100f4b50639dc4d39c9965733ef0a77ccad29568454d39d8877cb6ff432ab10524a0674ec2f4474e8b9c6fc02cd0cfdd94745508660845982535f15cd44bdeb3b8a80b05040a499f768e808bd240ae49f2c99058b28d066231fb3fedb07e1e20fb4017c7116c0f5272687fdab38045588e3cd78a872f636abdf0802a4ed677041ca3f3258444bcbad5f3cdf9aae00",
    "save_history_error": false,
    "transactions_required": []
  }
}
```

### 14. `send_transaction`

#### About

Place the transaction (previously created with `create_transaction`) into the payment queue for immediate sending to the p2p network. The record of the TX would be removed from payment queue in 24 hours if the TX has reached 720 confirmations.  Note, that if `armord` is not connected to internet, this method will nevertheless succeed.

Result of call will be `broadcast`, if transaction was successfully placed into the payment queue.


#### Input (params)

| Field                        | Type     | Mandatory | Default value | Description                      |
|------------------------------|----------|-----------|---------------|----------------------------------|
| `binary_transaction`         | `string` | Yes       | -             | Hex of binary transaction bytes. |

#### Output

| Field                | Type         | Description      |
|----------------------|--------------|------------------|
| `send_result`        | `string`     |  Result of call. |

#### Example 1

Let's create a transaction, which transfers `10000` AU to address `2AREy1c2nBj7NVWB3SNnVDhLEN8Jve1UQ6FQYJdn9BLsQeDaUdAoGTr5tD9zn7XouYErdGafrHzfQfNEGt9XyDPB9jdzoc5` from address `238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv` and returns change to address `238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv`.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:58082/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "send_transaction",
  "params": {
    "binary_transaction":"0400010280e0bcefa75707a007e22f8d035e9a0a97011f2df813d5217698f3bd1c2edb01dd0f7a12be48de1f97a7630d3b18ac868105280902904e68d0d8f454c6e9cad0b1fbaf6419544a6f8c7cc73e8ef3c76b1db7f04220a51f04b30891a03c2646dd415fc780f8282a949172d50a0bf9c81aa4e36188ef74396302e0a93bb2584e3614844e55831753e3856c70925132a77704ce70734f4ad6c65d9f27c20f1fd4efc6b4f988070072b0babb9aa75474addff726c8f6fcc72c56c712e114c702c0a8a504845c24dad76383b88b675318ee7afeb3d4830f0d48c61ce64c9bd587bb76882b2549ed1502b675fe07804e2bbd7d94cc9286411387b69891bd9ddfb559bdfeb361028095f52a177b3611f280c1f77a6819cdf6d56adfa90e04bc2a13caf9bae6844c2b2c0e7d4a8ee3b442fe3ef3e84b454bf92c4d0c61a0456c169b61b1d234a638ddfa0ab0090280d293ad03e2ec9ea1236333ed3af540fb326f304f4f2be5c52b51f8fd272a7e91107e6e363d2165dc4b54dd8dcb8538cf8a893e71d4cd3b55db17aadc137616e412594a72a80280b4c4c3216f24e7975b6d784005d72507bd7bb364bd76fb476797a94a5cd61d0d753c1e9da9b64a02a9e079d147ba3de3b67a8057207639aaaee7776f1f01bd1450b2608d64028088aca3cf0241faa145b6f83ea1e0f94617d88fba780e0cbc8f33e3b6e398d82f2f8b1831f3af2d75ea385da8499acbf68b78b59a723e638eed7cd853965ec353192847207e130280d0b8e1981add834e2d1e99e8a41390dcdfe069e78355c784475580a8739acb6c71ce8c89c24612022f80b4ca139c98c2586d69dcac05a879bf0e0a1a71979a6e3a422a1bed660280c0a8ca9a3a2ca928bb25975356236f2d66b739093d74beb4147a103c58075ea3f71a406f00cd336821603e5bb865401a85cc9e1c727815f6b507c9d7444b10ab3aea1750fb210012ae5f938d9fe26b95fdd23390d374d3780bb7846c10debee7b0dbc5a34668ead89e0d6213d0e506bf5bb5ba031d3558175ab7691d7315cd0795c490797374072547c9a07ba43bc7e376b9203a2061b0e2f568ad0e99288f34b430ece72e730544a62b94049bc4559006d113e2e942c2cf9b6154a6eda49576cf035f0cb63e035196a7dc9186a510b88ea64e4608550814149a2369a9ba89edafb5babc50fc0b975394708221ef25d07c4abb875bda89265cd222fc79de53e6b3c5a23ba16a00e4422ff48d903be2c4b25be8f6254c089df3975a556665e92045238ea99eca06598ac412836a434ce2d62f8643cdd3b09c5c42076e1e4d09e19b3487f3348b057bdb8ec9787e3a56f798b8c266602dabe41bcbf749fa403d96888793400c9f0af2452bd64e7c74cd89bef69cdb239af9e0838bb7276d6bfdab1a403dc36a9c00dcda7124a3f1842a9418757e98ed606ba334810b557b0f6d3ffff955dde2f40e"
  }
}'
```
__Output:__
```
{"id":"0","jsonrpc":"2.0","result":{"send_result":"broadcast"}}
```

