## Service location

By default, Bytecoin Node Service (`bytecoind`, Node Daemon) is bound only to `127.0.0.1` (`localhost`) interface, so it can be accessed only from the same computer it runs on. This is done to reduce number of external attack vectors. `bytecoind` itself has access to only public information, but it sometimes runs in the same process with `walletd`, which has access to wallet keys. To bind `bytecoind` to all network interfaces, use `--bytecoind-bind-address=0.0.0.0:8081` command line argument (specifying port is mandatory).

To make a JSON PRC request to the `bytecoind` you should make an HTTP POST request to an entry point:
```
http://<ip>:<port>/json_rpc
```
where:
* `<ip>` is IPv4 address of `bytecoind` service. If the service is on local machine, use `127.0.0.1` instead of `localhost`.
* `<port>` is TCP port of `bytecoind`. By default the service is bound to `8081`.

### Curl template

```
curl -s -u <user>:<pass> -X POST http://<ip>:<port>/json_rpc -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "id": "<id>", "method": "<method>", "params": {<params>}}'
```

## Methods

### Getting information about blockchain

| #   | Method                | Description                                                   |
|-----|-----------------------|---------------------------------------------------------------|
| 1.  | `check_sendproof`     | Checks validity of a sendproof.                               |
| 2.  | `get_block_header`    | TODO.                                                         |
| 3.  | `get_raw_block`       | Gets raw block from the blockchain.                           |
| 4.  | `get_raw_transaction` | Gets raw transaction from the blockchain.                     |
| 5.  | `get_statistics`      | Gets statistics about running `bytecoind`.                    |
| 6.  | `get_status`          | Returns status of `bytecoind`.                                |
| 7.  | `sync_blocks`         | Gets blockchain blocks for `walletd` and block explorer sync. |
| 8.  | `sync_mem_pool`       | Gets difference to transaction pool.                          |

### Creating transactions

| #   | Method              | Description                                                           |
|-----| --------------------|-----------------------------------------------------------------------|
| 9.  |`get_random_outputs` | Is used by `walletd` to get mix-ins when building transaction.        |
| 10. |`send_transaction`   | Adds transaction to pool. Usually should be called through `walletd`. |

### Mining (new version)

| #   | Method               | Description                    |
|-----|----------------------| -------------------------------|
| 11. | `get_block_template` | Gets block for mining.         |
| 12. | `get_currency_id`    | Returns hash of genesis block. |
| 13. | `submit_block`       | Submits mined block.           |

### Mining (legacy version)

| Method                   | Description                                                                          |
|--------------------------|--------------------------------------------------------------------------------------|
| `getcurrencyid`          | Returns hash of genesis block.                                                       |
| `getblocktemplate`       | Gets block for mining.                                                               |
| `submitblock`            | Submits mined block.                                                                 |
| `getlastblockheader`     | Gets last block header.                                                              |
| `getblockheaderbyhash`   | Gets block header by hash.                                                           |
| `getblockheaderbyheight` | Gets block header by height. Warning: This legacy method starts counting from `1`, \ |
|                          | so if you set height to `5000`, you will get header with height `4999`.              |

-----------------------------------------------------------------------------------------------------------------------

### 1. `check_sendproof`

#### About

Checks that given sendproof is valid and correct. Returns info about the sendproof if correct or error info with explanation if not.

#### Input (params)

| Field                        | Type     | Mandatory | Default value | Description           |
|------------------------------|----------|-----------|---------------|-----------------------|
| `sendproof`                  | `string` | Yes       | -             | A sendproof to check. |

#### Output

| Field                | Type     | Description                                             |
|----------------------|----------|---------------------------------------------------------|
| `transaction_hash`   | `string` | Hash of TX being proved.                                |
| `address`            | `string` | Address where the money where sent from.                |
| `amount`             | `uint64` | Amount of TX being proved.                              |
| `message`            | `string` | Message, user has included when creating the sendproof. |

#### Example 1

Let's check a sendproof that has been created before.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8081/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "check_sendproof",
  "params": {
  	"sendproof": "bcn1PRoof1R1qSQZb2f7qU4j9dPWkRhaK19GsNhUQxJPiEk2W5fjLdEZxBiKf8FsT67T1M2qk9zx33eEKMAtqLPLRzGtLyVhtMvbVAoTcLJmgn6QEvKH16XRAKeHobfr2piBHy9neyNe1WcTk5cPNhvaJjcNPhyzdQW4s3pfLxuj11htCn4ggDwsT1rBFqJeTQoQbSS3aNiUbpq2Raa1pydVWxHZN7Hz2Kt6ZGgcYZ6MiVLWrnXeVAAtGVuvJE3tU6J3JKr1aoZjtg2bPH5DimtTUhPwj1SwTwGGijYuv8rXQLSs7SuaiAJh3WbYyvhSCidQPPz44wMvMsS5eWtWK9DkYniUfzPoJr9zDkyS5z8A2V3BTjboHyeiHW6bSRyGWDy9gShFN6ExGzVdW2ZiF9GfP3M9GT2UXzZ4LP7jNK5opHmQcu3uAVbg53zXHy7AFKqAtvzns3n3mNY67AgGxxRfUQ99Fak77UMCGWqCoheGbSoJV7PFwjexNcEdBctQAVn931ik7MoawSdtdtExQafc2Tc6GqsLL1Pm5UcWugy1uBqVuYPjKXnzKJfX7L8h794bzBiXQUP5pNyrcEGYgZQ9Mfu6dGZuWksPBYMo9JrdsARPaL"
  }
}'

```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "transaction_hash": "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5",
    "address": "2AREy1c2nBj7NVWB3SNnVDhLEN8Jve1UQ6FQYJdn9BLsQeDaUdAoGTr5tD9zn7XouYErdGafrHzfQfNEGt9XyDPB9jdzoc5",
    "amount": 10000,
    "message": "Luck I’m your father!",
    "output_indexes": [
      0
    ]
  }
```
The sendproof is valid.


### 2. `get_block_header`

#### About

Returns block header requested either by its hash or height-or-depth value.

#### Input (params)

| Field                        | Type     | Mandatory | Default value | Description                        |
|------------------------------|----------|-----------|---------------|------------------------------------|
| `hash`                       | `string` | No        | -             | Hash of a block to get.            |
| `height_or_depth`            | `int32`  | No        | `2^31 − 1`    | Height or depth of a block to get. |


#### Output

| Field           | Type          | Description                                               |
|-----------------|---------------|-----------------------------------------------------------|
| `block_header`  | `BlockHeader` | Block header requested.                                   |
| `orphan_status` | `bool`        | Indicates that the block not in the canonical chain.      |
| `depth`         | `int32`       | Depth of the block.                                       |

#### Example 1

Lets request the header of a top block .

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8081/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_block_header",
  "params": {
    "height_or_depth": -1
  }
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "block_header": {
      "major_version": 4,
      "minor_version": 7,
      "timestamp": 1555509928,
      "previous_block_hash": "83c2eae866c7b90fbac9aca5f0e2a6a91797a16a2398c50b2cf004e167d9dddd",
      "binary_nonce": "48014f2a",
      "nonce": 709820744,
      "height": 75107,
      "hash": "7cb20a2209b25973101ab5d00ca19e8e1ee0b8762d559a0cfebdd37f7e0d2d53",
      "reward": 52838398769820,
      "cumulative_difficulty": 371228551824,
      "difficulty": 6663537,
      "base_reward": 52838398769820,
      "block_size": 854,
      "transactions_size": 721,
      "already_generated_coins": 4595527704992603600,
      "already_generated_transactions": 75348,
      "already_generated_key_outputs": 701148,
      "block_capacity_vote": 100000,
      "block_capacity_vote_median": 100000,
      "size_median": 0,
      "effective_size_median": 0,
      "timestamp_median": 1555506556,
      "transactions_fee": 0
    },
    "orphan_status": false,
    "depth": -1
  }
}
```

### 3. `get_raw_block`

#### About

Returns a block object (header, raw header, raw transactions, signatures, transactions & global indices). Can be used with either `hash` or `height_or_depth` parameters.

#### Input (params) - Option 1

| Field     | Type       | Mandatory | Default value    | Description  |
|-----------|------------|-----------|------------------|--------------|
| `hash`    | `string`   | Yes       | Empty            | Block hash.  |


#### Input (params) - Option 2

| Field             | Type       | Mandatory | Default value | Description                                                                                         |
|-------------------|------------|-----------|---------------|-------------------------------------------|
| `height_or_depth` | `int32`    | Yes       | Empty         | Positive values are read as height,<br>   |
|                   |            |           |               | negative values are read as depth`*`,<br> |
|                   |            |           |               | `0` is genesis block.                     |

`*`Depth is calculated from the tip block. Different nodes may have different tip numbers depending on blockchain sync status.

#### Output

| Field            | Type    | Description                                       |
|------------------|---------|---------------------------------------------------|
| `block`          | `Block` | Standard block object.                            |
| `orphan_status`  | `bool`  | Indicates whether the block is orphan or not.     |
| `depth`          | `int32` | Block's raw transactions with inputs and outputs. |


#### Example 1

Let's request raw block for the block with hash `b33dbedd5b1b7e1daf8dfbe3abd6d87a7727b5d5eb873b3cf5483f34942dd803`.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8081/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_raw_block",
  "params": {
    "hash": "d46ee2591266fb4d9d0780188092c1a43607bbdf7ba38214f85e4eeea47add19"
  }
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "block": {
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
      "raw_header": {
        "major_version": 4,
        "minor_version": 7,
        "previous_block_hash": "8dbef7d21fd21046248d04d0746737995f407d216c0aa28855b67daa28a86050",
        "root_block": {
          "major_version": 1,
          "minor_version": 0,
          "timestamp": 1555495771,
          "previous_block_hash": "",
          "nonce": "54001772",
          "transaction_count": 1,
          "coinbase_transaction_branch": [],
          "coinbase_transaction": {
            "version": 1,
            "unlock_block_or_timestamp": 0,
            "inputs": [],
            "outputs": [],
            "extra": "020c5cb6fb5b43f1e5ee3c7e94f10321000e8d9c551199f7c4b2a9bb9ff433b88cbaea3929b79346d9bb621f2cdc5d6b8b"
          },
          "blockchain_branch": []
        },
        "coinbase_transaction": {
          "version": 4,
          "unlock_block_or_timestamp": 0,
          "inputs": [
            {
              "type": "coinbase",
              "height": 74976
            }
          ],
          "outputs": [
            {
              "type": "key",
              "amount": 123000,
              "public_key": "2e4c6caf6d90d1fc338585eceaccff12d0613269f0a091a3236fd7096717e7e3",
              "encrypted_secret": "dee05545b6901b24c38dc5225587f7b981176856e251d84dca91347684919b9c",
              "encrypted_address_type": "ea"
            },
            {
              "type": "key",
              "amount": 738,
              "public_key": "4518e7cdc503105833b4dd6b09961acc491055468aeb67e60a182ac72123be2c",
              "encrypted_secret": "daee1017fb0e9a0289105f8aa939e4e2e9f45d38e79f9c3714d6c3e20dfc64d4",
              "encrypted_address_type": "98"
            },
            {
              "type": "key",
              "amount": 10000000,
              "public_key": "91b95b7c833d9ff48f51e175387c43ed835144f97135d504f9ed30323da1845d",
              "encrypted_secret": "ba40d033ec374d136fe158bfc8dbf600253ce7207f6ce9d96f54c35032f8538c",
              "encrypted_address_type": "25"
            },
            {
              "type": "key",
              "amount": 800000000,
              "public_key": "817bf7ed666fa5041a935b91e19262de91cb53e06e5f6489ddf771887a0b155f",
              "encrypted_secret": "f07f8bc5afd2585b91557f3c3a1743c3f77385c1ea0627936c0c7f018f37e547",
              "encrypted_address_type": "77"
            },
            {
              "type": "key",
              "amount": 4000000000,
              "public_key": "fc02acc5198b34e5abfab20b8b37dd49d58dc0996d4b41f5fc23168b36d14b1c",
              "encrypted_secret": "abf01c5dcaaae3c1336c1a0308d0034ba0db2bef0c09a6fbd2f9edca08137889",
              "encrypted_address_type": "70"
            },
            {
              "type": "key",
              "amount": 60000000000,
              "public_key": "92346bdb4937a93dc7ab030e48a93d24da49dc67413cfc3cbca2025d25ce2e39",
              "encrypted_secret": "f199854e4e7cabcc9a3a48f948820ab5089d1ea0746126c0eb3984d5c42469bf",
              "encrypted_address_type": "99"
            },
            {
              "type": "key",
              "amount": 800000000000,
              "public_key": "2240953be3e4a6b5173a2b79f25712c5af184c580cd9ad8827be470dc0167dfe",
              "encrypted_secret": "dfc1e99b6f866f7591bf08b8318e673f681dffae2939cee85a79e84b6904d1a1",
              "encrypted_address_type": "98"
            },
            {
              "type": "key",
              "amount": 2000000000000,
              "public_key": "f8c5a5b291f22607baa0b8fd0e80e17358a4e2c5cef140fd0e2ea53c0aedc07b",
              "encrypted_secret": "9c9be538f0847b291b988412d281aac353f399a12893c82d9eb7deb64738946a",
              "encrypted_address_type": "56"
            },
            {
              "type": "key",
              "amount": 50000000000000,
              "public_key": "2f8ca6988100cb9925944854a4c701dc9d4d857dd6408765300277b0415cdc11",
              "encrypted_secret": "477de88bfdedf9e31719501a03bd98cfccab4711d30e1b1e9869756fc141addf",
              "encrypted_address_type": "97"
            }
          ],
          "extra": "0403a08d06"
        },
        "transaction_hashes": [
          "fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5"
        ]
      },
      "raw_transactions": [
        {
          "version": 4,
          "unlock_block_or_timestamp": 0,
          "inputs": [
            {
              "type": "key",
              "amount": 3000000000000,
              "output_indexes": [
                928,
                6114,
                397,
                94,
                1306,
                151,
                31
              ],
              "key_image": "2df813d5217698f3bd1c2edb01dd0f7a12be48de1f97a7630d3b18ac86810528"
            }
          ],
          "outputs": [
            {
              "type": "key",
              "amount": 10000,
              "public_key": "68d0d8f454c6e9cad0b1fbaf6419544a6f8c7cc73e8ef3c76b1db7f04220a51f",
              "encrypted_secret": "04b30891a03c2646dd415fc780f8282a949172d50a0bf9c81aa4e36188ef7439",
              "encrypted_address_type": "63"
            },
            {
              "type": "key",
              "amount": 972000,
              "public_key": "b2584e3614844e55831753e3856c70925132a77704ce70734f4ad6c65d9f27c2",
              "encrypted_secret": "0f1fd4efc6b4f988070072b0babb9aa75474addff726c8f6fcc72c56c712e114",
              "encrypted_address_type": "c7"
            },
            {
              "type": "key",
              "amount": 9000000,
              "public_key": "845c24dad76383b88b675318ee7afeb3d4830f0d48c61ce64c9bd587bb76882b",
              "encrypted_secret": "2549ed1502b675fe07804e2bbd7d94cc9286411387b69891bd9ddfb559bdfeb3",
              "encrypted_address_type": "61"
            },
            {
              "type": "key",
              "amount": 90000000,
              "public_key": "177b3611f280c1f77a6819cdf6d56adfa90e04bc2a13caf9bae6844c2b2c0e7d",
              "encrypted_secret": "4a8ee3b442fe3ef3e84b454bf92c4d0c61a0456c169b61b1d234a638ddfa0ab0",
              "encrypted_address_type": "09"
            },
            {
              "type": "key",
              "amount": 900000000,
              "public_key": "e2ec9ea1236333ed3af540fb326f304f4f2be5c52b51f8fd272a7e91107e6e36",
              "encrypted_secret": "3d2165dc4b54dd8dcb8538cf8a893e71d4cd3b55db17aadc137616e412594a72",
              "encrypted_address_type": "a8"
            },
            {
              "type": "key",
              "amount": 9000000000,
              "public_key": "6f24e7975b6d784005d72507bd7bb364bd76fb476797a94a5cd61d0d753c1e9d",
              "encrypted_secret": "a9b64a02a9e079d147ba3de3b67a8057207639aaaee7776f1f01bd1450b2608d",
              "encrypted_address_type": "64"
            },
            {
              "type": "key",
              "amount": 90000000000,
              "public_key": "41faa145b6f83ea1e0f94617d88fba780e0cbc8f33e3b6e398d82f2f8b1831f3",
              "encrypted_secret": "af2d75ea385da8499acbf68b78b59a723e638eed7cd853965ec353192847207e",
              "encrypted_address_type": "13"
            },
            {
              "type": "key",
              "amount": 900000000000,
              "public_key": "dd834e2d1e99e8a41390dcdfe069e78355c784475580a8739acb6c71ce8c89c2",
              "encrypted_secret": "4612022f80b4ca139c98c2586d69dcac05a879bf0e0a1a71979a6e3a422a1bed",
              "encrypted_address_type": "66"
            },
            {
              "type": "key",
              "amount": 2000000000000,
              "public_key": "2ca928bb25975356236f2d66b739093d74beb4147a103c58075ea3f71a406f00",
              "encrypted_secret": "cd336821603e5bb865401a85cc9e1c727815f6b507c9d7444b10ab3aea1750fb",
              "encrypted_address_type": "21"
            }
          ],
          "extra": ""
        }
      ],
      "transactions": [
        {
          "unlock_block_or_timestamp": 0,
          "unlock_time": 0,
          "amount": 52864810123738,
          "fee": 0,
          "public_key": "",
          "anonymity": 0,
          "extra": "0403a08d06",
          "hash": "3ae22c4467fa7cdcee3f20a7b7ce51c570149618e68ce0ea03645a42629a8c10",
          "prefix_hash": "d0cac4c0708422c7ed44a230b82cd2ec8f27c42ea46119eb3e24b970ca58f280",
          "inputs_hash": "23f9c9e2575aa2c9ff1c51f389f8144a11b03e3bddf535f080e0c785facbce4c",
          "coinbase": true,
          "block_height": 74976,
          "block_hash": "d46ee2591266fb4d9d0780188092c1a43607bbdf7ba38214f85e4eeea47add19",
          "timestamp": 1555495771,
          "size": 652,
          "binary_size": 652
        },
        {
          "unlock_block_or_timestamp": 0,
          "unlock_time": 0,
          "amount": 2999999982000,
          "fee": 18000,
          "public_key": "",
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
      ],
      "output_stack_indexes": [
        [
          89,
          76,
          7550,
          7554,
          7476,
          7513,
          7428,
          4873,
          33198
        ],
        [
          77,
          79,
          7718,
          7420,
          7450,
          7508,
          7503,
          7801,
          4874
        ]
      ]
    },
    "orphan_status": false,
    "depth": -113
  }
}

```

#### Example 2

Let's request raw block for the block with height `1500004`. Positive values are read as height, negative values are read as depth`*`, `0` is genesis block.

`*`Depth is calculated from the tip block. Different nodes may have different tip numbers depending on blockchain sync status.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8081/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_raw_block",
  "params": {
    "height_or_depth": 74976
  }
}'
```

__Output:__
```
(same as in Example 1)
```

### 4. `get_raw_transaction`

#### About

Returns standard transaction object, raw transaction with inputs and outputs and input signatures (if `need_signatures` is set to `true`).

#### Input (params)

| Field             | Type       | Mandatory | Default value    | Description                                        |
|-------------------|------------|-----------|------------------|----------------------------------------------------|
| `hash`            | `string`   | Yes       | Empty            | Hash of a transaction being requested.             |
| `need_signatures` | `bool`     | No        | `false`          | If `true`, adds Signature objects to the response. |


#### Output

| Field              | Type             | Description                                                           |
|--------------------|------------------|-----------------------------------------------------------------------|
| `transaction`      | `Transaction`    | Standard Transaction object. Contains info only known to `bytecoind`. |
| `raw_transaction`  | `RawTransaction` | Raw transaction with inputs and outputs.                              |
| `signatures`       | `[][]Signature`  | Signatures for inputs of the transaction.                             |


#### Example 1

Let's request raw transaction for TX `7547cd3187173258a5aa13eec59d117de1da5f8b73589183b08115c539910b64` with `need_signatures` flag set to `true`.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8081/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_raw_transaction",
  "params": {
  	"hash":
"fe331d318ffa931647cec4d046e93c00da53944e63a134f68a1ba4a3501411c5"
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
    },
    "raw_transaction": {
      "version": 4,
      "unlock_block_or_timestamp": 0,
      "inputs": [
        {
          "type": "key",
          "amount": 3000000000000,
          "output_indexes": [
            928,
            6114,
            397,
            94,
            1306,
            151,
            31
          ],
          "key_image": "2df813d5217698f3bd1c2edb01dd0f7a12be48de1f97a7630d3b18ac86810528"
        }
      ],
      "outputs": [
        {
          "type": "key",
          "amount": 10000,
          "public_key": "68d0d8f454c6e9cad0b1fbaf6419544a6f8c7cc73e8ef3c76b1db7f04220a51f",
          "encrypted_secret": "04b30891a03c2646dd415fc780f8282a949172d50a0bf9c81aa4e36188ef7439",
          "encrypted_address_type": "63"
        },
        {
          "type": "key",
          "amount": 972000,
          "public_key": "b2584e3614844e55831753e3856c70925132a77704ce70734f4ad6c65d9f27c2",
          "encrypted_secret": "0f1fd4efc6b4f988070072b0babb9aa75474addff726c8f6fcc72c56c712e114",
          "encrypted_address_type": "c7"
        },
        {
          "type": "key",
          "amount": 9000000,
          "public_key": "845c24dad76383b88b675318ee7afeb3d4830f0d48c61ce64c9bd587bb76882b",
          "encrypted_secret": "2549ed1502b675fe07804e2bbd7d94cc9286411387b69891bd9ddfb559bdfeb3",
          "encrypted_address_type": "61"
        },
        {
          "type": "key",
          "amount": 90000000,
          "public_key": "177b3611f280c1f77a6819cdf6d56adfa90e04bc2a13caf9bae6844c2b2c0e7d",
          "encrypted_secret": "4a8ee3b442fe3ef3e84b454bf92c4d0c61a0456c169b61b1d234a638ddfa0ab0",
          "encrypted_address_type": "09"
        },
        {
          "type": "key",
          "amount": 900000000,
          "public_key": "e2ec9ea1236333ed3af540fb326f304f4f2be5c52b51f8fd272a7e91107e6e36",
          "encrypted_secret": "3d2165dc4b54dd8dcb8538cf8a893e71d4cd3b55db17aadc137616e412594a72",
          "encrypted_address_type": "a8"
        },
        {
          "type": "key",
          "amount": 9000000000,
          "public_key": "6f24e7975b6d784005d72507bd7bb364bd76fb476797a94a5cd61d0d753c1e9d",
          "encrypted_secret": "a9b64a02a9e079d147ba3de3b67a8057207639aaaee7776f1f01bd1450b2608d",
          "encrypted_address_type": "64"
        },
        {
          "type": "key",
          "amount": 90000000000,
          "public_key": "41faa145b6f83ea1e0f94617d88fba780e0cbc8f33e3b6e398d82f2f8b1831f3",
          "encrypted_secret": "af2d75ea385da8499acbf68b78b59a723e638eed7cd853965ec353192847207e",
          "encrypted_address_type": "13"
        },
        {
          "type": "key",
          "amount": 900000000000,
          "public_key": "dd834e2d1e99e8a41390dcdfe069e78355c784475580a8739acb6c71ce8c89c2",
          "encrypted_secret": "4612022f80b4ca139c98c2586d69dcac05a879bf0e0a1a71979a6e3a422a1bed",
          "encrypted_address_type": "66"
        },
        {
          "type": "key",
          "amount": 2000000000000,
          "public_key": "2ca928bb25975356236f2d66b739093d74beb4147a103c58075ea3f71a406f00",
          "encrypted_secret": "cd336821603e5bb865401a85cc9e1c727815f6b507c9d7444b10ab3aea1750fb",
          "encrypted_address_type": "21"
        }
      ],
      "extra": ""
    },
    "mixed_public_keys": [
      [
        "0cc162eab360f862fc4dead77aab664d17d5426ccf513f3fa7fd4310376d036c",
        "8ef5d82b0f4438ddf2c6f1e90b6450d5e3bf0940f2ecbd4c0d0d9ccae2688df8",
        "03ac6eb60497f5c313d1d69e0b9fbe6aa1a36beacc443e3930d0a3938158aeb6",
        "23525e9128e33714bb46143ac84525fd7f169f160a43a1a70beedf95f8cb549a",
        "ffb07ab989f2e6a378a88add2fa66602f3e3091cb33b3c1733dafba895ab15d3",
        "49eb2f0d90894741a8725f59d0dc7291a00fb2f40ff2aed9c0e8a1a921e05b20",
        "44830abc360bd57598932f130bf24b7d5129ee81dd3e7f200839229423b45997"
      ]
    ]
  }
}

```

### 5. `get_statistics`

#### About

Returns misc statistics about `bytecoind` being queried.

#### Input (params)

No parameters.

#### Output

| Field                                  | Type           | Description                                              |
|----------------------------------------|----------------|----------------------------------------------------------|
| `version`                              | `string`       | Version of the daemon.                                   |
| `platform`                             | `string`       | Operating system the daemon was launched in.             |
| `net`                                  | `string`       | `main`, `stage` or `test`.                               |
| `genesis_block_hash`                   | `string`       | Hash of genesis block.                                   |
| `peer_id`                              | `bool`         | Randomly generated unique peer id.                       |
| `start_time`                           | `timestamp`    | Timestamp of `bytecoind` start time in UTC.              |
| `checkpoints`                          | `[]Checkpoint` | Current Checkpoint objects.                              |
| `transaction_pool_size`                | `uint64`       | Size of local TX pool.                                   |
| `transaction_pool_max_size`            | `uint64`       | Max size of local TX pool.                               |
| `transaction_pool_lowest_fee_per_byte` | `uint64`       | Lowest fee per byte of local TX pool.                    |
| `upgrade_decided_height`               | `uint32`       | Upgrade height during a consensus update.                |
| `upgrade_votes_in_top_block`           | `uint32`       | Upgrade votes in top block during a consensus update.    |
| `peer_list_white`                      | `[]Peer`       | Peers `bytecoind` has successfully connected to.         |
| `peer_list_gray`                       | `[]Peer`       | Peers given by other nodes.                              |
| `connections`                          | `[]Connection` | Current connections to peers.                            |


#### Example 1

Let's make a `get_statistics` query to `bytecoind`.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8081/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_statistics"
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "version": "v3.4.2-beta-20190412 (amethyst)",
    "platform": "darwin",
    "net": "stage",
    "genesis_block_hash": "edd089c95237be0075d6dcc58a0e0af63a9551ddc8328d41648dc98448e8de80",
    "peer_id": 6406516779400159000,
    "start_time": 1555505335,
    "checkpoints": [
      {
        "height": 75087,
        "hash": "ecf38c6bd31746f65014d02484c32a8c66ff0d5f8539e9a982850dbaca440bb4",
        "key_id": 0,
        "counter": 66520,
        "signature": "997206cc755aa9f33b7206ed14fa6f35f591fd71baca4a3d4a51edad88897c0947c4fe4110a62d0b1ab9af7b02f0ca5c7dc1d600e1c78397ab6bfe6720d03b0c"
      }
    ],
    "transaction_pool_count": 0,
    "transaction_pool_size": 0,
    "transaction_pool_max_size": 4000000,
    "transaction_pool_lowest_fee_per_byte": 0,
    "upgrade_decided_height": 0,
    "upgrade_votes_in_top_block": 0,
    "peer_list_white": [],
    "peer_list_gray": [],
    "connected_peers": [
      {
        "peer_id": 17765294269699030000,
        "address": "145.239.3.130:8080",
        "is_incoming": false,
        "p2p_version": 4,
        "top_block_desc": {
          "hash": "8bfea9d373837d341c5c87a56ecad10c8eddf8e69786aec0942ae445dad35740",
          "height": 75090,
          "cumulative_difficulty": 0
        }
      },
      {
        "peer_id": 5309359925305110000,
        "address": "198.27.69.208:8080",
        "is_incoming": false,
        "p2p_version": 4,
        "top_block_desc": {
          "hash": "8bfea9d373837d341c5c87a56ecad10c8eddf8e69786aec0942ae445dad35740",
          "height": 75090,
          "cumulative_difficulty": 0
        }
      },
      {
        "peer_id": 3281592841578633000,
        "address": "144.76.106.36:8080",
        "is_incoming": false,
        "p2p_version": 4,
        "top_block_desc": {
          "hash": "8bfea9d373837d341c5c87a56ecad10c8eddf8e69786aec0942ae445dad35740",
          "height": 75090,
          "cumulative_difficulty": 0
        }
      }
    ],
    "node_database_size": 213848064
  }
}
```

### 6. `get_status`

#### About

Get status about state of `bytecoind`. This method supports longpolling. If you specify all input parameters, \
and they are equal to the current state of the `bytecoind`, you will get response only when some of them change. \
But if you specify only certain argument, changes to other arguments won't trigger the longpoll. For example, if \
you are interested in `outgoing_peer_count` only, you can specify only `outgoing_peer_count` in request and get \
response when `outgoing_peer_count changes`.

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
| `incoming_peer_count`              | `uint32` | Incoming peers to bytecoind.                                                             |
| `lower_level_error`                | `string` | Error on lower level (bytecoind for walletd, etc).                                       |
| `next_block_effective_median_size` | `uint32` | Created transaction raw size should be less this value, otherwise will not fit in block. |
| `outgoing_peer_count`              | `uint32` | Outgoing peers from bytecoind.                                                           |
| `recommended_fee_per_byte`         | `uint64` | Value of fee recommended.                                                                |
| `top_block_cumulative_difficulty`  | `uint64` | Cumulative difficulty of top local block.                                                |
| `top_block_difficulty`             | `uint64` | Difficulty of top local block.                                                           |
| `top_block_hash`                   | `string` | Hash of top local block.                                                                 |
| `top_block_height`                 | `uint32` | All transaction prior to that height have been processed by bytecoind.                   |
| `top_block_timestamp`              | `uint32` | Timestamp of top block.                                                                  |
| `top_block_timestamp_median`       | `uint32` | Median timestamp of top block.                                                           |
| `top_known_block_height`           | `uint32` | Largest of heights reported by external peers (network block height).                    |
| `transaction_pool_version`         | `uint32` | Adding or removing transaction from pool increments version.                             |


#### Example 1

Let's do a regular status request.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8081/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_status",
  "params": {}
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "top_block_hash": "64307850dafc593c562ad5986df002e8096e4c726677af9ae14760de9c3b3e55",
    "transaction_pool_version": 0,
    "outgoing_peer_count": 3,
    "incoming_peer_count": 0,
    "lower_level_error": "",
    "top_block_height": 75061,
    "top_block_difficulty": 6663188,
    "top_block_cumulative_difficulty": 370921236757,
    "top_block_timestamp": 1555505163,
    "top_block_timestamp_median": 1555502039,
    "recommended_fee_per_byte": 100,
    "next_block_effective_median_size": 98958,
    "recommended_max_transaction_size": 98958,
    "top_known_block_height": 75061
  }
}
```


### 7. `sync_blocks`

#### About

Fetches blocks from local blockchain. In order to perform a request a sparse chain (a specific sequence of local blocks) \
has to be assembled and sent. Returns missing blocks, `start_height` and regular `get_status` response.  

#### Input (params)

| Field                      | Type        | Mandatory | Default value | Description                                                      |
|----------------------------|-------------|-----------|---------------|------------------------------------------------------------------|
| `sparse_chain`             | `[]string`  | Yes       | Empty         | A specific sequence of local block hashes`*`.                    |
| `first_block_timestamp`    | `timestamp` | No        | `0`           | `bytecoind` won't return blocks earlier than this point in time. |
| `max_count`                | `uint32`    | No        | `100`         | Maximum number of blocks to return.                              |

`*` `sparse_chain` is a sequence of blocks hashes from the last known block to genesis block. \
It goes backward into blockchain like this: last ten blocks, then block in 2 blocks, block in 4 blocks, block in 8 blocks, ..., genesis block.

#### Output

| Field               | Type      | Description                                                                                          |
|---------------------|-----------|------------------------------------------------------------------------------------------------------|
| `blocks`            | `[]Block` | Contains `header`, `raw_header`, `raw_transactions`, `signatures`, `transactions`, `output_indexes`. |
| `start_height`      | `uint32`  | Height synchronization starts from.                                                                  |
| `status`            | `Status`  | Regular `get_status` response.                                                                       |



#### Example 1

Let's request not more than `2` blocks from `8fc8417addbe4b68cc8136d6b02e7f28b21a1314362b423d131df3747b01e701` after `first_block_timestamp` of 1533747347:

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8081/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "sync_blocks",
  "params": {
    "sparse_chain": ["64307850dafc593c562ad5986df002e8096e4c726677af9ae14760de9c3b3e55"]
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
          "timestamp": 1555505281,
          "previous_block_hash": "64307850dafc593c562ad5986df002e8096e4c726677af9ae14760de9c3b3e55",
          "binary_nonce": "c8409bb4",
          "nonce": 3030073544,
          "height": 75062,
          "hash": "784618b0cec9dc966f0faa3555ac414a7474c32eeaa598c1940829ad985301a7",
          "reward": 52847469877967,
          "cumulative_difficulty": 370927894464,
          "difficulty": 6657707,
          "base_reward": 52847469877967,
          "block_size": 855,
          "transactions_size": 722,
          "already_generated_coins": 4593149777489419000,
          "already_generated_transactions": 75303,
          "already_generated_key_outputs": 700724,
          "block_capacity_vote": 100000,
          "block_capacity_vote_median": 100000,
          "size_median": 0,
          "effective_size_median": 0,
          "timestamp_median": 1555502092,
          "transactions_fee": 0
        },
        "raw_header": {
          "major_version": 4,
          "minor_version": 7,
          "previous_block_hash": "64307850dafc593c562ad5986df002e8096e4c726677af9ae14760de9c3b3e55",
          "root_block": {
            "major_version": 1,
            "minor_version": 0,
            "timestamp": 1555505281,
            "previous_block_hash": "",
            "nonce": "c8409bb4",
            "transaction_count": 1,
            "coinbase_transaction_branch": [],
            "coinbase_transaction": {
              "version": 1,
              "unlock_block_or_timestamp": 0,
              "inputs": [],
              "outputs": [],
              "extra": "020c5cb7208143f1e5e80ee92d7c032100e64924be05a65b2b088e457c534d62e0325a8e36f55d41f736ee9c26cb3974ec"
            },
            "blockchain_branch": []
          },
          "coinbase_transaction": {
            "version": 4,
            "unlock_block_or_timestamp": 0,
            "inputs": [
              {
                "type": "coinbase",
                "height": 75062
              }
            ],
            "outputs": [
              {
                "type": "key",
                "amount": 877000,
                "public_key": "9dfba174166213cb9e097bc7b58cde4e07ade135baccd1ec2b3a63eacf690b3f",
                "encrypted_secret": "aac28d8e724482479bd4055508b9fa7cdf23376323c3ce0e9a770fb568ae5505",
                "encrypted_address_type": "a5"
              },
              {
                "type": "key",
                "amount": 967,
                "public_key": "49c5c294c6789ede541c0da2acd9c5484a1ce2441fc9c1b29da7b5357cd7d806",
                "encrypted_secret": "8afa2a98e25cd16fdbc40cb4d3946cab725aa3ab6bda96441e006fad857d1152",
                "encrypted_address_type": "c0"
              },
              {
                "type": "key",
                "amount": 9000000,
                "public_key": "f675154a11648480fcc0877246bb8d422ec322d6944a618401aa4a619c8ae2e7",
                "encrypted_secret": "e90786e5b82442e52a3bd3061a005bdc0a20ea01627c333f7dd47d0b19b0cdfb",
                "encrypted_address_type": "fe"
              },
              {
                "type": "key",
                "amount": 60000000,
                "public_key": "5d93b4544e2747e566520666804d8b19eed8838c5a534012f096d1b5d9ffbdea",
                "encrypted_secret": "d825d8097ef5d7fd4847909f58ee4ef7e90e516fc1d6259d0f9c1d38ec388f87",
                "encrypted_address_type": "44"
              },
              {
                "type": "key",
                "amount": 400000000,
                "public_key": "d956c48e6effcab3076e716e66e8fbfc69f889cbd8c12004e06b9f450ab20f17",
                "encrypted_secret": "203d33e7ea1749b2fa37851b4ebe9b91248656c76195c882741d4f9f44cf4466",
                "encrypted_address_type": "dc"
              },
              {
                "type": "key",
                "amount": 7000000000,
                "public_key": "ff8b1117af2d0075c8ae39f738803d318d642d60d4b4de55e20f099419a4bc37",
                "encrypted_secret": "7de35f5a180bb60a7769439c3c3ee3896bfeca541e14620c79adbf683b7523cc",
                "encrypted_address_type": "db"
              },
              {
                "type": "key",
                "amount": 40000000000,
                "public_key": "1edd1db09f21d83669afc181893e94a523d9353efce77d6c5b37e055a360ebd7",
                "encrypted_secret": "54bb04a9d80c261ea2b750626546de5c8f7e8f044559ec99726ef66348e8fb73",
                "encrypted_address_type": "96"
              },
              {
                "type": "key",
                "amount": 800000000000,
                "public_key": "6b2fbe949a936f0e0e0084f38efec32f207defcc0ae9133baa118ff1c73b1adf",
                "encrypted_secret": "c7f7e59e2127f47a0cea180d25247ca33dada1d450fb01805bc6d10272974bfd",
                "encrypted_address_type": "96"
              },
              {
                "type": "key",
                "amount": 2000000000000,
                "public_key": "165bc0c58e5cb8d54849fd2d91507fe74f9a05f232696c4528a28ac400c69e8c",
                "encrypted_secret": "304e1401c2a2971aeaf567b34c0d02faf277de3a778fc1a55cd5b5772620d394",
                "encrypted_address_type": "ca"
              },
              {
                "type": "key",
                "amount": 50000000000000,
                "public_key": "f9c3bb90b544f14dd86b2a0170589f503cc08c1669749b0b50b81ad9722a713f",
                "encrypted_secret": "a65bf6ecd42cda44f737ff9138d94a85997b2f47c45dff8390b2b37e606669b5",
                "encrypted_address_type": "a9"
              }
            ],
            "extra": "0403a08d06"
          },
          "transaction_hashes": []
        },
        "raw_transactions": [],
        "transactions": [
          {
            "unlock_block_or_timestamp": 0,
            "unlock_time": 0,
            "amount": 52847469877967,
            "fee": 0,
            "public_key": "",
            "anonymity": 0,
            "extra": "0403a08d06",
            "hash": "1bc640d365ecda63ce337aecfa2b4cfe20bc07c0e4a7c8829c80425563efd80e",
            "prefix_hash": "10e0bb26997e0337cc6ac2705c3c2488f093dbd572fb8de9b86976ccc39864db",
            "inputs_hash": "d196b88e8c2e5955d66969ab96b0d2af4ea744372ea66abac4dd732a53ce6cc6",
            "coinbase": true,
            "block_height": 75062,
            "block_hash": "784618b0cec9dc966f0faa3555ac414a7474c32eeaa598c1940829ad985301a7",
            "timestamp": 1555505281,
            "size": 722,
            "binary_size": 722
          }
        ],
        "output_stack_indexes": [
          [
            70,
            72,
            7725,
            7513,
            7510,
            7517,
            7517,
            7514,
            4960,
            33284
          ]
        ]
      },
      {
        "header": {
          "major_version": 4,
          "minor_version": 7,
          "timestamp": 1555505500,
          "previous_block_hash": "784618b0cec9dc966f0faa3555ac414a7474c32eeaa598c1940829ad985301a7",
          "binary_nonce": "5440004b",
          "nonce": 1258307668,
          "height": 75063,
          "hash": "7b9981930e2dbc625528fcd8e826770d86c619fe2163815052d0151d0ef8a596",
          "reward": 52847268280869,
          "cumulative_difficulty": 370934535123,
          "difficulty": 6640659,
          "base_reward": 52847268280869,
          "block_size": 854,
          "transactions_size": 721,
          "already_generated_coins": 4593202624757699600,
          "already_generated_transactions": 75304,
          "already_generated_key_outputs": 700734,
          "block_capacity_vote": 100000,
          "block_capacity_vote_median": 100000,
          "size_median": 0,
          "effective_size_median": 0,
          "timestamp_median": 1555502222,
          "transactions_fee": 0
        },
        "raw_header": {
          "major_version": 4,
          "minor_version": 7,
          "previous_block_hash": "784618b0cec9dc966f0faa3555ac414a7474c32eeaa598c1940829ad985301a7",
          "root_block": {
            "major_version": 1,
            "minor_version": 0,
            "timestamp": 1555505500,
            "previous_block_hash": "",
            "nonce": "5440004b",
            "transaction_count": 1,
            "coinbase_transaction_branch": [],
            "coinbase_transaction": {
              "version": 1,
              "unlock_block_or_timestamp": 0,
              "inputs": [],
              "outputs": [],
              "extra": "020c5cb7215c43f1e5e80ee92d7f032100240bdf5d64bad6dd026e392ca32d87228d999371e043203624d13026ecdcaa4c"
            },
            "blockchain_branch": []
          },
          "coinbase_transaction": {
            "version": 4,
            "unlock_block_or_timestamp": 0,
            "inputs": [
              {
                "type": "coinbase",
                "height": 75063
              }
            ],
            "outputs": [
              {
                "type": "key",
                "amount": 280000,
                "public_key": "1c40f8460a8b9463ae4e6f99d52bf98488ef4c4c78d5a4d4cf3fd40f748c07dd",
                "encrypted_secret": "11b669dcc913a6ef7a96edcca602be62765748c4154b754e3cbd56240e6603fa",
                "encrypted_address_type": "f5"
              },
              {
                "type": "key",
                "amount": 869,
                "public_key": "029756b91fc97ebb57f48ac55977c316a4dfca3e526d732a71865e5faa3b2880",
                "encrypted_secret": "ef5d698e1de98ad85a9cdc4189499042994ab63b96aec27b3c6aea6e58db9bbd",
                "encrypted_address_type": "6b"
              },
              {
                "type": "key",
                "amount": 8000000,
                "public_key": "fdde9d0abbb8a721167ca3b4ee8256849206a9681bd317c49cbf01c587cf021d",
                "encrypted_secret": "a44162f2d30dba908bad8e3b113afb4e206f3aca9a1a127a6841b1d8839f4455",
                "encrypted_address_type": "68"
              },
              {
                "type": "key",
                "amount": 60000000,
                "public_key": "b0f9b305d705361ce6317883df5f604914f2a2439c33471e67f6edcb15662dff",
                "encrypted_secret": "4f6ccf63a8024528bc87f3aff43771b8a140820eccb384c9ef3be35bedf1d226",
                "encrypted_address_type": "ec"
              },
              {
                "type": "key",
                "amount": 200000000,
                "public_key": "e81f24533f2d25e6acdb10b8f503533e6ff67806897863294828174d6d882703",
                "encrypted_secret": "97881fd129be1b4d408907a28d50e3364a417300f72dd9caaa703a92ddc0f043",
                "encrypted_address_type": "fe"
              },
              {
                "type": "key",
                "amount": 7000000000,
                "public_key": "65021ccdfe538b76a7fbcf35c522fe4889f5ec2dccb87050f40a98b045b71f05",
                "encrypted_secret": "0501ea5dc1008f305982e86637cc59ae4831e3e8028e20b8aa901f9b070a6b50",
                "encrypted_address_type": "6a"
              },
              {
                "type": "key",
                "amount": 40000000000,
                "public_key": "5b3978eebb87fb99c6cd0caace93d263d0c7ab485bb9259e9920f01692d74b6e",
                "encrypted_secret": "e1872d988aeed6d20a6c51009812753d56bf89a341c29136530a12f044059ef5",
                "encrypted_address_type": "eb"
              },
              {
                "type": "key",
                "amount": 800000000000,
                "public_key": "c9ee5594feb87430077cbe24cb597ce4c568c2749fc281ce9abe1dbea1b63fbf",
                "encrypted_secret": "3ebb54836e97e83e1b965881f6a1d697925830958160d7f05615b92a80e4c283",
                "encrypted_address_type": "49"
              },
              {
                "type": "key",
                "amount": 2000000000000,
                "public_key": "8c65d07aec70b801fbfbec0bcf367ff9a146ff42f5820984a925a4a9d64a3cb8",
                "encrypted_secret": "ab333fcb50bd3c5984f122400f51e8d11993b51af9cc5ea4a0ad130904651fae",
                "encrypted_address_type": "72"
              },
              {
                "type": "key",
                "amount": 50000000000000,
                "public_key": "021910d2c3b17452b08f54fa45a8fd6b93a0e26c8e85cf76e20044b490818942",
                "encrypted_secret": "443b50588b2623247f30d9b5186264ec71fc400a09d0a30b25f4fa11a004203b",
                "encrypted_address_type": "18"
              }
            ],
            "extra": "0403a08d06"
          },
          "transaction_hashes": []
        },
        "raw_transactions": [],
        "transactions": [
          {
            "unlock_block_or_timestamp": 0,
            "unlock_time": 0,
            "amount": 52847268280869,
            "fee": 0,
            "public_key": "",
            "anonymity": 0,
            "extra": "0403a08d06",
            "hash": "1cb5cedcca5b15b1f1dc25ad92771f81e9c7340475f1e3bb37af924abc486b74",
            "prefix_hash": "b7dd8066294f72eecaf6753debeb3bdce2d8b1bb074e5a532275bdb602762da5",
            "inputs_hash": "d82cc742ec3cd5868b24ce90862e46758cbe51eaaeb15b6c479d5012950da9a6",
            "coinbase": true,
            "block_height": 75063,
            "block_hash": "7b9981930e2dbc625528fcd8e826770d86c619fe2163815052d0151d0ef8a596",
            "timestamp": 1555505500,
            "size": 721,
            "binary_size": 721
          }
        ],
        "output_stack_indexes": [
          [
            93,
            61,
            7441,
            7514,
            7439,
            7518,
            7518,
            7515,
            4961,
            33285
          ]
        ]
      },
      {
        "header": {
          "major_version": 4,
          "minor_version": 7,
          "timestamp": 1555505506,
          "previous_block_hash": "7b9981930e2dbc625528fcd8e826770d86c619fe2163815052d0151d0ef8a596",
          "binary_nonce": "a04003d1",
          "nonce": 3506651296,
          "height": 75064,
          "hash": "e1678368b050c92929f1772e5f356734860c764f13687ce503f020b4cac57651",
          "reward": 52847066684539,
          "cumulative_difficulty": 370941169111,
          "difficulty": 6633988,
          "base_reward": 52847066684539,
          "block_size": 784,
          "transactions_size": 651,
          "already_generated_coins": 4593255471824384500,
          "already_generated_transactions": 75305,
          "already_generated_key_outputs": 700743,
          "block_capacity_vote": 100000,
          "block_capacity_vote_median": 100000,
          "size_median": 0,
          "effective_size_median": 0,
          "timestamp_median": 1555502355,
          "transactions_fee": 0
        },
        "raw_header": {
          "major_version": 4,
          "minor_version": 7,
          "previous_block_hash": "7b9981930e2dbc625528fcd8e826770d86c619fe2163815052d0151d0ef8a596",
          "root_block": {
            "major_version": 1,
            "minor_version": 0,
            "timestamp": 1555505506,
            "previous_block_hash": "",
            "nonce": "a04003d1",
            "transaction_count": 1,
            "coinbase_transaction_branch": [],
            "coinbase_transaction": {
              "version": 1,
              "unlock_block_or_timestamp": 0,
              "inputs": [],
              "outputs": [],
              "extra": "020c5cb7216243f1e5e80ee92d80032100fd6ac193eff263c0e3d70c8565b2e322ed1e13cd57b245157a14f3acb90e6973"
            },
            "blockchain_branch": []
          },
          "coinbase_transaction": {
            "version": 4,
            "unlock_block_or_timestamp": 0,
            "inputs": [
              {
                "type": "coinbase",
                "height": 75064
              }
            ],
            "outputs": [
              {
                "type": "key",
                "amount": 684000,
                "public_key": "7be3f3cd8e76221c2cf83d5d264ca83e9e023a0d7c749f0aac310baecc158366",
                "encrypted_secret": "a260d8ac6eb9295e6e89e0428eefc0f104f51dd7dea9017907f16bacbe8edef6",
                "encrypted_address_type": "1e"
              },
              {
                "type": "key",
                "amount": 539,
                "public_key": "aedef9f1da6bd17888a7df6f9dc0960dfb414d954540e47859334a22b35a6826",
                "encrypted_secret": "6d40de182737d7f5bb2ace4cc552f236ada75dc0b4b8a35f01e7757c0bc133fe",
                "encrypted_address_type": "fb"
              },
              {
                "type": "key",
                "amount": 6000000,
                "public_key": "2c48dfaf0c8c7931d37af549e0845323fc0df014a49d513cb5f039ad2ad544a7",
                "encrypted_secret": "d115c740e983ddfe636a496ca3286f69ea5e247e76d61b0332062db273c3e4cc",
                "encrypted_address_type": "e1"
              },
              {
                "type": "key",
                "amount": 60000000,
                "public_key": "21516a3ac22d1e06ef0083f16863f5b89781090932a898ffe32c8645a4cbefa8",
                "encrypted_secret": "f3489e00226596a510fecb26735bd57176ed94d813393df2eda2cf91bb2998c1",
                "encrypted_address_type": "b2"
              },
              {
                "type": "key",
                "amount": 7000000000,
                "public_key": "2cf6c65cf4fadb42d1c7847f249c7e6dac47d808bb385d5f334ca8072bf7f583",
                "encrypted_secret": "320a50f118f16ee0ddd8de8a1a667879a26650ded1899c0f8e5c4827d57002b1",
                "encrypted_address_type": "94"
              },
              {
                "type": "key",
                "amount": 40000000000,
                "public_key": "9e31b4fea018569a1059afcb381cb6bae0caebb5b63030f4829ed3c6eaa4e15a",
                "encrypted_secret": "73c290c6c72b2cf7093d69a97e705efe470c01007aa1dc15b20dd8dfe262c5c7",
                "encrypted_address_type": "97"
              },
              {
                "type": "key",
                "amount": 800000000000,
                "public_key": "c17e339369fff1374d0a1713bdfb72c5633103a481fc7e46e6335545c0a6e3ce",
                "encrypted_secret": "ddb28caf40bdd33a4ac01550bdc2074fcef9dc334296d9ca2bc84dbe020ac420",
                "encrypted_address_type": "c6"
              },
              {
                "type": "key",
                "amount": 2000000000000,
                "public_key": "eed3f09eb8b746e363c9a2aae564a1b04544e3c745b848a75501073adfe1bb13",
                "encrypted_secret": "fb74b018c69fe572ce7373812ed998695f7744892e9db7432e98c214a1491a43",
                "encrypted_address_type": "c5"
              },
              {
                "type": "key",
                "amount": 50000000000000,
                "public_key": "c955a6d8def57d366ec1440d979d9376c52a2836bc1c6971e71d2f3945bb4b33",
                "encrypted_secret": "de8fe69905d76e14212557149e5832cf7f966d3d2b5b61c66daf97535e705fbe",
                "encrypted_address_type": "be"
              }
            ],
            "extra": "0403a08d06"
          },
          "transaction_hashes": []
        },
        "raw_transactions": [],
        "transactions": [
          {
            "unlock_block_or_timestamp": 0,
            "unlock_time": 0,
            "amount": 52847066684539,
            "fee": 0,
            "public_key": "",
            "anonymity": 0,
            "extra": "0403a08d06",
            "hash": "60aa6d910d809ce8b0d46dc6182347f0604a5048e309a96857a10a0881d48bf9",
            "prefix_hash": "7368ed5142fb24e59c20523c231d750fca063586822a3a4a6fde2d3558360574",
            "inputs_hash": "c393ff942a6baf68a3c538d41d618f4741797940579fc92c61957d9f6d689da9",
            "coinbase": true,
            "block_height": 75064,
            "block_hash": "e1678368b050c92929f1772e5f356734860c764f13687ce503f020b4cac57651",
            "timestamp": 1555505506,
            "size": 651,
            "binary_size": 651
          }
        ],
        "output_stack_indexes": [
          [
            68,
            80,
            7436,
            7515,
            7519,
            7519,
            7516,
            4962,
            33286
          ]
        ]
      }
    ],
    "start_height": 75062,
    "status": {
      "top_block_hash": "e1678368b050c92929f1772e5f356734860c764f13687ce503f020b4cac57651",
      "transaction_pool_version": 0,
      "outgoing_peer_count": 3,
      "incoming_peer_count": 0,
      "lower_level_error": "",
      "top_block_height": 75064,
      "top_block_difficulty": 6633988,
      "top_block_cumulative_difficulty": 370941169111,
      "top_block_timestamp": 1555505506,
      "top_block_timestamp_median": 1555502355,
      "recommended_fee_per_byte": 100,
      "next_block_effective_median_size": 98958,
      "recommended_max_transaction_size": 98958,
      "top_known_block_height": 75064
    }
  }
}
```


### 8. `sync_mem_pool`


#### About

Returns difference between local and network memory pool. Accepts a sorted array of known transactions.

#### Input (params)

| Field                      | Type       | Mandatory | Default value | Description                                                        |
|----------------------------|------------|-----------|---------------|--------------------------------------------------------------------|
| `known_hashes`             | `[]string` | Yes       | Empty         | Array of transactions in local memory pool. Should be sent sorted. |


#### Output

| Field                              | Type               | Description                                                                              |
|------------------------------------|--------------------|------------------------------------------------------------------------------------------|
| `removed_hashes`                   | `[]string`         | Hashes no more in pool.                                                                  |
| `added_raw_transactions`           | `[]RawTransaction` | New transactions in pool in raw form.                                                    |
| `added_transactions`               | `[]Transaction`    | New transactions in pool in regular form.                                                |
| `status`                           | `Status`           | Regular `get_status` response.                                                           |




#### Example 1

Let's request the difference to the memory pool by sending hashes of TXs that we already have in local memory pool.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8081/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "sync_mem_pool",
  "params": {
    "known_hashes": [
      "64307850dafc593c562ad5986df002e8096e4c726677af9ae14760de9c3b3e55"
    ]
  }
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "removed_hashes": [
      "64307850dafc593c562ad5986df002e8096e4c726677af9ae14760de9c3b3e55"
    ],
    "added_raw_transactions": [],
    "added_transactions": [],
    "status": {
      "top_block_hash": "283961d6adde8da5ffbdcff0aed517a72a8c5b7c6a43a025d5fd86be33fe51f9",
      "transaction_pool_version": 0,
      "outgoing_peer_count": 3,
      "incoming_peer_count": 0,
      "lower_level_error": "",
      "top_block_height": 75066,
      "top_block_difficulty": 6633289,
      "top_block_cumulative_difficulty": 370954437181,
      "top_block_timestamp": 1555505613,
      "top_block_timestamp_median": 1555502528,
      "recommended_fee_per_byte": 100,
      "next_block_effective_median_size": 98958,
      "recommended_max_transaction_size": 98958,
      "top_known_block_height": 75066
    }
  }
}
```

### 9. `get_random_outputs`

#### About

Fetches necessary quantity (`output_count`) of random outputs for desired `amounts` with respect to specified `confirmed_height_or_depth`. \
Response may have less outputs than asked for some amounts, if blockchain lacks enough.


#### Input (params)

| Field                       | Type       | Mandatory | Default value                  | Description                                                          |
|-----------------------------|------------|-----------|--------------------------------|----------------------------------------------------------------------|
| `amounts`                   | `[]uint64` | Yes       | Empty                          | Amounts in Atomic Units in an Array.                                 |
| `output_count`              | `uint32`   | Yes       | `0`                            | Number of outputs to show for each specified amount in `amounts`.    |
| `confirmed_height_or_depth` | `int32`    | No        | `-(default confirmations) - 1` | Positive values are read as height, negative values are read as depth`*`, `0` is genesis block. Mix-ins will be selected from the [0..`confirmed_height_or_depth`] window. |

`*`Depth is calculated from the tip block. Different nodes may have different tip numbers depending on blockchain sync status.

#### Output

| Field                  | Type                   | Description                                     |
|------------------------|------------------------|-------------------------------------------------|
| `outputs`              | `{uint64 -> []Output}` | Map of outputs given for each amount specified. |


#### Example 1

Let's request two outputs for two amounts (`100` and `1000`) below the depth of `-10` (top block - 10). \
A total of four outputs is returned (two for each amount) from the window from block `0` to depth `-10`.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8081/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_random_outputs",
  "params": {
    "amounts": [
      100,
      1000
    ],
    "output_count": 2,
    "confirmed_height_or_depth": -10
  }
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "outputs": {
      "100": [
        {
          "amount": 100,
          "public_key": "571fd15c1027d28987a4f22b4dc4c35d20a99bc6aaf6799c2e630e625b06bfc9",
          "stack_index": 69,
          "global_index": 593778,
          "height": 63667,
          "unlock_block_or_timestamp": 63677,
          "unlock_time": 63677
        },
        {
          "amount": 100,
          "public_key": "8e9cad7b8bc74b2ed2e6df27e3a76138e3e356f74b5b37048fcc29e3b0048d6f",
          "stack_index": 74,
          "global_index": 635149,
          "height": 68063,
          "unlock_block_or_timestamp": 0,
          "unlock_time": 0
        }
      ],
      "1000": [
        {
          "amount": 1000,
          "public_key": "fdbc55ffac68e2edc06038a4bebe139b50c41bde4c5bd4b468937f5abd1401e2",
          "stack_index": 87,
          "global_index": 660792,
          "height": 70810,
          "unlock_block_or_timestamp": 0,
          "unlock_time": 0
        },
        {
          "amount": 1000,
          "public_key": "6fe75ba4bb2d75c7c7efa64a2568e4a0c8595e8df1ce5e564ab6e17cf2fb55e0",
          "stack_index": 63,
          "global_index": 501529,
          "height": 53875,
          "unlock_block_or_timestamp": 53885,
          "unlock_time": 53885
        }
      ]
    }
  }
}
```

### 10. `send_transaction`

#### About

Places the (previously created) transaction into the payment queue for sending to the p2p network. Transactions are kept in the payment queue until they are either confirmed in the blockchain with 720 confirmations or are determined to be conflicting with another transaction, which has 720 (or more) confirmations.

Result of call will be `broadcast`, if transaction was successfully placed into the payment queue. Note, that if `bytecoind` is not connected to internet, this method will nevertheless succeed.


#### Input (params)

| Field                 | Type     | Mandatory | Default value | Description                      |
|-----------------------|----------|-----------|---------------|----------------------------------|
| `binary_transaction`  | `string` | Yes       | -             | Hex of binary transaction bytes. |

#### Output

| Field                | Type     | Description      |
|----------------------|----------|------------------|
| `send_result`        | `string` |  Result of call. |


#### Example 1

Let's send a previously created transaction by submitting `binary_transaction` to `bytecoind`.

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8081/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "send_transaction",
  "params": {
    "binary_transaction": "0400010280e0bcefa75707a007e22f8d035e9a0a97011f2df813d5217698f3bd1c2edb01dd0f7a12be48de1f97a7630d3b18ac868105280902904e68d0d8f454c6e9cad0b1fbaf6419544a6f8c7cc73e8ef3c76b1db7f04220a51f04b30891a03c2646dd415fc780f8282a949172d50a0bf9c81aa4e36188ef74396302e0a93bb2584e3614844e55831753e3856c70925132a77704ce70734f4ad6c65d9f27c20f1fd4efc6b4f988070072b0babb9aa75474addff726c8f6fcc72c56c712e114c702c0a8a504845c24dad76383b88b675318ee7afeb3d4830f0d48c61ce64c9bd587bb76882b2549ed1502b675fe07804e2bbd7d94cc9286411387b69891bd9ddfb559bdfeb361028095f52a177b3611f280c1f77a6819cdf6d56adfa90e04bc2a13caf9bae6844c2b2c0e7d4a8ee3b442fe3ef3e84b454bf92c4d0c61a0456c169b61b1d234a638ddfa0ab0090280d293ad03e2ec9ea1236333ed3af540fb326f304f4f2be5c52b51f8fd272a7e91107e6e363d2165dc4b54dd8dcb8538cf8a893e71d4cd3b55db17aadc137616e412594a72a80280b4c4c3216f24e7975b6d784005d72507bd7bb364bd76fb476797a94a5cd61d0d753c1e9da9b64a02a9e079d147ba3de3b67a8057207639aaaee7776f1f01bd1450b2608d64028088aca3cf0241faa145b6f83ea1e0f94617d88fba780e0cbc8f33e3b6e398d82f2f8b1831f3af2d75ea385da8499acbf68b78b59a723e638eed7cd853965ec353192847207e130280d0b8e1981add834e2d1e99e8a41390dcdfe069e78355c784475580a8739acb6c71ce8c89c24612022f80b4ca139c98c2586d69dcac05a879bf0e0a1a71979a6e3a422a1bed660280c0a8ca9a3a2ca928bb25975356236f2d66b739093d74beb4147a103c58075ea3f71a406f00cd336821603e5bb865401a85cc9e1c727815f6b507c9d7444b10ab3aea1750fb210012ae5f938d9fe26b95fdd23390d374d3780bb7846c10debee7b0dbc5a34668ead89e0d6213d0e506bf5bb5ba031d3558175ab7691d7315cd0795c490797374072547c9a07ba43bc7e376b9203a2061b0e2f568ad0e99288f34b430ece72e730544a62b94049bc4559006d113e2e942c2cf9b6154a6eda49576cf035f0cb63e035196a7dc9186a510b88ea64e4608550814149a2369a9ba89edafb5babc50fc0b975394708221ef25d07c4abb875bda89265cd222fc79de53e6b3c5a23ba16a00e4422ff48d903be2c4b25be8f6254c089df3975a556665e92045238ea99eca06598ac412836a434ce2d62f8643cdd3b09c5c42076e1e4d09e19b3487f3348b057bdb8ec9787e3a56f798b8c266602dabe41bcbf749fa403d96888793400c9f0af2452bd64e7c74cd89bef69cdb239af9e0838bb7276d6bfdab1a403dc36a9c00dcda7124a3f1842a9418757e98ed606ba334810b557b0f6d3ffff955dde2f40e"
  }
}'

```

__Output:__
```
{
    "id": "0",
    "jsonrpc": "2.0",
    "result": {
        "send_result": "broadcast"
    }
}
```

### 10. `get_block_template`

#### Input (params)

TODO

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8081/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_block_template",
  "params": {
"wallet_address":"238HrUqVy8DMxHRufGEt6o1qmomTHbUp55FndtK7ABEuc2hUJQZFGjMZXNtsKQaAaZiVgnBuJgcG2Lt1ZEKcjv5s6fwStLv"}
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "difficulty": 6640132,
    "height": 75119,
    "reserved_offset": 0,
    "blocktemplate_blob": "040772e9d120d4182f3994be2948e09ea7ea6f99d8046b7eb5b232504255ee084af40100bcf1dce5050000000000000000000000000000000000000000000000000000000000000000000000000101000000230321000000000000000000000000000000000000000000000000000000000000000000010001ffefca0409f0a20402f57170e3ba88539050ccbd1619fc14761823a8a68e63a0cfd66f4c4c6a9ea97cef0402192fb3534da8c734b63688b0d9ab5ca1029c117c7c82209ffb26c3da0f0b1fb180e89226028cffabe271513700ca892580466f74e063876e905543584f14b0d8fcc697df7880d293ad030268eebe1dcaaa202fd5f525e95b9fa41fc89666a7007b206cd8eb7dc25fb0aad880e497d01202f39dc48a7fe8cda4b8803557fc63c2dbff6c1f3a7b5bf774ecab49c63793ef4380d88ee16f02c257cb89a27adf290b724fa3edb5b5d6655376d8136071b75fe9d9c32eba3e878080dd9da417027889f6a5140c9cdd5fc6cdbede55346c664e9a09b6d3b8bd1bd6f983f562504580c0a8ca9a3a02e5df316c04be4a94588ef4d3530662d62b0768321ed35bc7db0744a6d9313de780c0f4c198af0b021cde2144c5b4ca41e21d67231638b33c7e6fb4fd0fdff51f7217de0c2135e2232601884436b28ad3abfbfdf8500f1aa2637c17c30c59923be3611655f7a147fb89350403a08d0600",
    "status": "OK",
    "top_block_hash": "72e9d120d4182f3994be2948e09ea7ea6f99d8046b7eb5b232504255ee084af4",
    "transaction_pool_version": 0,
    "previous_block_hash": "6c262ff29faf730499545405f7389ff8714410d3dd54e517ef8e90e4644396cc",
    "cm_prehash": "",
    "cm_path": ""
  }
}
```

### 11. `get_currency_id`

#### Input (params)

TODO

__Input:__
```
curl -s -u user:pass -X POST http://127.0.0.1:8070/json_rpc -H 'Content-Type: application/json-rpc' -d '{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_currency_id"
}'
```

__Output:__
```
{
  "id": "0",
  "jsonrpc": "2.0",
  "result": {
    "currency_id_blob": "edd089c95237be0075d6dcc58a0e0af63a9551ddc8328d41648dc98448e8de80"
  }
}
```

### 12. `submit_block`
Used by miners.
