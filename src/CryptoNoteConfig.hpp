// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include "CryptoNote.hpp"
#include "common/StringTools.hpp"
#include "p2p/P2pProtocolTypes.hpp"

#ifndef CRYPTONOTE_NAME
#error CRYPTONOTE_NAME must be defined before compiling project
#endif

// All values below should only be used in code through Currency and Config classes, never directly.
// This approach allows unlimited customization through config file/command line parameters
// Never include this header into other headers
namespace cn { namespace parameters {

// Magics
const char GENESIS_COINBASE_TX_HEX[] =
    "010a01ff0001" "ccd4dfc60302" "9b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd088071" "2101" "a9fb59d721aa495decac1477605a1e6530e1615c0eace9333e8a7fde90fff908";
// Technically, we should not have predefined genesis block, first hard checkpoint is enough. This is bitcoin legacy.
constexpr UUID BYTECOIN_NETWORK = common::pfh<UUID>("11100111110001011011001210110111");  // Bender's nightmare

const Height UPGRADE_HEIGHT_V2                  = 2;
const Height UPGRADE_HEIGHT_V3                  = 3;
const Height UPGRADE_HEIGHT_V4                  = 4;
const Height KEY_IMAGE_SUBGROUP_CHECKING_HEIGHT = 5;

// Radical simplification of consensus rules starts from versions
// Amethyst blocks can contain v1 transactions
const uint8_t BLOCK_VERSION_AMETHYST       = 4;
const uint8_t TRANSACTION_VERSION_AMETHYST = 4;

const size_t MINIMUM_ANONYMITY_AMETHYST = 3;

// Emission and formats
const Amount MONEY_SUPPLY            = 2000000000000000; //std::numeric_limits<uint64_t>::max();
const unsigned EMISSION_SPEED_FACTOR = 21;
static_assert(EMISSION_SPEED_FACTOR > 0 && EMISSION_SPEED_FACTOR <= 8 * sizeof(uint64_t), "Bad EMISSION_SPEED_FACTOR");

const size_t DISPLAY_DECIMAL_POINT = 8;
const Amount MIN_DUST_THRESHOLD    = 1000000;            // Everything smaller will be split in groups of 3 digits
const Amount MAX_DUST_THRESHOLD    = 30000000000000000;  // Everything larger is dust because very few coins
const Amount SELF_DUST_THRESHOLD   = 1000;               // forfeit outputs smaller than this in a change

const uint64_t ADDRESS_BASE58_PREFIX          = 146;       // RR
const uint64_t ADDRESS_BASE58_PREFIX_AMETHYST = 1717961;  // addresses start with "amx1"
const uint64_t SENDPROOF_BASE58_PREFIX        = 2971951985097; // proofs start with "amaPRoof"
const uint64_t VIEWONLYWALLET_BASE58_PREFIX = 57429191753; // wallets start with "amAUDit"
const char BLOCKS_FILENAME[]       = "blocks.bin";
const char BLOCKINDEXES_FILENAME[] = "blockindexes.bin";

// Difficulty and rewards
const Timestamp DIFFICULTY_TARGET              = 120;
const Timestamp DIFFICULTY_WINDOWS_LWMA        = 90;
const Height EXPECTED_NUMBER_OF_BLOCKS_PER_DAY = 24 * 60 * 60 / DIFFICULTY_TARGET;

const Difficulty MINIMUM_DIFFICULTY_V1 = 1;  // Genesis and some first blocks in main net
const Difficulty MINIMUM_DIFFICULTY    = 5000;

const Height DIFFICULTY_WINDOW = 720;
const Height DIFFICULTY_CUT    = 60;  // out-of-family timestamps to cut after sorting
const Height DIFFICULTY_LAG    = 15;  // skip last blocks for difficulty calcs (against lowering difficulty attack)

static_assert(DIFFICULTY_WINDOW >= 2, "Bad DIFFICULTY_WINDOW");
static_assert(2 * DIFFICULTY_CUT <= DIFFICULTY_WINDOW - 2, "Bad DIFFICULTY_WINDOW or DIFFICULTY_CUT");

// Upgrade voting
const Height UPGRADE_VOTING_PERCENT = 90;
const Height UPGRADE_VOTING_WINDOW  = EXPECTED_NUMBER_OF_BLOCKS_PER_DAY;
const Height UPGRADE_WINDOW         = EXPECTED_NUMBER_OF_BLOCKS_PER_DAY * 7;  // Delay after voting
static_assert(60 <= UPGRADE_VOTING_PERCENT && UPGRADE_VOTING_PERCENT <= 100, "Bad UPGRADE_VOTING_PERCENT");
static_assert(UPGRADE_VOTING_WINDOW > 1, "Bad UPGRADE_VOTING_WINDOW");

// Timestamps
const Timestamp BLOCK_FUTURE_TIME_LIMIT             = 60 * 60 * 2;
const Height BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V1_3 = 60;
const Height BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW      = 59;
static_assert(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW % 2 == 1,
    "This window must be uneven for median timestamp to grow monotonically");

// Locking by timestamp and by block
const Height MAX_BLOCK_NUMBER = 500000000;

// Legacy pre amethyst locking constants
const Height LOCKED_TX_ALLOWED_DELTA_BLOCKS = 1;

constexpr Timestamp LOCKED_TX_ALLOWED_DELTA_SECONDS(Timestamp difficulty_target) {
	return difficulty_target * LOCKED_TX_ALLOWED_DELTA_BLOCKS;
}

const Height MINED_MONEY_UNLOCK_WINDOW = 10;

// Size limits
const size_t MAX_HEADER_SIZE         = 2048;
const size_t BLOCK_CAPACITY_VOTE_MIN = 100 * 1000;   // min block size
const size_t BLOCK_CAPACITY_VOTE_MAX = 2000 * 1000;  // max block size
static_assert(BLOCK_CAPACITY_VOTE_MAX >= BLOCK_CAPACITY_VOTE_MIN, "Bad TRANSACTIONS_SIZE_VOTE");
const Height BLOCK_CAPACITY_VOTE_WINDOW = 11;

// Legacy pre amethyst size limits
const size_t MINIMUM_SIZE_MEDIAN_V3 = 100000;
const size_t MINIMUM_SIZE_MEDIAN_V2 = 20000;
const size_t MINIMUM_SIZE_MEDIAN_V1 = 10000;

const Height MEIDAN_BLOCK_SIZE_WINDOW       = 100;
const size_t MAX_BLOCK_SIZE_INITIAL         = 20 * 1024;   // block transactions size
const size_t MAX_BLOCK_SIZE_GROWTH_PER_YEAR = 100 * 1024;  // block transactions size

// P2p ports, not strictly part of consensus
const uint16_t P2P_DEFAULT_PORT        = 58080;
const uint16_t RPC_DEFAULT_PORT        = 58081;
const uint16_t WALLET_RPC_DEFAULT_PORT = 58082;

// We do not want runtime conversion, so compile-time converter
constexpr PublicKey P2P_STAT_TRUSTED_PUBLIC_KEY =
    common::pfh<PublicKey>("E29507CA55455F37A3B783EE2C5123B8B6A34A0C5CAAE050922C6254161480C2");

constexpr PublicKey CHECKPOINT_PUBLIC_KEYS[] = {
    common::pfh<PublicKey>("a9fb59d721aa495decac1477605a1e6530e1615c0eace9333e8a7fde90fff908")
    //common::pfh<PublicKey>("9b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd088071"),
    //common::pfh<PublicKey>("6e03debc66cfeabe0fb8720f4ed3a433a16a40dc9b72e6d14679f0b8a784cd58"),
    //common::pfh<PublicKey>("7afcd21a758f0568d536bec2e613c8470c086c97f14dfec3f2a744492ad02f0f"),
    //common::pfh<PublicKey>("64aadc345b4e12c10ae19e02a1536550abf0cb5118e9ad7d4c7184215a551240"),
    //common::pfh<PublicKey>("247eb4681afe8fbbf09fa7145249be27f8afdaefb023850e1399aaf49747d5e4"),
    //common::pfh<PublicKey>("eb39db3c11b09c637a06122e48d0ee88603e7b216dda01901daa27c485d82eff")
};
constexpr PublicKey CHECKPOINT_PUBLIC_KEYS_TESTNET[] = {
	common::pfh<PublicKey>("a9fb59d721aa495decac1477605a1e6530e1615c0eace9333e8a7fde90fff908")
    //common::pfh<PublicKey>("577ac6a6cdc5e0114c5a7e6338f1332fd0684e2aaf7aa3efb415e9f623d04bf5"),
    //common::pfh<PublicKey>("49950afc665e2f23354c03559f67e01e4f23fe2f30c6c6037b4de6dbd914ed80"),
    //common::pfh<PublicKey>("07f8bba2577c0bfd9f5dc8af7319b6acbbde22bf95678927c707bb42e22fd157"),
    //common::pfh<PublicKey>("9d385d34b2b4a4eb21cc1eab33ad0763b43423bdf9921db20ca5b13edd595b35"),
    //common::pfh<PublicKey>("7b897d24abb76a31230b1de982be9b32a5f12dae716bbec4804a3866555e5cad"),
    //common::pfh<PublicKey>("89ccf482916c8e381e344542537d908be76a0180e4043bf748407bd7b3b7193c"),
    //common::pfh<PublicKey>("005d18764a7c4514d217d55f39633c8145e25afe91fd84837fc1a9ab5e048e8e")
};
constexpr PublicKey CHECKPOINT_PUBLIC_KEYS_STAGENET[] = {
	common::pfh<PublicKey>("a9fb59d721aa495decac1477605a1e6530e1615c0eace9333e8a7fde90fff908")
    //common::pfh<PublicKey>("11bcb3340a24e7cc2d3e4faa4c4f66ff7ef2813c1ae49e4f8b545d14b0f79bdc"),
    //common::pfh<PublicKey>("32be85c1afd74f924a7487a76dda12b4a9925adf6212c903d7188ebd16ce8495"),
    //common::pfh<PublicKey>("d1789d5103bc8328285124dfc77d3fd3c5d3d76e70616bb409d84d3f335326cf"),
    //common::pfh<PublicKey>("8ccd5e4828b4b3d785e0f9c910771271ad40e9b1f427db1df9021a7a4083288c"),
    //common::pfh<PublicKey>("6269b60e38cd1879807e3591f1e19b936c4d156a3d15b0693a8700ee7770e431"),
    //common::pfh<PublicKey>("c9b8aa2f09fb81f77c135d1eb23cd7eac5b66c409058d5b53f724a1b887fe70f"),
    //common::pfh<PublicKey>("62020c71bbf2447ee588b28c15430434f2ceac8443c40b6e48b627e437110981")
};

const char *const SEED_NODES[] = {
    "207.180.200.250:58080",
    "207.180.200.250:57080",
    "107.172.43.135:58080",
    "144.76.186.203:58080",
    "82.223.13.179:58080"
};
const char *const SEED_NODES_STAGENET[] = {
    "207.180.200.250:58080",
    "207.180.200.250:57080",
    "107.172.43.135:58080",
    "144.76.186.203:58080",
    "82.223.13.179:58080"
};
// testnet will have no seed nodes

constexpr const HardCheckpoint CHECKPOINTS[] = {
    {500, common::pfh("93457e2e8942edcadaebeadda8d78b520476abfcffeb499a0b88832f3ddb2335")},
    {10000, common::pfh("8ca6dee104f34c090171ab23b3875561916122683a6c560a6e5b61f2a30368f9")},
    {20000, common::pfh("2d04a899bfca9cd42f58aa275c5957532a6e865f08fa74156875c0d38a5e9845")},
    {30000, common::pfh("36b2d490940e3badec0c4ffe50db2de196c53ad8e3738ba87d7415fc22986c61")},
    {40000, common::pfh("dab79ac59adf1e0a7c1e6f0f741ae4a8ca4d1dbeead23cf79933a53d903c2239")},
    {50000, common::pfh("ccdf7c2c4b363a57ed5fe884c712a8d4313965e1d569aafe77cae6a0c7d0dc9a")},
    {60000, common::pfh("eb2d0f3e043d111dc929bad94d4776975aed1afd906f2eafabf97cacde8f4e04")},
    {68000, common::pfh("6eea30c9b3d1884019cc00ce77d079a508aacaa930f485679a6ee794c045ed3a")}
   ,{109739, common::pfh("123e88f375ca4a62a5bbcd29a975944961785b2d63f5874765880b4d2b10e0c5")}
   ,{109740, common::pfh("1e3d052a10895e40d13bdb823c0f158f76bb11661f4420e3f7cb607b150aed83")}
   ,{130175, common::pfh("89594bc8ae96d9f9939348b1ca29a6322a8c9f4c2968524c27fca9078012676f")}
   ,{130176, common::pfh("dd8244dbd2022c2dc15737d712f4744ff1398223f7107af533924d6a9c57e3bd")}
   ,{130177, common::pfh("52532259e58f3851f22f7d4564cfd442b762d0bc71d2db3a26d21ebb1c1f4f94")}
   ,{132350, common::pfh("a4098dae7962c2dc07f4ba9c3bf5ea6e9ba60ad523e87392225e3e266d11ace5")}
   ,{132351, common::pfh("107af3a99654f501ac29d90aa0a32106b5052b5de1ce97e3326b9e9a678d1361")}
   ,{139999, common::pfh("1e8baa8031e80eb86e5464cb4aeee550945dd5e2a1eede348d58da1505465664")}
};

// When adding checkpoint and BEFORE release, you MUST check that daemon fully syncs both mainnet and stagenet.

// Be extra careful when setting checkpoint around consensus update heights. Follow rules:
// 1. never set checkpoint after or to height where required # of votes for upgrade was gathered
// 2. never set checkpoint before height where upgrade happened (with desired major version)
// 3. after setting checkpoint after upgrade, modify upgrade_heights array

constexpr const HardCheckpoint CHECKPOINTS_STAGENET[] = {
	{(Height)(-1),common::pfh<Hash>("0000000000000000000000000000000000000000000000000000000000000000")}
};

}}  // namespace cn::parameters
