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
    "010a01ff0001ffffffffffff0f029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121013c086a48c15fb637a96991bc6d53caf77068b5ba6eeb3c82357228c49790584a";
// Technically, we should not have predefined genesis block, first hard checkpoint is enough. This is bitcoin legacy.
constexpr UUID BYTECOIN_NETWORK = common::pfh<UUID>("11100111110001011011001210110110");  // Bender's nightmare

const Height UPGRADE_HEIGHT_V2                  = 546603;
const Height UPGRADE_HEIGHT_V3                  = 985549;
const Height KEY_IMAGE_SUBGROUP_CHECKING_HEIGHT = 1267000;

// Radical simplification of consensus rules starts from versions
const uint8_t BLOCK_VERSION_AMETHYST       = 4;
const uint8_t TRANSACTION_VERSION_AMETHYST = 4;

const size_t MINIMUM_ANONYMITY_V1_3 = 0;
const size_t MINIMUM_ANONYMITY      = 3;

// Emission and formats
const Amount MONEY_SUPPLY            = std::numeric_limits<uint64_t>::max();
const unsigned EMISSION_SPEED_FACTOR = 18;
static_assert(EMISSION_SPEED_FACTOR <= 8 * sizeof(uint64_t), "Bad EMISSION_SPEED_FACTOR");

const size_t DISPLAY_DECIMAL_POINT = 8;
const Amount MIN_DUST_THRESHOLD    = 1000000;            // Everything smaller will be split in groups of 3 digits
const Amount MAX_DUST_THRESHOLD    = 30000000000000000;  // Everything larger is dust because very few coins
const Amount SELF_DUST_THRESHOLD   = 1000;               // forfeit outputs smaller than this in a change

const BinaryArray ADDRESS_BASE58_PREFIX{6};                                      // legacy addresses start with "2"
const BinaryArray ADDRESS_BASE58_PREFIX_UNLINKABLE{0xce, 0xf5, 0xe2};            // addresses start with "bcn1"
const BinaryArray ADDRESS_BASE58_PREFIX_AUDITABLE_UNLINKABLE{0xce, 0xf5, 0xe4};  // addresses start with "bcn2"
const char BLOCKS_FILENAME[]       = "blocks.bin";
const char BLOCKINDEXES_FILENAME[] = "blockindexes.bin";

// Difficulty and rewards
const Timestamp DIFFICULTY_TARGET              = 120;
const Height EXPECTED_NUMBER_OF_BLOCKS_PER_DAY = 24 * 60 * 60 / DIFFICULTY_TARGET;

const Difficulty MINIMUM_DIFFICULTY_V1 = 1;  // Genesis and some first blocks in main net
const Difficulty MINIMUM_DIFFICULTY    = 100000;

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
const uint16_t P2P_DEFAULT_PORT        = 8080;
const uint16_t RPC_DEFAULT_PORT        = 8081;
const uint16_t WALLET_RPC_DEFAULT_PORT = 8070;

// We do not want runtime conversion, so compile-time converter
constexpr PublicKey P2P_STAT_TRUSTED_PUBLIC_KEY =
    common::pfh<PublicKey>("E29507CA55455F37A3B783EE2C5123B8B6A34A0C5CAAE050922C6254161480C1");

constexpr PublicKey CHECKPOINT_PUBLIC_KEYS[] = {
    common::pfh<PublicKey>("b397e789ba603046d5750bbf490e1569f55dc9cf1f91edd2605d55d7bc3603fc"),
    common::pfh<PublicKey>("10fdd8f7331304b2818b86158be07e5e71441a3e96fccc3451f4c12862ce2d75"),
    common::pfh<PublicKey>("6e03debc66cfeabe0fb8720f4ed3a433a16a40dc9b72e6d14679f0b8a784cd58"),
    common::pfh<PublicKey>("7afcd21a758f0568d536bec2e613c8470c086c97f14dfec3f2a744492ad02f0f"),
    common::pfh<PublicKey>("64aadc345b4e12c10ae19e02a1536550abf0cb5118e9ad7d4c7184215a551240"),
    common::pfh<PublicKey>("247eb4681afe8fbbf09fa7145249be27f8afdaefb023850e1399aaf49747d5e4"),
    common::pfh<PublicKey>("eb39db3c11b09c637a06122e48d0ee88603e7b216dda01901daa27c485d82eff")};
constexpr PublicKey CHECKPOINT_PUBLIC_KEYS_TESTNET[] = {
    common::pfh<PublicKey>("577ac6a6cdc5e0114c5a7e6338f1332fd0684e2aaf7aa3efb415e9f623d04bf5"),
    common::pfh<PublicKey>("49950afc665e2f23354c03559f67e01e4f23fe2f30c6c6037b4de6dbd914ed80"),
    common::pfh<PublicKey>("07f8bba2577c0bfd9f5dc8af7319b6acbbde22bf95678927c707bb42e22fd157"),
    common::pfh<PublicKey>("9d385d34b2b4a4eb21cc1eab33ad0763b43423bdf9921db20ca5b13edd595b35"),
    common::pfh<PublicKey>("7b897d24abb76a31230b1de982be9b32a5f12dae716bbec4804a3866555e5cad"),
    common::pfh<PublicKey>("89ccf482916c8e381e344542537d908be76a0180e4043bf748407bd7b3b7193c"),
    common::pfh<PublicKey>("005d18764a7c4514d217d55f39633c8145e25afe91fd84837fc1a9ab5e048e8e")};
constexpr PublicKey CHECKPOINT_PUBLIC_KEYS_STAGENET[] = {
    common::pfh<PublicKey>("11bcb3340a24e7cc2d3e4faa4c4f66ff7ef2813c1ae49e4f8b545d14b0f79bdc"),
    common::pfh<PublicKey>("32be85c1afd74f924a7487a76dda12b4a9925adf6212c903d7188ebd16ce8495"),
    common::pfh<PublicKey>("d1789d5103bc8328285124dfc77d3fd3c5d3d76e70616bb409d84d3f335326cf"),
    common::pfh<PublicKey>("8ccd5e4828b4b3d785e0f9c910771271ad40e9b1f427db1df9021a7a4083288c"),
    common::pfh<PublicKey>("6269b60e38cd1879807e3591f1e19b936c4d156a3d15b0693a8700ee7770e431"),
    common::pfh<PublicKey>("c9b8aa2f09fb81f77c135d1eb23cd7eac5b66c409058d5b53f724a1b887fe70f"),
    common::pfh<PublicKey>("62020c71bbf2447ee588b28c15430434f2ceac8443c40b6e48b627e437110981")};

const char *const SEED_NODES[] = {
    "207.246.127.160:8080", "108.61.174.232:8080", "45.32.156.183:8080", "45.76.29.96:8080"};
const char *const SEED_NODES_STAGENET[] = {
    "207.246.127.160:10080", "108.61.174.232:10080", "45.32.156.183:10080", "45.76.29.96:10080"};
// testnet will have no seed nodes

constexpr const HardCheckpoint CHECKPOINTS[] = {
    {79000, common::pfh<Hash>("cae33204e624faeb64938d80073bb7bbacc27017dc63f36c5c0f313cad455a02")},
    {140000, common::pfh<Hash>("993059fb6ab92db7d80d406c67a52d9c02d873ca34b6290a12b744c970208772")},
    {200000, common::pfh<Hash>("a5f74c7542077df6859f48b5b1f9c3741f29df38f91a47e14c94b5696e6c3073")},
    {230580, common::pfh<Hash>("32bd7cb6c68a599cf2861941f29002a5e203522b9af54f08dfced316f6459103")},
    {260000, common::pfh<Hash>("f68e70b360ca194f48084da7a7fd8e0251bbb4b5587f787ca65a6f5baf3f5947")},
    {300000, common::pfh<Hash>("8e80861713f68354760dc10ea6ea79f5f3ff28f39b3f0835a8637463b09d70ff")},
    {390285, common::pfh<Hash>("e00bdc9bf407aeace2f3109de11889ed25894bf194231d075eddaec838097eb7")},
    {417000, common::pfh<Hash>("2dc96f8fc4d4a4d76b3ed06722829a7ab09d310584b8ecedc9b578b2c458a69f")},
    {427193, common::pfh<Hash>("00feabb08f2d5759ed04fd6b799a7513187478696bba2db2af10d4347134e311")},
    {453537, common::pfh<Hash>("d17de6916c5aa6ffcae575309c80b0f8fdcd0a84b5fa8e41a841897d4b5a4e97")},
    {462250, common::pfh<Hash>("13468d210a5ec884cf839f0259f247ccf3efef0414ac45172033d32c739beb3e")},
    {468000, common::pfh<Hash>("251bcbd398b1f593193a7210934a3d87f692b2cb0c45206150f59683dd7e9ba1")},
    {480200, common::pfh<Hash>("363544ac9920c778b815c2fdbcbca70a0d79b21f662913a42da9b49e859f0e5b")},
    {484500, common::pfh<Hash>("5cdf2101a0a62a0ab2a1ca0c15a6212b21f6dbdc42a0b7c0bcf65ca40b7a14fb")},
    {506000, common::pfh<Hash>("3d54c1132f503d98d3f0d78bb46a4503c1a19447cb348361a2232e241cb45a3c")},
    {544000, common::pfh<Hash>("f69dc61b6a63217f32fa64d5d0f9bd920873f57dfd79ebe1d7d6fb1345b56fe0")},
    {553300, common::pfh<Hash>("f7a5076b887ce5f4bb95b2729c0edb6f077a463f04f1bffe7f5cb0b16bb8aa5f")},
    {580000, common::pfh<Hash>("93aea06936fa4dc0a84c9109c9d5f0e1b0815f96898171e42fd2973d262ed9ac")},
    {602000, common::pfh<Hash>("a05fd2fccbb5f567ece940ebb62a82fdb1517ff5696551ae704e5f0ef8edb979")},
    {623000, common::pfh<Hash>("7c92dd374efd0221065c7d98fce0568a1a1c130b5da28bb3f338cdc367b93d0b")},
    {645000, common::pfh<Hash>("1eeba944c0dd6b9a1228a425a74076fbdbeaf9b657ba7ef02547d99f971de70d")},
    {667000, common::pfh<Hash>("a020c8fcaa567845d04b520bb7ebe721e097a9bed2bdb8971081f933b5b42995")},
    {689000, common::pfh<Hash>("212ec2698c5ebd15d6242d59f36c2d186d11bb47c58054f476dd8e6b1c7f0008")},
    {713000, common::pfh<Hash>("a03f836c4a19f907cd6cac095eb6f56f5279ca2d1303fb7f826750dcb9025495")},
    {750300, common::pfh<Hash>("5117631dbeb5c14748a91127a515ecbf13f6849e14fda7ee03cd55da41f1710c")},
    {780000, common::pfh<Hash>("8dd55a9bae429e3685b90317281e633917023d3512eb7f37372209d1a5fc1070")},
    {785500, common::pfh<Hash>("de1a487d70964d25ed6f7de196866f357a293e867ee81313e7fd0352d0126bdd")},
    {789000, common::pfh<Hash>("acef490bbccce3b7b7ae8554a414f55413fbf4ca1472c6359b126a4439bd9f01")},
    {796000, common::pfh<Hash>("04e387a00d35db21d4d93d04040b31f22573972a7e61d72cc07d0ab69bcb9c44")},
    {800000, common::pfh<Hash>("d7fa4eea02e5ce60b949136569c0ea7ac71ea46e0065311054072ac415560b86")},
    {804000, common::pfh<Hash>("bcc8b3782499aae508c40d5587d1cc5d68281435ea9bfc6804a262047f7b934d")},
    {810500, common::pfh<Hash>("302b2349f221232820adc3dadafd8a61b035491e33af669c78a687949eb0a381")},
    {816000, common::pfh<Hash>("32b7fdd4e4d715db81f8f09f4ba5e5c78e8113f2804d61a57378baee479ce745")},
    {822000, common::pfh<Hash>("a3c9603c6813a0dc0efc40db288c356d1a7f02d1d2e47bee04346e73715f8984")},
    {841000, common::pfh<Hash>("2cffb6504ee38f708a6256a63585f9382b3b426e64b4504236c70678bd160dce")},
    {890000, common::pfh<Hash>("a7132932ea31236ce6b8775cd1380edf90b5e536ee4202c77b69a3d62445fcd2")},
    {894000, common::pfh<Hash>("ae2624ea1472ecc36de0d812f21a32da2d4afc7d5770830083cbaf652209d316")},
    {979000, common::pfh<Hash>("d8290eb4eedbe638f5dbadebcaf3ea434857ce96168185dc04f75b6cc1f4fda6")},
    {985548, common::pfh<Hash>("8d53e0d97594755a621feaee0978c0431fc01f42b85ff76a03af8641e2009d57")},
    {985549, common::pfh<Hash>("dc6f8d9319282475c981896b98ff9772ae2499533c2302c32faf65115aaf2554")},
    {996000, common::pfh<Hash>("c9a9243049acc7773a3e58ae354d66f8ea83996ece93ffbaad0b8b42b5fb7223")},
    {1021000, common::pfh<Hash>("a0c4107d327ffeb31dabe135a7124191b0a5ef7c4fa34f06babc1f0546ab938e")},
    {1039000, common::pfh<Hash>("8c9208940fc92539fac98cc658b95d240635f8729ee8bd756d6bdbab52de2c04")},
    {1170000, common::pfh<Hash>("f48441157749e89687dfa6edec2128ff332bdaa9eb139f2330a193e3139d2980")},
    {1268000, common::pfh<Hash>("d49fcaec1d53095e2c244913f123bfd4b26eabb6d75aca7b77a00de8aa8ac680")},
    {1272000, common::pfh<Hash>("2fb2c50328c8345d2f0a16b3ec4ea680a8a93730358494265ada9edbb9bfa1a6")},
    {1273000, common::pfh<Hash>("496a9238c654d79c48d269224aa75d61f51831bae6dc744f5e709bec11c7c9f2")},
    {1278000, common::pfh<Hash>("de0225cd279ca27cc8d4f8da1b5b92ba0112e48b3777b8c50301846ccfc9146b")},
    {1283000, common::pfh<Hash>("826043db95e9801f038f254d223ce0d0912da269dcce1461b5f0f05ddfae9e1c")},
    {1324000, common::pfh<Hash>("981e6f6871a7c295b56c5ce544adb5a7d52540ee23e15474b4357c7728952fef")},
    {1329000, common::pfh<Hash>("b88ed8dfe95a19bd6377f77c01d87df9cf7bd14cd6de7ec616beca95deb1fc85")},
    {1343000, common::pfh<Hash>("1696231b026b4e10412b16d65ba036c9750d287ab76da7e25efd4ba3fa9ed999")},
    {1372000, common::pfh<Hash>("55e02f544df808a12d3c2809b8c7490f8b0729aef196745240e94522c69a7181")},
    {1398000, common::pfh<Hash>("5e9eaf424ffba3957c569efc119a6e9ba0a636af99c44ea4cb921654ba634146")},
    {1422000, common::pfh<Hash>("edae8fec5d6572c84b4c6c794922b1e4ce97d82a057c77235407e29568525a46")},
    {1451000, common::pfh<Hash>("327814e8ee24650ad95d62b61e066d884abbb9d5ac18cd258baf24086c2a0882")},
    {1479000, common::pfh<Hash>("16c9a464514685d325ac06b82e4476d0d5467c59b733f5fbd950e9931e58d18c")},
    {1510000, common::pfh<Hash>("fcdc93636c47266f6d71606456d5767b7bc4567adbe8055b6d72b56401b48ece")},
    {1540000, common::pfh<Hash>("8014ee1613e13aea282f95b343cf46c376cf8050f801a145665ae80e33a867a1")},
    {1560000, common::pfh<Hash>("1a28c09c74b4b1ad97e4d65b99f97e62aa4f225be5b33017efc07c5c708b83ef")},
    {1579000, common::pfh<Hash>("debfa79d14ff49dc7e8c24e5e27a22f9a67819124a7dcd187c67493a969044be")},
    {1605000, common::pfh<Hash>("a34a41f2b5091f28f234b55a6255a9727fed355ca41233d59f779b2f87d1a359")},
    {1628000, common::pfh<Hash>("4e7b55e53402c71c45cb97f8ed78ed3f128c802008c83b0153aa52c30b740c68")},
    {1670000, common::pfh<Hash>("58770b800108c72512a386783fd0a4326c74dc9f99b538337a195945b89a9a6f")}};

constexpr const HardCheckpoint CHECKPOINTS_STAGENET[] = {
    {450, common::pfh<Hash>("c69823a6b3e0c1f724411e697219a9d31a2df900cb49bb0488b1a91a9989a805")},
    {30000, common::pfh<Hash>("4a3b02206d120bab6c3bef4a7bcbc1934b5327c27c181d790f4db407dc92c640")}};
}}  // namespace cn::parameters
