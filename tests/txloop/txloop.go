package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"

	"github.com/boltdb/bolt"
	"github.com/powerman/rpc-codec/jsonrpc2"
)

const (
	getStatusMethod         = "get_status"
	getAddressesMethod      = "get_addresses"
	getTransfersMethod      = "get_transfers"
	getBalanceMethod        = "get_balance"
	createAddressesMethod   = "create_addresses"
	createTransactionMethod = "create_transaction"

	defaultConfirmations  = 5
	defaultBalanceHeight  = -defaultConfirmations - 1
	defaultAnonymityLevel = 3

	addrBatchSize = 50000
	maxTxs        = 20
	maxTransfers  = 20
	txAmountDiv   = 77773 // 777787
)

var (
	metaBucket    = []byte("meta")
	balanceBucket = []byte("balance")

	allBuckets = [][]byte{
		metaBucket,
		balanceBucket,
	}

	syncedHeightKey = []byte("synced_height")
)

type (
	Transaction struct {
		// fields for new transactions
		UnlockTime uint64     `json:"unlock_time,omitempty"` // timestamp | blockIndex, see function isTransactionSpendTimeUnlocked below
		Transfers  []Transfer `json:"transfers"`             // includes only transfers we can view
		PaymentId  string     `json:"payment_id,omitempty"`  // omit or set to all zero-hash to indicates no payment id
		Anonymity  uint32     `json:"anonymity"`             // recommended to set to DEFAULT_ANONYMITY_LEVEL for new transactions, for existing transactions min(input anonymity will be returned)

		// after transaction is created
		Hash   string `json:"hash"`
		Fee    int64  `json:"fee"`
		PK     string `json:"public_key"`    // transaction public key
		Extra  string `json:"extra"` // payment_id packed here with some cryptographic data required for transaction
		IsBase bool   `json:"coinbase"`
		Amount uint64 `json:"amount"` // Amount transferred, this info is just for fun

		// after transaction is included in block
		BlockHeight uint64 `json:"block_height"`
		BlockHash   string `json:"block_hash"` // For mempool transactions block_hash is all zeroes (absent from Json)
		Timestamp   uint64 `json:"timestamp"`  // Timestamp of block, which hosts transaction. For mempool transactions this is the time node first seen this transaction.
	}

	BlockHeader struct {
		MajorVersion      uint8  `json:"major_version"`
		MinorVersion      uint8  `json:"minor_version"`
		Timestamp         uint64 `json:"timestamp"`
		PreviousBlockHash string `json:"previous_block_hash"`
		Nonce             uint32 `json:"nonce"`

		Height                       uint64 `json:"height"`
		Hash                         string `json:"hash"`
		Reward                       uint64 `json:"reward"`
		CumulativeDifficulty         uint64 `json:"cumulative_difficulty"`
		Difficulty                   uint64 `json:"difficulty"`
		BaseReward                   uint64 `json:"base_reward"`
		BlockSize                    uint32 `json:"block_size"`                   // Only sum of all transactions including coinbase
		TransactionsCumulativeSize   uint32 `json:"transactions_cumulative_size"` // Sum of all transactions without coinbase
		AlreadyGeneratedCoins        uint64 `json:"already_generated_coins"`
		AlreadyGeneratedTransactions uint64 `json:"already_generated_transactions"`
		SizeMedian                   uint32 `json:"size_median"`
		EffectiveSizeMedian          uint32 `json:"effective_size_median"` // max(100000, size_median) for block version 3, allows sudden peaks in network capacity
		TimestampMedian              uint64 `json:"timestamp_median"`
		TimestampUnlock              uint64 `json:"timestamp_unlock"` // can be used for guaranteed output unlocking, as 1. block.timestamp_unlock < block.timestamp and 2. nextBlock.timestamp_unlock >= currentBlock.timestamp_unlock
		TotalFeeAmount               uint64 `json:"total_fee_amount"`
	}

	Block struct {
		Header       BlockHeader   `json:"header"`
		Transactions []Transaction `json:"transactions"`
	}

	Transfer struct {
		Address string   `json:"address"`
		Amount  int64    `json:"amount"`         // Will be negative if transfer is from that address
		Ours    bool     `json:"ours,omitempty"` // true for addresses in wallet, false for others. Other addresses are recognized only for transactions which have proof data stored in <coin_folder>/history
		Locked  bool     `json:"locked,omitempty"`
		Outputs []Output `json:"outputs,omitempty"`
	}

	Output struct {
		Amount      uint64 `json:"amount"`
		PK          string `json:"public_key"`
		GlobalIndex uint32 `json:"global_index"`

		// Added from transaction
		UnlockTime uint64 `json:"unlock_time"` // timestamp | blockIndex, see function isTransactionSpendTimeUnlocked below
		IndexInTx  uint32 `json:"index_in_tx"` // # of output, output keys depend on transaction_public_key and this index, so they are different for the same address

		// Added from block
		Height uint64 `json:"height"`

		// Added by wallet for recognized outputs
		KeyImage string `json:"key_image"`
		TxPK     string `json:"transaction_public_key"`
		Address  string `json:"address"`
		IsDust   bool   `json:"dust"`
	}

	Balance struct {
		Spendable           uint64 `json:"spendable"`
		SpendableDust       uint64 `json:"spendable_dust"`
		LockedOrUnconfirmed uint64 `json:"locked_or_unconfirmed"`
	}
)

type (
	getStatusReq struct {
		TopBlockHash      string `json:"top_block_hash"`
		TxPoolVersion     uint32 `json:"transaction_pool_version"` // Pool version is reset to 1 on every new block. Pool version is incremented on every modification to pool
		OutgoingPeerCount uint32 `json:"outgoing_peer_count"`
		IncomingPeerCount uint32 `json:"incoming_peer_count"`
	}

	getStatusResp struct {
		getStatusReq

		TopBlockHeight      uint64 `json:"top_block_height"`
		TopBlockTimestamp   uint64 `json:"top_block_timestamp"`
		RecommendedFeePerKb uint64 `json:"recommended_fee_per_byte"`
	}

	getAddressesReq struct{}

	getAddressesResp struct {
		Addresses []string `json:"addresses"`
		ViewOnly  bool     `json:"view_only"`
	}

	getTransfersReq struct {
		Address    string `json:"address"`
		FromHeight uint64 `json:"from_height"`
		ToHeight   uint64 `json:"to_height"`
	}

	getTransfersResp struct {
		Blocks            []Block    `json:"blocks"`
		UnlockedTransfers []Transfer `json:"unlocked_transfers"`
	}

	getBalanceReq struct {
		Address       string `json:"address"`         // empty for all addresses
		HeightOrDepth int    `json:"height_or_depth"` // sophisticated clients usually set it to top_block_height - confirmations, simple clients to -1 - confirmations
	}

	getBalanceResp struct {
		Balance
	}

	createAddressesReq struct {
		SpendSecretKeys []string `json:"spend_secret_keys"`
	}

	createAddressesResp struct {
		Addresses []string `json:"addresses"`
	}

	createTransactionReq struct {
		Transaction Transaction `json:"transaction"` // You fill only basic info (anonymity, optional unlock_time, optional payment_id) and transfers. All positive transfers (amount > 0) will be added as outputs. For all negative transfers (amount < 0), spendable for requested sum and address will be selected and added as inputs

		SpendAddress    string `json:"spend_address"`     // If this is not empty, will spend (and optimize) outputs for this address to get neccessary funds. Otherwise will spend any output in the wallet
		AnySpendAddress bool   `json:"any_spend_address"` // if you set spend_address to empty, you should set any_spend_address to true. This is protection against client bug when spend_address is forgotten or accidentally set to null, etc
		ChangeAddress   string `json:"change_address"`    // Change will be returned to change_address.

		ConfirmedHeightOrDepth int    `json:"confirmed_height_or_depth"` // Mix-ins will be selected from the [0..confirmed_height] window. Reorganizations larger than confirmations may change mix-in global indices, making transaction invalid.
		FeePerKb               int64  `json:"fee_per_byte"`                // Fee of created transaction will be close to the size of tx * fee_per_byte. You can check it in response.transaction.fee before sending, if you wish
		Optimization           string `json:"optimization"`              // Wallet outputs optimization (fusion). Leave empty to use normal optimization, good for wallets with balanced sends to recieves count. You can save on a few percent of fee (on average) by specifying "minimal" for wallet receiving far less transactions than sending. You should use "aggressive" for wallet recieving far more transactions than sending, this option will use every opportunity to reduce number of outputs. For better optimization use as little anonymity as possible. If anonymity is set to 0, wallet will prioritize optimizing out dust and crazy (large but not round) denominations of outputs.
		SaveHistory            bool   `json:"save_history"`              // If true, wallet will save encrypted transaction data (~100 bytes per used address) in <coin_folder>/history/<tid>.txh. With this data it is possible to generate public-checkable proofs of sending funds to specific addresses.
		SendImmediately        bool   `json:"send_immediately"`          // Specifying false is useful if you wish to review transaction fee before sending. Specifying true will call SendRawTransactions and fill send_result
	}

	createTransactionResp struct {
		RawTransaction  string      `json:"binary_transaction"` // Empty if error
		TransactionHash string      `json:"transaction_hash"`
		Transaction     Transaction `json:"transaction"` // contains only fee, hash, blockIndex and anonymity for now...
		SendResult      string      `json:"send_result"` // Empty if !send_immediately. Otherwise see method below
	}
)

type balanceInfo struct {
	firstAddress string
	balances     map[string]uint64
}

func initDB(path string) (*bolt.DB, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range allBuckets {
			_, err := tx.CreateBucketIfNotExists(bucket)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

func formatUint(a uint64) []byte {
	return []byte(strconv.FormatUint(a, 10))
}

func parseUint(s []byte) (uint64, error) {
	if s == nil {
		return 0, nil
	}

	return strconv.ParseUint(string(s), 10, 64)
}

func roundtrip(client *jsonrpc2.Client, method string, req interface{}, resp interface{}) error {
	defer func(t time.Time) {
		dt := time.Now().Sub(t)
		log.Printf("%v took %v", method, dt)
	}(time.Now())

	log.Printf("doing %v...", method)

	err := client.Call(method, req, resp)
	if err != nil {
		r, _ := json.Marshal(req)
		return fmt.Errorf("%v(%v) RPC failed: %v", method, string(r), err)
	}

	return nil
}

func generateAddresses(c *jsonrpc2.Client, total int, batchSize int) ([]string, error) {
	r := []string(nil)

	var existing getAddressesResp
	err := roundtrip(c, getAddressesMethod, getAddressesReq{}, &existing)
	if err != nil {
		return nil, err
	}

	r = append(r, existing.Addresses...)
	log.Printf("total %v addresses", len(r))

	for len(r) < total+1 {
		var created createAddressesResp
		err := roundtrip(c, createAddressesMethod, createAddressesReq{SpendSecretKeys: make([]string, batchSize)}, &created)
		if err != nil {
			return nil, err
		}

		r = append(r, created.Addresses...)
		log.Printf("total %v addresses", len(r))
	}

	return r, nil
}

func loop(db *bolt.DB, c *jsonrpc2.Client, bi *balanceInfo, maxSyncBatchSize int) error {
	var syncedHeight uint64
	err := db.View(func(tx *bolt.Tx) error {
		var err error
		syncedHeight, err = parseUint(tx.Bucket(metaBucket).Get(syncedHeightKey))
		return err
	})
	if err != nil {
		return err
	}

	log.Printf("synced up to %v", syncedHeight)

	var (
		req  getStatusReq
		resp getStatusResp
	)
	for {
		req = resp.getStatusReq
		err = roundtrip(c, getStatusMethod, req, &resp)
		if err != nil {
			return err
		}

		log.Printf("tip updated to %v @ %v", resp.TopBlockHeight, resp.TopBlockHash)

		if resp.TopBlockHash == req.TopBlockHash {
			continue
		}

		if resp.TopBlockHeight < defaultConfirmations {
			return fmt.Errorf("not enough blocks in the blockchain")
		}

		historyTop := resp.TopBlockHeight - defaultConfirmations
		syncedHeight, err = syncFromTo(db, c, bi, syncedHeight, historyTop, maxSyncBatchSize)
		if err != nil {
			return err
		}

		err = transferSome(c, bi, resp.RecommendedFeePerKb)
		if err != nil {
			return err
		}
	}

	return nil
}

func syncFromTo(db *bolt.DB, c *jsonrpc2.Client, bi *balanceInfo, from uint64, to uint64, maxSyncBatchSize int) (uint64, error) {
	for from <= to {
		batchSize := uint64(rand.Intn(maxSyncBatchSize)) + 1

		req := getTransfersReq{
			FromHeight: from,
			ToHeight:   from + batchSize,
		}
		if req.ToHeight > to+1 {
			req.ToHeight = to + 1
		}

		var resp getTransfersResp
		err := roundtrip(c, getTransfersMethod, req, &resp)
		if err != nil {
			return 0, err
		}

		log.Printf("got %v blocks of history from %v to %v", len(resp.Blocks), req.FromHeight, req.ToHeight)

		err = db.Update(func(tx *bolt.Tx) error {
			tx.Bucket(metaBucket).Put(syncedHeightKey, formatUint(req.ToHeight))

			buck := tx.Bucket(balanceBucket)
			for _, b := range resp.Blocks {
				for _, tx := range b.Transactions {
					for _, tr := range tx.Transfers {
						err := doTransfer(tr, buck, bi)
						if err != nil {
							return err
						}
					}
				}
			}
			for _, tr := range resp.UnlockedTransfers {
				err := doTransfer(tr, buck, bi)
				if err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			return 0, err
		}

		from = req.ToHeight
	}

	return from, nil
}

func doTransfer(tr Transfer, b *bolt.Bucket, bi *balanceInfo) error {
	if tr.Ours && !tr.Locked {
		addr := []byte(tr.Address)

		balance, err := parseUint(b.Get(addr))
		if err != nil {
			return err
		}

		if tr.Amount >= 0 {
			balance += uint64(tr.Amount)
		} else {
			balance -= uint64(-tr.Amount)
		}

		bi.balances[tr.Address] = balance

		b.Put(addr, formatUint(balance))

		log.Printf("%v: %v (delta %v)", tr.Address, balance, tr.Amount)
	}

	return nil
}

func transferSome(c *jsonrpc2.Client, bi *balanceInfo, recommendedFeePerKb uint64) error {
	if len(bi.balances) == 0 {
		return nil
	}

	balance := bi.balances[bi.firstAddress]
	toSend := rand.Intn(maxTxs) + 1

	log.Printf("sending %v txs", toSend)

	for sent := 0; sent < toSend; sent++ {
		var (
			req = createTransactionReq{
				Transaction: Transaction{
					Anonymity: uint32(rand.Intn(defaultAnonymityLevel)),
				},
				SpendAddress:           bi.firstAddress,
				ChangeAddress:          bi.firstAddress,
				ConfirmedHeightOrDepth: defaultBalanceHeight,
				FeePerKb:               rand.Int63n(int64(recommendedFeePerKb)),
				Optimization:           "",
				SaveHistory:            true,
				SendImmediately:        true,
			}
			resp createTransactionResp
		)

		transfers := 0
		transfersTotal := rand.Intn(maxTransfers) + 1
		totalAmount := uint64(0)
		for addr := range bi.balances {
			if addr == bi.firstAddress {
				continue
			}
			if transfers >= transfersTotal {
				break
			}
			transfers++

			amount := int64(balance / txAmountDiv)
			if amount == 0 {
				log.Printf("no money to send")
				return nil
			}
			amount = rand.Int63n(amount) + 1

			req.Transaction.Transfers = append(req.Transaction.Transfers, Transfer{
				Address: addr,
				Amount:  amount,
			})

			balance -= uint64(amount)
			totalAmount += uint64(amount)
		}
		if len(req.Transaction.Transfers) == 0 {
			return nil
		}

		err := roundtrip(c, createTransactionMethod, req, &resp)
		if err != nil || resp.RawTransaction == "" {
			log.Printf("failed to create tx for %v, err %v, %#v, got %#v", totalAmount, err, req, resp)
			return nil
		}

		log.Printf("sent tx %v for %v with %v transfers, fee %v and block height %v", resp.TransactionHash, totalAmount, len(req.Transaction.Transfers), resp.Transaction.Fee, resp.Transaction.BlockHeight)
	}

	return nil
}

func main() {
	var (
		walletdAddr      = flag.String("walletAddr", "http://localhost:8070/json_rpc", "walletd RPC address")
		numAddresses     = flag.Int("numAddresses", 1000000, "number of addresses to manage")
		dbFilename       = flag.String("dbFilename", "txloop.db", "database filename")
		maxSyncBatchSize = flag.Int("maxSyncBatchSize", 1000, "history sync batch size (in blocks)")
	)

	flag.Parse()

	db, err := initDB(*dbFilename)
	if err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}
	defer db.Close()

	c := jsonrpc2.NewHTTPClient(*walletdAddr)
	defer c.Close()

	addrs, err := generateAddresses(c, *numAddresses+1, addrBatchSize)
	if err != nil {
		log.Fatalf("failed to generate addresses: %v", err)
	}

	balances := make(map[string]uint64, len(addrs))
	err = db.View(func(tx *bolt.Tx) error {
		for _, addr := range addrs {
			balance, err := parseUint(tx.Bucket(balanceBucket).Get([]byte(addr)))
			if err != nil {
				return err
			}
			balances[addr] = balance
		}
		return nil
	})
	if err != nil {
		log.Fatalf("failed to read balances: %v", err)
	}

	err = loop(db, c, &balanceInfo{balances: balances, firstAddress: addrs[0]}, *maxSyncBatchSize)
	log.Fatal(err)
}
