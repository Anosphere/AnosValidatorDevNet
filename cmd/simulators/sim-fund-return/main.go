// sim-fund-return exercises P2.3b return-stake + kick end-to-end on a live network
// (spec-19 §6.2, build-plan §P2.3):
//
//   - Stake a Guardian G (authorizer) and a staker S (both 1-year). Capture their deposit_txids.
//   - RETURN S's stake: a Guardian-authorized Fund SEND opens a TRANSFER chain that COPIES S's
//     keys, created by the keyless Fund (id = DerivedAccountID(TRANSFER, S pubkey, Fund, fundSeq)),
//     locked for the 1-year tier. S claims the chain, then drains it to itself AFTER the unlock.
//     S's stake row flips to Returned.
//   - KICK G's stake: a Guardian-authorized Fund SEND to the Fund itself forfeits G's stake
//     (status → Kicked), dropping G's Guardian weight.
//
// Prints STAKE_FINGERPRINT (incl. statuses) + FUND_BALANCE for cross-node / resync comparison.
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, FUND_ACCOUNT_HEX, EPOCH_MS,
// GENESIS_UNIX_MS, STAKE_LOCK_1YR_EPOCHS.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"anos/internal/core"
	"anos/internal/crypto"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func main() {
	c := simkit.NewClient(mustEnv("VALIDATOR_URL_LIST"))
	genSeed := simkit.MustSeedFromHex(mustEnv("GENESIS_SEED_HEX"))
	genesis := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, genSeed, genSeed)
	if hex.EncodeToString(genesis.IDBytes()) != strings.ToLower(mustEnv("GENESIS_HEX")) {
		log.Fatal("config mismatch: GENESIS_SEED_HEX vs GENESIS_HEX")
	}
	fund := mustHex32(mustEnv("FUND_ACCOUNT_HEX"))
	epochMs := mustUint(mustEnv("EPOCH_MS"))
	genesisMs := mustUint(mustEnv("GENESIS_UNIX_MS"))
	lock1yr := mustUint(mustEnv("STAKE_LOCK_1YR_EPOCHS"))

	banner("STEP 1: stake Guardian G (authorizer) + staker S, both 1yr")
	g := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	s := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	fundFromGenesis(c, genesis, g, anos(9_000))
	fundFromGenesis(c, genesis, s, anos(7_000))
	gDeposit := stakeGuardian(c, g, fund, anos(8_000)) // weight 4
	sStakeAmt := anos(6_000)
	sDeposit := stakeGuardian(c, s, fund, sStakeAmt) // weight 3
	waitForStakeCount(c, 2)

	banner("STEP 2: RETURN S's stake (bootstrap Fund SEND signed by G)")
	fhead, fseq, err := c.Head(fund[:])
	if err != nil {
		log.Fatalf("read fund: %v", err)
	}
	fundSeq := fseq + 1
	chain := simkit.DerivedReturnChain(s, fund, fundSeq)
	ret := simkit.BuildFundReturnSend(fund, fhead, fundSeq, chain.ID, sStakeAmt, epoch(epochMs, genesisMs), sDeposit)
	if err := simkit.SignFundSend(ret, []*simkit.Account{g}); err != nil {
		log.Fatalf("sign return: %v", err)
	}
	c.MustSubmit(ret)
	c.WaitForSeqAtLeast(fund[:], fundSeq, 500*time.Millisecond, 120*time.Second)
	assert(stakeStatus(c, sDeposit) == 1, "S's stake must be Returned (status 1)")
	log.Printf("S's stake returned; transfer chain id=%x", chain.ID[:6])

	banner("STEP 3: S claims the return chain, then drains it to itself after unlock")
	rid := c.WaitForReceivable(chain.IDBytes(), nil, 1*time.Second, 60*time.Second)
	// The chain's unlock must be >= creation_epoch + lock1yr; stamp generously past now.
	unlock := epoch(epochMs, genesisMs) + lock1yr + 2
	openRx := simkit.BuildOpeningReceive(chain, rid, ptr(s.ID), unlock)
	chain.MustSign(openRx)
	c.MustSubmit(openRx)
	c.WaitForSeqAtLeast(chain.IDBytes(), 1, 500*time.Millisecond, 60*time.Second)
	if st, err := c.GetAccount(chain.IDBytes()); err != nil || st.Balance != sStakeAmt {
		log.Fatalf("return chain balance = %v (err %v), want %d", st, err, sStakeAmt)
	}
	log.Printf("S claimed the return chain (balance %d); waiting for unlock epoch %d", sStakeAmt, unlock)

	// Wait until the unlock epoch passes, then drain the chain to S (release-to-dest).
	for epoch(epochMs, genesisMs) <= unlock {
		time.Sleep(time.Duration(epochMs) * time.Millisecond)
	}
	chHead, chSeq, _ := c.Head(chain.IDBytes())
	drain := simkit.BuildSend(chain, chHead, chSeq+1, s.ID, sStakeAmt, 0) // zero-fee full-balance drain
	chain.MustSign(drain)
	c.MustSubmit(drain)
	c.WaitForSeqAtLeast(chain.IDBytes(), chSeq+1, 500*time.Millisecond, 120*time.Second)
	// S claims the released funds (non-opening RECEIVE; S already exists).
	rid2 := c.WaitForReceivable(s.IDBytes(), nil, 1*time.Second, 60*time.Second)
	sHead, sSeq, _ := c.Head(s.IDBytes())
	recv := simkit.BuildReceive(s, sHead, sSeq+1, rid2)
	s.MustSign(recv)
	c.MustSubmit(recv)
	c.WaitForSeqAtLeast(s.IDBytes(), sSeq+1, 500*time.Millisecond, 60*time.Second)
	log.Printf("S drained the returned chain to itself after the lock")

	banner("STEP 4: KICK G's stake (Fund SEND Fund->itself, signed by G)")
	fhead, fseq, _ = c.Head(fund[:])
	kick := simkit.BuildFundKickSend(fund, fhead, fseq+1, epoch(epochMs, genesisMs), gDeposit)
	if err := simkit.SignFundSend(kick, []*simkit.Account{g}); err != nil {
		log.Fatalf("sign kick: %v", err)
	}
	c.MustSubmit(kick)
	c.WaitForSeqAtLeast(fund[:], fseq+1, 500*time.Millisecond, 120*time.Second)
	assert(stakeStatus(c, gDeposit) == 2, "G's stake must be Kicked (status 2)")
	log.Printf("G's stake kicked")

	banner("RESULT")
	fundSt, _ := c.GetAccount(fund[:])
	log.Printf("ALL CHECKS PASSED")
	log.Printf("FUND_BALANCE=%d", fundSt.Balance)
	log.Printf("STAKE_FINGERPRINT=%s", stakeFingerprint(c))
}

// ── helpers ──

func anos(n uint64) uint64     { return n * core.UnitsPerAnos }
func ptr(b [32]byte) *[32]byte { return &b }

func epoch(epochMs, genesisMs uint64) uint64 {
	now := uint64(time.Now().UnixMilli())
	if now <= genesisMs || epochMs == 0 {
		return 1
	}
	return (now-genesisMs)/epochMs + 1
}

func fundFromGenesis(c *simkit.Client, genesis, acct *simkit.Account, amount uint64) {
	head, seq, err := c.Head(genesis.IDBytes())
	if err != nil {
		log.Fatalf("read genesis: %v", err)
	}
	tx := simkit.BuildSend(genesis, head, seq+1, acct.ID, amount, core.ExpectedFee(amount))
	genesis.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(genesis.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
	rid := c.WaitForReceivable(acct.IDBytes(), nil, 1*time.Second, 120*time.Second)
	rtx := simkit.BuildOpeningReceive(acct, rid, nil, 0)
	acct.MustSign(rtx)
	c.MustSubmit(rtx)
	c.WaitForSeqAtLeast(acct.IDBytes(), 1, 500*time.Millisecond, 120*time.Second)
}

// stakeGuardian stakes `amount` @1yr and returns the deposit_txid.
func stakeGuardian(c *simkit.Client, from *simkit.Account, fund [32]byte, amount uint64) [32]byte {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read staker: %v", err)
	}
	tx := simkit.BuildStakeSend(from, head, seq+1, fund, amount, core.ExpectedFee(amount), "guardian", pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR, nil)
	from.MustSign(tx)
	txid, err := crypto.TxID(tx)
	if err != nil {
		log.Fatalf("txid: %v", err)
	}
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(from.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
	return txid
}

type stakeJSON struct {
	DepositTxid string `json:"deposit_txid"`
	StakerID    string `json:"staker_id"`
	StakedFor   string `json:"staked_for"`
	Amount      uint64 `json:"amount"`
	TimeDelay   string `json:"time_delay"`
	Status      uint8  `json:"status"`
}

func getStakesJSON(c *simkit.Client) []stakeJSON {
	var out []stakeJSON
	resp, err := http.Get(c.URLs[0] + "/debug/fund/stakes")
	if err != nil {
		log.Fatalf("GET stakes: %v", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		log.Fatalf("decode stakes: %v", err)
	}
	return out
}

func stakeStatus(c *simkit.Client, depositTxid [32]byte) uint8 {
	h := hex.EncodeToString(depositTxid[:])
	for _, s := range getStakesJSON(c) {
		if s.DepositTxid == h {
			return s.Status
		}
	}
	log.Fatalf("stake %x not found", depositTxid[:4])
	return 255
}

func waitForStakeCount(c *simkit.Client, n int) {
	deadline := time.Now().Add(120 * time.Second)
	for {
		if len(getStakesJSON(c)) >= n {
			return
		}
		if time.Now().After(deadline) {
			log.Fatalf("timed out waiting for %d stakes", n)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func stakeFingerprint(c *simkit.Client) string {
	rows := getStakesJSON(c)
	sort.Slice(rows, func(i, j int) bool { return rows[i].DepositTxid < rows[j].DepositTxid })
	h := sha256.New()
	for _, s := range rows {
		fmt.Fprintf(h, "%s|%s|%d|%s|%d\n", s.DepositTxid, s.StakerID, s.Amount, s.TimeDelay, s.Status)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mustHex32(s string) [32]byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		log.Fatalf("expected 32-byte hex, got %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func mustUint(s string) uint64 {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		log.Fatalf("expected uint, got %q", s)
	}
	return v
}

func assert(cond bool, msg string) {
	if !cond {
		log.Fatalf("ASSERT FAILED: %s", msg)
	}
}

func banner(s string) {
	log.Printf("──────────────────────────────────────── %s", s)
}

func mustEnv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}
