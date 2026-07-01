// sim-enroute-recovery exercises P5.5 en-route stake recovery end-to-end on a live network (working
// notes §3.4 "Recovery — FINALIZED" (D), build-plan §P5.5):
//
//   - Stake a Guardian G (authorizer) + two stakers S1, S2 (1-year). Register a fresh beneficiary B.
//   - RETURN each staker's stake to ITSELF (a Guardian-authorized return; the chain copies the staker's
//     keys, row → Returned) — modelling a return in flight. Each staker then "loses" its auth key.
//   - S1 — the NOT-YET-OPENED edge: the staker BREAKGLASS-OPENS the stuck return chain, then
//     BREAKGLASS-RETURNS it to the (keyless) Fund. Row → Reverted (status 3), value back in the pool.
//   - S2 — the ALREADY-OPENED edge: the chain is opened with the AUTH key first, then BREAKGLASS-RETURNED
//     to the Fund. Row → Reverted — proving the bg-return works on an already-opened chain too.
//   - NEGATIVE: a Guardian-authorized recovery of a Reverted stake to B WITHOUT the owner's authorization
//     is REJECTED (a quorum can enact but never redirect — the theft guard holds on Reverted rows too).
//   - POSITIVE: the same recovery carrying S's BREAKGLASS owner_auth is accepted: the Fund opens a
//     TRANSFER chain copying B's keys, S's row flips Reverted → the TERMINAL Recovered (status 4). B
//     claims + drains the recovered stake after the Guardian-chosen delay.
//
// Prints STAKE_FINGERPRINT (incl. statuses) + FUND_BALANCE for cross-node / resync comparison.
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, FUND_ACCOUNT_HEX, EPOCH_MS, GENESIS_UNIX_MS.
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

// the Guardian-chosen return delay (short so the sim can drain quickly; replaces the tier lock).
const chosenDelay = 2

// stake status codes (mirroring core.StakeStatus) surfaced by /debug/fund/stakes.
const (
	statusReturned  = 1
	statusReverted  = 3
	statusRecovered = 4
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
	env := &simEnv{c: c, fund: fund, epochMs: epochMs, genesisMs: genesisMs}

	banner("STEP 1: stake Guardian G (authorizer) + stakers S1,S2 (1yr); register beneficiary B")
	g := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	s1 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	s2 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	b := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING) // the recovery beneficiary (fresh keys)
	fundFromGenesis(c, genesis, g, anos(9_000))
	fundFromGenesis(c, genesis, s1, anos(7_000))
	fundFromGenesis(c, genesis, s2, anos(7_000))
	fundFromGenesis(c, genesis, b, anos(10)) // B just needs to be key-registered
	stakeGuardian(c, g, fund, anos(8_000))   // weight 4 (authorizer)
	stakeAmt := anos(6_000)
	s1Deposit := stakeGuardian(c, s1, fund, stakeAmt)
	s2Deposit := stakeGuardian(c, s2, fund, stakeAmt)
	waitForStakeCount(c, 3)

	banner("STEP 2: S1 — NOT-YET-OPENED edge: return→bg-open→bg-return→Reverted")
	chain1 := env.returnToStaker(s1, s1Deposit, stakeAmt) // Fund mints the S1-keyed return chain, row Returned
	assert(stakeStatus(c, s1Deposit) == statusReturned, "S1's stake must be Returned (status 1)")
	env.breakglassOpen(s1, chain1) // the staker lost the auth key → the breakglass key opens the stuck chain
	env.breakglassReturnToFund(chain1, stakeAmt)
	env.waitForStakeStatus(s1Deposit, statusReverted)
	log.Printf("S1: en-route stake recovered to the Fund (Reverted)")

	banner("STEP 3: S2 — ALREADY-OPENED edge: return→auth-open→bg-return→Reverted")
	chain2 := env.returnToStaker(s2, s2Deposit, stakeAmt)
	assert(stakeStatus(c, s2Deposit) == statusReturned, "S2's stake must be Returned (status 1)")
	env.authOpen(s2, chain2) // opened with the auth key (before it was lost)
	env.breakglassReturnToFund(chain2, stakeAmt)
	env.waitForStakeStatus(s2Deposit, statusReverted)
	log.Printf("S2: bg-return of an already-opened chain also reverts the row")

	banner("STEP 4: NEGATIVE — recovering a Reverted stake to B WITHOUT owner_auth is rejected")
	fhead, fseq, err := c.Head(fund[:])
	if err != nil {
		log.Fatalf("read fund: %v", err)
	}
	fundSeq := fseq + 1
	recChainNoAuth := simkit.DerivedReturnChain(b, fund, fundSeq)
	noAuth := simkit.BuildFundGeneralizedReturnSend(fund, fhead, fundSeq, recChainNoAuth.ID, stakeAmt, epoch(epochMs, genesisMs), s1Deposit, b.ID, chosenDelay, nil)
	if err := simkit.SignFundSend(noAuth, []*simkit.Account{g}); err != nil {
		log.Fatalf("sign no-auth recovery: %v", err)
	}
	if err := c.Submit(noAuth); err == nil {
		log.Fatal("ASSERT FAILED: recovering a Reverted stake without owner_auth was accepted (theft guard breached)")
	}
	log.Printf("rejected as expected: recovering a Reverted stake still needs the owner's authorization")

	banner("STEP 5: POSITIVE — recover S1's Reverted stake to B via S1's BREAKGLASS owner_auth → Recovered")
	recChain := env.recoverToB(s1, s1Deposit, b, stakeAmt)
	env.waitForStakeStatus(s1Deposit, statusRecovered)
	log.Printf("S1's stake flipped to the terminal Recovered status")
	env.drainReturnChainToB(b, recChain, stakeAmt)

	banner("RESULT")
	fundSt, _ := c.GetAccount(fund[:])
	log.Printf("ALL CHECKS PASSED")
	log.Printf("FUND_BALANCE=%d", fundSt.Balance)
	log.Printf("STAKE_FINGERPRINT=%s", stakeFingerprint(c))
}

// simEnv bundles the live-network handles the flow helpers need.
type simEnv struct {
	c         *simkit.Client
	fund      [32]byte
	epochMs   uint64
	genesisMs uint64
}

// returnToStaker submits a Guardian-authorized return of `deposit` to the STAKER itself (B == staker, no
// owner_auth needed) and waits for the row to flip to Returned. Returns the staker-keyed return chain.
func (e *simEnv) returnToStaker(staker *simkit.Account, deposit [32]byte, amount uint64) *simkit.Account {
	fhead, fseq, err := e.c.Head(e.fund[:])
	if err != nil {
		log.Fatalf("read fund: %v", err)
	}
	fundSeq := fseq + 1
	chain := simkit.DerivedReturnChain(staker, e.fund, fundSeq) // copies the staker's keys
	// B == the staker → not a redirect → no owner_auth; a Guardian-chosen delay (drops the tier lock).
	ret := simkit.BuildFundGeneralizedReturnSend(e.fund, fhead, fundSeq, chain.ID, amount, epoch(e.epochMs, e.genesisMs), deposit, staker.ID, chosenDelay, nil)
	if err := simkit.SignFundSend(ret, []*simkit.Account{guardianG}); err != nil {
		log.Fatalf("sign return: %v", err)
	}
	e.c.MustSubmit(ret)
	e.c.WaitForSeqAtLeast(e.fund[:], fundSeq, 500*time.Millisecond, 120*time.Second)
	log.Printf("return committed; staker-keyed chain id=%x", chain.ID[:6])
	return chain
}

// breakglassOpen opens the stuck return chain with the staker's BREAKGLASS key (the not-yet-opened edge).
func (e *simEnv) breakglassOpen(staker, chain *simkit.Account) {
	rid := e.c.WaitForReceivable(chain.IDBytes(), nil, 1*time.Second, 60*time.Second)
	unlock := epoch(e.epochMs, e.genesisMs) + chosenDelay + 2
	openRx := simkit.BuildOpeningReceive(chain, rid, ptr(staker.ID), unlock)
	chain.MustSignBreakglass(openRx) // the chain shares the staker's breakglass key; reveals it
	e.c.MustSubmit(openRx)
	e.c.WaitForSeqAtLeast(chain.IDBytes(), 1, 500*time.Millisecond, 60*time.Second)
	log.Printf("breakglass-opened the stuck chain id=%x", chain.ID[:6])
}

// authOpen opens the return chain with the (not-yet-lost) auth key (the already-opened edge).
func (e *simEnv) authOpen(staker, chain *simkit.Account) {
	rid := e.c.WaitForReceivable(chain.IDBytes(), nil, 1*time.Second, 60*time.Second)
	unlock := epoch(e.epochMs, e.genesisMs) + chosenDelay + 2
	openRx := simkit.BuildOpeningReceive(chain, rid, ptr(staker.ID), unlock)
	chain.MustSign(openRx) // the chain shares the staker's auth key
	e.c.MustSubmit(openRx)
	e.c.WaitForSeqAtLeast(chain.IDBytes(), 1, 500*time.Millisecond, 60*time.Second)
	log.Printf("auth-opened the chain id=%x", chain.ID[:6])
}

// breakglassReturnToFund drains the (Fund-sourced) chain back to the keyless Fund via the breakglass key —
// UNGATED (any epoch, no attestors). ApplyTx marks the referenced stake row Reverted.
func (e *simEnv) breakglassReturnToFund(chain *simkit.Account, amount uint64) {
	chHead, chSeq, err := e.c.Head(chain.IDBytes())
	if err != nil {
		log.Fatalf("read chain: %v", err)
	}
	ret := simkit.BuildSend(chain, chHead, chSeq+1, e.fund, amount, 0) // return-to-source == the Fund
	chain.MustSignBreakglass(ret)
	e.c.MustSubmit(ret)
	e.c.WaitForSeqAtLeast(chain.IDBytes(), chSeq+1, 500*time.Millisecond, 120*time.Second)
	log.Printf("breakglass-returned chain id=%x to the Fund", chain.ID[:6])
}

// recoverToB submits a Guardian-authorized C2 recovery of a REVERTED stake to beneficiary B, carrying the
// owner's BREAKGLASS owner_auth (the auth key is lost). Returns the B-keyed recovery chain.
func (e *simEnv) recoverToB(staker *simkit.Account, deposit [32]byte, b *simkit.Account, amount uint64) *simkit.Account {
	fhead, fseq, err := e.c.Head(e.fund[:])
	if err != nil {
		log.Fatalf("read fund: %v", err)
	}
	fundSeq := fseq + 1
	chain := simkit.DerivedReturnChain(b, e.fund, fundSeq) // copies B's keys
	oa := staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, deposit, b.ID, true)
	rec := simkit.BuildFundGeneralizedReturnSend(e.fund, fhead, fundSeq, chain.ID, amount, epoch(e.epochMs, e.genesisMs), deposit, b.ID, chosenDelay, oa)
	if err := simkit.SignFundSend(rec, []*simkit.Account{guardianG}); err != nil {
		log.Fatalf("sign recovery: %v", err)
	}
	e.c.MustSubmit(rec)
	e.c.WaitForSeqAtLeast(e.fund[:], fundSeq, 500*time.Millisecond, 120*time.Second)
	log.Printf("recovery committed; B-keyed chain id=%x", chain.ID[:6])
	return chain
}

// drainReturnChainToB claims the B-keyed recovery chain and drains it to B after the Guardian-chosen delay.
func (e *simEnv) drainReturnChainToB(b, chain *simkit.Account, amount uint64) {
	rid := e.c.WaitForReceivable(chain.IDBytes(), nil, 1*time.Second, 60*time.Second)
	unlock := epoch(e.epochMs, e.genesisMs) + chosenDelay + 2
	openRx := simkit.BuildOpeningReceive(chain, rid, ptr(b.ID), unlock)
	chain.MustSign(openRx) // the chain shares B's keys
	e.c.MustSubmit(openRx)
	e.c.WaitForSeqAtLeast(chain.IDBytes(), 1, 500*time.Millisecond, 60*time.Second)
	if st, err := e.c.GetAccount(chain.IDBytes()); err != nil || st.Balance != amount {
		log.Fatalf("recovery chain balance = %v (err %v), want %d", st, err, amount)
	}
	for epoch(e.epochMs, e.genesisMs) <= unlock {
		time.Sleep(time.Duration(e.epochMs) * time.Millisecond)
	}
	chHead, chSeq, _ := e.c.Head(chain.IDBytes())
	drain := simkit.BuildSend(chain, chHead, chSeq+1, b.ID, amount, 0) // release-to-dest = B, zero-fee
	chain.MustSign(drain)
	e.c.MustSubmit(drain)
	e.c.WaitForSeqAtLeast(chain.IDBytes(), chSeq+1, 500*time.Millisecond, 120*time.Second)
	rid2 := e.c.WaitForReceivable(b.IDBytes(), nil, 1*time.Second, 60*time.Second)
	bHead, bSeq, _ := e.c.Head(b.IDBytes())
	recv := simkit.BuildReceive(b, bHead, bSeq+1, rid2)
	b.MustSign(recv)
	e.c.MustSubmit(recv)
	e.c.WaitForSeqAtLeast(b.IDBytes(), bSeq+1, 500*time.Millisecond, 60*time.Second)
	log.Printf("B claimed the recovered stake after the Guardian-chosen delay")
}

func (e *simEnv) waitForStakeStatus(deposit [32]byte, want uint8) {
	deadline := time.Now().Add(120 * time.Second)
	for {
		if stakeStatus(e.c, deposit) == want {
			return
		}
		if time.Now().After(deadline) {
			log.Fatalf("timed out waiting for stake %x to reach status %d", deposit[:4], want)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// guardianG is the shared authorizer, set in STEP 1 (kept as a package global so the helpers can sign).
var guardianG *simkit.Account

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
	if guardianG == nil {
		guardianG = from // the first staker is G, the authorizer
	}
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
	bts, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(bts) != 32 {
		log.Fatalf("expected 32-byte hex, got %q", s)
	}
	var out [32]byte
	copy(out[:], bts)
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
