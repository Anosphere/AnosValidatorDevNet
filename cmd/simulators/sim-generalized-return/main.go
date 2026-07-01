// sim-generalized-return exercises P5.4 C2 in-Fund stake recovery (generalized return) end-to-end on a
// live network (working notes §3.4 "Recovery — FINALIZED", build-plan §P5.4):
//
//   - Stake a Guardian G (authorizer) and a staker S (1-year). Register a fresh beneficiary B (the
//     recovery target — a base-owner, key-registered account NOT holding S's keys).
//   - NEGATIVE: a Guardian-authorized generalized return of S's stake to B WITHOUT the owner's
//     authorization is REJECTED (a quorum can enact but never redirect — the theft guard).
//   - POSITIVE: the same return carrying S's owner_auth (signed over (deposit_txid, B)) is accepted:
//     the Fund opens a TRANSFER chain that copies B's keys (id = DerivedAccountID(TRANSFER, B pubkey,
//     Fund, fundSeq)) locked for the GUARDIAN-CHOSEN delay (not the tier lock). S's stake flips to
//     Returned. B claims the chain and drains it to itself after the chosen delay.
//   - Repeat the POSITIVE flow once more with the owner's BREAKGLASS-key authorization (recovery when
//     the auth key is lost), returning a second staker's stake to B.
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

	banner("STEP 2: NEGATIVE — a generalized return to B WITHOUT owner_auth is rejected")
	fhead, fseq, err := c.Head(fund[:])
	if err != nil {
		log.Fatalf("read fund: %v", err)
	}
	fundSeq := fseq + 1
	chain := simkit.DerivedReturnChain(b, fund, fundSeq) // chain copies B's keys
	noAuth := simkit.BuildFundGeneralizedReturnSend(fund, fhead, fundSeq, chain.ID, stakeAmt, epoch(epochMs, genesisMs), s1Deposit, b.ID, chosenDelay, nil)
	if err := simkit.SignFundSend(noAuth, []*simkit.Account{g}); err != nil {
		log.Fatalf("sign no-auth return: %v", err)
	}
	if err := c.Submit(noAuth); err == nil {
		log.Fatal("ASSERT FAILED: a generalized return without owner_auth was accepted (theft guard breached)")
	}
	log.Printf("rejected as expected: redirecting a stake needs the owner's authorization")

	banner("STEP 3: POSITIVE — return S1's stake to B with S1's owner_auth (auth key)")
	oa := s1.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, s1Deposit, b.ID, false)
	generalizedReturnToB(c, fund, epochMs, genesisMs, b, chain, fundSeq, stakeAmt, s1Deposit, oa)
	assert(stakeStatus(c, s1Deposit) == 1, "S1's stake must be Returned (status 1)")
	drainReturnChainToB(c, epochMs, genesisMs, b, chain, stakeAmt)

	banner("STEP 4: POSITIVE — return S2's stake to B via S2's BREAKGLASS owner_auth (lost auth key)")
	fhead, fseq, _ = c.Head(fund[:])
	fundSeq2 := fseq + 1
	chain2 := simkit.DerivedReturnChain(b, fund, fundSeq2)
	bgAuth := s2.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, s2Deposit, b.ID, true) // breakglass reveal
	generalizedReturnToB(c, fund, epochMs, genesisMs, b, chain2, fundSeq2, stakeAmt, s2Deposit, bgAuth)
	assert(stakeStatus(c, s2Deposit) == 1, "S2's stake must be Returned (status 1)")
	drainReturnChainToB(c, epochMs, genesisMs, b, chain2, stakeAmt)

	banner("RESULT")
	fundSt, _ := c.GetAccount(fund[:])
	log.Printf("ALL CHECKS PASSED")
	log.Printf("FUND_BALANCE=%d", fundSt.Balance)
	log.Printf("STAKE_FINGERPRINT=%s", stakeFingerprint(c))
}

// generalizedReturnToB submits a Guardian-authorized C2 return of `deposit` to beneficiary B and waits
// for the Fund SEND to commit + the stake row to flip to Returned.
func generalizedReturnToB(c *simkit.Client, fund [32]byte, epochMs, genesisMs uint64, b, chain *simkit.Account, fundSeq, amount uint64, deposit [32]byte, oa *pb.StakeOwnerAuth) {
	fhead, _, err := c.Head(fund[:])
	if err != nil {
		log.Fatalf("read fund: %v", err)
	}
	ret := simkit.BuildFundGeneralizedReturnSend(fund, fhead, fundSeq, chain.ID, amount, epoch(epochMs, genesisMs), deposit, b.ID, chosenDelay, oa)
	if err := simkit.SignFundSend(ret, []*simkit.Account{guardianG}); err != nil {
		log.Fatalf("sign return: %v", err)
	}
	c.MustSubmit(ret)
	c.WaitForSeqAtLeast(fund[:], fundSeq, 500*time.Millisecond, 120*time.Second)
	log.Printf("generalized return committed; chain (B-keyed) id=%x", chain.ID[:6])
}

// drainReturnChainToB claims the B-keyed return chain and drains it to B after the Guardian-chosen delay.
func drainReturnChainToB(c *simkit.Client, epochMs, genesisMs uint64, b, chain *simkit.Account, amount uint64) {
	rid := c.WaitForReceivable(chain.IDBytes(), nil, 1*time.Second, 60*time.Second)
	unlock := epoch(epochMs, genesisMs) + chosenDelay + 2
	openRx := simkit.BuildOpeningReceive(chain, rid, ptr(b.ID), unlock)
	chain.MustSign(openRx) // the chain shares B's keys
	c.MustSubmit(openRx)
	c.WaitForSeqAtLeast(chain.IDBytes(), 1, 500*time.Millisecond, 60*time.Second)
	if st, err := c.GetAccount(chain.IDBytes()); err != nil || st.Balance != amount {
		log.Fatalf("return chain balance = %v (err %v), want %d", st, err, amount)
	}
	for epoch(epochMs, genesisMs) <= unlock {
		time.Sleep(time.Duration(epochMs) * time.Millisecond)
	}
	chHead, chSeq, _ := c.Head(chain.IDBytes())
	drain := simkit.BuildSend(chain, chHead, chSeq+1, b.ID, amount, 0) // release-to-dest = B, zero-fee
	chain.MustSign(drain)
	c.MustSubmit(drain)
	c.WaitForSeqAtLeast(chain.IDBytes(), chSeq+1, 500*time.Millisecond, 120*time.Second)
	rid2 := c.WaitForReceivable(b.IDBytes(), nil, 1*time.Second, 60*time.Second)
	bHead, bSeq, _ := c.Head(b.IDBytes())
	recv := simkit.BuildReceive(b, bHead, bSeq+1, rid2)
	b.MustSign(recv)
	c.MustSubmit(recv)
	c.WaitForSeqAtLeast(b.IDBytes(), bSeq+1, 500*time.Millisecond, 60*time.Second)
	log.Printf("B claimed the recovered stake after the Guardian-chosen delay")
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
