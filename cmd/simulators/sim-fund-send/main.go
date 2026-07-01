// sim-fund-send exercises P2.3a weighted-Guardian Fund SENDs end-to-end on a live network
// (spec-18 §7.3, spec-19 §6.2, build-plan §P2.3):
//
//   - Stake three SPENDING accounts as 1-year Guardians (weights 4 / 3 / 3 → eligible total 10).
//   - Fund SEND A (BOOTSTRAP, M=0): the keyless Fund spends, authorized solely by a verify-only
//     HybridMultiSig; with no active Guardians yet the threshold collapses to the N>=1 floor, so
//     a single eligible Guardian (here all three) authorizes it. The recipient claims the payout.
//   - Fund SEND B (≥70% PASS): now all three are active (M=10), so the quorum is ceil(0.7*10)=7;
//     G1+G2 = 7 passes.
//   - Fund SEND C (BELOW-THRESHOLD FAIL): G2+G3 = 6 < 7 — asserted to NEVER advance the Fund
//     chain (rejected deterministically every epoch), and the recipient gets no receivable.
//
// It prints FUND_SEND_COUNT, FUND_BALANCE and GUARDIANS_FINGERPRINT so the live harness can
// compare across nodes and across a wipe+resync (the Fund chain + the derived Guardian-activity
// projection both rebuild by replay).
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, FUND_ACCOUNT_HEX, EPOCH_MS,
// GENESIS_UNIX_MS.
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
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func main() {
	c := simkit.NewClient(mustEnv("VALIDATOR_URL_LIST"))

	genSeed := simkit.MustSeedFromHex(mustEnv("GENESIS_SEED_HEX"))
	genIDHex := strings.ToLower(mustEnv("GENESIS_HEX"))
	genesis := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, genSeed, genSeed)
	if hex.EncodeToString(genesis.IDBytes()) != genIDHex {
		log.Fatalf("config mismatch: GENESIS_SEED_HEX derives id %s but GENESIS_HEX=%s",
			hex.EncodeToString(genesis.IDBytes()), genIDHex)
	}
	fund := mustHex32(mustEnv("FUND_ACCOUNT_HEX"))
	epochMs := mustUint(mustEnv("EPOCH_MS"))
	genesisMs := mustUint(mustEnv("GENESIS_UNIX_MS"))

	// ── Step 0: Fund queryable from epoch 0. ──
	banner("STEP 0: Fund queryable")
	if f0, err := c.GetAccount(fund[:]); err != nil {
		log.Fatalf("Fund not queryable: %v", err)
	} else {
		assert(f0.AccountClass == pb.AccountClass_ACCOUNT_CLASS_FUND, "Fund class must be FUND")
	}

	// ── Step 1: fund + stake three Guardians (1yr, weights 4/3/3). ──
	banner("STEP 1: stake three 1-year Guardians (weights 4 / 3 / 3)")
	g1 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	g2 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	g3 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	fundFromGenesis(c, genesis, g1, anos(9_000))
	fundFromGenesis(c, genesis, g2, anos(7_000))
	fundFromGenesis(c, genesis, g3, anos(7_000))
	stakeGuardian(c, g1, fund, anos(8_000)) // weight floor(8000/2000) = 4
	stakeGuardian(c, g2, fund, anos(6_000)) // weight 3
	stakeGuardian(c, g3, fund, anos(6_000)) // weight 3
	waitForStakeCount(c, 3)
	// Confirm the derived weights before relying on them for the quorum math.
	roles := getRolesJSON(c)
	assertEq("g1 weight", role(roles, g1.ID).GuardianWeight, 4)
	assertEq("g2 weight", role(roles, g2.ID).GuardianWeight, 3)
	assertEq("g3 weight", role(roles, g3.ID).GuardianWeight, 3)

	// ── Step 2: Fund SEND A — BOOTSTRAP (M=0 → N>=1 floor). ──
	banner("STEP 2: Fund SEND A (bootstrap, signed by all three Guardians)")
	recipientA := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	payoutA := anos(100)
	sendFund(c, fund, recipientA.ID, payoutA, epoch(epochMs, genesisMs), []*simkit.Account{g1, g2, g3})
	c.WaitForSeqAtLeast(fund[:], 2, 500*time.Millisecond, 120*time.Second)
	log.Printf("Fund SEND A finalized (Fund seq -> 2)")

	// Recipient claims the payout (normal receivable, claimed directly).
	ridA := c.WaitForReceivable(recipientA.IDBytes(), nil, 1*time.Second, 60*time.Second)
	rtx := simkit.BuildOpeningReceive(recipientA, ridA, nil, 0)
	recipientA.MustSign(rtx)
	c.MustSubmit(rtx)
	c.WaitForSeqAtLeast(recipientA.IDBytes(), 1, 500*time.Millisecond, 60*time.Second)
	if st, err := c.GetAccount(recipientA.IDBytes()); err != nil || st.Balance != payoutA {
		log.Fatalf("recipient A balance = %v (err %v), want %d", st, err, payoutA)
	}
	log.Printf("recipient A claimed the %d-unit payout", payoutA)

	// All three Guardians are now active → M = 10 for subsequent sends.
	gset := waitForGuardianCount(c, 3)
	log.Printf("active Guardians: %d", len(gset))

	// ── Step 3: Fund SEND B — ≥70% PASS (G1+G2 = 7 >= ceil(0.7*10)=7). ──
	banner("STEP 3: Fund SEND B (G1+G2 weight 7 >= 70% of active 10)")
	recipientB := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	sendFund(c, fund, recipientB.ID, anos(50), epoch(epochMs, genesisMs), []*simkit.Account{g1, g2})
	c.WaitForSeqAtLeast(fund[:], 3, 500*time.Millisecond, 120*time.Second)
	log.Printf("Fund SEND B finalized (Fund seq -> 3)")

	// ── Step 4: Fund SEND C — BELOW-THRESHOLD FAIL (G2+G3 = 6 < 7). ──
	banner("STEP 4: Fund SEND C (G2+G3 weight 6 < 7 — must NOT finalize)")
	recipientC := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	sendFund(c, fund, recipientC.ID, anos(50), epoch(epochMs, genesisMs), []*simkit.Account{g2, g3})
	// It is rejected deterministically every epoch: assert the Fund chain stays at seq 3 and the
	// recipient never gets a receivable, over several epochs.
	assertFundSeqStays(c, fund, 3, 9*time.Duration(epochMs)*time.Millisecond)
	if recs, _ := c.ListReceivables(recipientC.IDBytes()); len(recs) != 0 {
		log.Fatalf("below-threshold Fund SEND C minted a receivable (%d) — must be rejected", len(recs))
	}
	log.Printf("Fund SEND C correctly rejected (Fund seq still 3, no receivable)")

	// ── Summary fingerprints. ──
	banner("RESULT")
	fundSt, err := c.GetAccount(fund[:])
	if err != nil {
		log.Fatalf("read fund: %v", err)
	}
	log.Printf("ALL CHECKS PASSED")
	log.Printf("FUND_SEND_COUNT=%d", fundSt.Seq-1) // real sends = seq advanced past the synthetic seed (1)
	log.Printf("FUND_BALANCE=%d", fundSt.Balance)
	log.Printf("GUARDIANS_FINGERPRINT=%s", guardiansFingerprint(getGuardiansJSON(c)))
}

// ── helpers ──

func anos(n uint64) uint64 { return n * core.UnitsPerAnos }

// epoch mirrors engine.epochAtUnixMs: floor((now-genesis)/epochMs)+1.
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

func stakeGuardian(c *simkit.Client, from *simkit.Account, fund [32]byte, amount uint64) {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read staker: %v", err)
	}
	// staked_for tag is immaterial to Guardian weight (any 1-year stake counts); use "guardian".
	tx := simkit.BuildStakeSend(from, head, seq+1, fund, amount, core.ExpectedFee(amount), "guardian", pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR, nil)
	from.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(from.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
}

func sendFund(c *simkit.Client, fund, to [32]byte, amount, fundEpoch uint64, signers []*simkit.Account) {
	head, seq, err := c.Head(fund[:])
	if err != nil {
		log.Fatalf("read fund: %v", err)
	}
	tx := simkit.BuildFundSend(fund, head, seq+1, to, amount, fundEpoch)
	if err := simkit.SignFundSend(tx, signers); err != nil {
		log.Fatalf("sign fund send: %v", err)
	}
	c.MustSubmit(tx)
}

func assertFundSeqStays(c *simkit.Client, fund [32]byte, wantSeq uint64, dur time.Duration) {
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		st, err := c.GetAccount(fund[:])
		if err == nil && st.Seq != wantSeq {
			log.Fatalf("Fund seq advanced to %d (want it to stay %d): a below-threshold send finalized!", st.Seq, wantSeq)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

type roleJSON struct {
	Identity       string `json:"identity"`
	IsBanker       bool   `json:"is_banker"`
	IsAttestor     bool   `json:"is_attestor"`
	GuardianWeight uint64 `json:"guardian_weight"`
}

type stakeJSON struct {
	DepositTxid string `json:"deposit_txid"`
}

type guardianJSON struct {
	GuardianID      string `json:"guardian_id"`
	LastActiveEpoch uint64 `json:"last_active_epoch"`
}

func getRolesJSON(c *simkit.Client) []roleJSON {
	var out []roleJSON
	getJSON(c.URLs[0]+"/debug/fund/roles", &out)
	return out
}

func getGuardiansJSON(c *simkit.Client) []guardianJSON {
	var out []guardianJSON
	getJSON(c.URLs[0]+"/debug/fund/guardians", &out)
	return out
}

func waitForStakeCount(c *simkit.Client, n int) {
	deadline := time.Now().Add(120 * time.Second)
	for {
		var s []stakeJSON
		getJSON(c.URLs[0]+"/debug/fund/stakes", &s)
		if len(s) >= n {
			return
		}
		if time.Now().After(deadline) {
			log.Fatalf("timed out waiting for %d stake rows (have %d)", n, len(s))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func waitForGuardianCount(c *simkit.Client, n int) []guardianJSON {
	deadline := time.Now().Add(120 * time.Second)
	for {
		g := getGuardiansJSON(c)
		if len(g) >= n {
			return g
		}
		if time.Now().After(deadline) {
			log.Fatalf("timed out waiting for %d active Guardians (have %d)", n, len(g))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func getJSON(url string, out interface{}) {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		log.Fatalf("decode %s: %v", url, err)
	}
}

func role(roles []roleJSON, id [32]byte) roleJSON {
	h := hex.EncodeToString(id[:])
	for _, r := range roles {
		if r.Identity == h {
			return r
		}
	}
	log.Fatalf("no role entry for identity %x", id[:4])
	return roleJSON{}
}

// guardiansFingerprint is a deterministic digest of the Guardian-activity projection (sorted by
// id) for cross-node / resync comparison.
func guardiansFingerprint(gs []guardianJSON) string {
	cp := append([]guardianJSON(nil), gs...)
	sort.Slice(cp, func(i, j int) bool { return cp[i].GuardianID < cp[j].GuardianID })
	h := sha256.New()
	for _, g := range cp {
		fmt.Fprintf(h, "%s|%d\n", g.GuardianID, g.LastActiveEpoch)
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
		log.Fatalf("expected uint, got %q: %v", s, err)
	}
	return v
}

func assertEq(what string, got, want uint64) {
	if got != want {
		log.Fatalf("ASSERT FAILED (%s): got %d, want %d", what, got, want)
	}
}

func assert(cond bool, msg string) {
	if !cond {
		log.Fatalf("ASSERT FAILED: %s", msg)
	}
}

func banner(s string) {
	log.Printf("────────────────────────────────────────")
	log.Printf("  %s", s)
}

func mustEnv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}
