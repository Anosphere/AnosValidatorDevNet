// sim-fund-stakes exercises the P2.2 stake reference table end-to-end on a live network
// (spec-18 §7, spec-19 §5, build-plan §P2.2):
//
//   - Real signed stake-deposit SENDs (to == Fund id, carrying staked_for/time_delay) are
//     accepted through the normal submit/consensus path and appended to the derived
//     reference table, queryable via /debug/fund/stakes from the read API.
//   - An UNKNOWN staked_for tag is stored, not rejected (open namespace).
//   - A sub-floor Attestor stake is stored but NOT role-eligible (the floor is a membership
//     predicate, not a deposit gate); a same-amount unknown-tag stake is equally accepted.
//   - Per-identity 1-year aggregation drives the Guardian weight (floor(Σ 1yr / 2000 anos));
//     1-month stakes confer none.
//   - A plain pool contribution to the Fund (no staked_for) records NO stake row.
//
// It prints STAKE_COUNT and STAKES_FINGERPRINT so the live harness can compare the table
// across nodes and across a wipe+resync (the table is derived — rebuilt by replay).
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, FUND_ACCOUNT_HEX.
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

	// ── Step 0: Fund queryable from epoch 0. ──
	banner("STEP 0: Fund queryable from epoch 0")
	if f0, err := c.GetAccount(fund[:]); err != nil {
		log.Fatalf("Fund not queryable (seed missing?): %v", err)
	} else {
		assert(f0.AccountClass == pb.AccountClass_ACCOUNT_CLASS_FUND, "Fund class must be FUND")
	}

	// ── Step 1: fund two SPENDING stakers from genesis. ──
	banner("STEP 1: fund stakers G and H from genesis")
	G := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	H := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	fundFromGenesis(c, genesis, G, anos(85_000))
	fundFromGenesis(c, genesis, H, anos(10_000))

	// ── Step 2: stake deposits. ──
	// G: a 60k Banker stake @1yr and a 10k Attestor stake @1yr (same identity → aggregated
	//    Guardian weight = floor((60000+10000)/2000) = 35; IsBanker + IsAttestor true).
	// H: a 4k "masterpod" (UNKNOWN tag) @1yr (stored, weight floor(4000/2000)=2) and a 4k
	//    Attestor @1mo (sub-floor AND 1mo → stored, NOT attestor-eligible, 0 guardian weight).
	banner("STEP 2: stake deposits (banker / attestor / unknown tag / sub-floor)")
	stakeSend(c, G, fund, anos(60_000), core.StakedForBanker, pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR)
	stakeSend(c, G, fund, anos(10_000), core.StakedForAttestor, pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR)
	stakeSend(c, H, fund, anos(4_000), "masterpod", pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR)
	stakeSend(c, H, fund, anos(4_000), core.StakedForAttestor, pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_MONTH)

	// A plain pool contribution (no staked_for) must add NO stake row.
	plainContribution(c, G, fund, anos(1_000))

	// ── Step 3: read back the table + role derivation. ──
	banner("STEP 3: assert the reference table + role derivation")
	stakes := waitForStakeCount(c, 4)
	roles := getRolesJSON(c)

	// Exactly the 4 stake rows (the plain pool contribution added none).
	assertEq("stake count", uint64(len(stakes)), 4)

	// Tag-by-amount checks (amounts are in base units).
	assert(findStake(stakes, G.ID, core.StakedForBanker, anos(60_000)), "G banker 60k@1yr stored")
	assert(findStake(stakes, G.ID, core.StakedForAttestor, anos(10_000)), "G attestor 10k@1yr stored")
	assert(findStake(stakes, H.ID, "masterpod", anos(4_000)), "H unknown-tag 'masterpod' stored (not rejected)")
	assert(findStake(stakes, H.ID, core.StakedForAttestor, anos(4_000)), "H sub-floor attestor stored (not rejected)")

	// Role derivation.
	rG, rH := role(roles, G.ID), role(roles, H.ID)
	assert(rG.IsBanker, "G is a Banker (60k >= 50k floor)")
	assert(rG.IsAttestor, "G is an Attestor (10k >= 5k floor)")
	assertEq("G guardian weight", rG.GuardianWeight, 35) // floor((60000+10000)/2000)
	assert(!rH.IsBanker, "H is NOT a Banker (no banker stake)")
	assert(!rH.IsAttestor, "H is NOT an Attestor (sub-floor 4k < 5k)")
	assertEq("H guardian weight", rH.GuardianWeight, 2) // floor(4000/2000), 1mo stake excluded

	log.Printf("ALL CHECKS PASSED")
	log.Printf("STAKE_COUNT=%d", len(stakes))
	log.Printf("STAKES_FINGERPRINT=%s", fingerprint(stakes))
}

// ── helpers ──

func anos(n uint64) uint64 { return n * core.UnitsPerAnos }

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

func stakeSend(c *simkit.Client, from *simkit.Account, fund [32]byte, amount uint64, stakedFor string, delay pb.StakeTimeDelay) {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read staker: %v", err)
	}
	tx := simkit.BuildStakeSend(from, head, seq+1, fund, amount, core.ExpectedFee(amount), stakedFor, delay, nil)
	from.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(from.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
}

func plainContribution(c *simkit.Client, from *simkit.Account, fund [32]byte, amount uint64) {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read sender: %v", err)
	}
	tx := simkit.BuildSend(from, head, seq+1, fund, amount, core.ExpectedFee(amount))
	from.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(from.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
}

type stakeJSON struct {
	DepositTxid string `json:"deposit_txid"`
	StakerID    string `json:"staker_id"`
	StakedFor   string `json:"staked_for"`
	Amount      uint64 `json:"amount"`
	TimeDelay   string `json:"time_delay"`
	Status      uint8  `json:"status"`
}

type roleJSON struct {
	Identity       string `json:"identity"`
	IsBanker       bool   `json:"is_banker"`
	IsAttestor     bool   `json:"is_attestor"`
	GuardianWeight uint64 `json:"guardian_weight"`
}

func getStakesJSON(c *simkit.Client) []stakeJSON {
	var out []stakeJSON
	getJSON(c.URLs[0]+"/debug/fund/stakes", &out)
	return out
}

func getRolesJSON(c *simkit.Client) []roleJSON {
	var out []roleJSON
	getJSON(c.URLs[0]+"/debug/fund/roles", &out)
	return out
}

func waitForStakeCount(c *simkit.Client, n int) []stakeJSON {
	deadline := time.Now().Add(120 * time.Second)
	for {
		s := getStakesJSON(c)
		if len(s) >= n {
			return s
		}
		if time.Now().After(deadline) {
			log.Fatalf("timed out waiting for %d stake rows (have %d)", n, len(s))
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

func findStake(stakes []stakeJSON, staker [32]byte, tag string, amount uint64) bool {
	id := hex.EncodeToString(staker[:])
	for _, s := range stakes {
		if s.StakerID == id && s.StakedFor == tag && s.Amount == amount && s.Status == 0 {
			return true
		}
	}
	return false
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

// fingerprint is a deterministic digest of the table (sorted by deposit_txid) for
// cross-node / resync comparison.
func fingerprint(stakes []stakeJSON) string {
	cp := append([]stakeJSON(nil), stakes...)
	sort.Slice(cp, func(i, j int) bool { return cp[i].DepositTxid < cp[j].DepositTxid })
	h := sha256.New()
	for _, s := range cp {
		fmt.Fprintf(h, "%s|%s|%s|%d|%s|%d\n", s.DepositTxid, s.StakerID, s.StakedFor, s.Amount, s.TimeDelay, s.Status)
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
