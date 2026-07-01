// sim-banker-rotate demonstrates P4.2 self-signed key/IP rotation (build-plan §P4.2, working
// notes §3.7). Rotation reuses the P4.1 mechanism: a banker rotates by sending a SMALL ADDITIVE
// self-signed Banker deposit carrying a new consensus key / endpoint, and the keep-max-by-send-seq
// BBankerInfo projection REPLACES the identity's single descriptor (it never appends). This sim
// pins the rotation CONTRACT end to end against the live, Fund-derived set (/debug/fund/bankers):
//
//  1. A SPENDING banker B1 stakes "banker" (>= 50k anos, 1-month tier) with consensus key K1 +
//     endpoint E1 → it appears in the validator set as (K1, E1).
//  2. ROTATE key+endpoint: B1 sends a SUB-FLOOR (1 anos) additive "banker" deposit carrying a NEW
//     key K2 + endpoint E2. The set updates to (K2, E2); the OLD key K1 is GONE from the set
//     entirely; B1 is still a Banker (its original 50k stake is active) and has exactly ONE
//     descriptor row. (Sub-floor deposit ⇒ membership is preserved purely by the original stake.)
//  3. ENDPOINT-ONLY rotate: B1 sends another sub-floor deposit carrying the SAME key K2 but a new
//     endpoint E3. The set updates to (K2, E3); the old endpoint E2 is gone.
//
// In P4.2 the env list still drives LIVE consensus (the list→Fund flip is P4.3). This sim reads one
// node (URLs[0]); the CROSS-NODE agreement + RESYNC determinism of the rotated descriptor projection is
// verified by the live harness, which folds /debug/fund/bankers into its 3-node agreement + post-resync
// hash. The activation-boundary "old key is dead" semantics land in P4.3.
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, FUND_ACCOUNT_HEX.
package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"anos/internal/core"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func main() {
	urls := mustEnv("VALIDATOR_URL_LIST")
	c := simkit.NewClient(urls)

	genSeed := simkit.MustSeedFromHex(mustEnv("GENESIS_SEED_HEX"))
	genIDHex := strings.ToLower(mustEnv("GENESIS_HEX"))
	genesis := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, genSeed, genSeed)
	if hex.EncodeToString(genesis.IDBytes()) != genIDHex {
		log.Fatalf("config mismatch: GENESIS_SEED_HEX derives id %s but GENESIS_HEX=%s",
			hex.EncodeToString(genesis.IDBytes()), genIDHex)
	}
	fund := fundAccountID()

	const (
		bankerStake = uint64(60_000) * core.UnitsPerAnos // > the 50k banker floor
		rotateAmt   = uint64(1) * core.UnitsPerAnos      // SUB-FLOOR additive rotation deposit
		grant       = uint64(80_000) * core.UnitsPerAnos // genesis grant (stake + rotations + fees)
	)
	oneMonth := pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_MONTH

	// ---------------------------------------------------------------
	// STEP 1: B1 stakes banker with consensus key K1 + endpoint E1.
	// ---------------------------------------------------------------
	banner("STEP 1: B1 stakes banker (K1, E1)")
	B1 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	fundAndOpen(c, genesis, B1, grant)
	k1 := simkit.RandomConsensusKey()
	const e1 = "10.0.0.11:9090"
	bankerStakeSend(c, B1, fund, bankerStake, oneMonth, k1, e1)
	waitBankerKey(c, B1.IDBytes(), k1, e1, "STEP 1")
	assertExactlyOneDescriptor(c, B1.IDBytes(), "STEP 1")
	log.Printf("OK: B1=%x in the set as (K1=%x, E1=%s)", B1.IDBytes()[:4], k1[:6], e1)

	// ---------------------------------------------------------------
	// STEP 2: rotate KEY+ENDPOINT to (K2, E2) via a SUB-FLOOR deposit.
	//   - the new descriptor replaces the old (one row per identity)
	//   - the OLD key K1 is GONE from the set
	//   - membership is preserved purely by the original 50k stake
	// ---------------------------------------------------------------
	banner("STEP 2: rotate to (K2, E2) — sub-floor deposit, old key must be GONE")
	k2 := simkit.RandomConsensusKey()
	const e2 = "10.0.0.12:9090"
	bankerStakeSend(c, B1, fund, rotateAmt, oneMonth, k2, e2)
	waitBankerKey(c, B1.IDBytes(), k2, e2, "STEP 2")
	assertExactlyOneDescriptor(c, B1.IDBytes(), "STEP 2")
	assertKeyAbsent(c, k1, "STEP 2") // the rotated-away key must not linger anywhere in the set
	log.Printf("OK: B1 rotated to (K2=%x, E2=%s); old key K1 gone; still a banker via its 50k stake", k2[:6], e2)

	// ---------------------------------------------------------------
	// STEP 3: ENDPOINT-ONLY rotate to E3 (same key K2).
	// ---------------------------------------------------------------
	banner("STEP 3: endpoint-only rotate to E3 (same key K2)")
	const e3 = "10.0.0.13:9090"
	bankerStakeSend(c, B1, fund, rotateAmt, oneMonth, k2, e3)
	waitBankerKey(c, B1.IDBytes(), k2, e3, "STEP 3")
	assertExactlyOneDescriptor(c, B1.IDBytes(), "STEP 3")
	// Confirm the descriptor moved to E3 and is no longer E2 (the old endpoint is gone).
	if got := bankerEndpoint(c, B1.IDBytes()); got != e3 {
		log.Fatalf("FAIL [STEP 3]: endpoint = %q, want %q (endpoint-only rotation did not take)", got, e3)
	}
	log.Printf("OK: B1 endpoint rotated to %s (key unchanged at K2)", e3)

	banner("ALL CHECKS PASSED")
}

// --- flow helpers (shared shape with sim-banker-join) ---

func fundAndOpen(c *simkit.Client, genesis, acct *simkit.Account, amount uint64) {
	normalSend(c, genesis, acct.ID, amount)
	rid := c.WaitForReceivable(acct.IDBytes(), nil, 1*time.Second, 120*time.Second)
	tx := simkit.BuildOpeningReceive(acct, rid, nil, 0)
	acct.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(acct.IDBytes(), 1, 500*time.Millisecond, 120*time.Second)
}

func normalSend(c *simkit.Client, from *simkit.Account, to [32]byte, amount uint64) {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read sender: %v", err)
	}
	tx := simkit.BuildSend(from, head, seq+1, to, amount, core.ExpectedFee(amount))
	from.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(from.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
}

func bankerStakeSend(c *simkit.Client, from *simkit.Account, fund [32]byte, amount uint64, delay pb.StakeTimeDelay, consensusPubkey []byte, endpoint string) {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read banker: %v", err)
	}
	tx := simkit.BuildBankerStakeSend(from, head, seq+1, fund, amount, core.ExpectedFee(amount), delay, consensusPubkey, endpoint)
	from.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(from.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
}

// --- read API ---

type bankerRow struct {
	Identity     string `json:"identity"`
	ConsensusKey string `json:"consensus_pubkey"`
	Endpoint     string `json:"endpoint"`
}

func getBankers(c *simkit.Client) []bankerRow {
	resp, err := http.Get(c.URLs[0] + "/debug/fund/bankers")
	if err != nil {
		log.Fatalf("GET /debug/fund/bankers: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var rows []bankerRow
	if err := json.Unmarshal(body, &rows); err != nil {
		log.Fatalf("decode bankers: %v", err)
	}
	return rows
}

// waitBankerKey polls until the validator set lists `id` with exactly consensusKey + endpoint.
func waitBankerKey(c *simkit.Client, id, consensusKey []byte, endpoint, label string) {
	wantID := hex.EncodeToString(id)
	wantKey := hex.EncodeToString(consensusKey)
	deadline := time.Now().Add(120 * time.Second)
	for {
		for _, r := range getBankers(c) {
			if r.Identity == wantID && r.ConsensusKey == wantKey && r.Endpoint == endpoint {
				return
			}
		}
		if time.Now().After(deadline) {
			log.Fatalf("[%s] timed out waiting for banker %x key=%x endpoint=%s in the set",
				label, id[:4], consensusKey[:6], endpoint)
		}
		time.Sleep(1 * time.Second)
	}
}

// assertExactlyOneDescriptor confirms the identity has exactly one row in the set (a rotation
// REPLACES the single per-identity descriptor — it must never produce a second).
func assertExactlyOneDescriptor(c *simkit.Client, id []byte, label string) {
	wantID := hex.EncodeToString(id)
	n := 0
	for _, r := range getBankers(c) {
		if r.Identity == wantID {
			n++
		}
	}
	if n != 1 {
		log.Fatalf("[%s] FAIL: identity %x has %d descriptor rows, want exactly 1", label, id[:4], n)
	}
}

// assertKeyAbsent confirms a rotated-away consensus key no longer appears for ANY identity.
func assertKeyAbsent(c *simkit.Client, consensusKey []byte, label string) {
	keyHex := hex.EncodeToString(consensusKey)
	for _, r := range getBankers(c) {
		if r.ConsensusKey == keyHex {
			log.Fatalf("[%s] FAIL: rotated-away key %x is still in the set (identity %s)", label, consensusKey[:6], r.Identity[:8])
		}
	}
}

// bankerEndpoint returns the endpoint currently recorded for `id` ("" if absent).
func bankerEndpoint(c *simkit.Client, id []byte) string {
	wantID := hex.EncodeToString(id)
	for _, r := range getBankers(c) {
		if r.Identity == wantID {
			return r.Endpoint
		}
	}
	return ""
}

// --- misc ---

func fundAccountID() [32]byte {
	h := strings.TrimSpace(os.Getenv("FUND_ACCOUNT_HEX"))
	if h == "" {
		log.Fatal("FUND_ACCOUNT_HEX is required")
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		log.Fatalf("FUND_ACCOUNT_HEX must be 32 hex-encoded bytes: %v", err)
	}
	var f [32]byte
	copy(f[:], b)
	return f
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
