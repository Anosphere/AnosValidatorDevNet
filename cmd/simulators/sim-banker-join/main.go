// sim-banker-join demonstrates the P4.1 Fund-derived validator set (spec-18 §3.7, build-plan §P4.1):
//
//  1. A SPENDING account B1 stakes "banker" (>= 50k anos, 1-month tier) carrying a consensus P-256
//     key K1 + endpoint E1. The Fund-derived set (/debug/fund/bankers) then lists B1 with K1/E1.
//  2. ROTATION (last-write-wins): B1 sends a small additive "banker" deposit carrying a NEW key K2 +
//     endpoint E2. The set updates to K2/E2 (the higher send-seq wins) — B1 stays a Banker (its 50k
//     stake is still active).
//  3. A second banker B2 joins → the set has both, sorted by identity.
//  4. NEGATIVE: a banker deposit carrying a MALFORMED consensus key does not change B1's descriptor
//     (membership-not-rejection: the deposit is recorded as a stake but contributes no descriptor).
//
// In P4.1 the env list still drives LIVE consensus; this set is exposed read-only for cross-node
// agreement + resync verification (the P4.3 flip switches the live source to it).
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, FUND_ACCOUNT_HEX.
package main

import (
	"bytes"
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
		rotateAmt   = uint64(1) * core.UnitsPerAnos      // small additive rotation deposit
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
	const e1 = "10.0.0.1:9090"
	bankerStakeSend(c, B1, fund, bankerStake, oneMonth, k1, e1)
	waitBankerKey(c, B1.IDBytes(), k1, e1, "STEP 1")
	log.Printf("OK: B1=%x in the validator set with K1=%x endpoint=%s", B1.IDBytes()[:4], k1[:6], e1)

	// ---------------------------------------------------------------
	// STEP 2: B1 rotates to K2 + E2 (last-write-wins).
	// ---------------------------------------------------------------
	banner("STEP 2: B1 rotates to (K2, E2) — last-write-wins")
	k2 := simkit.RandomConsensusKey()
	const e2 = "10.0.0.2:9090"
	bankerStakeSend(c, B1, fund, rotateAmt, oneMonth, k2, e2)
	waitBankerKey(c, B1.IDBytes(), k2, e2, "STEP 2")
	log.Printf("OK: B1 descriptor rotated to K2=%x endpoint=%s (B1 still a banker via its 50k stake)", k2[:6], e2)

	// ---------------------------------------------------------------
	// STEP 3: B2 joins → the set has both.
	// ---------------------------------------------------------------
	banner("STEP 3: B2 stakes banker → the set has two")
	B2 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	fundAndOpen(c, genesis, B2, grant)
	kb2 := simkit.RandomConsensusKey()
	const eb2 = "10.0.0.3:9090"
	bankerStakeSend(c, B2, fund, bankerStake, oneMonth, kb2, eb2)
	waitBankerKey(c, B2.IDBytes(), kb2, eb2, "STEP 3")
	if n := len(getBankers(c)); n < 2 {
		log.Fatalf("FAIL: expected >= 2 bankers in the set, got %d", n)
	}
	log.Printf("OK: B2=%x joined; the set lists both bankers", B2.IDBytes()[:4])

	// ---------------------------------------------------------------
	// STEP 4: NEGATIVE — a malformed-key deposit doesn't change B1's descriptor.
	// ---------------------------------------------------------------
	banner("STEP 4: NEGATIVE — malformed consensus key leaves B1's descriptor unchanged")
	bad := bytes.Repeat([]byte{0x00}, 33) // 33 bytes but not a valid compressed P-256 point
	bankerStakeSend(c, B1, fund, rotateAmt, oneMonth, bad, "10.0.0.9:9090")
	// Give it a few epochs to finalize, then confirm B1 still resolves to K2/E2 (the malformed
	// deposit is recorded as a stake but contributes no descriptor).
	time.Sleep(6 * time.Second)
	waitBankerKey(c, B1.IDBytes(), k2, e2, "STEP 4")
	log.Printf("OK: malformed-key banker deposit did not change B1's descriptor (still K2/E2)")

	banner("ALL CHECKS PASSED")
}

// --- flow helpers ---

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
