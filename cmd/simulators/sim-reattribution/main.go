// sim-reattribution exercises P5.4b C1 in-Fund stake recovery (re-attribution) end-to-end on a live
// network (working notes §3.4 "Recovery — FINALIZED", build-plan §P5.4b):
//
//   - Stake a Guardian G (authorizer) and a BANKER A (50k @ 1mo) carrying a consensus key K_A + endpoint.
//     A appears in the Fund-derived validator set (/debug/fund/bankers).
//   - NEGATIVE: re-attributing A's stake to a fresh account B WITHOUT the owner's authorization is
//     REJECTED (a quorum can enact but never redirect — the theft guard).
//   - POSITIVE: the same re-attribution carrying A's owner_auth (op = re-attribute) flips the stake
//     row's owner A→B IN PLACE (kept Active, same amount/tier) and B INHERITS A's carried descriptor
//     (K_A, E_A) so validator-set membership is seamless: A drops out of the set, B takes its slot.
//   - ROTATE: B then rotates to its own key K_B via a normal P4.2 self-signed deposit; the inherited
//     seq-0 descriptor is overridden by B's own (seq >= 2) → B is now in the set as K_B, K_A is gone.
//
// The seq-0 inheritance determinism is validated by the harness's 3-node bankers-agreement + the
// verifying resync rebuilding BYTE-IDENTICAL bankers. Prints STAKE_FINGERPRINT + FUND_BALANCE.
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, FUND_ACCOUNT_HEX, EPOCH_MS, GENESIS_UNIX_MS.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

	banner("STEP 1: stake Guardian G (authorizer) + BANKER A (K_A, E_A); register beneficiary B")
	g := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	a := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	b := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	fundAndOpen(c, genesis, g, anos(9_000))
	fundAndOpen(c, genesis, a, anos(60_000))
	fundAndOpen(c, genesis, b, anos(10))
	stakeGuardian(c, g, fund, anos(8_000)) // weight 4 (authorizer)
	kA := simkit.RandomConsensusKey()
	const eA = "10.0.0.21:9090"
	aDeposit := bankerStake(c, a, fund, anos(50_000), kA, eA)
	waitBankerKey(c, a.IDBytes(), kA, eA, "STEP 1")
	log.Printf("OK: A=%x in the set as (K_A=%x, E_A=%s)", a.IDBytes()[:4], kA[:6], eA)

	banner("STEP 2: NEGATIVE — re-attribute A→B WITHOUT owner_auth is rejected")
	fhead, fseq, err := c.Head(fund[:])
	if err != nil {
		log.Fatalf("read fund: %v", err)
	}
	noAuth := simkit.BuildFundReattributeSend(fund, fhead, fseq+1, epoch(epochMs, genesisMs), aDeposit, b.ID, kA, eA, nil)
	if err := simkit.SignFundSend(noAuth, []*simkit.Account{g}); err != nil {
		log.Fatalf("sign no-auth re-attribution: %v", err)
	}
	if err := c.Submit(noAuth); err == nil {
		log.Fatal("ASSERT FAILED: a re-attribution without owner_auth was accepted (theft guard breached)")
	}
	log.Printf("rejected as expected: re-attributing a stake needs the owner's authorization")

	banner("STEP 3: POSITIVE — re-attribute A→B with A's owner_auth; B inherits (K_A, E_A)")
	fhead, fseq, _ = c.Head(fund[:])
	oa := a.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReattribute, aDeposit, b.ID, false)
	reat := simkit.BuildFundReattributeSend(fund, fhead, fseq+1, epoch(epochMs, genesisMs), aDeposit, b.ID, kA, eA, oa)
	if err := simkit.SignFundSend(reat, []*simkit.Account{g}); err != nil {
		log.Fatalf("sign re-attribution: %v", err)
	}
	c.MustSubmit(reat)
	c.WaitForSeqAtLeast(fund[:], fseq+1, 500*time.Millisecond, 120*time.Second)
	// The stake row's owner flipped A→B, still Active (status 0), same amount.
	waitStakeOwner(c, aDeposit, b.ID)
	assert(stakeStatus(c, aDeposit) == 0, "re-attributed stake must stay Active (status 0)")
	// B took A's validator slot; A is out.
	waitBankerKey(c, b.IDBytes(), kA, eA, "STEP 3")
	assertIdentityAbsent(c, a.IDBytes(), "STEP 3")
	log.Printf("OK: stake re-attributed A→B; B inherited (K_A, E_A); A dropped from the set")

	banner("STEP 4: ROTATE — B rotates to its own key K_B (overrides the inherited seq-0 descriptor)")
	kB := simkit.RandomConsensusKey()
	const eB = "10.0.0.22:9090"
	bankerStake(c, b, fund, anos(1), kB, eB) // sub-floor self-signed rotation (P4.2)
	waitBankerKey(c, b.IDBytes(), kB, eB, "STEP 4")
	assertKeyAbsent(c, kA, "STEP 4") // A's key is fully gone now that B rotated
	log.Printf("OK: B rotated to (K_B=%x, E_B=%s); inherited K_A gone", kB[:6], eB)

	banner("RESULT")
	fundSt, _ := c.GetAccount(fund[:])
	log.Printf("ALL CHECKS PASSED")
	log.Printf("FUND_BALANCE=%d", fundSt.Balance)
	log.Printf("STAKE_FINGERPRINT=%s", stakeFingerprint(c))
}

// ── helpers ──

func anos(n uint64) uint64 { return n * core.UnitsPerAnos }

func epoch(epochMs, genesisMs uint64) uint64 {
	now := uint64(time.Now().UnixMilli())
	if now <= genesisMs || epochMs == 0 {
		return 1
	}
	return (now-genesisMs)/epochMs + 1
}

func fundAndOpen(c *simkit.Client, genesis, acct *simkit.Account, amount uint64) {
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

// stakeGuardian stakes `amount` @1yr (guardian weight) and returns the deposit_txid.
func stakeGuardian(c *simkit.Client, from *simkit.Account, fund [32]byte, amount uint64) [32]byte {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read staker: %v", err)
	}
	tx := simkit.BuildStakeSend(from, head, seq+1, fund, amount, core.ExpectedFee(amount), "guardian", pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR, nil)
	from.MustSign(tx)
	txid, _ := crypto.TxID(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(from.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
	return txid
}

// bankerStake makes a direct SPENDING banker deposit (@1mo) carrying the consensus key + endpoint,
// returning the deposit_txid. A sub-floor amount performs a P4.2 key/endpoint rotation.
func bankerStake(c *simkit.Client, from *simkit.Account, fund [32]byte, amount uint64, key []byte, endpoint string) [32]byte {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read banker: %v", err)
	}
	tx := simkit.BuildBankerStakeSend(from, head, seq+1, fund, amount, core.ExpectedFee(amount), pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_MONTH, key, endpoint)
	from.MustSign(tx)
	txid, _ := crypto.TxID(tx)
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

// waitStakeOwner polls until the stake at depositTxid is attributed to `owner`.
func waitStakeOwner(c *simkit.Client, depositTxid, owner [32]byte) {
	h := hex.EncodeToString(depositTxid[:])
	wantOwner := hex.EncodeToString(owner[:])
	deadline := time.Now().Add(120 * time.Second)
	for {
		for _, s := range getStakesJSON(c) {
			if s.DepositTxid == h && s.StakerID == wantOwner {
				return
			}
		}
		if time.Now().After(deadline) {
			log.Fatalf("timed out waiting for stake %x to be owned by %x", depositTxid[:4], owner[:4])
		}
		time.Sleep(500 * time.Millisecond)
	}
}

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

func waitBankerKey(c *simkit.Client, id, key []byte, endpoint, label string) {
	wantID := hex.EncodeToString(id)
	wantKey := hex.EncodeToString(key)
	deadline := time.Now().Add(120 * time.Second)
	for {
		for _, r := range getBankers(c) {
			if r.Identity == wantID && r.ConsensusKey == wantKey && r.Endpoint == endpoint {
				return
			}
		}
		if time.Now().After(deadline) {
			log.Fatalf("[%s] timed out waiting for banker %x key=%x endpoint=%s", label, id[:4], key[:6], endpoint)
		}
		time.Sleep(1 * time.Second)
	}
}

func assertIdentityAbsent(c *simkit.Client, id []byte, label string) {
	wantID := hex.EncodeToString(id)
	for _, r := range getBankers(c) {
		if r.Identity == wantID {
			log.Fatalf("[%s] FAIL: identity %x is still in the validator set (should have dropped out)", label, id[:4])
		}
	}
}

func assertKeyAbsent(c *simkit.Client, key []byte, label string) {
	keyHex := hex.EncodeToString(key)
	for _, r := range getBankers(c) {
		if r.ConsensusKey == keyHex {
			log.Fatalf("[%s] FAIL: key %x is still in the set (identity %s)", label, key[:6], r.Identity[:8])
		}
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
