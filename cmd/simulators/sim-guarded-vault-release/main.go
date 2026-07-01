// sim-guarded-vault-release demonstrates the P3.2 GUARDED/VAULT attestor-gated release
// lifecycle end to end on hybrid keys (spec-18 §5.3/§5.4, spec-19 §6.1):
//
//  1. Stake ATTESTOR_QUORUM_M attestors: M SPENDING accounts each stake >= 5,000 anos to the
//     Fund tagged "attestor" (a direct stake; SPENDING may stake directly).
//  2. A GUARDED account UG is funded and sends to a derived transfer chain; because the source
//     is GUARDED the spawned chain carries release_requires_attestor (verified via the read API).
//  3. POSITIVE: after the GUARDED unlock, release-to-dest signed by the chain's controlling key
//     PLUS the M-of-N attestor multisig finalizes (and before unlock it does not).
//  4. NEGATIVE: a sibling chain's release with only M-1 attestor signatures never finalizes.
//  5. UNGATED: a third sibling chain returns to its source (UG) with no attestors at any epoch.
//  6. VAULT: the same positive release works for a VAULT source at its (longer) unlock.
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, GENESIS_UNIX_MS, EPOCH_MS,
// GUARDED_DELAY_EPOCHS, VAULT_DELAY_EPOCHS, ATTESTOR_QUORUM_M.
package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
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

	genesisMs := getenvInt64("GENESIS_UNIX_MS", 0)
	epochMs := getenvInt64("EPOCH_MS", 5000)
	guardedDelay := getenvUint64("GUARDED_DELAY_EPOCHS", 8)
	vaultDelay := getenvUint64("VAULT_DELAY_EPOCHS", 12)
	quorumM := int(getenvUint64("ATTESTOR_QUORUM_M", 2))
	if genesisMs == 0 {
		log.Fatal("GENESIS_UNIX_MS is required")
	}
	if quorumM < 1 {
		log.Fatal("ATTESTOR_QUORUM_M must be >= 1")
	}
	log.Printf("epoch params: genesisMs=%d epochMs=%d guardedDelay=%d vaultDelay=%d attestorM=%d (epoch=%d)",
		genesisMs, epochMs, guardedDelay, vaultDelay, quorumM, currentEpoch(genesisMs, epochMs))

	const (
		attestorStake = uint64(6_000) * core.UnitsPerAnos // > the 5,000-anos attestor floor
		fundAmount    = uint64(2_000) * core.UnitsPerAnos
		moveAmount    = uint64(100) * core.UnitsPerAnos
	)

	// ---------------------------------------------------------------
	// STEP 1: stake M attestors (SPENDING accounts staking directly).
	// ---------------------------------------------------------------
	banner("STEP 1: stake the attestor quorum")
	fund := fundAccountID()
	attestors := make([]*simkit.Account, quorumM)
	for i := 0; i < quorumM; i++ {
		a := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
		attestors[i] = a
		// genesis funds the attestor enough to stake + pay the first-hop fee.
		normalSend(c, genesis, a.ID, attestorStake+uint64(10)*core.UnitsPerAnos)
		rid := c.WaitForReceivable(a.IDBytes(), nil, 1*time.Second, 120*time.Second)
		openReceive(c, a, rid, nil, 0)
		// stake -> Fund tagged "attestor" (1-month tier is fine; attestor membership ignores tier).
		stakeToFund(c, a, fund, attestorStake, "attestor")
		log.Printf("OK: attestor %d = %x staked %d anos", i, a.IDBytes()[:4], attestorStake/core.UnitsPerAnos)
	}
	// Let the stake deposits finalize into the table before any release reads the snapshot.
	settle(genesisMs, epochMs, 3)

	// ---------------------------------------------------------------
	// STEP 2: fund a GUARDED account and spawn three transfer chains.
	// ---------------------------------------------------------------
	banner("STEP 2: fund a GUARDED account UG and open transfer chains")
	UG := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_GUARDED)
	D := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	normalSend(c, genesis, UG.ID, fundAmount)
	ridUG := c.WaitForReceivable(UG.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, UG, ridUG, nil, 0)
	ugSt := mustAccount(c, UG.IDBytes())
	assert(ugSt.AccountClass == pb.AccountClass_ACCOUNT_CLASS_GUARDED, "UG should be GUARDED")
	log.Printf("OK: UG is GUARDED with %d units; D(dest)=%x", ugSt.Balance, D.IDBytes()[:4])

	// T1 = positive release; T2 = negative (<M); T3 = return-to-source (ungated).
	T1, t1Seq := fundTransferChain(c, UG, moveAmount)
	T2, _ := fundTransferChain(c, UG, moveAmount)
	T3, _ := fundTransferChain(c, UG, moveAmount)
	log.Printf("T1=%x T2=%x T3=%x (derived from UG; t1 send seq %d)", T1.IDBytes()[:4], T2.IDBytes()[:4], T3.IDBytes()[:4], t1Seq)

	unlock := currentEpoch(genesisMs, epochMs) + guardedDelay + 3
	openTransfer(c, T1, D.ID, unlock)
	openTransfer(c, T2, D.ID, unlock)
	openTransfer(c, T3, D.ID, unlock)

	// The read API must report release_requires_attestor on a GUARDED-sourced chain.
	assertAttestorGated(c, T1.IDBytes(), true)
	log.Printf("OK: T1 reports release_requires_attestor (GUARDED source)")

	// ---------------------------------------------------------------
	// STEP 3: release-before-unlock with a full quorum must not finalize.
	// ---------------------------------------------------------------
	banner("STEP 3: release T1 -> D BEFORE unlock must be rejected (even with a full quorum)")
	releaseToDest(c, T1, D.ID, moveAmount, attestors[:quorumM]) // submitted early
	if waitSeqOrTimeout(c, T1.IDBytes(), 2, 3, genesisMs, epochMs) {
		log.Fatal("FAIL: release-before-unlock finalized (timelock not enforced)")
	}
	log.Printf("OK: release-before-unlock did not finalize (epoch=%d < unlock=%d)", currentEpoch(genesisMs, epochMs), unlock)

	// ---------------------------------------------------------------
	// STEP 4: NEGATIVE — below-quorum release never finalizes.
	// ---------------------------------------------------------------
	banner("STEP 4: NEGATIVE — release T2 with M-1 attestor sigs must not finalize")
	waitUntilEpoch(unlock+1, genesisMs, epochMs)
	if quorumM >= 2 {
		releaseToDest(c, T2, D.ID, moveAmount, attestors[:quorumM-1]) // one short of M
		if waitSeqOrTimeout(c, T2.IDBytes(), 2, 4, genesisMs, epochMs) {
			log.Fatal("FAIL: below-quorum release finalized (attestor gate not enforced)")
		}
		log.Printf("OK: below-quorum (M-1=%d) release did not finalize", quorumM-1)
	} else {
		log.Printf("SKIP: ATTESTOR_QUORUM_M=1 has no below-quorum case")
	}

	// ---------------------------------------------------------------
	// STEP 5: POSITIVE — full-quorum release at/after unlock finalizes.
	// ---------------------------------------------------------------
	banner("STEP 5: POSITIVE — release T1 -> D with the full M-of-N quorum")
	releaseToDest(c, T1, D.ID, moveAmount, attestors[:quorumM]) // idempotent re-submit (same txid)
	c.WaitForSeqAtLeast(T1.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, T1.IDBytes()).Balance == 0, "T1 should be drained after release")
	relRID := c.WaitForReceivable(D.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, D, relRID, nil, 0)
	assert(mustAccount(c, D.IDBytes()).Balance == moveAmount, "D should have received the released amount")
	log.Printf("OK: GUARDED release with %d attestors finalized; D received %d units", quorumM, moveAmount)

	// ---------------------------------------------------------------
	// STEP 6: UNGATED — return-to-source needs no attestors, any epoch.
	// ---------------------------------------------------------------
	banner("STEP 6: UNGATED — return T3 -> UG with no attestors")
	transferReturn(c, T3, UG.ID, moveAmount) // no multisig
	c.WaitForSeqAtLeast(T3.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, T3.IDBytes()).Balance == 0, "T3 should be drained after return")
	retRID := c.WaitForReceivable(UG.IDBytes(), nil, 1*time.Second, 120*time.Second)
	plainReceive(c, UG, retRID)
	log.Printf("OK: return-to-source finalized with no attestor signatures (ungated)")

	// ---------------------------------------------------------------
	// STEP 7: VAULT — the same gate works for a VAULT source.
	// ---------------------------------------------------------------
	banner("STEP 7: VAULT source release with the M-of-N quorum")
	UV := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_VAULT)
	normalSend(c, genesis, UV.ID, fundAmount)
	ridUV := c.WaitForReceivable(UV.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, UV, ridUV, nil, 0)
	assert(mustAccount(c, UV.IDBytes()).AccountClass == pb.AccountClass_ACCOUNT_CLASS_VAULT, "UV should be VAULT")
	TV, _ := fundTransferChain(c, UV, moveAmount)
	vUnlock := currentEpoch(genesisMs, epochMs) + vaultDelay + 3
	openTransfer(c, TV, D.ID, vUnlock)
	assertAttestorGated(c, TV.IDBytes(), true)
	log.Printf("TV=%x reports release_requires_attestor (VAULT source); unlock=%d", TV.IDBytes()[:4], vUnlock)
	waitUntilEpoch(vUnlock+1, genesisMs, epochMs)
	releaseToDest(c, TV, D.ID, moveAmount, attestors[:quorumM])
	c.WaitForSeqAtLeast(TV.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, TV.IDBytes()).Balance == 0, "TV should be drained after release")
	log.Printf("OK: VAULT release with %d attestors finalized", quorumM)

	banner("ALL CHECKS PASSED")
}

// --- flow helpers ---

// fundTransferChain sends moveAmount from a GUARDED/VAULT source to the derived transfer chain
// that exact SEND spawns, returning the chain account and the send seq (its creation nonce).
func fundTransferChain(c *simkit.Client, source *simkit.Account, moveAmount uint64) (*simkit.Account, uint64) {
	head, seq, err := c.Head(source.IDBytes())
	if err != nil {
		log.Fatalf("read source: %v", err)
	}
	sendSeq := seq + 1
	chain := simkit.DerivedTransferAccount(source, sendSeq)
	tx := simkit.BuildSend(source, head, sendSeq, chain.ID, moveAmount, core.ExpectedFee(moveAmount))
	source.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(source.IDBytes(), sendSeq, 500*time.Millisecond, 120*time.Second)
	return chain, sendSeq
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

// stakeToFund stakes `amount` from a SPENDING account directly to the Fund with the given tag.
func stakeToFund(c *simkit.Client, from *simkit.Account, fund [32]byte, amount uint64, tag string) {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read staker: %v", err)
	}
	tx := simkit.BuildStakeSend(from, head, seq+1, fund, amount, core.ExpectedFee(amount), tag,
		pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_MONTH, nil)
	from.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(from.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
}

// releaseToDest submits an attestor-gated release-to-dest: chain key Tx.sig + M-of-N attestor
// multisig. It does NOT wait (callers decide whether it should finalize).
func releaseToDest(c *simkit.Client, chain *simkit.Account, to [32]byte, balance uint64, attestors []*simkit.Account) {
	head, seq, err := c.Head(chain.IDBytes())
	if err != nil {
		log.Fatalf("read transfer chain: %v", err)
	}
	tx := simkit.BuildSend(chain, head, seq+1, to, balance, 0)
	if err := simkit.SignAttestorRelease(tx, chain, attestors); err != nil {
		log.Fatalf("sign attestor release: %v", err)
	}
	_ = c.Submit(tx)
}

// transferReturn submits a zero-fee return-to-source drain (no attestors).
func transferReturn(c *simkit.Client, chain *simkit.Account, to [32]byte, balance uint64) {
	head, seq, err := c.Head(chain.IDBytes())
	if err != nil {
		log.Fatalf("read transfer chain: %v", err)
	}
	tx := simkit.BuildSend(chain, head, seq+1, to, balance, 0)
	chain.MustSign(tx)
	_ = c.Submit(tx)
}

func openReceive(c *simkit.Client, acct *simkit.Account, rid [32]byte, transferDest *[32]byte, unlock uint64) {
	tx := simkit.BuildOpeningReceive(acct, rid, transferDest, unlock)
	acct.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(acct.IDBytes(), 1, 500*time.Millisecond, 120*time.Second)
}

// openTransfer opens a derived transfer chain (waits for its funding receivable first).
func openTransfer(c *simkit.Client, chain *simkit.Account, dest [32]byte, unlock uint64) {
	rid := c.WaitForReceivable(chain.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, chain, rid, &dest, unlock)
	st := mustAccount(c, chain.IDBytes())
	assert(st.AccountClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER, "chain should be TRANSFER")
}

func plainReceive(c *simkit.Client, acct *simkit.Account, rid [32]byte) {
	head, seq, err := c.Head(acct.IDBytes())
	if err != nil {
		log.Fatalf("read account: %v", err)
	}
	tx := simkit.BuildReceive(acct, head, seq+1, rid)
	acct.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(acct.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
}

func mustAccount(c *simkit.Client, acct []byte) *pb.AccountState {
	st, err := c.GetAccount(acct)
	if err != nil {
		return &pb.AccountState{Account: &pb.AccountId{V: acct}, Head: &pb.Hash32{V: make([]byte, 32)}}
	}
	return st
}

// --- epoch helpers (validator-identical) ---

func currentEpoch(genesisMs, epochMs int64) uint64 {
	now := time.Now().UnixMilli()
	if now < genesisMs {
		return 1
	}
	return uint64((now-genesisMs)/epochMs) + 1
}

func waitUntilEpoch(target uint64, genesisMs, epochMs int64) {
	for currentEpoch(genesisMs, epochMs) < target {
		time.Sleep(time.Duration(epochMs) * time.Millisecond / 2)
	}
}

func settle(genesisMs, epochMs int64, epochs uint64) {
	waitUntilEpoch(currentEpoch(genesisMs, epochMs)+epochs, genesisMs, epochMs)
}

func waitSeqOrTimeout(c *simkit.Client, acct []byte, wantSeq, epochs uint64, genesisMs, epochMs int64) bool {
	deadline := currentEpoch(genesisMs, epochMs) + epochs
	for currentEpoch(genesisMs, epochMs) <= deadline {
		if mustAccount(c, acct).Seq >= wantSeq {
			return true
		}
		time.Sleep(time.Duration(epochMs) * time.Millisecond / 2)
	}
	return mustAccount(c, acct).Seq >= wantSeq
}

// --- misc ---

// fundAccountID reads FUND_ACCOUNT_HEX (the manifest Fund id the validators are configured with).
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

// assertAttestorGated checks the /debug/accounts/heads read API reports the expected
// release_requires_attestor flag for a transfer chain.
func assertAttestorGated(c *simkit.Client, acct []byte, want bool) {
	got, ok := releaseRequiresAttestor(c, acct)
	if !ok {
		log.Fatalf("chain %x not found in /debug/accounts/heads", acct[:4])
	}
	if got != want {
		log.Fatalf("chain %x release_requires_attestor = %v, want %v", acct[:4], got, want)
	}
}

// releaseRequiresAttestor reads /debug/accounts/heads from the first validator URL and returns the
// release_requires_attestor flag for the given account (ok=false if the account is absent).
func releaseRequiresAttestor(c *simkit.Client, acct []byte) (bool, bool) {
	if len(c.URLs) == 0 {
		log.Fatal("no validator URLs configured")
	}
	resp, err := http.Get(c.URLs[0] + "/debug/accounts/heads")
	if err != nil {
		log.Fatalf("GET /debug/accounts/heads: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var rows []struct {
		Account           string `json:"account"`
		ReleaseNeedsAttsr bool   `json:"release_requires_attestor"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		log.Fatalf("decode heads: %v", err)
	}
	want := hex.EncodeToString(acct)
	for _, r := range rows {
		if r.Account == want {
			return r.ReleaseNeedsAttsr, true
		}
	}
	return false, false
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

func getenvInt64(k string, def int64) int64 {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func getenvUint64(k string, def uint64) uint64 {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}
