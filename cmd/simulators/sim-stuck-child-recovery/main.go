// sim-stuck-child-recovery demonstrates P5.3 end to end on hybrid keys (spec-19 §6.4, Working Notes
// §3.4 "(B) Stuck ordinary transfer chain"). When the controlling (auth) key of an ORDINARY transfer
// chain is lost, the owner's revealed BREAKGLASS key can still return the funds to the source — on ANY
// ordinary chain, not just a breakglass-origin one — UNGATED (no attestors, any epoch, zero-fee). The
// recovery gate lives at the SOURCE: a revealed key can only push value BACK toward the safe source
// (where the source's own breakglass move carries the +1-week window + attestor quorum), never OUT to
// the destination.
//
//  1. Fund a TIMELOCKED source U and establish it.
//  2. RECOVER: U funds an ordinary transfer chain T1 (long unlock) whose auth key is then "lost". The
//     read API confirms T1 is NEITHER breakglass_origin NOR attestor-gated. A breakglass-signed
//     return-to-source finalizes immediately, well before unlock; U receives the funds back.
//  3. NEGATIVE + recover: U funds a second ordinary chain T2 (short unlock). Past unlock, a
//     breakglass-signed RELEASE-to-dest must NOT finalize (release via breakglass stays
//     breakglass-origin-only). The same T2 is then recovered via a breakglass return-to-source.
//
// (A breakglass return on a Fund-sourced return-stake chain — out of scope, P5.5 — is exercised by the
// core unit tests; it needs the full Guardian-return flow to construct live.)
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, GENESIS_UNIX_MS, EPOCH_MS,
// TIMELOCKED_DELAY_EPOCHS.
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
	delay := getenvUint64("TIMELOCKED_DELAY_EPOCHS", 6)
	if genesisMs == 0 {
		log.Fatal("GENESIS_UNIX_MS is required")
	}
	log.Printf("epoch params: genesisMs=%d epochMs=%d delay=%d (epoch=%d)",
		genesisMs, epochMs, delay, currentEpoch(genesisMs, epochMs))

	const (
		fundAmount = uint64(1000) * core.UnitsPerAnos
		moveAmount = uint64(100) * core.UnitsPerAnos
	)

	// ---------------------------------------------------------------
	// STEP 1: fund U and establish it as TIMELOCKED.
	// ---------------------------------------------------------------
	banner("STEP 1: fund U and establish it as TIMELOCKED")
	U := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED)
	D := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING) // an intended release destination
	normalSend(c, genesis, U.ID, fundAmount)
	ridU := c.WaitForReceivable(U.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, U, ridU, nil, 0)
	assert(mustAccount(c, U.IDBytes()).AccountClass == pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, "U should be TIMELOCKED")
	log.Printf("OK: U=%x is TIMELOCKED with %d units", U.IDBytes()[:4], mustAccount(c, U.IDBytes()).Balance)

	// ---------------------------------------------------------------
	// STEP 2: RECOVER a stuck ordinary chain T1 via a breakglass return-to-source.
	// ---------------------------------------------------------------
	banner("STEP 2: RECOVER — breakglass return-to-source on an ordinary chain T1 (auth key lost)")
	// Long unlock: the release is far off, so the funds are genuinely "stuck" for the intended path.
	unlockFar := currentEpoch(genesisMs, epochMs) + delay + 100
	T1 := fundOrdinaryChain(c, U, moveAmount, D.ID, unlockFar)
	// T1 is an ordinary transfer chain: NEITHER breakglass_origin NOR attestor-gated.
	assertChainFlags(c, T1.IDBytes(), false, false)
	log.Printf("OK: T1=%x is an ordinary (non-breakglass, non-attestor) chain, unlock=%d (epoch=%d)",
		T1.IDBytes()[:4], unlockFar, currentEpoch(genesisMs, epochMs))

	// The auth key is "lost". Recover with the breakglass key: return-to-source, immediate, ungated.
	breakglassReturn(c, T1, U.ID, moveAmount)
	c.WaitForSeqAtLeast(T1.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, T1.IDBytes()).Balance == 0, "T1 should be drained after the breakglass return")
	log.Printf("OK: breakglass return-to-source finalized well before unlock (epoch=%d < unlock=%d), ungated",
		currentEpoch(genesisMs, epochMs), unlockFar)
	retRID := c.WaitForReceivable(U.IDBytes(), nil, 1*time.Second, 120*time.Second)
	plainReceive(c, U, retRID)
	log.Printf("OK: U reclaimed the stuck funds; U balance now %d units", mustAccount(c, U.IDBytes()).Balance)

	// ---------------------------------------------------------------
	// STEP 3: NEGATIVE — a breakglass RELEASE-to-dest on an ordinary chain must never finalize.
	// ---------------------------------------------------------------
	banner("STEP 3: NEGATIVE — breakglass release-to-dest on an ordinary chain T2 must not finalize")
	unlockNear := currentEpoch(genesisMs, epochMs) + delay + 2
	T2 := fundOrdinaryChain(c, U, moveAmount, D.ID, unlockNear)
	log.Printf("T2=%x (ordinary chain, unlock=%d)", T2.IDBytes()[:4], unlockNear)

	// Wait until PAST unlock, so the ONLY reason a breakglass release fails is the breakglass-origin rule
	// (not the timelock) — proving the destination is never reachable via a revealed key on an ordinary
	// chain, even when a normal release would be time-permitted.
	waitUntilEpoch(unlockNear+1, genesisMs, epochMs)
	breakglassReleaseToDest(c, T2, D.ID, moveAmount)
	if waitSeqOrTimeout(c, T2.IDBytes(), 2, 4, genesisMs, epochMs) {
		log.Fatal("FAIL: a breakglass release-to-dest on an ordinary chain finalized (must be breakglass-origin only)")
	}
	log.Printf("OK: breakglass release-to-dest did not finalize past unlock (epoch=%d > unlock=%d)",
		currentEpoch(genesisMs, epochMs), unlockNear)

	// T2 is still recoverable to the source via the breakglass key (the safe direction always works).
	breakglassReturn(c, T2, U.ID, moveAmount)
	c.WaitForSeqAtLeast(T2.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, T2.IDBytes()).Balance == 0, "T2 should be drained after the breakglass return")
	t2RID := c.WaitForReceivable(U.IDBytes(), nil, 1*time.Second, 120*time.Second)
	plainReceive(c, U, t2RID)
	log.Printf("OK: T2 recovered to the source via breakglass return (the only breakglass path on an ordinary chain)")

	banner("ALL CHECKS PASSED")
}

// --- flow helpers ---

// fundOrdinaryChain sends `moveAmount` from a TIMELOCKED source into the derived transfer chain that
// exact SEND spawns (auth-signed, so the chain is an ORDINARY, non-breakglass-origin chain), then opens
// the chain (auth-signed) with the given release destination + unlock. Returns the opened chain.
func fundOrdinaryChain(c *simkit.Client, source *simkit.Account, moveAmount uint64, dest [32]byte, unlock uint64) *simkit.Account {
	head, seq, err := c.Head(source.IDBytes())
	if err != nil {
		log.Fatalf("read source: %v", err)
	}
	sendSeq := seq + 1
	chain := simkit.DerivedTransferAccount(source, sendSeq)
	send := simkit.BuildSend(source, head, sendSeq, chain.ID, moveAmount, core.ExpectedFee(moveAmount))
	source.MustSign(send) // auth key: ordinary (non-breakglass) hop-1
	c.MustSubmit(send)
	c.WaitForSeqAtLeast(source.IDBytes(), sendSeq, 500*time.Millisecond, 120*time.Second)

	rid := c.WaitForReceivable(chain.IDBytes(), nil, 1*time.Second, 120*time.Second)
	open := simkit.BuildOpeningReceive(chain, rid, &dest, unlock)
	chain.MustSign(open) // auth key opens it (the key is lost only AFTER the chain exists)
	c.MustSubmit(open)
	c.WaitForSeqAtLeast(chain.IDBytes(), 1, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, chain.IDBytes()).AccountClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER, "chain should be TRANSFER")
	return chain
}

// breakglassReturn submits a zero-fee, full-balance return-to-source drain signed by the chain's
// REVEALED breakglass key (the P5.3 recovery) and waits for it to finalize.
func breakglassReturn(c *simkit.Client, chain *simkit.Account, source [32]byte, balance uint64) {
	head, seq, err := c.Head(chain.IDBytes())
	if err != nil {
		log.Fatalf("read chain: %v", err)
	}
	tx := simkit.BuildSend(chain, head, seq+1, source, balance, 0)
	chain.MustSignBreakglass(tx) // the chain shares the source's breakglass key; reveals it
	_ = c.Submit(tx)
}

// breakglassReleaseToDest submits a zero-fee, full-balance release-to-DEST drain signed by the chain's
// REVEALED breakglass key (no attestor multisig — an ordinary chain is not attestor-gated). It must
// NOT finalize; callers verify that.
func breakglassReleaseToDest(c *simkit.Client, chain *simkit.Account, dest [32]byte, balance uint64) {
	head, seq, err := c.Head(chain.IDBytes())
	if err != nil {
		log.Fatalf("read chain: %v", err)
	}
	tx := simkit.BuildSend(chain, head, seq+1, dest, balance, 0)
	chain.MustSignBreakglass(tx)
	_ = c.Submit(tx) // rejected at the submit/gossip gate + at epoch close; never finalizes
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

func openReceive(c *simkit.Client, acct *simkit.Account, rid [32]byte, transferDest *[32]byte, unlock uint64) {
	tx := simkit.BuildOpeningReceive(acct, rid, transferDest, unlock)
	acct.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(acct.IDBytes(), 1, 500*time.Millisecond, 120*time.Second)
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

// --- read-API cross-check ---

// assertChainFlags checks /debug/accounts/heads reports the expected release_requires_attestor +
// breakglass_origin flags for a transfer chain.
func assertChainFlags(c *simkit.Client, acct []byte, wantAttestor, wantBreakglass bool) {
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
		BreakglassOrigin  bool   `json:"breakglass_origin"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		log.Fatalf("decode heads: %v", err)
	}
	want := hex.EncodeToString(acct)
	for _, r := range rows {
		if r.Account == want {
			if r.ReleaseNeedsAttsr != wantAttestor || r.BreakglassOrigin != wantBreakglass {
				log.Fatalf("chain %x flags attestor=%v breakglass=%v, want attestor=%v breakglass=%v",
					acct[:4], r.ReleaseNeedsAttsr, r.BreakglassOrigin, wantAttestor, wantBreakglass)
			}
			return
		}
	}
	log.Fatalf("chain %x not found in /debug/accounts/heads", acct[:4])
}

// --- epoch helpers (validator-identical: epoch = (now-genesis)/epochMs + 1) ---

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
