// sim-breakglass demonstrates the P5.1 breakglass-move lifecycle end to end on hybrid keys
// (spec-19 §6.4, keys-spec §7.3) plus the escrow breakglass-alt-key slot (spec-19 §6.3):
//
//  1. Stake ATTESTOR_QUORUM_M attestors (SPENDING accounts staking "attestor" directly).
//  2. Fund a SPENDING source S (recovery works even on an unrestricted account). S drains via its
//     REVEALED breakglass key to a derived transfer chain B; the validator FORCES TRANSFER routing
//     and the read API reports B as breakglass_origin + release_requires_attestor.
//  3. OWNER CANCEL: a second breakglass drain B2 is cancelled via return-to-source signed by the
//     AUTH key (the owner still holds it) — free, any epoch, no attestors.
//  4. RELEASE: after the +window unlock, B releases to recovery dest D, authorized by the REVEALED
//     breakglass key + the M-of-N attestor quorum; D receives the funds.
//  5. NEGATIVE: a forged breakglass drain (a stranger's revealed key over S's chain) never finalizes.
//  6. ESCROW: a two-party escrow drains 2-of-2 where ONE party signs with its revealed breakglass key.
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, GENESIS_UNIX_MS, EPOCH_MS,
// BREAKGLASS_EXTRA_EPOCHS, ATTESTOR_QUORUM_M, ESCROW_ATTESTATION_DELAY_EPOCHS, FUND_ACCOUNT_HEX.
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
	breakglassExtra := getenvUint64("BREAKGLASS_EXTRA_EPOCHS", 5)
	escrowDelay := getenvUint64("ESCROW_ATTESTATION_DELAY_EPOCHS", 6)
	quorumM := int(getenvUint64("ATTESTOR_QUORUM_M", 2))
	if genesisMs == 0 {
		log.Fatal("GENESIS_UNIX_MS is required")
	}
	if quorumM < 1 {
		log.Fatal("ATTESTOR_QUORUM_M must be >= 1")
	}
	log.Printf("epoch params: genesisMs=%d epochMs=%d breakglassExtra=%d attestorM=%d (epoch=%d)",
		genesisMs, epochMs, breakglassExtra, quorumM, currentEpoch(genesisMs, epochMs))

	const (
		attestorStake = uint64(6_000) * core.UnitsPerAnos // > the 5,000-anos attestor floor
		fundAmount    = uint64(2_000) * core.UnitsPerAnos
		moveAmount    = uint64(100) * core.UnitsPerAnos
	)
	fund := fundAccountID()

	// ---------------------------------------------------------------
	// STEP 1: stake the attestor quorum.
	// ---------------------------------------------------------------
	banner("STEP 1: stake the attestor quorum")
	attestors := make([]*simkit.Account, quorumM)
	for i := 0; i < quorumM; i++ {
		a := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
		attestors[i] = a
		normalSend(c, genesis, a.ID, attestorStake+uint64(10)*core.UnitsPerAnos)
		rid := c.WaitForReceivable(a.IDBytes(), nil, 1*time.Second, 120*time.Second)
		openReceive(c, a, rid)
		stakeToFund(c, a, fund, attestorStake, "attestor")
		log.Printf("OK: attestor %d = %x staked %d anos", i, a.IDBytes()[:4], attestorStake/core.UnitsPerAnos)
	}
	settle(genesisMs, epochMs, 3)

	// ---------------------------------------------------------------
	// STEP 2: breakglass-drain a SPENDING source S to a transfer chain B.
	// ---------------------------------------------------------------
	banner("STEP 2: breakglass-drain a SPENDING account S -> chain B")
	S := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	D := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING) // recovery destination
	normalSend(c, genesis, S.ID, fundAmount)
	ridS := c.WaitForReceivable(S.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, S, ridS)
	assert(mustAccount(c, S.IDBytes()).AccountClass == pb.AccountClass_ACCOUNT_CLASS_SPENDING, "S should be SPENDING")

	B, bSeq := breakglassDrain(c, S, moveAmount)
	// Generous window so the unlock is still in the future after the owner-cancel step's wall-clock
	// (the before-unlock negative is checked HERE, immediately, while we are provably pre-unlock).
	unlock := currentEpoch(genesisMs, epochMs) + breakglassExtra + 12 // SPENDING class delay 0 + window
	openBreakglassChain(c, B, D.ID, unlock)
	// A breakglass chain is breakglass_origin AND release_requires_attestor, even from a SPENDING source.
	assertChainFlags(c, B.IDBytes(), true, true)
	log.Printf("OK: B=%x (from send seq %d) is breakglass_origin + attestor-gated; unlock=%d (epoch=%d)",
		B.IDBytes()[:4], bSeq, unlock, currentEpoch(genesisMs, epochMs))

	// NEGATIVE (checked now, well before unlock): a release with a full quorum must NOT finalize while
	// the chain is locked. The submitted tx stays pooled and finalizes only once epoch >= unlock.
	breakglassRelease(c, B, D.ID, moveAmount, attestors[:quorumM])
	if waitSeqOrTimeout(c, B.IDBytes(), 2, 2, genesisMs, epochMs) {
		log.Fatal("FAIL: breakglass release finalized BEFORE the unlock window")
	}
	log.Printf("OK: release-before-unlock did not finalize (epoch=%d < unlock=%d)", currentEpoch(genesisMs, epochMs), unlock)

	// ---------------------------------------------------------------
	// STEP 3: OWNER CANCEL — a second drain B2 returned to source by the AUTH key.
	// ---------------------------------------------------------------
	banner("STEP 3: OWNER CANCEL — return-to-source on a second breakglass drain (auth key)")
	B2, _ := breakglassDrain(c, S, moveAmount)
	openBreakglassChain(c, B2, D.ID, currentEpoch(genesisMs, epochMs)+breakglassExtra+3)
	// Owner cancels with the AUTH key (return-to-source is free, any epoch, no attestors).
	authReturn(c, B2, S.ID, moveAmount)
	c.WaitForSeqAtLeast(B2.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, B2.IDBytes()).Balance == 0, "B2 should be drained after the owner cancel")
	cancelRID := c.WaitForReceivable(S.IDBytes(), nil, 1*time.Second, 120*time.Second)
	plainReceive(c, S, cancelRID)
	log.Printf("OK: owner cancelled B2 via return-to-source with the auth key (no attestors)")

	// ---------------------------------------------------------------
	// STEP 4: RELEASE B -> D after the window with the breakglass key + attestor quorum.
	// ---------------------------------------------------------------
	banner("STEP 4: RELEASE B -> D (revealed breakglass key + M-of-N attestors) after the window")
	waitUntilEpoch(unlock+1, genesisMs, epochMs)
	breakglassRelease(c, B, D.ID, moveAmount, attestors[:quorumM]) // idempotent re-submit (pooled one may already finalize)
	c.WaitForSeqAtLeast(B.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, B.IDBytes()).Balance == 0, "B should be drained after release")
	relRID := c.WaitForReceivable(D.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, D, relRID)
	assert(mustAccount(c, D.IDBytes()).Balance == moveAmount, "D should have received the recovered funds")
	log.Printf("OK: breakglass release with %d attestors finalized; D recovered %d units", quorumM, moveAmount)

	// ---------------------------------------------------------------
	// STEP 5: NEGATIVE — a forged breakglass drain never finalizes.
	// ---------------------------------------------------------------
	banner("STEP 5: NEGATIVE — a forged breakglass key drain on S must not finalize")
	stranger := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	head, seq, err := c.Head(S.IDBytes())
	if err != nil {
		log.Fatalf("read S: %v", err)
	}
	forgedChain := simkit.DerivedTransferAccount(S, seq+1)
	forged := simkit.BuildSend(S, head, seq+1, forgedChain.ID, moveAmount, core.ExpectedFee(moveAmount))
	stranger.MustSignBreakglass(forged) // a stranger's revealed key — does NOT match S's commitment
	_ = c.Submit(forged)
	if waitSeqOrTimeout(c, S.IDBytes(), seq+1, 3, genesisMs, epochMs) {
		log.Fatal("FAIL: a forged breakglass drain finalized (commitment gate not enforced)")
	}
	log.Printf("OK: forged breakglass drain did not advance S's chain (rejected at the commitment check)")

	// ---------------------------------------------------------------
	// STEP 6: ESCROW — 2-of-2 drain where one party uses its breakglass key.
	// ---------------------------------------------------------------
	banner("STEP 6: ESCROW — 2-of-2 outflow with one party's revealed breakglass key")
	P1 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	P2 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	D2 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	normalSend(c, genesis, P1.ID, fundAmount)
	rP1 := c.WaitForReceivable(P1.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, P1, rP1)

	// P1 funds + opens an escrow with P2 (P1 is the funder/signer; one funding SEND).
	hP1, sP1, err := c.Head(P1.IDBytes())
	if err != nil {
		log.Fatalf("read P1: %v", err)
	}
	escSeq := sP1 + 1
	esc := simkit.DerivedEscrowAccount(P1, P2, P1, escSeq)
	fundEsc := simkit.BuildSend(P1, hP1, escSeq, esc.ID, moveAmount, core.ExpectedFee(moveAmount))
	P1.MustSign(fundEsc)
	c.MustSubmit(fundEsc)
	c.WaitForSeqAtLeast(P1.IDBytes(), escSeq, 500*time.Millisecond, 120*time.Second)
	escRID := c.WaitForReceivable(esc.IDBytes(), nil, 1*time.Second, 120*time.Second)
	trigger := currentEpoch(genesisMs, epochMs) + escrowDelay + 3
	opening := simkit.BuildEscrowOpening(esc, escRID, trigger, false)
	esc.Funder.MustSign(opening)
	c.MustSubmit(opening)
	c.WaitForSeqAtLeast(esc.IDBytes(), 1, 500*time.Millisecond, 120*time.Second)
	log.Printf("OK: escrow %x funded + opened (parties %x / %x)", esc.IDBytes()[:4], esc.Lo.IDBytes()[:4], esc.Hi.IDBytes()[:4])

	// Drain 2-of-2: Lo signs normally, Hi signs with its REVEALED breakglass key.
	eh, es, err := c.Head(esc.IDBytes())
	if err != nil {
		log.Fatalf("read escrow: %v", err)
	}
	drain := simkit.BuildEscrowOutflow(esc, eh, es+1, D2.ID, moveAmount)
	if err := simkit.SignEscrowOutflowWith(drain, []*simkit.Account{esc.Lo}, []*simkit.Account{esc.Hi}); err != nil {
		log.Fatalf("sign escrow drain: %v", err)
	}
	c.MustSubmit(drain)
	c.WaitForSeqAtLeast(esc.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, esc.IDBytes()).Balance == 0, "escrow should be drained")
	// The 2-of-2 (one slot via a breakglass key) succeeded: the escrow emptied and minted a receivable
	// to D2 (claiming it is the ordinary recipient flow, already covered by other sims).
	escDestRID := c.WaitForReceivable(D2.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, D2, escDestRID)
	assert(mustAccount(c, D2.IDBytes()).Balance == moveAmount, "D2 should have received the escrow funds")
	log.Printf("OK: escrow 2-of-2 (one breakglass slot) drained %d units to D2=%x", moveAmount, D2.IDBytes()[:4])

	banner("ALL CHECKS PASSED")
}

// --- flow helpers ---

// breakglassDrain sends moveAmount from S via its REVEALED breakglass key to the derived transfer
// chain that exact SEND spawns, returning the chain and the send seq (its creation nonce).
func breakglassDrain(c *simkit.Client, source *simkit.Account, moveAmount uint64) (*simkit.Account, uint64) {
	head, seq, err := c.Head(source.IDBytes())
	if err != nil {
		log.Fatalf("read source: %v", err)
	}
	sendSeq := seq + 1
	chain := simkit.DerivedTransferAccount(source, sendSeq)
	tx := simkit.BuildSend(source, head, sendSeq, chain.ID, moveAmount, core.ExpectedFee(moveAmount))
	source.MustSignBreakglass(tx) // signed by the breakglass key, reveals it
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(source.IDBytes(), sendSeq, 500*time.Millisecond, 120*time.Second)
	return chain, sendSeq
}

// openBreakglassChain opens a breakglass-spawned transfer chain with the breakglass key (the
// recoverer lost the auth key), pinning its release destination + unlock.
func openBreakglassChain(c *simkit.Client, chain *simkit.Account, dest [32]byte, unlock uint64) {
	rid := c.WaitForReceivable(chain.IDBytes(), nil, 1*time.Second, 120*time.Second)
	tx := simkit.BuildOpeningReceive(chain, rid, &dest, unlock)
	chain.MustSignBreakglass(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(chain.IDBytes(), 1, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, chain.IDBytes()).AccountClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER, "chain should be TRANSFER")
}

// breakglassRelease submits a release-to-dest authorized by the chain's REVEALED breakglass key
// (Tx.sig) + the M-of-N attestor multisig. It does NOT wait (callers decide).
func breakglassRelease(c *simkit.Client, chain *simkit.Account, to [32]byte, balance uint64, attestors []*simkit.Account) {
	head, seq, err := c.Head(chain.IDBytes())
	if err != nil {
		log.Fatalf("read chain: %v", err)
	}
	tx := simkit.BuildSend(chain, head, seq+1, to, balance, 0)
	if err := simkit.SignBreakglassRelease(tx, chain, attestors); err != nil {
		log.Fatalf("sign breakglass release: %v", err)
	}
	_ = c.Submit(tx)
}

// authReturn submits a zero-fee return-to-source drain signed by the chain's AUTH key (owner cancel).
func authReturn(c *simkit.Client, chain *simkit.Account, to [32]byte, balance uint64) {
	head, seq, err := c.Head(chain.IDBytes())
	if err != nil {
		log.Fatalf("read chain: %v", err)
	}
	tx := simkit.BuildSend(chain, head, seq+1, to, balance, 0)
	chain.MustSign(tx) // auth key
	_ = c.Submit(tx)
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

func openReceive(c *simkit.Client, acct *simkit.Account, rid [32]byte) {
	tx := simkit.BuildOpeningReceive(acct, rid, nil, 0)
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

// --- read-API cross-checks ---

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
