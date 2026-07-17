// sim-guarded-vault-release demonstrates the GUARDED/VAULT lifecycle end to end on hybrid keys
// with the forquinn second user key U2 (spec-18 §5.3/§5.4, spec-19 §6.1, forquinn item 1):
//
//  1. Stake ATTESTOR_QUORUM_M attestors (SPENDING accounts staking "attestor" directly).
//  2. A GUARDED account UG1 opens WITH a U2 registration (PoP-verified at the opening) and funds a
//     transfer chain T1 with a U2-SIGNED hop-1 (D4: a single user signature is U1 OR U2). The
//     spawned chain reports release_requires_attestor and inherits U2 by derived copy (D2).
//  3. RATE LIMIT (forquinn confirm-item 2): UG1's immediate second hop-1 does NOT finalize inside
//     GUARDED_SEND_MIN_INTERVAL_EPOCHS, then finalizes once the window passes (funding T3).
//  4. PATH (a): T1's release-to-dest signed by BOTH user keys (Tx.sig=U1 + sig2=U2, NO attestors)
//     does not finalize before unlock, then finalizes at unlock. D receives the funds.
//  5. U2-SIGNED CANCEL: T3 returns to UG1 signed by U2 alone (any epoch, never gated), and UG1
//     claims the return with a U2-signed RECEIVE.
//  6. PATH (b): UG2's chain T2 releases with ONE user signature (U2!) + the M-of-N attestor
//     quorum; UG3's chain T2b with only M-1 attestor signatures never finalizes. (UG1/UG2/UG3
//     all send within one window — the rate limit is per-account.)
//  7. VAULT: UV (with U2) funds TV and releases via path (a) at the (longer) vault unlock.
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, GENESIS_UNIX_MS, EPOCH_MS,
// GUARDED_DELAY_EPOCHS, VAULT_DELAY_EPOCHS, ATTESTOR_QUORUM_M, GUARDED_SEND_MIN_INTERVAL_EPOCHS.
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
	sendInterval := getenvUint64("GUARDED_SEND_MIN_INTERVAL_EPOCHS", 6)
	if genesisMs == 0 {
		log.Fatal("GENESIS_UNIX_MS is required")
	}
	if quorumM < 1 {
		log.Fatal("ATTESTOR_QUORUM_M must be >= 1")
	}
	log.Printf("epoch params: genesisMs=%d epochMs=%d guardedDelay=%d vaultDelay=%d attestorM=%d sendInterval=%d (epoch=%d)",
		genesisMs, epochMs, guardedDelay, vaultDelay, quorumM, sendInterval, currentEpoch(genesisMs, epochMs))

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
	// STEP 2: open a GUARDED account UG1 WITH U2 and fund T1 via a U2-signed hop-1.
	// ---------------------------------------------------------------
	banner("STEP 2: guarded UG1 opens with a U2 registration; U2-signed hop-1 funds T1")
	UG1 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_GUARDED).AttachU2(simkit.RandSeed())
	D := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	normalSend(c, genesis, UG1.ID, fundAmount)
	ridUG1 := c.WaitForReceivable(UG1.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openGuardedReceive(c, UG1, ridUG1)
	ug1St := mustAccount(c, UG1.IDBytes())
	assert(ug1St.AccountClass == pb.AccountClass_ACCOUNT_CLASS_GUARDED, "UG1 should be GUARDED")
	log.Printf("OK: UG1 is GUARDED (U2 registered at opening) with %d units; D(dest)=%x", ug1St.Balance, D.IDBytes()[:4])

	T1, t1Seq := fundTransferChain(c, UG1, moveAmount, true /* U2-signed hop-1 (D4) */)
	t1SendEpoch := currentEpoch(genesisMs, epochMs) // ≈ the finalization epoch the rate limit stamps
	log.Printf("OK: U2-signed hop-1 finalized (seq %d, ~epoch %d); T1=%x", t1Seq, t1SendEpoch, T1.IDBytes()[:4])

	// ---------------------------------------------------------------
	// STEP 3: RATE LIMIT — an immediate second hop-1 must NOT finalize inside the window.
	// ---------------------------------------------------------------
	banner("STEP 3: rate limit — UG1's immediate second send is blocked, then passes")
	head, seq, err := c.Head(UG1.IDBytes())
	if err != nil {
		log.Fatalf("read UG1: %v", err)
	}
	t3Seq := seq + 1
	T3 := simkit.DerivedTransferAccount(UG1, t3Seq)
	t3Fund := simkit.BuildSend(UG1, head, t3Seq, T3.ID, moveAmount, core.ExpectedFee(moveAmount))
	UG1.MustSign(t3Fund) // U1-signed this time — both keys are rate-limited alike
	_ = c.Submit(t3Fund)
	blockEpochs := uint64(1)
	if sendInterval > 4 {
		blockEpochs = sendInterval - 3 // assert well inside the window (margin for the stamp/observation skew)
	}
	if waitSeqOrTimeout(c, UG1.IDBytes(), t3Seq, blockEpochs, genesisMs, epochMs) {
		log.Fatal("FAIL: second guarded send finalized inside the rate-limit window")
	}
	log.Printf("OK: second send blocked for %d epochs (window %d)", blockEpochs, sendInterval)

	// Open T1 and submit its (path-a) release EARLY while the window runs — the release must not
	// finalize before unlock (STEP 5 confirms it lands at unlock).
	t1Unlock := currentEpoch(genesisMs, epochMs) + guardedDelay + 3
	openTransfer(c, T1, D.ID, t1Unlock)
	assertAttestorGated(c, T1.IDBytes(), true)
	log.Printf("OK: T1 opened (unlock=%d) and reports release_requires_attestor", t1Unlock)
	pathARelease(c, T1, D.ID, moveAmount)
	if waitSeqOrTimeout(c, T1.IDBytes(), 2, 3, genesisMs, epochMs) {
		log.Fatal("FAIL: path (a) release finalized before unlock (timelock not enforced)")
	}
	log.Printf("OK: pre-unlock path (a) release did not finalize (epoch=%d < unlock=%d)", currentEpoch(genesisMs, epochMs), t1Unlock)

	// Window over → the SAME queued funding send must now finalize (resubmit is an idempotent dup).
	waitUntilEpoch(t1SendEpoch+sendInterval+2, genesisMs, epochMs)
	_ = c.Submit(t3Fund)
	c.WaitForSeqAtLeast(UG1.IDBytes(), t3Seq, 500*time.Millisecond, 120*time.Second)
	log.Printf("OK: second send finalized after the window (epoch=%d)", currentEpoch(genesisMs, epochMs))
	t3Unlock := currentEpoch(genesisMs, epochMs) + guardedDelay + 3
	openTransfer(c, T3, D.ID, t3Unlock)

	// ---------------------------------------------------------------
	// STEP 4: U2-SIGNED CANCEL — T3 returns to UG1 with U2 alone, any epoch, never gated.
	// ---------------------------------------------------------------
	banner("STEP 4: U2-signed cancel of T3 (return-to-source, ungated)")
	transferReturn(c, T3, UG1.ID, moveAmount, true /* U2-signed */)
	c.WaitForSeqAtLeast(T3.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, T3.IDBytes()).Balance == 0, "T3 should be drained after the cancel")
	retRID := c.WaitForReceivable(UG1.IDBytes(), nil, 1*time.Second, 120*time.Second)
	plainReceive(c, UG1, retRID, true /* U2-signed claim (D4 on a non-opening RECEIVE) */)
	log.Printf("OK: U2-signed cancel + U2-signed claim finalized (no attestors, before unlock)")

	// ---------------------------------------------------------------
	// STEP 5: PATH (a) — the pending U1+U2 release finalizes at unlock, with NO attestors.
	// ---------------------------------------------------------------
	banner("STEP 5: PATH (a) — T1 releases to D with BOTH user keys, no attestor quorum")
	waitUntilEpoch(t1Unlock+1, genesisMs, epochMs)
	pathARelease(c, T1, D.ID, moveAmount) // idempotent re-submit (same txid as the queued one)
	c.WaitForSeqAtLeast(T1.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, T1.IDBytes()).Balance == 0, "T1 should be drained after the path (a) release")
	relRID := c.WaitForReceivable(D.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, D, relRID, nil, 0)
	assert(mustAccount(c, D.IDBytes()).Balance == moveAmount, "D should have received the released amount")
	log.Printf("OK: path (a) release finalized with zero attestor signatures; D received %d units", moveAmount)

	// ---------------------------------------------------------------
	// STEP 6: PATH (b) — one user sig (U2) + the M-of-N quorum; below-quorum never finalizes.
	// ---------------------------------------------------------------
	banner("STEP 6: PATH (b) — U2 user sig + attestor quorum on T2; M-1 sigs on T2b never finalize")
	UG2 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_GUARDED).AttachU2(simkit.RandSeed())
	normalSend(c, genesis, UG2.ID, fundAmount)
	ridUG2 := c.WaitForReceivable(UG2.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openGuardedReceive(c, UG2, ridUG2)
	T2, _ := fundTransferChain(c, UG2, moveAmount, false /* U1-signed hop-1 */)
	t2Unlock := currentEpoch(genesisMs, epochMs) + guardedDelay + 3
	openTransfer(c, T2, D.ID, t2Unlock)

	UG3 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_GUARDED).AttachU2(simkit.RandSeed())
	normalSend(c, genesis, UG3.ID, fundAmount)
	ridUG3 := c.WaitForReceivable(UG3.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openGuardedReceive(c, UG3, ridUG3)
	T2b, _ := fundTransferChain(c, UG3, moveAmount, false)
	t2bUnlock := currentEpoch(genesisMs, epochMs) + guardedDelay + 3
	openTransfer(c, T2b, D.ID, t2bUnlock)
	log.Printf("UG1/UG2/UG3 all sent within one window — the rate limit is per-account")

	waitUntilEpoch(t2bUnlock+1, genesisMs, epochMs)
	if quorumM >= 2 {
		releaseToDest(c, T2b, D.ID, moveAmount, attestors[:quorumM-1], false) // one short of M
		if waitSeqOrTimeout(c, T2b.IDBytes(), 2, 4, genesisMs, epochMs) {
			log.Fatal("FAIL: below-quorum release finalized (attestor gate not enforced)")
		}
		log.Printf("OK: below-quorum (M-1=%d) release did not finalize", quorumM-1)
	} else {
		log.Printf("SKIP: ATTESTOR_QUORUM_M=1 has no below-quorum case")
	}
	releaseToDest(c, T2, D.ID, moveAmount, attestors[:quorumM], true /* U2 user sig (D4) */)
	c.WaitForSeqAtLeast(T2.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, T2.IDBytes()).Balance == 0, "T2 should be drained after the path (b) release")
	log.Printf("OK: path (b) release (U2 user sig + %d attestors) finalized", quorumM)

	// ---------------------------------------------------------------
	// STEP 7: VAULT — same U2 scheme, path (a), at the longer vault unlock.
	// ---------------------------------------------------------------
	banner("STEP 7: VAULT source with U2 releases via path (a)")
	UV := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_VAULT).AttachU2(simkit.RandSeed())
	normalSend(c, genesis, UV.ID, fundAmount)
	ridUV := c.WaitForReceivable(UV.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openGuardedReceive(c, UV, ridUV)
	assert(mustAccount(c, UV.IDBytes()).AccountClass == pb.AccountClass_ACCOUNT_CLASS_VAULT, "UV should be VAULT")
	TV, _ := fundTransferChain(c, UV, moveAmount, false)
	vUnlock := currentEpoch(genesisMs, epochMs) + vaultDelay + 3
	openTransfer(c, TV, D.ID, vUnlock)
	assertAttestorGated(c, TV.IDBytes(), true)
	log.Printf("TV=%x reports release_requires_attestor (VAULT source); unlock=%d", TV.IDBytes()[:4], vUnlock)
	waitUntilEpoch(vUnlock+1, genesisMs, epochMs)
	pathARelease(c, TV, D.ID, moveAmount)
	c.WaitForSeqAtLeast(TV.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, TV.IDBytes()).Balance == 0, "TV should be drained after the vault path (a) release")
	log.Printf("OK: VAULT path (a) release finalized")

	banner("ALL CHECKS PASSED")
}

// --- flow helpers ---

// fundTransferChain sends moveAmount from a GUARDED/VAULT source to the derived transfer chain
// that exact SEND spawns (U2-signed when useU2 — D4), returning the chain account and the send
// seq (its creation nonce). The chain inherits the source's U2 by derived copy (D2).
func fundTransferChain(c *simkit.Client, source *simkit.Account, moveAmount uint64, useU2 bool) (*simkit.Account, uint64) {
	head, seq, err := c.Head(source.IDBytes())
	if err != nil {
		log.Fatalf("read source: %v", err)
	}
	sendSeq := seq + 1
	chain := simkit.DerivedTransferAccount(source, sendSeq)
	tx := simkit.BuildSend(source, head, sendSeq, chain.ID, moveAmount, core.ExpectedFee(moveAmount))
	if useU2 {
		if err := source.SignWithU2(tx); err != nil {
			log.Fatalf("U2-sign hop-1: %v", err)
		}
	} else {
		source.MustSign(tx)
	}
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

// releaseToDest submits a path-(b) attestor-gated release-to-dest: ONE user signature (the
// chain's copied U1, or its copied U2 when userSigU2 — D4) + the attestor multisig. It does NOT
// wait (callers decide whether it should finalize).
func releaseToDest(c *simkit.Client, chain *simkit.Account, to [32]byte, balance uint64, attestors []*simkit.Account, userSigU2 bool) {
	head, seq, err := c.Head(chain.IDBytes())
	if err != nil {
		log.Fatalf("read transfer chain: %v", err)
	}
	tx := simkit.BuildSend(chain, head, seq+1, to, balance, 0)
	if userSigU2 {
		if err := chain.SignWithU2(tx); err != nil {
			log.Fatalf("U2-sign release: %v", err)
		}
		if err := simkit.SignFundSend(tx, attestors); err != nil { // attestor multisig over the same m
			log.Fatalf("sign attestor quorum: %v", err)
		}
	} else if err := simkit.SignAttestorRelease(tx, chain, attestors); err != nil {
		log.Fatalf("sign attestor release: %v", err)
	}
	_ = c.Submit(tx)
}

// pathARelease submits an attestor-FREE release-to-dest signed by BOTH user keys (Tx.sig=U1,
// sig2=U2 — forquinn path (a), fixed roles D5). It does NOT wait.
func pathARelease(c *simkit.Client, chain *simkit.Account, to [32]byte, balance uint64) {
	head, seq, err := c.Head(chain.IDBytes())
	if err != nil {
		log.Fatalf("read transfer chain: %v", err)
	}
	tx := simkit.BuildSend(chain, head, seq+1, to, balance, 0)
	if err := simkit.SignPathARelease(tx, chain); err != nil {
		log.Fatalf("sign path (a) release: %v", err)
	}
	_ = c.Submit(tx)
}

// transferReturn submits a zero-fee return-to-source drain (no attestors; U2-signed when useU2).
func transferReturn(c *simkit.Client, chain *simkit.Account, to [32]byte, balance uint64, useU2 bool) {
	head, seq, err := c.Head(chain.IDBytes())
	if err != nil {
		log.Fatalf("read transfer chain: %v", err)
	}
	tx := simkit.BuildSend(chain, head, seq+1, to, balance, 0)
	if useU2 {
		if err := chain.SignWithU2(tx); err != nil {
			log.Fatalf("U2-sign cancel: %v", err)
		}
	} else {
		chain.MustSign(tx)
	}
	_ = c.Submit(tx)
}

func openReceive(c *simkit.Client, acct *simkit.Account, rid [32]byte, transferDest *[32]byte, unlock uint64) {
	tx := simkit.BuildOpeningReceive(acct, rid, transferDest, unlock)
	acct.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(acct.IDBytes(), 1, 500*time.Millisecond, 120*time.Second)
}

// openGuardedReceive opens a GUARDED/VAULT account registering its U2 (+PoP) on the opening
// block (forquinn item 1; AttachU2 must have been called). The opening itself is U1-signed.
func openGuardedReceive(c *simkit.Client, acct *simkit.Account, rid [32]byte) {
	tx, err := simkit.BuildGuardedOpeningReceive(acct, rid)
	if err != nil {
		log.Fatalf("build guarded opening: %v", err)
	}
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

// plainReceive claims a receivable on an established account (U2-signed when useU2 — D4 accepts
// U1 OR U2 on a non-opening RECEIVE).
func plainReceive(c *simkit.Client, acct *simkit.Account, rid [32]byte, useU2 bool) {
	head, seq, err := c.Head(acct.IDBytes())
	if err != nil {
		log.Fatalf("read account: %v", err)
	}
	tx := simkit.BuildReceive(acct, head, seq+1, rid)
	if useU2 {
		if err := acct.SignWithU2(tx); err != nil {
			log.Fatalf("U2-sign receive: %v", err)
		}
	} else {
		acct.MustSign(tx)
	}
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
