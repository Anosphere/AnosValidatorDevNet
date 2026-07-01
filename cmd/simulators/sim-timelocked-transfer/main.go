// sim-timelocked-transfer demonstrates the TIMELOCKED + TRANSFER-chain lifecycle
// end to end on hybrid (post-quantum) keys, with P1.3 copied-key transfer chains:
//
//  1. genesis (SPENDING) funds a fresh user U, who receives as TIMELOCKED.
//  2. U moves funds out by sending to a transfer chain T; because U is TIMELOCKED,
//     the receivable is stamped required_dest_class = TRANSFER. T is NOT a fresh
//     account — it is the DERIVED chain that send spawns: it copies U's auth+breakglass
//     keys and its id = DerivedAccountID(TRANSFER, U pubkey, U id, send seq) (P1.3).
//  3. T opens itself as a TRANSFER chain (first RECEIVE) with destination D and an
//     unlock epoch = creation_epoch + TIMELOCKED_DELAY_EPOCHS. Its opening block
//     registers the COPIED (U's) hybrid pubkey + breakglass commitment, signed by U's
//     key; validators enforce account-id == DerivedAccountID(TRANSFER, …, send seq).
//  4. Release T -> D before unlock does not finalize; after unlock it does.
//  5. A second chain T2 is RETURNED to its source U before unlock (always allowed) —
//     the drain is signed by U's own key, proving the source key controls the chain.
//
// Negative checks: a SPENDING claim of the transfer-restricted receivable does not
// finalize (source-side restriction); a chain with U's copied keys but a WRONG
// creation nonce does not finalize (nonce binding); release-before-unlock does not
// finalize.
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, GENESIS_UNIX_MS, EPOCH_MS,
// TIMELOCKED_DELAY_EPOCHS.
package main

import (
	"encoding/hex"
	"log"
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
	delay := getenvUint64("TIMELOCKED_DELAY_EPOCHS", 120960)
	if genesisMs == 0 {
		log.Fatal("GENESIS_UNIX_MS is required")
	}
	log.Printf("epoch params: genesisMs=%d epochMs=%d delay=%d (current epoch=%d)",
		genesisMs, epochMs, delay, currentEpoch(genesisMs, epochMs))

	U := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED)
	D := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	log.Printf("U=%x D=%x (transfer chains are derived from U's send seq)", U.IDBytes()[:4], D.IDBytes()[:4])

	const fundAmount = uint64(1000) * core.UnitsPerAnos
	const moveAmount = uint64(100) * core.UnitsPerAnos

	// 1) genesis -> U; U opens as TIMELOCKED.
	banner("STEP 1: fund U and establish it as TIMELOCKED")
	normalSend(c, genesis, U.ID, fundAmount)
	ridU := c.WaitForReceivable(U.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, U, ridU, nil, 0)
	uSt := mustAccount(c, U.IDBytes())
	assert(uSt.AccountClass == pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, "U should be TIMELOCKED")
	assert(uSt.Balance == fundAmount, "U should hold the funded amount")
	log.Printf("OK: U is TIMELOCKED with %d units", uSt.Balance)

	// 2) U -> T1. T1 is the DERIVED transfer chain spawned by this exact SEND: it copies
	// U's auth+breakglass keys and its id = DerivedAccountID(TRANSFER, U pubkey, U id,
	// sendSeq). The funding send MUST use sendSeq (the nonce the validator independently
	// re-derives from the receivable's from_seq).
	banner("STEP 2: U sends to its derived transfer chain T1 (copied keys + nonce id)")
	T1, t1SendSeq := fundTransferChain(c, U, moveAmount)
	log.Printf("T1=%x (derived from U send seq %d)", T1.IDBytes()[:4], t1SendSeq)
	ridT1 := c.WaitForReceivable(T1.IDBytes(), nil, 1*time.Second, 120*time.Second)

	// Negative check: a fresh SPENDING account claiming the transfer-restricted
	// receivable must not finalize.
	banner("NEGATIVE CHECK: SPENDING claim of a transfer-restricted receivable must not finalize")
	bad := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	badRecv := simkit.BuildOpeningReceive(bad, ridT1, nil, 0)
	bad.MustSign(badRecv)
	_ = c.Submit(badRecv) // accepted into pool (sig valid); rejected at epoch close
	if waitSeqOrTimeout(c, bad.IDBytes(), 1, 4, genesisMs, epochMs) {
		log.Fatal("FAIL: SPENDING claim of a transfer-restricted receivable finalized")
	}
	log.Printf("OK: SPENDING claim did not finalize (source-side restriction enforced)")

	// Negative check: a chain with U's COPIED keys but a WRONG creation nonce (a send
	// seq that doesn't match the funding receivable's from_seq) must not finalize — the
	// validator re-derives the id from from_seq and rejects the mismatch. This isolates
	// the nonce binding: copied keys + valid signature, only the nonce is wrong.
	banner("NEGATIVE CHECK: wrong-nonce transfer chain must not finalize")
	wrongNonce := simkit.DerivedTransferAccount(U, t1SendSeq+1) // wrong nonce
	unlockBad := currentEpoch(genesisMs, epochMs) + delay + 3
	badNonce := simkit.BuildOpeningReceive(wrongNonce, ridT1, &D.ID, unlockBad)
	wrongNonce.MustSign(badNonce)
	_ = c.Submit(badNonce) // sig valid (U's key); rejected at epoch close on id mismatch
	if waitSeqOrTimeout(c, wrongNonce.IDBytes(), 1, 4, genesisMs, epochMs) {
		log.Fatal("FAIL: wrong-nonce transfer chain finalized (creation nonce not enforced)")
	}
	log.Printf("OK: wrong-nonce chain did not finalize (creation-nonce id enforced)")

	// 3) T1 opens as TRANSFER with unlock = now + delay + margin.
	banner("STEP 3: open T1 as a TRANSFER chain")
	unlock1 := currentEpoch(genesisMs, epochMs) + delay + 3
	log.Printf("T1 unlock epoch = %d", unlock1)
	openReceive(c, T1, ridT1, &D.ID, unlock1)
	t1St := mustAccount(c, T1.IDBytes())
	assert(t1St.AccountClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER, "T1 should be TRANSFER")
	assert(t1St.Balance == moveAmount, "T1 should hold the moved amount")
	log.Printf("OK: T1 is a TRANSFER chain holding %d units, unlock %d", t1St.Balance, unlock1)

	// 4a) release T1 -> D BEFORE unlock: must not finalize.
	banner("STEP 4a: release T1 -> D BEFORE unlock must be rejected")
	transferOut(c, T1, D.ID, t1St.Balance) // submitted early; should not finalize yet
	if waitSeqOrTimeout(c, T1.IDBytes(), 2, 4, genesisMs, epochMs) {
		log.Fatal("FAIL: release-before-unlock finalized (timelock not enforced)")
	}
	log.Printf("OK: release-before-unlock did not finalize (epoch=%d < unlock=%d)",
		currentEpoch(genesisMs, epochMs), unlock1)

	// 4b) wait for unlock, then release.
	banner("STEP 4b: wait for unlock, then release T1 -> D")
	waitUntilEpoch(unlock1+1, genesisMs, epochMs)
	transferOut(c, T1, D.ID, t1St.Balance)
	c.WaitForSeqAtLeast(T1.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, T1.IDBytes()).Balance == 0, "T1 should be drained after release")
	log.Printf("OK: T1 released and drained")

	// 4c) D receives the released funds (poll — robust to which release tx won).
	banner("STEP 4c: D receives the released funds")
	relRID := c.WaitForReceivable(D.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, D, relRID, nil, 0)
	dSt := mustAccount(c, D.IDBytes())
	assert(dSt.Balance == moveAmount, "D should have received the released amount")
	log.Printf("OK: D received %d units (class=%s)", dSt.Balance, dSt.AccountClass)

	// 5) return-to-source: U -> T2 -> back to U before unlock. This is the owner cancel:
	// T2 copies U's keys, so the drain back to U is signed by U's own auth key (the chain
	// shares U's private key) — proof that the source key controls the derived chain.
	banner("STEP 5: return-to-source demo (T2 -> U before unlock; source key controls chain)")
	T2, t2SendSeq := fundTransferChain(c, U, moveAmount)
	log.Printf("T2=%x (derived from U send seq %d)", T2.IDBytes()[:4], t2SendSeq)
	ridT2 := c.WaitForReceivable(T2.IDBytes(), nil, 1*time.Second, 120*time.Second)
	unlock2 := currentEpoch(genesisMs, epochMs) + delay + 3
	openReceive(c, T2, ridT2, &D.ID, unlock2)
	t2St := mustAccount(c, T2.IDBytes())
	assert(t2St.AccountClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER, "T2 should be TRANSFER")

	transferOut(c, T2, U.ID, t2St.Balance) // return to source, signed by U's key (copied)
	c.WaitForSeqAtLeast(T2.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, T2.IDBytes()).Balance == 0, "T2 should be drained after return")
	log.Printf("OK: T2 returned to source while still locked (epoch=%d < unlock=%d)",
		currentEpoch(genesisMs, epochMs), unlock2)

	// U receives the returned funds (non-opening RECEIVE — U already exists).
	retRID := c.WaitForReceivable(U.IDBytes(), nil, 1*time.Second, 120*time.Second)
	plainReceive(c, U, retRID)
	uSt = mustAccount(c, U.IDBytes())
	log.Printf("OK: U received returned funds; U balance now %d units (class=%s)", uSt.Balance, uSt.AccountClass)

	banner("ALL CHECKS PASSED")
}

// --- flow helpers ---

// fundTransferChain sends `moveAmount` from a TIMELOCKED/GUARDED/VAULT source to the
// derived transfer chain that exact SEND spawns, returning the chain account and the
// send seq used as its creation nonce. The chain copies the source's keys, so its id
// depends on the send's seq — which is why the chain is derived and the send issued in
// one step (the validator re-derives the same id from the receivable's from_seq).
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

// normalSend submits a fee-bearing SEND and waits for the sender's seq to advance.
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

// transferOut submits a zero-fee, full-balance TRANSFER outbound (release or
// return). It does NOT wait (callers decide whether it should finalize).
func transferOut(c *simkit.Client, from *simkit.Account, to [32]byte, balance uint64) {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read transfer chain: %v", err)
	}
	tx := simkit.BuildSend(from, head, seq+1, to, balance, 0)
	from.MustSign(tx)
	_ = c.Submit(tx)
}

// openReceive submits an account-opening RECEIVE (with registration) and waits.
func openReceive(c *simkit.Client, acct *simkit.Account, rid [32]byte, transferDest *[32]byte, unlock uint64) {
	tx := simkit.BuildOpeningReceive(acct, rid, transferDest, unlock)
	acct.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(acct.IDBytes(), 1, 500*time.Millisecond, 120*time.Second)
}

// plainReceive submits a non-opening RECEIVE on an already-established account.
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
		// treat as fresh/zero
		return &pb.AccountState{Account: &pb.AccountId{V: acct}, Head: &pb.Hash32{V: make([]byte, 32)}}
	}
	return st
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
