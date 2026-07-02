// sim-opening-dos demonstrates the P7.1 opening-DoS gate (bestEffortOpeningCheck) end to end on the
// live 3-validator network. It proves the grindable, zero-cost opening-slot stall is closed:
//
//  1. Genesis funds a fresh victim V, minting V's opening receivable. We build + sign V's real
//     opening RECEIVE and compute its txid.
//  2. ATTACK: an attacker grinds a forged opening (its OWN key over V's account id) to a LOWER txid
//     than V's real opening — so under lowest-txid-wins it would seize V's opening conflict slot
//     (sha256(V || 0 || 1)) and stall V forever. The gate must REJECT it at /submit (all nodes).
//  3. More never-finalizable shapes at an absent account's opening slot are rejected: a bare junk
//     SEND, a multisig-carrying junk SEND (Option B), and a FUND-class opening RECEIVE.
//  4. RECOVERY: V's real opening then finalizes and its head == the real opening's txid (proving the
//     ground junk did NOT take the slot), and V's chain keeps working (a follow-on SEND finalizes).
//
// Every junk tx is gate-rejected (never enters any pool/state), so the network stays converged for
// the harness's 3-node agreement + verifying-resync checks; only V's legit opening + SEND finalize.
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, GENESIS_UNIX_MS, EPOCH_MS.
package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"anos/internal/core"
	"anos/internal/crypto"
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
	if genesisMs == 0 {
		log.Fatal("GENESIS_UNIX_MS is required")
	}
	log.Printf("epoch params: genesisMs=%d epochMs=%d (epoch=%d)", genesisMs, epochMs, currentEpoch(genesisMs, epochMs))

	const fundAmount = uint64(2_000) * core.UnitsPerAnos

	// ---------------------------------------------------------------
	// STEP 1: genesis funds a victim V and we build V's real opening.
	// ---------------------------------------------------------------
	banner("STEP 1: fund victim V; build V's real opening RECEIVE")
	V := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	normalSend(c, genesis, V.ID, fundAmount)
	ridV := c.WaitForReceivable(V.IDBytes(), nil, 1*time.Second, 120*time.Second)
	legit := simkit.BuildOpeningReceive(V, ridV, nil, 0)
	V.MustSign(legit)
	legitID, err := crypto.TxID(legit)
	if err != nil {
		log.Fatalf("legit opening txid: %v", err)
	}
	log.Printf("OK: V=%x funded; real opening txid=%x", V.IDBytes()[:4], legitID[:6])

	// ---------------------------------------------------------------
	// STEP 2: grind a forged opening to a LOWER txid, then it must be rejected at the gate.
	// ---------------------------------------------------------------
	banner("STEP 2: ATTACK — grind a forged opening (attacker key over V's id) to a lower txid")
	attacker := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	junk, junkID := grindForgedOpening(attacker, V.ID, legitID)
	log.Printf("OK: ground forged opening txid=%x < real txid=%x (would win lowest-txid-wins)", junkID[:6], legitID[:6])
	// V is not yet opened on any node → the account is absent everywhere → all 3 nodes reject.
	if err := c.Submit(junk); err == nil {
		log.Fatal("FAIL: forged lower-txid opening was ACCEPTED — the opening gate is not enforced (DoS)")
	} else {
		log.Printf("OK: forged opening rejected at the gate: %v", err)
	}

	// ---------------------------------------------------------------
	// STEP 3: other never-finalizable shapes at an absent account's opening slot are rejected.
	// ---------------------------------------------------------------
	banner("STEP 3: NEGATIVE — junk SEND / multisig SEND / FUND-class opening all rejected")
	absent := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING) // never funded → absent

	// (a) A bare SEND at the opening slot: no SEND is a valid first block.
	bareSend := simkit.BuildSend(absent, [32]byte{}, 1, V.ID, 1000, core.ExpectedFee(1000))
	rejectAtGate(c, bareSend, "bare SEND at the opening slot")

	// (b) A multisig-carrying SEND at the opening slot (Option B: rejected regardless of the multisig).
	msSend := simkit.BuildSend(absent, [32]byte{}, 1, V.ID, 1000, core.ExpectedFee(1000))
	msSend.MultiSig = &pb.HybridMultiSig{Entries: []*pb.HybridSigEntry{{
		SignerId: &pb.AccountId{V: make([]byte, 32)},
		Sig:      &pb.HybridSig{V: []byte{0x01}},
	}}}
	rejectAtGate(c, msSend, "multisig-carrying SEND at the opening slot")

	// (c) An opening RECEIVE declaring class FUND (a keyless singleton, never opened by RECEIVE).
	fundOpen := simkit.BuildOpeningReceive(attacker, ridV, nil, 0)
	fundOpen.Account = &pb.AccountId{V: absent.IDBytes()}
	fundOpen.GetReceive().AccountClass = pb.AccountClass_ACCOUNT_CLASS_FUND
	attacker.MustSign(fundOpen)
	rejectAtGate(c, fundOpen, "FUND-class opening RECEIVE")

	// ---------------------------------------------------------------
	// STEP 4: V's real opening finalizes and wins the slot; V's chain keeps working.
	// ---------------------------------------------------------------
	banner("STEP 4: RECOVERY — V's real opening finalizes and wins the contested slot")
	c.MustSubmit(legit)
	if !waitSeqOrTimeout(c, V.IDBytes(), 1, 30, genesisMs, epochMs) {
		log.Fatal("FAIL: V's real opening did not finalize (junk stalled the opening slot?)")
	}
	head, _, err := c.Head(V.IDBytes())
	if err != nil {
		log.Fatalf("read V head: %v", err)
	}
	if !bytes.Equal(head[:], legitID[:]) {
		log.Fatalf("FAIL: V's head=%x != real opening txid=%x (a different tx took the slot)", head[:6], legitID[:6])
	}
	st := mustAccount(c, V.IDBytes())
	assert(st.AccountClass == pb.AccountClass_ACCOUNT_CLASS_SPENDING, "V should be SPENDING")
	assert(st.Balance == fundAmount, "V should hold the funded balance")
	log.Printf("OK: V opened at seq 1 with head == real opening txid; balance=%d", st.Balance)

	// V's chain keeps working past the contested opening (a follow-on SEND to a fresh account).
	W := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	normalSend(c, V, W.ID, 100*core.UnitsPerAnos)
	log.Printf("OK: V sent onward to W=%x (chain functional after the contested opening)", W.IDBytes()[:4])

	// ---------------------------------------------------------------
	// STEP 5: the RELABEL bypass is closed by validity-aware candidate proposal.
	// ---------------------------------------------------------------
	// A forged opening RELABELLED as TRANSFER over V2's id is DEFERRED by the front-door gate (a TRANSFER
	// opening's id derives from unsynced state, so it can't be judged at submit) — so it ENTERS the pool
	// with a LOWER txid than V2's real opening. Under a validity-BLIND lowest-txid pick it would win the
	// slot, fail epoch-close validate, and starve V2. Validity-aware proposal must skip the invalid junk
	// and still propose+finalize V2's real opening. We sustain the attack (re-inject the junk each epoch)
	// while V2 retries, and V2 must still open.
	banner("STEP 5: relabel bypass (TRANSFER-labelled junk) closed by validity-aware proposal")
	V2 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	normalSend(c, genesis, V2.ID, fundAmount)
	ridV2 := c.WaitForReceivable(V2.IDBytes(), nil, 1*time.Second, 120*time.Second)
	legit2 := simkit.BuildOpeningReceive(V2, ridV2, nil, 0)
	V2.MustSign(legit2)
	legit2ID, err := crypto.TxID(legit2)
	if err != nil {
		log.Fatalf("legit2 txid: %v", err)
	}
	junk2, junk2ID := grindRelabelledTransferJunk(attacker, V2.ID, legit2ID)
	log.Printf("OK: ground TRANSFER-labelled junk txid=%x < real txid=%x", junk2ID[:6], legit2ID[:6])
	// The front-door gate DEFERS the TRANSFER junk (it must — unjudgeable at submit), so it is accepted.
	if err := c.Submit(junk2); err != nil {
		log.Fatalf("FAIL: the TRANSFER-labelled junk should be DEFERRED (accepted) at the front-door gate, got: %v", err)
	}
	log.Printf("OK: TRANSFER junk deferred into the pool (front-door gate can't judge it) — the real fix must catch it")
	// Sustain the attack + retry the real opening until V2 opens.
	opened := false
	for ep := 0; ep < 30 && !opened; ep++ {
		_ = c.Submit(junk2)  // re-inject the lower-txid junk each epoch (it is evicted at each commit)
		_ = c.Submit(legit2) // re-submit the real opening (one-shot-per-epoch eviction)
		opened = waitSeqOrTimeout(c, V2.IDBytes(), 1, 1, genesisMs, epochMs)
	}
	if !opened {
		log.Fatal("FAIL: V2 opening starved by lower-txid TRANSFER junk (validity-aware proposal not closing the relabel bypass)")
	}
	head2, _, err := c.Head(V2.IDBytes())
	if err != nil {
		log.Fatalf("read V2 head: %v", err)
	}
	if !bytes.Equal(head2[:], legit2ID[:]) {
		log.Fatalf("FAIL: V2 head=%x != real opening txid=%x (relabelled junk took the slot)", head2[:6], legit2ID[:6])
	}
	log.Printf("OK: V2 opened despite sustained lower-txid TRANSFER junk — the relabel bypass is closed")

	banner("ALL CHECKS PASSED")
}

// grindRelabelledTransferJunk builds a forged opening over victimID carrying the attacker's key but
// RELABELLED as a TRANSFER opening (a well-formed, signable shape the front-door gate must defer),
// grinding its receivable_id until the txid beats `beat`. It references a bogus receivable, so the
// authoritative validate rejects it (ErrUnknownRecv) — the validity-aware proposal must skip it.
func grindRelabelledTransferJunk(attacker *simkit.Account, victimID [32]byte, beat [32]byte) (*pb.Tx, [32]byte) {
	var dest [32]byte
	dest[0] = 0xde
	for i := 0; i < 100000; i++ {
		var rid [32]byte
		rid[0], rid[1], rid[2], rid[3] = byte(i), byte(i>>8), byte(i>>16), byte(i>>24)
		tx := simkit.BuildOpeningReceive(attacker, rid, nil, 0)
		tx.Account = &pb.AccountId{V: append([]byte(nil), victimID[:]...)}
		rb := tx.GetReceive()
		rb.AccountClass = pb.AccountClass_ACCOUNT_CLASS_TRANSFER
		rb.TransferDestination = &pb.AccountId{V: append([]byte(nil), dest[:]...)}
		rb.TransferUnlockEpoch = 1_000_000
		attacker.MustSign(tx)
		id, err := crypto.TxID(tx)
		if err != nil {
			log.Fatalf("relabelled junk txid: %v", err)
		}
		if bytes.Compare(id[:], beat[:]) < 0 {
			return tx, id
		}
	}
	log.Fatal("could not grind a lower-txid TRANSFER-labelled junk")
	return nil, [32]byte{}
}

// grindForgedOpening builds a base-class opening RECEIVE carrying `attacker`'s key over `victimID`,
// grinding its receivable_id (folded into the txid) + signing with the attacker's own key until the
// txid beats `beat`. That lower txid would win the opening conflict slot under lowest-txid-wins.
func grindForgedOpening(attacker *simkit.Account, victimID [32]byte, beat [32]byte) (*pb.Tx, [32]byte) {
	for i := 0; i < 100000; i++ {
		var rid [32]byte
		rid[0], rid[1], rid[2], rid[3] = byte(i), byte(i>>8), byte(i>>16), byte(i>>24)
		tx := simkit.BuildOpeningReceive(attacker, rid, nil, 0) // class + key = attacker's
		tx.Account = &pb.AccountId{V: append([]byte(nil), victimID[:]...)}
		attacker.MustSign(tx) // a valid self-signature over the victim's id — the forge
		id, err := crypto.TxID(tx)
		if err != nil {
			log.Fatalf("forged txid: %v", err)
		}
		if bytes.Compare(id[:], beat[:]) < 0 {
			return tx, id
		}
	}
	log.Fatal("could not grind a lower-txid forged opening (astronomically unlikely)")
	return nil, [32]byte{}
}

// rejectAtGate submits tx and fails unless every node rejected it (the gate is deterministic, so a
// never-finalizable shape is refused by all 3 → Client.Submit returns an error).
func rejectAtGate(c *simkit.Client, tx *pb.Tx, what string) {
	if err := c.Submit(tx); err == nil {
		log.Fatalf("FAIL: %s was accepted — the opening gate is not enforced", what)
	} else {
		log.Printf("OK: %s rejected at the gate: %v", what, err)
	}
}

// --- flow helpers (mirroring the other sims) ---

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
