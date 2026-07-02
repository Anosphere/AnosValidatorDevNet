package core

// P7.1 opening-DoS gate (bestEffortOpeningCheck). These tests pin the submit/gossip-time gate that
// closes the grindable, zero-cost stall where a junk SEND/RECEIVE on a not-yet-created account grabs
// that account's opening conflict slot (sha256(account||prev||seq) with prev=0, seq=1) so the real
// opening can never be proposed. The gate is best-effort (ApplyTx untouched → resync-safe); it rejects
// ONLY a provably-never-finalizable shape at the exact opening slot on a GENUINELY-ABSENT account and
// defers everything else. The house triad every gate test pins: legit → nil; provably-never-
// finalizable → error; not-at-position (present account / wrong seq / wrong prev) → nil (defer).
//
// The one legitimate "an account chain begins with a SEND" case is the Fund + genesis distributor,
// both seeded at genesis (always present, first real block seq>=2) — the present-account and seq==1
// guards exclude them twice over, so they can never reach the reject arm. (End-to-end live + resync
// determinism is exercised by sim-opening-dos + the live harness.)

import (
	"bytes"
	"testing"

	"anos/internal/crypto"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

// zeroPrev is the canonical opening-slot predecessor (a 32-byte zero hash).
func zeroPrev() *pb.Hash32 { return &pb.Hash32{V: make([]byte, 32)} }

// forgeBaseOpeningOverID builds a base-class opening RECEIVE carrying `signer`'s auth pubkey but
// pointing at `victimID` — the core forge (an attacker self-signs a RECEIVE with its OWN key over a
// victim's account id). The carried key does not derive to victimID, so the gate must reject it.
func forgeBaseOpeningOverID(signer *simkit.Account, victimID [32]byte, rid [32]byte) *pb.Tx {
	tx := simkit.BuildOpeningReceive(signer, rid, nil, 0) // class = signer.Class, auth_pubkey = signer key
	tx.Account = &pb.AccountId{V: append([]byte(nil), victimID[:]...)}
	return tx
}

func TestBestEffortOpeningGate(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t), newTValidator(t), newTValidator(t)})
	var rid [32]byte
	rid[0] = 0x77

	// --- LEGIT openings defer (nil) ---

	// (1) A well-formed base opening RECEIVE (carried key derives to the account id) — the holder's
	// own account. The gate must NOT reject it.
	holder := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	legit := simkit.BuildOpeningReceive(holder, rid, nil, 0)
	if err := e.bestEffortOpeningCheck(legit); err != nil {
		t.Fatalf("legit base opening rejected at the gate: %v", err)
	}

	// (2) A TRANSFER-chain opening RECEIVE defers — its id derives from the funding receivable + key
	// source, which may be unsynced here (ambiguous → defer, like the breakglass opening gate).
	src := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, [32]byte{0x11}, [32]byte{0x12})
	chain := simkit.DerivedTransferAccount(src, 6)
	var dest [32]byte
	dest[0] = 0xd0
	xfer := simkit.BuildOpeningReceive(chain, rid, &dest, 100)
	if err := e.bestEffortOpeningCheck(xfer); err != nil {
		t.Fatalf("TRANSFER opening must defer (nil): %v", err)
	}

	// --- PROVABLY-NEVER-FINALIZABLE shapes at the opening slot → reject ---

	// (3) The core forge: an opening RECEIVE with an ATTACKER key over a VICTIM's id.
	victim := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	attacker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x21}, [32]byte{0x22})
	forged := forgeBaseOpeningOverID(attacker, victim.ID, rid)
	if err := e.bestEffortOpeningCheck(forged); err == nil {
		t.Fatal("forged base opening (attacker key over victim id) must be rejected")
	}

	// (4) A bare junk SEND at the opening slot on an absent account (no SEND is a valid first block).
	absent := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	junkSend := simkit.BuildSend(absent, [32]byte{}, 1, dest, 1000, ExpectedFee(1000))
	if err := e.bestEffortOpeningCheck(junkSend); err == nil {
		t.Fatal("a SEND at the opening slot on an absent account must be rejected")
	}

	// (5) A junk SEND carrying a HybridMultiSig at the opening slot — Option B: rejected regardless of
	// the multisig, because a SEND can never be a first block and no legit keyless/multisig SEND is
	// ever at seq=1 on an absent account (Fund/escrow/release are all seq>=2 on existing accounts).
	msSend := simkit.BuildSend(absent, [32]byte{}, 1, dest, 1000, ExpectedFee(1000))
	msSend.MultiSig = &pb.HybridMultiSig{Entries: []*pb.HybridSigEntry{{
		SignerId: &pb.AccountId{V: make([]byte, 32)},
		Sig:      &pb.HybridSig{V: []byte{0x01}},
	}}}
	if err := e.bestEffortOpeningCheck(msSend); err == nil {
		t.Fatal("a multisig-carrying SEND at the opening slot on an absent account must be rejected (Option B)")
	}

	// (6) An opening RECEIVE declaring class FUND (a keyless singleton never opened by RECEIVE).
	fundOpen := forgeBaseOpeningOverID(attacker, victim.ID, rid)
	fundOpen.GetReceive().AccountClass = pb.AccountClass_ACCOUNT_CLASS_FUND
	if err := e.bestEffortOpeningCheck(fundOpen); err == nil {
		t.Fatal("an opening RECEIVE declaring class FUND must be rejected")
	}

	// (7) An opening RECEIVE with UNSPECIFIED class (validate requires a concrete class).
	unspecOpen := forgeBaseOpeningOverID(attacker, victim.ID, rid)
	unspecOpen.GetReceive().AccountClass = pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED
	if err := e.bestEffortOpeningCheck(unspecOpen); err == nil {
		t.Fatal("an opening RECEIVE with UNSPECIFIED class must be rejected")
	}

	// (8) A base opening RECEIVE with NO auth_pubkey — this shape is deferred (no sig check) by
	// resolveAuthPubKeyDB today, so the gate must reject it (can't derive; validate requires 2625 B).
	noKey := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: &pb.AccountId{V: victim.IDBytes()},
		Prev:    zeroPrev(),
		Seq:     1,
		Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
			ReceivableId: &pb.Hash32{V: rid[:]},
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
		}},
	}
	if err := e.bestEffortOpeningCheck(noKey); err == nil {
		t.Fatal("a base opening RECEIVE with no auth_pubkey must be rejected")
	}

	// (9) A non-SEND/non-RECEIVE (UNSPECIFIED) tx at the opening slot: its conflict key ignores
	// tx.Type, so it must be rejected too (only an opening RECEIVE can create an account).
	junkType := simkit.BuildSend(absent, [32]byte{}, 1, dest, 1000, ExpectedFee(1000))
	junkType.Type = pb.TxType_TX_TYPE_UNSPECIFIED
	if err := e.bestEffortOpeningCheck(junkType); err == nil {
		t.Fatal("an UNSPECIFIED-typed tx at the opening slot on an absent account must be rejected")
	}

	// --- NOT-AT-POSITION / owned-elsewhere → defer (nil) ---

	// (10) Existing account at the opening slot: even a forged RECEIVE defers — the account is present,
	// so it's not an opening, and the cached-key sig check upstream already covers it.
	seedSpendingKeyed(t, e.cfg.DB, victim, [32]byte{0xab}, 1_000_000, 3)
	forgedPresent := forgeBaseOpeningOverID(attacker, victim.ID, rid)
	if err := e.bestEffortOpeningCheck(forgedPresent); err != nil {
		t.Fatalf("a forged opening on a PRESENT account must defer (nil): %v", err)
	}

	// (11) The Fund is seeded (always present): a seq=1/prev=0 tx on the Fund id must defer.
	fundSend := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: append([]byte(nil), e.cfg.FundAccount[:]...)},
		Prev:    zeroPrev(),
		Seq:     1,
		Body:    &pb.Tx_Send{Send: &pb.TxBodySend{To: &pb.AccountId{V: dest[:]}, AccountClass: pb.AccountClass_ACCOUNT_CLASS_FUND}},
	}
	if err := e.bestEffortOpeningCheck(fundSend); err != nil {
		t.Fatalf("a tx at the opening slot on the seeded Fund must defer (nil): %v", err)
	}

	// (12) Wrong seq (>=2): the gate defers immediately (a legit keyless/multisig SEND lives here).
	seq2 := simkit.BuildSend(absent, [32]byte{0xcd}, 2, dest, 1000, ExpectedFee(1000))
	if err := e.bestEffortOpeningCheck(seq2); err != nil {
		t.Fatalf("a seq>=2 tx must defer (nil): %v", err)
	}

	// (13) seq=1 with a NON-zero prev: not the opening slot (different conflict key) → defer.
	nonZeroPrev := forgeBaseOpeningOverID(attacker, victim.ID, rid)
	nonZeroPrev.Account = &pb.AccountId{V: absent.IDBytes()} // absent account, forged key
	nonZeroPrev.Prev = &pb.Hash32{V: bytes.Repeat([]byte{0x01}, 32)}
	if err := e.bestEffortOpeningCheck(nonZeroPrev); err != nil {
		t.Fatalf("a seq=1 tx with a non-zero prev must defer (nil): %v", err)
	}

	// (14) A reveal on a base-class forge does NOT grant a bypass: the derivation still mismatches, so
	// it is rejected (attaching a reveal must not evade judgeAbsentOpening). Target the still-absent
	// account (victim was seeded above in case 10, so it would take the present-account defer path).
	revealForge := forgeBaseOpeningOverID(attacker, absent.ID, rid)
	revealForge.RevealedBreakglassPubkey = &pb.HybridPubKey{V: attacker.BreakglassPubBytes()}
	if err := e.bestEffortOpeningCheck(revealForge); err == nil {
		t.Fatal("a reveal-carrying base-class forge over an absent id must still be rejected")
	}

	// (15) A reveal-carrying SEND at the opening slot is rejected — no SEND is a valid first block, and
	// attaching a reveal must not be a one-field bypass of the SEND-reject arm (review finding).
	revealSend := simkit.BuildSend(absent, [32]byte{}, 1, victim.ID, 1000, ExpectedFee(1000))
	revealSend.RevealedBreakglassPubkey = &pb.HybridPubKey{V: attacker.BreakglassPubBytes()}
	if err := e.bestEffortOpeningCheck(revealSend); err == nil {
		t.Fatal("a reveal-carrying SEND at the opening slot must be rejected")
	}

	// (16) A TRANSFER-class opening defers even with a reveal (legit breakglass/return-stake openings are
	// TRANSFER; the derivation needs unsynced state — the residual is closed by validity-aware proposal).
	revealXfer := simkit.BuildOpeningReceive(chain, rid, &dest, 100) // class TRANSFER
	revealXfer.RevealedBreakglassPubkey = &pb.HybridPubKey{V: attacker.BreakglassPubBytes()}
	if err := e.bestEffortOpeningCheck(revealXfer); err != nil {
		t.Fatalf("a TRANSFER opening (even with a reveal) must defer (nil): %v", err)
	}

	// (17) An unknown enum class value over an absent id (attacker key) is rejected — validate derives an
	// unknown class as BaseAccountID(0, ap), so the gate must too (review finding: one-byte relabel).
	unknownForge := forgeBaseOpeningOverID(attacker, absent.ID, rid)
	unknownForge.GetReceive().AccountClass = pb.AccountClass(99)
	if err := e.bestEffortOpeningCheck(unknownForge); err == nil {
		t.Fatal("an unknown-class forge over an absent id must be rejected")
	}
}

// TestOpeningGateTxidGrindLosesToGate is the capstone: it proves (a) the DoS is real — a forged junk
// opening can be ground to a LOWER txid than the legit opening (lowest-txid-wins would hand it the
// conflict slot), and (b) the gate rejects that exact ground variant while deferring the legit
// opening. No prior test grinds txids to force conflict-slot ordering; this is the new pattern.
func TestOpeningGateTxidGrindLosesToGate(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t), newTValidator(t), newTValidator(t)})

	victim := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	attacker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x31}, [32]byte{0x32})

	var legitRID [32]byte
	legitRID[0] = 0xa1
	legit := simkit.BuildOpeningReceive(victim, legitRID, nil, 0)
	victim.MustSign(legit) // a RECEIVE txid folds Tx.sig
	legitID, err := crypto.TxID(legit)
	if err != nil {
		t.Fatalf("legit txid: %v", err)
	}

	// Grind the forged junk's receivable_id (a free field folded into the txid) until it beats the
	// legit opening's txid. The attacker signs each candidate with its OWN key (a valid self-signature
	// over the victim's id — exactly the forge); crypto.TxID over ~uniform digests → a hit in a few tries.
	var junk *pb.Tx
	var junkID [32]byte
	found := false
	for i := 0; i < 100000; i++ {
		var rid [32]byte
		rid[0], rid[1], rid[2], rid[3] = byte(i), byte(i>>8), byte(i>>16), byte(i>>24)
		cand := forgeBaseOpeningOverID(attacker, victim.ID, rid)
		attacker.MustSign(cand)
		id, err := crypto.TxID(cand)
		if err != nil {
			t.Fatalf("cand txid: %v", err)
		}
		if bytes.Compare(id[:], legitID[:]) < 0 {
			junk, junkID, found = cand, id, true
			break
		}
	}
	if !found {
		t.Fatal("could not grind a lower-txid junk opening (astronomically unlikely — investigate)")
	}

	// The DoS is real: the ground junk shares the victim's opening conflict slot and has the lower
	// txid, so without the gate it would become the approved candidate and stall the real opening.
	if !bytes.Equal(conflictSlotFor(t, junk), conflictSlotFor(t, legit)) {
		t.Fatal("junk and legit must share the opening conflict slot")
	}
	if bytes.Compare(junkID[:], legitID[:]) >= 0 {
		t.Fatal("ground junk must have the lower txid")
	}

	// The gate rejects the ground junk and defers the legit opening.
	if err := e.bestEffortOpeningCheck(junk); err == nil {
		t.Fatal("the ground junk opening must be rejected at the gate")
	}
	if err := e.bestEffortOpeningCheck(legit); err != nil {
		t.Fatalf("the legit opening must defer (nil): %v", err)
	}
}

// conflictSlotFor computes the conflict-slot key the engine uses (sha256(account||prev||seq)) so the
// grind test can assert junk and legit collide. Mirrors conflictKeyHash.
func conflictSlotFor(t *testing.T, tx *pb.Tx) []byte {
	t.Helper()
	key, ok := conflictKeyHash(tx)
	if !ok {
		t.Fatal("conflictKeyHash produced no key")
	}
	return append([]byte(nil), key[:]...)
}

// TestBuildCandidateListProposesLowestValid is the CORE P7.1 fix: when an opening slot holds a
// ground-LOW invalid junk block AND the real (higher-txid) valid opening, buildCandidateList must
// propose the VALID one — not the blindly-lowest junk. This closes the class-relabel bypass of the
// stateless front-door gate (the attacker labels junk TRANSFER/ESCROW to defer past the gate; the
// validity-aware proposal skips it regardless of label). Without the fix, the junk (lower txid) would
// be the sole proposal, fail epoch-close validate, and starve the victim's opening indefinitely.
func TestBuildCandidateListProposesLowestValid(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t), newTValidator(t), newTValidator(t)})

	victim := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	attacker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x41}, [32]byte{0x42})

	var rid, dest [32]byte
	rid[0], dest[0] = 0xb1, 0xd0

	// The victim's real, VALID opening for V.
	legit := simkit.BuildOpeningReceive(victim, rid, nil, 0)
	victim.MustSign(legit)
	legitID, err := crypto.TxID(legit)
	if err != nil {
		t.Fatalf("legit txid: %v", err)
	}
	legitRaw, err := CanonicalTxBytes(legit)
	if err != nil {
		t.Fatalf("legit bytes: %v", err)
	}

	// Grind a junk opening over V's id, RELABELLED TRANSFER (the class the front-door gate must defer),
	// to a LOWER txid than legit. It is invalid (its receivable is absent → ErrUnknownRecv).
	var junk *pb.Tx
	var junkID [32]byte
	found := false
	for i := 0; i < 100000; i++ {
		var jrid [32]byte
		jrid[0], jrid[1], jrid[2], jrid[3] = byte(i), byte(i>>8), byte(i>>16), byte(i>>24)
		cand := forgeBaseOpeningOverID(attacker, victim.ID, jrid)
		r := cand.GetReceive()
		r.AccountClass = pb.AccountClass_ACCOUNT_CLASS_TRANSFER // the relabel bypass
		r.TransferDestination = &pb.AccountId{V: append([]byte(nil), dest[:]...)}
		r.TransferUnlockEpoch = 100
		attacker.MustSign(cand) // re-sign over the relabelled bytes
		id, terr := crypto.TxID(cand)
		if terr != nil {
			t.Fatalf("cand txid: %v", terr)
		}
		if bytes.Compare(id[:], legitID[:]) < 0 {
			junk, junkID, found = cand, id, true
			break
		}
	}
	if !found {
		t.Fatal("could not grind a lower-txid junk opening")
	}
	junkRaw, err := CanonicalTxBytes(junk)
	if err != nil {
		t.Fatalf("junk bytes: %v", err)
	}

	// A snapshot in which legit VALIDATES (V absent, its unrestricted receivable present) and junk does
	// NOT (its receivable is absent). Assert the precondition so the test can't pass vacuously.
	snap := &Snapshot{
		Accounts: map[[32]byte]AccountSnap{},
		Receivables: map[[32]byte]ReceivableSnap{
			rid: {From: victim.ID, To: victim.ID, Amount: 100, RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED},
		},
		Epoch:       10,
		FundAccount: e.cfg.FundAccount,
	}
	if _, verr := ValidateTxAgainstSnapshot(legit, snap); verr != nil {
		t.Fatalf("precondition: legit opening must validate: %v", verr)
	}
	if _, verr := ValidateTxAgainstSnapshot(junk, snap); verr == nil {
		t.Fatal("precondition: relabelled junk must be invalid")
	}

	// Both contest the SAME opening slot; junk has the lower txid.
	slot, ok := conflictKeyHash(legit)
	if !ok {
		t.Fatal("no conflict key")
	}
	e.mu.Lock()
	e.conflictPool = map[[32]byte][][32]byte{slot: {legitID, junkID}}
	e.txPool = map[[32]byte][]byte{legitID: legitRaw, junkID: junkRaw}
	e.mu.Unlock()

	_, ids := e.buildCandidateList(10, snap)

	hasLegit, hasJunk := false, false
	for _, id := range ids {
		if id == legitID {
			hasLegit = true
		}
		if id == junkID {
			hasJunk = true
		}
	}
	if !hasLegit {
		t.Fatal("buildCandidateList must propose the VALID opening (validity-aware proposal)")
	}
	if hasJunk {
		t.Fatal("buildCandidateList must NOT propose the ground-low INVALID junk")
	}
}
