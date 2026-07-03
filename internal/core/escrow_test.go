package core

// P3.3 ESCROW + attested-escrow (spec-18 §5.6, spec-19 §6.3, keys-spec §6.2).
//
// These tests pin escrow governance at the ValidateTxAgainstSnapshot level (the consensus
// authority) and the ApplyTx level (the no-revalidation resync path):
//   - the funder-signed opening RECEIVE: id derivation, canonical party order, funder anchor,
//     trigger-delay floor, attested-fee headroom, restricted-source routing, single-funding;
//   - the keyless 2-of-2 full-balance outflow (any destination) and the 1-of-2 → Fund attestation
//     trigger (attested escrows only, at/after the delay; a plain-escrow 1-of-2 → Fund is rejected);
//   - the apply path: ESCROW_META round-trips, the attested fee is deducted to the Fund, the drain
//     empties the escrow, and a to==Fund trigger credits the Fund;
//   - the keyless escrow-outflow txid binds the exact signer set (and is byte-identical to the
//     no-Tx.sig form), closing the multisig-swap fork the same way the Fund-SEND / release txids do.

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// --- test escrow party identity (hybrid keypair + breakglass commitment + SPENDING id) ---

type tParty struct {
	priv   *crypto.HybridPrivateKey
	pub    *crypto.HybridPubKey
	commit [64]byte
	id     [32]byte // SPENDING account-id (used when this party is the funder / funding source)
}

func newParty(seed byte) *tParty {
	priv, pub := crypto.GenerateHybridKeyFromSeed([32]byte{seed, 0xe5})
	_, bgPub := crypto.GenerateHybridKeyFromSeed([32]byte{seed, 0xb6})
	tb := crypto.AccountTypeByteForClass(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	return &tParty{
		priv:   priv,
		pub:    pub,
		commit: crypto.BreakglassCommitment(bgPub.Encode()),
		id:     crypto.BaseAccountID(tb, pub.Encode()),
	}
}

// canonicalParties sorts two parties into (lo, hi) by HybridPubKey bytes — the same order
// crypto.EscrowKeyblob / ESCROW_META use.
func canonicalParties(a, b *tParty) (lo, hi *tParty) {
	if bytes.Compare(a.pub.Encode(), b.pub.Encode()) <= 0 {
		return a, b
	}
	return b, a
}

func escrowIDFor(lo, hi *tParty, funderID [32]byte, fromSeq uint64) [32]byte {
	return crypto.DerivedAccountID(crypto.AccountTypeEscrow,
		crypto.EscrowKeyblob(lo.pub.Encode(), hi.pub.Encode()), funderID, fromSeq)
}

// buildEscrowOpening builds a funder-signed opening RECEIVE. lo/hi are passed in the given order
// (so a test can deliberately submit a non-canonical order); attested toggles the flag.
func buildEscrowOpening(escID, rid [32]byte, funder, lo, hi *tParty, trigger uint64, attested bool) *pb.Tx {
	tx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: &pb.AccountId{V: append([]byte(nil), escID[:]...)},
		Prev:    &pb.Hash32{V: make([]byte, 32)},
		Seq:     1,
		Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
			ReceivableId: &pb.Hash32{V: append([]byte(nil), rid[:]...)},
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_ESCROW,
			AuthPubkey:   &pb.HybridPubKey{V: funder.pub.Encode()},
			EscrowOpen: &pb.EscrowOpen{
				PartyLoPubkey:           &pb.HybridPubKey{V: lo.pub.Encode()},
				PartyLoBreakglassCommit: &pb.Hash64{V: lo.commit[:]},
				PartyHiPubkey:           &pb.HybridPubKey{V: hi.pub.Encode()},
				PartyHiBreakglassCommit: &pb.Hash64{V: hi.commit[:]},
				AttestationTriggerEpoch: trigger,
				Attested:                attested,
			},
		}},
	}
	if err := crypto.SignTxHybrid(tx, funder.priv); err != nil {
		panic(err)
	}
	return tx
}

func buildEscrowOutflow(escID, prevHead [32]byte, seq uint64, to [32]byte, amount uint64) *pb.Tx {
	return &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: append([]byte(nil), escID[:]...)},
		Prev:    &pb.Hash32{V: append([]byte(nil), prevHead[:]...)},
		Seq:     seq,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: append([]byte(nil), to[:]...)},
			Amount:       amount,
			Fee:          0,
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_ESCROW,
		}},
	}
}

func attachEscrowMultiSig(t *testing.T, tx *pb.Tx, signers ...*tParty) {
	t.Helper()
	m, _, err := crypto.MsgHash(tx)
	if err != nil {
		t.Fatalf("msghash: %v", err)
	}
	ms := &pb.HybridMultiSig{}
	for _, p := range signers {
		sig, err := p.priv.Sign(m)
		if err != nil {
			t.Fatalf("party sign: %v", err)
		}
		ms.Entries = append(ms.Entries, &pb.HybridSigEntry{
			SignerId: &pb.AccountId{V: append([]byte(nil), p.id[:]...)},
			Sig:      &pb.HybridSig{V: sig.Encode()},
		})
	}
	tx.MultiSig = ms
}

// --- opening fixture ---

type escrowOpenFixture struct {
	snap                *Snapshot
	funder, other       *tParty
	lo, hi              *tParty
	escID, rid          [32]byte
	fromSeq, fundAmount uint64
}

const (
	escrowEpoch   = uint64(10)
	escrowDelay   = uint64(6)
	escrowTrigger = escrowEpoch + escrowDelay // minimal valid trigger
	escrowFromSeq = uint64(4)
)

func newEscrowOpenFixture(t *testing.T, fundAmount uint64) *escrowOpenFixture {
	t.Helper()
	funder, other := newParty(0x11), newParty(0x22)
	lo, hi := canonicalParties(funder, other)
	escID := escrowIDFor(lo, hi, funder.id, escrowFromSeq)
	var rid [32]byte
	rid[0], rid[1] = 0x42, 0x99
	snap := &Snapshot{Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			funder.id: {Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: funder.pub.Encode()},
		},
		Receivables: map[[32]byte]ReceivableSnap{
			rid: {From: funder.id, To: escID, Amount: fundAmount, FromSeq: escrowFromSeq,
				RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED},
		},
		Epoch:                        escrowEpoch,
		EscrowAttestationDelayEpochs: escrowDelay,
		FundAccount:                  testFund,
	}
	return &escrowOpenFixture{snap: snap, funder: funder, other: other, lo: lo, hi: hi,
		escID: escID, rid: rid, fromSeq: escrowFromSeq, fundAmount: fundAmount}
}

func TestEscrowOpeningValidate(t *testing.T) {
	t.Run("accept plain opening", func(t *testing.T) {
		f := newEscrowOpenFixture(t, anosUnits(5))
		tx := buildEscrowOpening(f.escID, f.rid, f.funder, f.lo, f.hi, escrowTrigger, false)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("valid plain escrow opening rejected: %v", err)
		}
	})

	t.Run("accept attested opening (amount > fee)", func(t *testing.T) {
		f := newEscrowOpenFixture(t, AttestedEscrowFee+1)
		tx := buildEscrowOpening(f.escID, f.rid, f.funder, f.lo, f.hi, escrowTrigger, true)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("valid attested escrow opening rejected: %v", err)
		}
	})

	t.Run("reject attested funding <= fee", func(t *testing.T) {
		f := newEscrowOpenFixture(t, AttestedEscrowFee) // exactly the fee → no positive balance
		tx := buildEscrowOpening(f.escID, f.rid, f.funder, f.lo, f.hi, escrowTrigger, true)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("attested opening with amount == fee accepted")
		}
	})

	t.Run("reject non-canonical party order", func(t *testing.T) {
		f := newEscrowOpenFixture(t, anosUnits(5))
		// Submit hi/lo swapped: party_lo > party_hi → rejected.
		tx := buildEscrowOpening(f.escID, f.rid, f.funder, f.hi, f.lo, escrowTrigger, false)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("non-canonical (lo > hi) party order accepted")
		}
	})

	t.Run("reject funder not a party", func(t *testing.T) {
		f := newEscrowOpenFixture(t, anosUnits(5))
		stranger := newParty(0x33)
		// Funder signs but is neither party; the id is still over lo/hi so it can match acct, but the
		// funder-is-a-party check must reject. Register the stranger as the funding source so the sig +
		// source-key checks pass and we isolate the "funder must be a party" failure.
		f.snap.Accounts[stranger.id] = AccountSnap{Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: stranger.pub.Encode()}
		// Re-derive escID with the stranger as creator so the id check itself passes (isolating the
		// funder-must-be-a-party failure).
		escID := escrowIDFor(f.lo, f.hi, stranger.id, f.fromSeq)
		f.snap.Receivables[f.rid] = ReceivableSnap{From: stranger.id, To: escID, Amount: f.fundAmount, FromSeq: f.fromSeq}
		tx := buildEscrowOpening(escID, f.rid, stranger, f.lo, f.hi, escrowTrigger, false)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("opening whose funder is neither party accepted")
		}
	})

	t.Run("reject funder not the funding source", func(t *testing.T) {
		f := newEscrowOpenFixture(t, anosUnits(5))
		// The funder (a party) signs, but the receivable's source is `other` (the counterparty), not
		// the signer. The escrow id is creator-bound to `other`, so make it match; the funder-anchor
		// (signer must equal the source's key) must still reject.
		f.snap.Accounts[f.other.id] = AccountSnap{Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: f.other.pub.Encode()}
		escID := escrowIDFor(f.lo, f.hi, f.other.id, f.fromSeq)
		f.snap.Receivables[f.rid] = ReceivableSnap{From: f.other.id, To: escID, Amount: f.fundAmount, FromSeq: f.fromSeq}
		tx := buildEscrowOpening(escID, f.rid, f.funder, f.lo, f.hi, escrowTrigger, false)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("opening signed by a party who is not the funding source accepted")
		}
	})

	t.Run("reject wrong id (nonce mismatch)", func(t *testing.T) {
		f := newEscrowOpenFixture(t, anosUnits(5))
		wrong := escrowIDFor(f.lo, f.hi, f.funder.id, f.fromSeq+1) // different nonce → different id
		f.snap.Receivables[f.rid] = ReceivableSnap{From: f.funder.id, To: wrong, Amount: f.fundAmount, FromSeq: f.fromSeq}
		tx := buildEscrowOpening(wrong, f.rid, f.funder, f.lo, f.hi, escrowTrigger, false)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("opening whose account-id does not derive from (keyblob, funder, nonce) accepted")
		}
	})

	t.Run("reject trigger before delay", func(t *testing.T) {
		f := newEscrowOpenFixture(t, anosUnits(5))
		tx := buildEscrowOpening(f.escID, f.rid, f.funder, f.lo, f.hi, escrowTrigger-1, false)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("opening with trigger < creation + delay accepted")
		}
	})

	t.Run("reject restricted-class funding source", func(t *testing.T) {
		f := newEscrowOpenFixture(t, anosUnits(5))
		// A TIMELOCKED source mints a TRANSFER-restricted receivable → cannot fund an escrow directly.
		f.snap.Accounts[f.funder.id] = AccountSnap{Class: pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, AuthPubKey: f.funder.pub.Encode()}
		f.snap.Receivables[f.rid] = ReceivableSnap{From: f.funder.id, To: f.escID, Amount: f.fundAmount,
			FromSeq: f.fromSeq, RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER}
		tx := buildEscrowOpening(f.escID, f.rid, f.funder, f.lo, f.hi, escrowTrigger, false)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("restricted-class source funding an escrow directly accepted")
		}
	})

	t.Run("reject unparseable counterparty pubkey", func(t *testing.T) {
		// Review finding #1: a length-valid but cryptographically-unparseable counterparty key must be
		// rejected (else the 2-of-2 slot can never be satisfied → a deadlocked escrow).
		f := newEscrowOpenFixture(t, anosUnits(5))
		funder := newParty(0x55) // a valid party (will be party_lo)
		garbage := bytes.Repeat([]byte{0xff}, crypto.HybridPubKeySize)
		// funder.pub < all-0xff, so funder is party_lo and `garbage` is party_hi (canonical order holds).
		var escID [32]byte
		escID[0] = 0xec
		f.snap.Accounts[funder.id] = AccountSnap{Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: funder.pub.Encode()}
		f.snap.Receivables[f.rid] = ReceivableSnap{From: funder.id, To: escID, Amount: anosUnits(5), FromSeq: f.fromSeq}
		tx := &pb.Tx{
			Type:    pb.TxType_TX_TYPE_RECEIVE,
			Account: &pb.AccountId{V: escID[:]},
			Prev:    &pb.Hash32{V: make([]byte, 32)},
			Seq:     1,
			Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
				ReceivableId: &pb.Hash32{V: f.rid[:]},
				AccountClass: pb.AccountClass_ACCOUNT_CLASS_ESCROW,
				AuthPubkey:   &pb.HybridPubKey{V: funder.pub.Encode()},
				EscrowOpen: &pb.EscrowOpen{
					PartyLoPubkey:           &pb.HybridPubKey{V: funder.pub.Encode()},
					PartyLoBreakglassCommit: &pb.Hash64{V: funder.commit[:]},
					PartyHiPubkey:           &pb.HybridPubKey{V: garbage},
					PartyHiBreakglassCommit: &pb.Hash64{V: make([]byte, breakglassCommitLen)},
					AttestationTriggerEpoch: escrowTrigger,
				},
			}},
		}
		if err := crypto.SignTxHybrid(tx, funder.priv); err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("escrow opening with an unparseable counterparty pubkey accepted")
		}
	})

	t.Run("reject opening carrying single-owner breakglass_commitment", func(t *testing.T) {
		f := newEscrowOpenFixture(t, anosUnits(5))
		tx := buildEscrowOpening(f.escID, f.rid, f.funder, f.lo, f.hi, escrowTrigger, false)
		tx.GetReceive().BreakglassCommitment = &pb.Hash64{V: f.funder.commit[:]}
		if err := crypto.SignTxHybrid(tx, f.funder.priv); err != nil { // re-sign over the mutated body
			t.Fatalf("re-sign: %v", err)
		}
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("escrow opening carrying the single-owner breakglass_commitment accepted")
		}
	})
}

// TestEscrowOpeningTxIDBindsEscrowOpen pins the consensus-critical malleability/fork closure: the
// opening txid (and the funder's signature) must bind ALL escrow_open fields. Two openings differing
// only in the attested flag, the trigger epoch, or a party's breakglass commitment must have
// DIFFERENT txids — otherwise a peer could flip those fields under one txid → divergent ESCROW_META.
func TestEscrowOpeningTxIDBindsEscrowOpen(t *testing.T) {
	f := newEscrowOpenFixture(t, anosUnits(5))
	base := buildEscrowOpening(f.escID, f.rid, f.funder, f.lo, f.hi, escrowTrigger, false)
	baseID, err := crypto.TxID(base)
	if err != nil {
		t.Fatalf("txid: %v", err)
	}

	// Flip the attested flag → different txid.
	att := buildEscrowOpening(f.escID, f.rid, f.funder, f.lo, f.hi, escrowTrigger, true)
	if id, _ := crypto.TxID(att); id == baseID {
		t.Error("opening txid must change when the attested flag flips")
	}
	// Change the trigger epoch → different txid.
	trig := buildEscrowOpening(f.escID, f.rid, f.funder, f.lo, f.hi, escrowTrigger+1, false)
	if id, _ := crypto.TxID(trig); id == baseID {
		t.Error("opening txid must change when the trigger epoch changes")
	}

	// Tampering escrow_open WITHOUT re-signing must break signature verification (the fields are in
	// the signed preimage). Flip attested on the signed `base` tx and re-validate.
	base.GetReceive().GetEscrowOpen().Attested = true
	if _, err := ValidateTxAgainstSnapshot(base, f.snap); err == nil {
		t.Error("tampering the attested flag without re-signing was accepted (escrow_open not in the preimage)")
	}
}

// --- outflow fixture ---

type escrowOutFixture struct {
	snap     *Snapshot
	lo, hi   *tParty
	escID    [32]byte
	head     [32]byte
	balance  uint64
	stranger *tParty // a keyed identity that is NEITHER party
}

func newEscrowOutFixture(t *testing.T, attested bool, trigger uint64) *escrowOutFixture {
	t.Helper()
	a, b := newParty(0x11), newParty(0x22)
	lo, hi := canonicalParties(a, b)
	stranger := newParty(0x44)
	var escID, head [32]byte
	escID[0], head[0] = 0xe0, 0x71
	const balance = uint64(777)
	var flags byte
	if attested {
		flags = escrowFlagAttested
	}
	snap := &Snapshot{Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			escID: {
				Head: head, Balance: balance, Seq: 1,
				Class:            pb.AccountClass_ACCOUNT_CLASS_ESCROW,
				EscrowPartyLoPub: lo.pub.Encode(),
				EscrowPartyHiPub: hi.pub.Encode(),
				EscrowTrigger:    trigger,
				EscrowFlags:      flags,
			},
		},
		Receivables: map[[32]byte]ReceivableSnap{},
		Epoch:       escrowEpoch,
		FundAccount: testFund,
	}
	return &escrowOutFixture{snap: snap, lo: lo, hi: hi, escID: escID, head: head, balance: balance, stranger: stranger}
}

// outflowTx builds a full-balance zero-fee escrow drain to `to` (no signatures yet).
func (f *escrowOutFixture) outflowTx(to [32]byte) *pb.Tx {
	return buildEscrowOutflow(f.escID, f.head, 2, to, f.balance)
}

func TestEscrowOutflow2of2(t *testing.T) {
	var dest [32]byte
	dest[0] = 0xd1

	t.Run("accept 2-of-2 to any destination", func(t *testing.T) {
		f := newEscrowOutFixture(t, false, 0)
		tx := f.outflowTx(dest)
		attachEscrowMultiSig(t, tx, f.lo, f.hi)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("valid 2-of-2 escrow outflow rejected: %v", err)
		}
	})

	t.Run("2-of-2 order-independent + extra non-party ignored", func(t *testing.T) {
		f := newEscrowOutFixture(t, false, 0)
		tx := f.outflowTx(dest)
		attachEscrowMultiSig(t, tx, f.hi, f.stranger, f.lo) // both parties present, plus a stranger
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("2-of-2 with a stranger entry rejected: %v", err)
		}
	})

	t.Run("reject single party (plain escrow)", func(t *testing.T) {
		f := newEscrowOutFixture(t, false, 0)
		tx := f.outflowTx(dest)
		attachEscrowMultiSig(t, tx, f.lo)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("1-of-2 escrow outflow accepted on a plain escrow")
		}
	})

	t.Run("reject stranger-only", func(t *testing.T) {
		f := newEscrowOutFixture(t, false, 0)
		tx := f.outflowTx(dest)
		attachEscrowMultiSig(t, tx, f.stranger, f.stranger)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("escrow outflow authorized only by a non-party accepted")
		}
	})

	t.Run("reject partial balance", func(t *testing.T) {
		f := newEscrowOutFixture(t, false, 0)
		tx := buildEscrowOutflow(f.escID, f.head, 2, dest, f.balance-1)
		attachEscrowMultiSig(t, tx, f.lo, f.hi)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("partial-balance escrow outflow accepted")
		}
	})

	t.Run("reject nonzero fee", func(t *testing.T) {
		f := newEscrowOutFixture(t, false, 0)
		tx := f.outflowTx(dest)
		tx.GetSend().Fee = 1
		attachEscrowMultiSig(t, tx, f.lo, f.hi)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("escrow outflow with a nonzero fee accepted")
		}
	})

	t.Run("reject Tx.sig on keyless outflow", func(t *testing.T) {
		f := newEscrowOutFixture(t, false, 0)
		tx := f.outflowTx(dest)
		attachEscrowMultiSig(t, tx, f.lo, f.hi)
		if err := crypto.SignTxHybrid(tx, f.lo.priv); err != nil { // smuggle in a Tx.sig
			t.Fatalf("sign: %v", err)
		}
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("keyless escrow outflow carrying a Tx.sig accepted")
		}
	})

	t.Run("reject stake-deposit fields on outflow to Fund", func(t *testing.T) {
		// Review finding #4: a to==Fund escrow outflow carrying staked_for would append a phantom stake
		// row to the keyless escrow id. Build a 2-of-2 → Fund with staked_for set → must be rejected.
		f := newEscrowOutFixture(t, false, 0)
		tx := f.outflowTx(f.snap.FundAccount)
		tx.GetSend().StakedFor = "banker"
		tx.GetSend().TimeDelay = pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_MONTH
		attachEscrowMultiSig(t, tx, f.lo, f.hi)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("escrow outflow carrying stake-deposit fields accepted")
		}
	})
}

func TestEscrowAttestationTrigger(t *testing.T) {
	const trigger = escrowEpoch // trigger epoch reached at the snapshot epoch

	t.Run("accept 1-of-2 to Fund after delay on attested escrow", func(t *testing.T) {
		f := newEscrowOutFixture(t, true, trigger)
		tx := f.outflowTx(f.snap.FundAccount)
		attachEscrowMultiSig(t, tx, f.lo) // a single party
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("attested 1-of-2 → Fund trigger rejected: %v", err)
		}
	})

	t.Run("reject 1-of-2 to Fund before trigger epoch", func(t *testing.T) {
		f := newEscrowOutFixture(t, true, escrowEpoch+1) // trigger in the future
		tx := f.outflowTx(f.snap.FundAccount)
		attachEscrowMultiSig(t, tx, f.lo)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("attested 1-of-2 → Fund trigger accepted before the trigger epoch")
		}
	})

	t.Run("reject 1-of-2 to Fund on a PLAIN escrow", func(t *testing.T) {
		f := newEscrowOutFixture(t, false, trigger) // plain escrow, trigger reached
		tx := f.outflowTx(f.snap.FundAccount)
		attachEscrowMultiSig(t, tx, f.lo)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("plain-escrow 1-of-2 → Fund accepted (only attested escrows have a trigger)")
		}
	})

	t.Run("reject 1-of-2 to a non-Fund destination", func(t *testing.T) {
		f := newEscrowOutFixture(t, true, trigger)
		var dest [32]byte
		dest[0] = 0xd1
		tx := f.outflowTx(dest)
		attachEscrowMultiSig(t, tx, f.lo)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("attested 1-of-2 to a non-Fund destination accepted")
		}
	})

	t.Run("accept 2-of-2 to Fund (always allowed)", func(t *testing.T) {
		f := newEscrowOutFixture(t, true, trigger)
		tx := f.outflowTx(f.snap.FundAccount)
		attachEscrowMultiSig(t, tx, f.lo, f.hi)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("2-of-2 escrow outflow to the Fund rejected: %v", err)
		}
	})
}

// TestEscrowOutflowTxIDBindsSigners pins the keyless escrow-outflow txid: SHA256(sign_bytes ||
// multisig_digest) (no Tx.sig folded — byte-identical to the keyless-Fund-SEND form) and it binds
// the EXACT signer set (order-independently). Without this, two outflows with the same body but
// different signer sets would share a txid → a multisig-swap fork.
func TestEscrowOutflowTxIDBindsSigners(t *testing.T) {
	f := newEscrowOutFixture(t, false, 0)
	var dest [32]byte
	dest[0] = 0xd1

	tx := f.outflowTx(dest)
	attachEscrowMultiSig(t, tx, f.lo, f.hi)
	id, err := crypto.TxID(tx)
	if err != nil {
		t.Fatalf("txid: %v", err)
	}

	sb, err := crypto.SignBytesACTE(tx)
	if err != nil {
		t.Fatalf("signbytes: %v", err)
	}
	dig, err := crypto.FundMultiSigDigest(tx.MultiSig)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	want := sha256.Sum256(append(append([]byte{}, sb...), dig...))
	if id != want {
		t.Error("keyless escrow-outflow txid != SHA256(sign_bytes || multisig_digest)")
	}

	// Reorder entries → same txid (canonical sort inside the digest).
	tx.MultiSig.Entries[0], tx.MultiSig.Entries[1] = tx.MultiSig.Entries[1], tx.MultiSig.Entries[0]
	if id2, _ := crypto.TxID(tx); id2 != id {
		t.Error("escrow-outflow txid must be independent of multisig entry order")
	}

	// Different signer set → different txid (binds the set).
	tx2 := f.outflowTx(dest)
	attachEscrowMultiSig(t, tx2, f.lo, f.stranger)
	if id2, _ := crypto.TxID(tx2); id2 == id {
		t.Error("escrow-outflow txid must change when the signer set changes")
	}
}

// --- apply path (resync determinism) ---

// TestEscrowApplyOpenAndDrain pins the ApplyTx escrow paths end-to-end against a real DB: an
// attested opening stores ESCROW_META, deducts the attested fee to the Fund, and credits the rest;
// a to==Fund trigger drain empties the escrow and credits the Fund the remaining balance.
func TestEscrowApplyOpenAndDrain(t *testing.T) {
	db := newFundTestDB(t)
	fund := testFund
	seedFundRecord(t, db, fund)

	funder, other := newParty(0x11), newParty(0x22)
	lo, hi := canonicalParties(funder, other)
	const fromSeq = uint64(4)
	const fundAmount = uint64(1_000_000) // 1 Anos; > AttestedEscrowFee
	escID := escrowIDFor(lo, hi, funder.id, fromSeq)
	var funderHead, rid [32]byte
	funderHead[0], rid[0] = 0x01, 0x42

	// Seed the funding source (keyed) and the funding receivable the opening claims.
	if err := db.Update(func(tx *bbolt.Tx) error {
		if err := putAccountRecord(tx, funder.id, AccountRecord{
			Head: funderHead, Balance: 5_000_000, Seq: fromSeq,
			Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: funder.pub.Encode(),
		}); err != nil {
			return err
		}
		rec := &pb.Receivable{
			Id: &pb.Hash32{V: rid[:]}, From: &pb.AccountId{V: funder.id[:]}, To: &pb.AccountId{V: escID[:]},
			Amount: fundAmount, FromSeq: fromSeq,
		}
		rr, _ := proto.Marshal(rec)
		return putReceivableRaw(tx, rid, rr)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Apply the attested opening RECEIVE.
	opening := buildEscrowOpening(escID, rid, funder, lo, hi, escrowTrigger, true)
	openRaw, _ := proto.Marshal(opening)
	openTxid := txidFor(escID, 1)
	if err := db.Update(func(tx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: tx}, openRaw, opening, openTxid, fund, testEcon)
	}); err != nil {
		t.Fatalf("ApplyTx opening: %v", err)
	}

	// ESCROW_META round-trips; balance = amount - attested fee; Fund credited the fee.
	var rec AccountRecord
	var fundBal uint64
	if err := db.View(func(tx *bbolt.Tx) error {
		r, ok := getAccountRecord(tx, escID)
		if !ok {
			t.Fatal("escrow record missing after opening")
		}
		rec = r
		fr, _ := getAccountRecord(tx, fund)
		fundBal = fr.Balance
		return nil
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
	if rec.Class != pb.AccountClass_ACCOUNT_CLASS_ESCROW {
		t.Fatalf("escrow class = %v", rec.Class)
	}
	if !bytes.Equal(rec.EscrowPartyLoPub, lo.pub.Encode()) || !bytes.Equal(rec.EscrowPartyHiPub, hi.pub.Encode()) {
		t.Error("ESCROW_META party pubkeys not stored in canonical order")
	}
	if !bytes.Equal(rec.EscrowPartyLoBG, lo.commit[:]) || !bytes.Equal(rec.EscrowPartyHiBG, hi.commit[:]) {
		t.Error("ESCROW_META breakglass commitments not stored")
	}
	if rec.EscrowTrigger != escrowTrigger || rec.EscrowFlags&escrowFlagAttested == 0 {
		t.Errorf("ESCROW_META trigger/flags wrong: trigger=%d flags=%d", rec.EscrowTrigger, rec.EscrowFlags)
	}
	if rec.AuthPubKey != nil || rec.BreakglassCommit != nil {
		t.Error("escrow record must not carry a single-owner AUTH_PUBKEY/BREAKGLASS_COMMIT")
	}
	if rec.Balance != fundAmount-AttestedEscrowFee {
		t.Errorf("escrow balance = %d, want %d", rec.Balance, fundAmount-AttestedEscrowFee)
	}
	if fundBal != AttestedEscrowFee {
		t.Errorf("Fund balance after attested opening = %d, want %d (the attested fee)", fundBal, AttestedEscrowFee)
	}

	// The packed record must round-trip byte-identically (resync rebuilds it from replay).
	if rt, ok := unpackAccountRecord(packAccountRecord(rec)); !ok || rt.EscrowTrigger != rec.EscrowTrigger ||
		!bytes.Equal(rt.EscrowPartyHiPub, rec.EscrowPartyHiPub) || rt.EscrowFlags != rec.EscrowFlags {
		t.Error("ESCROW_META does not round-trip through pack/unpack")
	}

	// Idempotent re-apply of the opening must not double-charge the Fund.
	if err := db.Update(func(tx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: tx}, openRaw, opening, openTxid, fund, testEcon)
	}); err != nil {
		t.Fatalf("re-apply opening: %v", err)
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		fr, _ := getAccountRecord(tx, fund)
		if fr.Balance != AttestedEscrowFee {
			t.Errorf("re-apply double-charged the Fund: balance = %d", fr.Balance)
		}
		return nil
	}); err != nil {
		t.Fatalf("read fund: %v", err)
	}

	// Apply a to==Fund trigger drain: escrow → 0, Fund += remaining balance.
	escBal := fundAmount - AttestedEscrowFee
	drain := buildEscrowOutflow(escID, openTxid, 2, fund, escBal)
	attachEscrowMultiSig(t, drain, lo) // a single party (apply does not re-verify the quorum)
	drainRaw, _ := proto.Marshal(drain)
	drainTxid := txidFor(escID, 2)
	if err := db.Update(func(tx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: tx}, drainRaw, drain, drainTxid, fund, testEcon)
	}); err != nil {
		t.Fatalf("ApplyTx drain: %v", err)
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		er, _ := getAccountRecord(tx, escID)
		if er.Balance != 0 {
			t.Errorf("escrow balance after drain = %d, want 0", er.Balance)
		}
		fr, _ := getAccountRecord(tx, fund)
		if fr.Balance != AttestedEscrowFee+escBal {
			t.Errorf("Fund balance after trigger drain = %d, want %d", fr.Balance, AttestedEscrowFee+escBal)
		}
		return nil
	}); err != nil {
		t.Fatalf("read after drain: %v", err)
	}
}

// TestEscrowSingleFunding pins that an escrow accepts exactly one (opening) RECEIVE.
func TestEscrowSingleFunding(t *testing.T) {
	f := newEscrowOutFixture(t, false, 0)
	// A second RECEIVE on an existing escrow (class ESCROW in the snapshot) must be rejected.
	var rid2 [32]byte
	rid2[0] = 0x77
	f.snap.Receivables[rid2] = ReceivableSnap{From: f.stranger.id, To: f.escID, Amount: 5}
	tx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: &pb.AccountId{V: f.escID[:]},
		Prev:    &pb.Hash32{V: f.head[:]},
		Seq:     2,
		Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
			ReceivableId: &pb.Hash32{V: rid2[:]},
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_ESCROW,
		}},
	}
	// A second RECEIVE on an escrow must be rejected (single-funding is FIRM). Two independent gates
	// catch it: the keyless escrow has no cached auth pubkey, so signature resolution fails, and the
	// single-funding guard rejects a second RECEIVE on a TRANSFER/ESCROW account. Either is sufficient.
	if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
		t.Error("second RECEIVE on an escrow accepted (single-funding violated)")
	}
}
