package core

// forquinn phase 2 — guarded/vault second user key (U2) and the either-or spend rule.
//
// Pins the §2.6 validation matrix at the consensus authority (ValidateTxAgainstSnapshot) with the
// ApplyTx lockstep mirror (resync replays apply WITHOUT validate, so every structural rule must
// hold on both paths):
//   - GUARDED/VAULT opening: U2 required + PoP-verified (lengths, != U1, parseable, bound to the
//     account id); rejected on every other opening class and every non-opening RECEIVE; the U2
//     fold means a stripped/swapped block breaks the U1 signature.
//   - TRANSFER chains inherit U2 by DERIVED COPY in ApplyTx (D2 — never carried), and a release
//     verifies against the copied key straight off the snapshot.
//   - Release gate either-or: path (a) = Tx.sig under U1 AND sig2 under U2 (fixed roles, D5), no
//     multisig, no case fields; path (b) = one user sig (U1 OR U2, D4) + the attestor quorum.
//   - sig2 reject-everywhere-not-path-(a): normal/hop-1/Fund sends, cancels, non-gated releases,
//     and every RECEIVE (sig2 is txid-folded + third-party-attachable — the multisig grind class).
//   - The 24h guarded rate limit (§2.8): validate checks the finalized LastGuardedSendEpoch
//     against the snapshot epoch; ApplyTx stamps the finalization epoch.
//   - D1: a restricted-class (TIMELOCKED/GUARDED/VAULT) account cannot SEND directly to the Fund.
//
// The submit/gossip gates (judgeAbsentOpening, bestEffortReleaseCheck) are pinned with the house
// triad: legit → nil/defer, provably-never-finalizable → reject, ambiguous → defer.

import (
	"strings"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// --- raw-key U2 account fixture (full control over every field for the negative shapes) ---

type tU2Account struct {
	class  pb.AccountClass
	priv   *crypto.HybridPrivateKey
	pub    *crypto.HybridPubKey
	u2Priv *crypto.HybridPrivateKey
	u2Pub  *crypto.HybridPubKey
	id     [32]byte
	bg     []byte // 64-B breakglass commitment
}

func newTU2Account(class pb.AccountClass, seed byte) *tU2Account {
	priv, pub := crypto.GenerateHybridKeyFromSeed([32]byte{seed, 0x01})
	u2Priv, u2Pub := crypto.GenerateHybridKeyFromSeed([32]byte{seed, 0x02})
	_, bgPub := crypto.GenerateHybridKeyFromSeed([32]byte{seed, 0x03})
	commit := crypto.BreakglassCommitment(bgPub.Encode())
	return &tU2Account{
		class: class, priv: priv, pub: pub, u2Priv: u2Priv, u2Pub: u2Pub,
		id: crypto.BaseAccountID(crypto.AccountTypeByteForClass(class), pub.Encode()),
		bg: append([]byte(nil), commit[:]...),
	}
}

// popSigOver returns U2's proof-of-possession over m_u2 = U2RegistrationDigest(acct, u2Pub) —
// normally acct == a.id; a different acct builds the cross-account-replay negative.
func (a *tU2Account) popSigOver(t *testing.T, acct [32]byte) []byte {
	t.Helper()
	m, err := crypto.U2RegistrationDigest(acct, a.u2Pub.Encode())
	if err != nil {
		t.Fatalf("pop digest: %v", err)
	}
	sig, err := a.u2Priv.Sign(m)
	if err != nil {
		t.Fatalf("pop sign: %v", err)
	}
	return sig.Encode()
}

// opening builds the account-opening RECEIVE claiming rid (auth pubkey + bg commitment; a U2
// block when withU2), signed by U1. Mutate-and-resign via mut for the negative shapes.
func (a *tU2Account) opening(t *testing.T, rid [32]byte, withU2 bool, mut func(*pb.TxBodyReceive)) *pb.Tx {
	t.Helper()
	body := &pb.TxBodyReceive{
		ReceivableId:         &pb.Hash32{V: append([]byte(nil), rid[:]...)},
		AccountClass:         a.class,
		AuthPubkey:           &pb.HybridPubKey{V: a.pub.Encode()},
		BreakglassCommitment: &pb.Hash64{V: append([]byte(nil), a.bg...)},
	}
	if withU2 {
		body.U2 = &pb.U2Registration{
			Pubkey: &pb.HybridPubKey{V: a.u2Pub.Encode()},
			PopSig: &pb.HybridSig{V: a.popSigOver(t, a.id)},
		}
	}
	if mut != nil {
		mut(body)
	}
	tx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: &pb.AccountId{V: append([]byte(nil), a.id[:]...)},
		Prev:    &pb.Hash32{V: make([]byte, 32)},
		Seq:     1,
		Body:    &pb.Tx_Receive{Receive: body},
	}
	if err := crypto.SignTxHybrid(tx, a.priv); err != nil {
		t.Fatalf("sign opening: %v", err)
	}
	return tx
}

// openingSnap is a snapshot holding only the funding receivable for a's opening.
func openingSnap(a *tU2Account, rid [32]byte) *Snapshot {
	var funder [32]byte
	funder[0] = 0xfa
	return &Snapshot{Econ: testEcon,
		Accounts:    map[[32]byte]AccountSnap{},
		Receivables: map[[32]byte]ReceivableSnap{rid: {From: funder, To: a.id, Amount: 500, FromSeq: 1}},
		FundAccount: testFund,
	}
}

func wantErrContaining(t *testing.T, err error, frag, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted, want reject containing %q", what, frag)
	}
	if !strings.Contains(err.Error(), frag) {
		t.Fatalf("%s: rejected with %q, want the %q rule", what, err, frag)
	}
}

// --- opening matrix: validate ---

func TestU2OpeningValidate(t *testing.T) {
	var rid [32]byte
	rid[0] = 0x1d

	for _, class := range []pb.AccountClass{
		pb.AccountClass_ACCOUNT_CLASS_GUARDED, pb.AccountClass_ACCOUNT_CLASS_VAULT,
	} {
		t.Run("accept valid "+class.String(), func(t *testing.T) {
			a := newTU2Account(class, 0x10+byte(class))
			if _, err := ValidateTxAgainstSnapshot(a.opening(t, rid, true, nil), openingSnap(a, rid)); err != nil {
				t.Fatalf("valid %v opening with U2 rejected: %v", class, err)
			}
		})
	}

	t.Run("reject missing U2", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x20)
		_, err := ValidateTxAgainstSnapshot(a.opening(t, rid, false, nil), openingSnap(a, rid))
		wantErrContaining(t, err, "u2 pubkey must be present", "guarded opening without a U2")
	})

	t.Run("reject missing PoP", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x21)
		tx := a.opening(t, rid, true, func(b *pb.TxBodyReceive) { b.U2.PopSig = nil })
		_, err := ValidateTxAgainstSnapshot(tx, openingSnap(a, rid))
		wantErrContaining(t, err, "proof-of-possession must be present", "guarded opening without a PoP")
	})

	t.Run("reject wrong-key PoP", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x22)
		other := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x23)
		tx := a.opening(t, rid, true, func(b *pb.TxBodyReceive) {
			// PoP signed by a DIFFERENT U2 key over the right digest shape.
			m, _ := crypto.U2RegistrationDigest(a.id, a.u2Pub.Encode())
			sig, _ := other.u2Priv.Sign(m)
			b.U2.PopSig = &pb.HybridSig{V: sig.Encode()}
		})
		_, err := ValidateTxAgainstSnapshot(tx, openingSnap(a, rid))
		wantErrContaining(t, err, "proof-of-possession does not verify", "PoP by a key that does not hold U2")
	})

	t.Run("reject cross-account PoP replay", func(t *testing.T) {
		// A PoP over ANOTHER account id (D12 binds the id, so a captured PoP cannot be replayed
		// onto a different account's opening).
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x24)
		var otherID [32]byte
		otherID[0] = 0xee
		tx := a.opening(t, rid, true, func(b *pb.TxBodyReceive) {
			b.U2.PopSig = &pb.HybridSig{V: a.popSigOver(t, otherID)}
		})
		_, err := ValidateTxAgainstSnapshot(tx, openingSnap(a, rid))
		wantErrContaining(t, err, "proof-of-possession does not verify", "PoP bound to a different account id")
	})

	t.Run("reject u2 == u1", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x25)
		tx := a.opening(t, rid, true, func(b *pb.TxBodyReceive) {
			// U2 = the U1 auth pubkey, with a PoP signed by U1 over the right digest — every
			// check but the inequality would pass (D6: path (a) must be a real 2-key rule).
			m, _ := crypto.U2RegistrationDigest(a.id, a.pub.Encode())
			sig, _ := a.priv.Sign(m)
			b.U2 = &pb.U2Registration{
				Pubkey: &pb.HybridPubKey{V: a.pub.Encode()},
				PopSig: &pb.HybridSig{V: sig.Encode()},
			}
		})
		_, err := ValidateTxAgainstSnapshot(tx, openingSnap(a, rid))
		wantErrContaining(t, err, "must differ from the auth pubkey", "U2 equal to U1")
	})

	t.Run("reject unparseable U2", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x26)
		tx := a.opening(t, rid, true, func(b *pb.TxBodyReceive) {
			junk := make([]byte, crypto.HybridPubKeySize) // zero bytes: length-valid, not a key
			b.U2.Pubkey = &pb.HybridPubKey{V: junk}
		})
		if _, err := ValidateTxAgainstSnapshot(tx, openingSnap(a, rid)); err == nil {
			t.Fatal("length-valid but unparseable U2 accepted (would deadlock path (a))")
		}
	})

	t.Run("stripped U2 breaks the U1 signature", func(t *testing.T) {
		// The U2 block is folded into the signed preimage: stripping it WITHOUT re-signing must
		// fail the signature check (the P1.2 fork-closure property), not merely the presence rule.
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x27)
		tx := a.opening(t, rid, true, nil)
		tx.GetReceive().U2 = nil // strip after signing
		if _, err := ValidateTxAgainstSnapshot(tx, openingSnap(a, rid)); err == nil {
			t.Fatal("stripped-U2 opening accepted (fold must bind U2 to the signature)")
		}
	})

	for _, class := range []pb.AccountClass{
		pb.AccountClass_ACCOUNT_CLASS_SPENDING, pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED,
	} {
		t.Run("reject u2 on "+class.String()+" opening", func(t *testing.T) {
			a := newTU2Account(class, 0x30+byte(class))
			tx := a.opening(t, rid, true, nil) // carries a (well-formed!) U2 block
			_, err := ValidateTxAgainstSnapshot(tx, openingSnap(a, rid))
			wantErrContaining(t, err, "only valid on a guarded/vault account-opening", "U2 on a "+class.String()+" opening")
		})
	}

	t.Run("reject u2 on TRANSFER opening", func(t *testing.T) {
		// A chain opening never CARRIES a U2 (derived copy, D2) — content-based reject before any
		// transfer-specific validation.
		src := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x35)
		chainID := crypto.DerivedAccountID(crypto.AccountTypeTransfer, src.pub.Encode(), src.id, 2)
		var dest [32]byte
		dest[0] = 0xd0
		snap := &Snapshot{Econ: testEcon,
			Accounts: map[[32]byte]AccountSnap{
				src.id: {Class: src.class, AuthPubKey: src.pub.Encode(), BreakglassCommit: src.bg, U2PubKey: src.u2Pub.Encode()},
			},
			Receivables: map[[32]byte]ReceivableSnap{rid: {
				From: src.id, To: chainID, Amount: 500, FromSeq: 2,
				RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			}},
			FundAccount: testFund, GuardedDelayEpochs: 8, VaultDelayEpochs: 12, Epoch: 5,
		}
		body := &pb.TxBodyReceive{
			ReceivableId:         &pb.Hash32{V: rid[:]},
			AccountClass:         pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			AuthPubkey:           &pb.HybridPubKey{V: src.pub.Encode()},
			BreakglassCommitment: &pb.Hash64{V: src.bg},
			TransferDestination:  &pb.AccountId{V: dest[:]},
			TransferUnlockEpoch:  100,
			U2: &pb.U2Registration{
				Pubkey: &pb.HybridPubKey{V: src.u2Pub.Encode()},
				PopSig: &pb.HybridSig{V: src.popSigOver(t, chainID)},
			},
		}
		tx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_RECEIVE, Account: &pb.AccountId{V: chainID[:]},
			Prev: &pb.Hash32{V: make([]byte, 32)}, Seq: 1,
			Body: &pb.Tx_Receive{Receive: body},
		}
		if err := crypto.SignTxHybrid(tx, src.priv); err != nil {
			t.Fatalf("sign: %v", err)
		}
		_, err := ValidateTxAgainstSnapshot(tx, snap)
		wantErrContaining(t, err, "only valid on a guarded/vault account-opening", "carried U2 on a TRANSFER opening")
	})

	t.Run("reject u2 on non-opening RECEIVE", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x36)
		var head [32]byte
		head[0] = 0x51
		snap := openingSnap(a, rid)
		snap.Accounts[a.id] = AccountSnap{ // account EXISTS → non-opening
			Head: head, Balance: 100, Seq: 1, Class: a.class,
			AuthPubKey: a.pub.Encode(), U2PubKey: a.u2Pub.Encode(),
		}
		snap.Receivables[rid] = ReceivableSnap{From: [32]byte{0xfa}, To: a.id, Amount: 500, FromSeq: 2}
		body := &pb.TxBodyReceive{
			ReceivableId: &pb.Hash32{V: rid[:]},
			AccountClass: a.class,
			U2: &pb.U2Registration{
				Pubkey: &pb.HybridPubKey{V: a.u2Pub.Encode()},
				PopSig: &pb.HybridSig{V: a.popSigOver(t, a.id)},
			},
		}
		tx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_RECEIVE, Account: &pb.AccountId{V: a.id[:]},
			Prev: &pb.Hash32{V: head[:]}, Seq: 2,
			Body: &pb.Tx_Receive{Receive: body},
		}
		if err := crypto.SignTxHybrid(tx, a.priv); err != nil {
			t.Fatalf("sign: %v", err)
		}
		_, err := ValidateTxAgainstSnapshot(tx, snap)
		wantErrContaining(t, err, "only valid on a guarded/vault account-opening", "U2 on a non-opening RECEIVE")
	})
}

// --- opening matrix: ApplyTx lockstep (resync replays without validate) ---

func TestU2OpeningApplyLockstep(t *testing.T) {
	var rid [32]byte
	rid[0] = 0x1e

	seedReceivable := func(t *testing.T, db *bbolt.DB, to [32]byte) {
		t.Helper()
		var funder [32]byte
		funder[0] = 0xfa
		rec := &pb.Receivable{
			Id: &pb.Hash32{V: rid[:]}, From: &pb.AccountId{V: funder[:]}, To: &pb.AccountId{V: to[:]},
			Amount: 500, FromSeq: 1,
		}
		rr, _ := proto.Marshal(rec)
		if err := db.Update(func(tx *bbolt.Tx) error { return putReceivableRaw(tx, rid, rr) }); err != nil {
			t.Fatalf("seed receivable: %v", err)
		}
	}
	apply := func(t *testing.T, db *bbolt.DB, tx *pb.Tx) error {
		t.Helper()
		raw, _ := proto.Marshal(tx)
		txid, err := crypto.TxID(tx)
		if err != nil {
			return err
		}
		return db.Update(func(dbtx *bbolt.Tx) error {
			return ApplyTx(&bboltTxView{tx: dbtx}, raw, tx, txid, testFund, testEcon, 7)
		})
	}

	t.Run("valid guarded opening stores U2", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x40)
		db := newFundTestDB(t)
		seedReceivable(t, db, a.id)
		if err := apply(t, db, a.opening(t, rid, true, nil)); err != nil {
			t.Fatalf("apply valid guarded opening: %v", err)
		}
		_ = db.View(func(dbtx *bbolt.Tx) error {
			rec, ok := getAccountRecord(dbtx, a.id)
			if !ok {
				t.Fatal("guarded record missing after apply")
			}
			if string(rec.U2PubKey) != string(a.u2Pub.Encode()) {
				t.Error("applied guarded record does not cache the registered U2 pubkey")
			}
			return nil
		})
	})

	t.Run("apply rejects missing U2", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x41)
		db := newFundTestDB(t)
		seedReceivable(t, db, a.id)
		if err := apply(t, db, a.opening(t, rid, false, nil)); err == nil {
			t.Fatal("ApplyTx accepted a guarded opening without a U2 (validate rejects it — lockstep broken)")
		}
	})

	t.Run("apply rejects bad PoP", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x42)
		other := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x43)
		db := newFundTestDB(t)
		seedReceivable(t, db, a.id)
		tx := a.opening(t, rid, true, func(b *pb.TxBodyReceive) {
			m, _ := crypto.U2RegistrationDigest(a.id, a.u2Pub.Encode())
			sig, _ := other.u2Priv.Sign(m)
			b.U2.PopSig = &pb.HybridSig{V: sig.Encode()}
		})
		if err := apply(t, db, tx); err == nil {
			t.Fatal("ApplyTx accepted a guarded opening with a non-verifying PoP")
		}
	})

	t.Run("apply rejects u2 == u1", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x44)
		db := newFundTestDB(t)
		seedReceivable(t, db, a.id)
		tx := a.opening(t, rid, true, func(b *pb.TxBodyReceive) {
			m, _ := crypto.U2RegistrationDigest(a.id, a.pub.Encode())
			sig, _ := a.priv.Sign(m)
			b.U2 = &pb.U2Registration{Pubkey: &pb.HybridPubKey{V: a.pub.Encode()}, PopSig: &pb.HybridSig{V: sig.Encode()}}
		})
		if err := apply(t, db, tx); err == nil {
			t.Fatal("ApplyTx accepted u2 == u1")
		}
	})

	t.Run("apply rejects u2 on a SPENDING opening", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_SPENDING, 0x45)
		db := newFundTestDB(t)
		seedReceivable(t, db, a.id)
		if err := apply(t, db, a.opening(t, rid, true, nil)); err == nil {
			t.Fatal("ApplyTx accepted a U2 block on a SPENDING opening")
		}
	})

	t.Run("apply rejects sig2 on a RECEIVE", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x46)
		db := newFundTestDB(t)
		seedReceivable(t, db, a.id)
		tx := a.opening(t, rid, true, nil)
		s2, _ := a.u2Priv.Sign([32]byte{0x99})
		tx.Sig2 = &pb.HybridSig{V: s2.Encode()}
		if err := apply(t, db, tx); err == nil {
			t.Fatal("ApplyTx accepted sig2 on a RECEIVE")
		}
	})
}

// --- release gate: path (a) / path (b) either-or ---

type u2ReleaseFixture struct {
	snap    *Snapshot
	u1Priv  *crypto.HybridPrivateKey
	u2Priv  *crypto.HybridPrivateKey
	chainID [32]byte
	src     [32]byte
	dest    [32]byte
	head    [32]byte
	unlock  uint64
	balance uint64
	a1, a2  *tAttestor
}

// newU2ReleaseFixture builds an attestor-flagged TRANSFER chain at its position whose record
// carries BOTH copied user keys (withU2 controls U2), plus two staked attestors (M=2).
func newU2ReleaseFixture(t *testing.T, flagSet, withU2 bool) *u2ReleaseFixture {
	t.Helper()
	u1Priv, u1Pub := crypto.GenerateHybridKeyFromSeed([32]byte{0x61, 0x01})
	u2Priv, u2Pub := crypto.GenerateHybridKeyFromSeed([32]byte{0x61, 0x02})
	a1, a2 := newAttestor(0x71), newAttestor(0x72)

	var chainID, src, dest, head [32]byte
	chainID[0], src[0], dest[0], head[0] = 0xc2, 0x52, 0xd2, 0x72
	const unlock = uint64(20)
	const balance = uint64(1000)

	var flags byte
	if flagSet {
		flags = transferFlagReleaseRequiresAttestor
	}
	cs := AccountSnap{
		Head: head, Balance: balance, Seq: 1,
		Class:          pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
		TransferSource: src, TransferDest: dest, TransferUnlock: unlock, TransferFlags: flags,
		AuthPubKey: u1Pub.Encode(),
	}
	if withU2 {
		cs.U2PubKey = u2Pub.Encode()
	}
	snap := &Snapshot{Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			chainID: cs,
			a1.id:   {Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: a1.pub.Encode()},
			a2.id:   {Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: a2.pub.Encode()},
		},
		Receivables:     map[[32]byte]ReceivableSnap{},
		Epoch:           unlock,
		FundAccount:     testFund,
		AttestorQuorumM: 2,
		FundStakeRows: []StakeRow{
			attestorStake(a1, 0x74, 5_000),
			attestorStake(a2, 0x75, 5_000),
		},
	}
	return &u2ReleaseFixture{
		snap: snap, u1Priv: u1Priv, u2Priv: u2Priv, chainID: chainID, src: src, dest: dest,
		head: head, unlock: unlock, balance: balance, a1: a1, a2: a2,
	}
}

// unsignedDrain builds the full-balance zero-fee TRANSFER outbound to `to` (unsigned).
func (f *u2ReleaseFixture) unsignedDrain(to [32]byte) *pb.Tx {
	return &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: append([]byte(nil), f.chainID[:]...)},
		Prev:    &pb.Hash32{V: append([]byte(nil), f.head[:]...)},
		Seq:     2,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: append([]byte(nil), to[:]...)},
			Amount:       f.balance,
			Fee:          0,
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
		}},
	}
}

// signPathA sets Tx.sig with sig1Priv and sig2 with sig2Priv, both over the same digest m
// (normal roles: sig1Priv = U1, sig2Priv = U2; swap them to build the D5 negative).
func signPathA(t *testing.T, tx *pb.Tx, sig1Priv, sig2Priv *crypto.HybridPrivateKey) {
	t.Helper()
	if err := crypto.SignTxHybrid(tx, sig1Priv); err != nil {
		t.Fatalf("sign path (a) Tx.sig: %v", err)
	}
	m, _, err := crypto.MsgHash(tx)
	if err != nil {
		t.Fatalf("msghash: %v", err)
	}
	s2, err := sig2Priv.Sign(m)
	if err != nil {
		t.Fatalf("sign sig2: %v", err)
	}
	tx.Sig2 = &pb.HybridSig{V: s2.Encode()}
}

func TestReleaseEitherOr(t *testing.T) {
	t.Run("accept path (a) U1+U2", func(t *testing.T) {
		f := newU2ReleaseFixture(t, true, true)
		tx := f.unsignedDrain(f.dest)
		signPathA(t, tx, f.u1Priv, f.u2Priv)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("valid path (a) release rejected: %v", err)
		}
	})

	t.Run("reject path (a) with wrong-key sig2", func(t *testing.T) {
		f := newU2ReleaseFixture(t, true, true)
		other, _ := crypto.GenerateHybridKeyFromSeed([32]byte{0x9a})
		tx := f.unsignedDrain(f.dest)
		signPathA(t, tx, f.u1Priv, other)
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "sig2 does not verify", "sig2 by a key that is not the chain's U2")
	})

	t.Run("reject path (a) swapped roles", func(t *testing.T) {
		// Tx.sig under U2 + sig2 under U1: both keys signed, but D5 fixes the roles.
		f := newU2ReleaseFixture(t, true, true)
		tx := f.unsignedDrain(f.dest)
		signPathA(t, tx, f.u2Priv, f.u1Priv)
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "must verify under the chain's copied U1", "role-swapped path (a)")
	})

	t.Run("reject path (a) plus multisig", func(t *testing.T) {
		f := newU2ReleaseFixture(t, true, true)
		tx := f.unsignedDrain(f.dest)
		attachAttestorMultiSig(t, tx, f.a1, f.a2)
		signPathA(t, tx, f.u1Priv, f.u2Priv)
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "must not carry a multisig", "path (a) + multisig junk row")
	})

	t.Run("reject path (a) with case fields", func(t *testing.T) {
		f := newU2ReleaseFixture(t, true, true)
		tx := f.unsignedDrain(f.dest)
		s := tx.GetSend()
		s.CaseNonce = make([]byte, crypto.CaseFieldSize)
		s.AttestationHash = make([]byte, crypto.CaseFieldSize)
		signPathA(t, tx, f.u1Priv, f.u2Priv)
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "must not carry attestor case fields", "path (a) carrying case fields")
	})

	t.Run("reject path (a) on a chain without U2", func(t *testing.T) {
		f := newU2ReleaseFixture(t, true, false) // flag set, NO U2 on the record
		tx := f.unsignedDrain(f.dest)
		signPathA(t, tx, f.u1Priv, f.u2Priv)
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "no registered second user key", "path (a) on a U2-less chain")
	})

	t.Run("reject path (a) before unlock", func(t *testing.T) {
		f := newU2ReleaseFixture(t, true, true)
		f.snap.Epoch = f.unlock - 1
		tx := f.unsignedDrain(f.dest)
		signPathA(t, tx, f.u1Priv, f.u2Priv)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Fatal("path (a) release accepted before unlock (the window must gate both paths)")
		}
	})

	t.Run("accept path (b) with U1 user sig", func(t *testing.T) {
		f := newU2ReleaseFixture(t, true, true)
		tx := f.unsignedDrain(f.dest)
		setTestCaseFields(tx) // phase 3: the attestor path requires the case commitment
		if err := crypto.SignTxHybrid(tx, f.u1Priv); err != nil {
			t.Fatalf("sign: %v", err)
		}
		attachAttestorMultiSig(t, tx, f.a1, f.a2)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("path (b) with U1 + quorum rejected: %v", err)
		}
	})

	t.Run("accept path (b) with U2 user sig", func(t *testing.T) {
		// D4: "one user signature" means U1 OR U2 — the U2 holder can drive the attestor path.
		f := newU2ReleaseFixture(t, true, true)
		tx := f.unsignedDrain(f.dest)
		setTestCaseFields(tx)
		if err := crypto.SignTxHybrid(tx, f.u2Priv); err != nil {
			t.Fatalf("sign: %v", err)
		}
		attachAttestorMultiSig(t, tx, f.a1, f.a2)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("path (b) with U2 + quorum rejected: %v", err)
		}
	})

	t.Run("reject sig2 on a non-gated release", func(t *testing.T) {
		f := newU2ReleaseFixture(t, false, true) // flag UNSET (plain timelocked chain)
		tx := f.unsignedDrain(f.dest)
		signPathA(t, tx, f.u1Priv, f.u2Priv)
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "not attestor-gated", "sig2 on a flag-unset release")
	})

	t.Run("reject sig2 on a cancel", func(t *testing.T) {
		f := newU2ReleaseFixture(t, true, true)
		tx := f.unsignedDrain(f.src)
		signPathA(t, tx, f.u1Priv, f.u2Priv)
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "return-to-source must not carry a second user signature", "sig2 on a cancel")
	})

	t.Run("reject case fields on a cancel", func(t *testing.T) {
		f := newU2ReleaseFixture(t, true, true)
		tx := f.unsignedDrain(f.src)
		s := tx.GetSend()
		s.CaseNonce = make([]byte, crypto.CaseFieldSize)
		s.AttestationHash = make([]byte, crypto.CaseFieldSize)
		if err := crypto.SignTxHybrid(tx, f.u1Priv); err != nil {
			t.Fatalf("sign: %v", err)
		}
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "return-to-source must not carry attestor case fields", "case fields on a cancel")
	})

	t.Run("accept U2-signed cancel", func(t *testing.T) {
		// D4: the cancel is a single-user-sig op — U2 alone can drive it.
		f := newU2ReleaseFixture(t, true, true)
		f.snap.Epoch = 1 // cancels are never window-gated
		tx := f.unsignedDrain(f.src)
		if err := crypto.SignTxHybrid(tx, f.u2Priv); err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("U2-signed cancel rejected: %v", err)
		}
	})
}

// --- sig2 reject-everywhere on the remaining shapes ---

func TestSig2RejectedEverywhereElse(t *testing.T) {
	t.Run("normal send", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_SPENDING, 0x50)
		var head, to [32]byte
		head[0], to[0] = 0x63, 0x64
		snap := &Snapshot{Econ: testEcon,
			Accounts: map[[32]byte]AccountSnap{
				a.id: {Head: head, Balance: 1_000_000, Seq: 1, Class: a.class, AuthPubKey: a.pub.Encode()},
			},
			FundAccount: testFund,
		}
		const amt = uint64(100)
		tx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: a.id[:]},
			Prev: &pb.Hash32{V: head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: to[:]}, Amount: amt, Fee: ExpectedFee(amt), AccountClass: a.class,
			}},
		}
		signPathA(t, tx, a.priv, a.u2Priv)
		_, err := ValidateTxAgainstSnapshot(tx, snap)
		wantErrContaining(t, err, "normal send must not carry a second user signature", "sig2 on a normal send")
	})

	t.Run("guarded hop-1 send", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x51)
		var head, to [32]byte
		head[0], to[0] = 0x65, 0x66
		snap := &Snapshot{Econ: testEcon,
			Accounts: map[[32]byte]AccountSnap{
				a.id: {Head: head, Balance: 1_000_000, Seq: 1, Class: a.class,
					AuthPubKey: a.pub.Encode(), U2PubKey: a.u2Pub.Encode()},
			},
			FundAccount: testFund,
		}
		const amt = uint64(100)
		tx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: a.id[:]},
			Prev: &pb.Hash32{V: head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: to[:]}, Amount: amt, Fee: ExpectedFee(amt), AccountClass: a.class,
			}},
		}
		signPathA(t, tx, a.priv, a.u2Priv)
		if _, err := ValidateTxAgainstSnapshot(tx, snap); err == nil {
			t.Fatal("sig2 on a guarded hop-1 send accepted")
		}
	})

	t.Run("keyless fund send", func(t *testing.T) {
		var head, to [32]byte
		head[0], to[0] = 0x67, 0x68
		snap := &Snapshot{Econ: testEcon,
			Accounts: map[[32]byte]AccountSnap{
				testFund: {Head: head, Balance: 1_000_000, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_FUND},
			},
			FundAccount: testFund,
		}
		other, _ := crypto.GenerateHybridKeyFromSeed([32]byte{0x9b})
		tx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: testFund[:]},
			Prev: &pb.Hash32{V: head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: to[:]}, Amount: 100, Fee: 0,
				AccountClass: pb.AccountClass_ACCOUNT_CLASS_FUND,
			}},
		}
		m, _, err := crypto.MsgHash(tx)
		if err != nil {
			t.Fatalf("msghash: %v", err)
		}
		s2, _ := other.Sign(m)
		tx.Sig2 = &pb.HybridSig{V: s2.Encode()}
		_, verr := ValidateTxAgainstSnapshot(tx, snap)
		wantErrContaining(t, verr, "fund send must not carry a second user signature", "sig2 on a keyless Fund send")
	})

	t.Run("opening RECEIVE", func(t *testing.T) {
		var rid [32]byte
		rid[0] = 0x1f
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x52)
		tx := a.opening(t, rid, true, nil)
		m, _, _ := crypto.MsgHash(tx)
		s2, _ := a.u2Priv.Sign(m)
		tx.Sig2 = &pb.HybridSig{V: s2.Encode()}
		_, err := ValidateTxAgainstSnapshot(tx, openingSnap(a, rid))
		wantErrContaining(t, err, "RECEIVE must not carry a second user signature", "sig2 on an opening RECEIVE")
	})
}

// --- U1-or-U2 single-signature resolution (D4) on the account's own chain ---

func TestU2SingleSigResolution(t *testing.T) {
	a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0x55)
	var head, to [32]byte
	head[0], to[0] = 0x69, 0x6a
	newSnap := func() *Snapshot {
		return &Snapshot{Econ: testEcon,
			Accounts: map[[32]byte]AccountSnap{
				a.id: {Head: head, Balance: 1_000_000, Seq: 1, Class: a.class,
					AuthPubKey: a.pub.Encode(), U2PubKey: a.u2Pub.Encode()},
			},
			Receivables: map[[32]byte]ReceivableSnap{},
			FundAccount: testFund,
		}
	}
	hop1 := func() *pb.Tx {
		const amt = uint64(100)
		return &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: a.id[:]},
			Prev: &pb.Hash32{V: head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: to[:]}, Amount: amt, Fee: ExpectedFee(amt), AccountClass: a.class,
			}},
		}
	}

	t.Run("U1-signed hop-1 accepted", func(t *testing.T) {
		tx := hop1()
		if err := crypto.SignTxHybrid(tx, a.priv); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateTxAgainstSnapshot(tx, newSnap()); err != nil {
			t.Fatalf("U1-signed hop-1 rejected: %v", err)
		}
	})
	t.Run("U2-signed hop-1 accepted", func(t *testing.T) {
		tx := hop1()
		if err := crypto.SignTxHybrid(tx, a.u2Priv); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateTxAgainstSnapshot(tx, newSnap()); err != nil {
			t.Fatalf("U2-signed hop-1 rejected (D4: U1 OR U2): %v", err)
		}
	})
	t.Run("third-key hop-1 rejected", func(t *testing.T) {
		other, _ := crypto.GenerateHybridKeyFromSeed([32]byte{0x9c})
		tx := hop1()
		if err := crypto.SignTxHybrid(tx, other); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateTxAgainstSnapshot(tx, newSnap()); err == nil {
			t.Fatal("hop-1 signed by neither U1 nor U2 accepted")
		}
	})
	t.Run("U2-signed non-opening RECEIVE accepted", func(t *testing.T) {
		var rid [32]byte
		rid[0] = 0x2a
		snap := newSnap()
		snap.Receivables[rid] = ReceivableSnap{From: [32]byte{0xfa}, To: a.id, Amount: 500, FromSeq: 3}
		tx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_RECEIVE, Account: &pb.AccountId{V: a.id[:]},
			Prev: &pb.Hash32{V: head[:]}, Seq: 2,
			Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
				ReceivableId: &pb.Hash32{V: rid[:]}, AccountClass: a.class,
			}},
		}
		if err := crypto.SignTxHybrid(tx, a.u2Priv); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateTxAgainstSnapshot(tx, snap); err != nil {
			t.Fatalf("U2-signed non-opening RECEIVE rejected (D4 uniform): %v", err)
		}
	})
}

// --- D2 derived copy through ApplyTx + via-snapshot release verify ---

func TestChainDerivedU2Copy(t *testing.T) {
	run := func(t *testing.T, srcClass pb.AccountClass, srcHasU2 bool) (AccountRecord, *tU2Account) {
		t.Helper()
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		src := newTU2Account(srcClass, 0x80+byte(srcClass))

		const fromSeq = uint64(3)
		const amt = uint64(500)
		chainID := crypto.DerivedAccountID(crypto.AccountTypeTransfer, src.pub.Encode(), src.id, fromSeq)
		var srcHead, dest, rid [32]byte
		srcHead[0], dest[0], rid[0] = 0x02, 0xd3, 0x43

		if err := db.Update(func(tx *bbolt.Tx) error {
			rec := AccountRecord{
				Head: srcHead, Balance: 1_000_000, Seq: fromSeq, Class: srcClass,
				AuthPubKey: src.pub.Encode(), BreakglassCommit: src.bg,
			}
			if srcHasU2 {
				rec.U2PubKey = src.u2Pub.Encode()
			}
			if err := putAccountRecord(tx, src.id, rec); err != nil {
				return err
			}
			rcv := &pb.Receivable{
				Id: &pb.Hash32{V: rid[:]}, From: &pb.AccountId{V: src.id[:]}, To: &pb.AccountId{V: chainID[:]},
				Amount: amt, RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER, FromSeq: fromSeq,
			}
			rr, _ := proto.Marshal(rcv)
			return putReceivableRaw(tx, rid, rr)
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		ptx := &pb.Tx{
			Type:    pb.TxType_TX_TYPE_RECEIVE,
			Account: &pb.AccountId{V: chainID[:]},
			Prev:    &pb.Hash32{V: make([]byte, 32)},
			Seq:     1,
			Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
				ReceivableId:         &pb.Hash32{V: rid[:]},
				AccountClass:         pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
				TransferDestination:  &pb.AccountId{V: dest[:]},
				TransferUnlockEpoch:  50,
				AuthPubkey:           &pb.HybridPubKey{V: src.pub.Encode()},
				BreakglassCommitment: &pb.Hash64{V: src.bg},
			}},
		}
		raw, _ := proto.Marshal(ptx)
		txid := txidFor(chainID, 1)
		if err := db.Update(func(tx *bbolt.Tx) error {
			return ApplyTx(&bboltTxView{tx: tx}, raw, ptx, txid, testFund, testEcon, 9)
		}); err != nil {
			t.Fatalf("ApplyTx chain opening: %v", err)
		}
		var rec AccountRecord
		_ = db.View(func(tx *bbolt.Tx) error {
			r, ok := getAccountRecord(tx, chainID)
			if !ok {
				t.Fatal("chain record missing after apply")
			}
			rec = r
			return nil
		})
		return rec, src
	}

	t.Run("guarded source copies U2 and releases via path (a)", func(t *testing.T) {
		rec, src := run(t, pb.AccountClass_ACCOUNT_CLASS_GUARDED, true)
		if string(rec.U2PubKey) != string(src.u2Pub.Encode()) {
			t.Fatal("chain did not derive-copy the guarded source's U2 (D2)")
		}
		if rec.TransferFlags&transferFlagReleaseRequiresAttestor == 0 {
			t.Fatal("guarded-sourced chain missing release_requires_attestor")
		}
		// Via-snapshot release verify: mirror the applied record into a snapshot and release
		// path (a) with the SOURCE's two keys (the chain copies them).
		chainID := crypto.DerivedAccountID(crypto.AccountTypeTransfer, src.pub.Encode(), src.id, 3)
		snap := &Snapshot{Econ: testEcon,
			Accounts: map[[32]byte]AccountSnap{chainID: {
				Head: rec.Head, Balance: rec.Balance, Seq: rec.Seq, Class: rec.Class,
				TransferSource: rec.TransferSource, TransferDest: rec.TransferDest,
				TransferUnlock: rec.TransferUnlock, TransferFlags: rec.TransferFlags,
				AuthPubKey: rec.AuthPubKey, U2PubKey: rec.U2PubKey,
			}},
			Receivables: map[[32]byte]ReceivableSnap{},
			Epoch:       rec.TransferUnlock, // at unlock
			FundAccount: testFund, AttestorQuorumM: 2,
		}
		tx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: chainID[:]},
			Prev: &pb.Hash32{V: rec.Head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: rec.TransferDest[:]}, Amount: rec.Balance, Fee: 0,
				AccountClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			}},
		}
		signPathA(t, tx, src.priv, src.u2Priv)
		if _, err := ValidateTxAgainstSnapshot(tx, snap); err != nil {
			t.Fatalf("path (a) release against the applied chain record rejected: %v", err)
		}
	})

	t.Run("timelocked chain unaffected", func(t *testing.T) {
		rec, src := run(t, pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, false)
		if len(rec.U2PubKey) != 0 {
			t.Fatal("timelocked-sourced chain must not carry a U2")
		}
		if rec.TransferFlags&transferFlagReleaseRequiresAttestor != 0 {
			t.Fatal("timelocked-sourced chain must not be attestor-flagged")
		}
		chainID := crypto.DerivedAccountID(crypto.AccountTypeTransfer, src.pub.Encode(), src.id, 3)
		snap := &Snapshot{Econ: testEcon,
			Accounts: map[[32]byte]AccountSnap{chainID: {
				Head: rec.Head, Balance: rec.Balance, Seq: rec.Seq, Class: rec.Class,
				TransferSource: rec.TransferSource, TransferDest: rec.TransferDest,
				TransferUnlock: rec.TransferUnlock, TransferFlags: rec.TransferFlags,
				AuthPubKey: rec.AuthPubKey,
			}},
			Receivables: map[[32]byte]ReceivableSnap{},
			Epoch:       rec.TransferUnlock,
			FundAccount: testFund, AttestorQuorumM: 2,
		}
		// A plain single-sig release still works...
		plain := &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: chainID[:]},
			Prev: &pb.Hash32{V: rec.Head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: rec.TransferDest[:]}, Amount: rec.Balance, Fee: 0,
				AccountClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			}},
		}
		if err := crypto.SignTxHybrid(plain, src.priv); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateTxAgainstSnapshot(plain, snap); err != nil {
			t.Fatalf("plain timelocked release rejected: %v", err)
		}
		// ...and a sig2 variant is rejected (not attestor-gated).
		withSig2 := &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: chainID[:]},
			Prev: &pb.Hash32{V: rec.Head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: rec.TransferDest[:]}, Amount: rec.Balance, Fee: 0,
				AccountClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			}},
		}
		signPathA(t, withSig2, src.priv, src.u2Priv)
		if _, err := ValidateTxAgainstSnapshot(withSig2, snap); err == nil {
			t.Fatal("sig2 accepted on a timelocked (non-gated) release")
		}
	})
}

// --- the guarded rate limit (§2.8) + D1 Fund-donation reject ---

func TestGuardedSendRateLimit(t *testing.T) {
	build := func(a *tU2Account, head [32]byte, to [32]byte) *pb.Tx {
		const amt = uint64(100)
		tx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: a.id[:]},
			Prev: &pb.Hash32{V: head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: to[:]}, Amount: amt, Fee: ExpectedFee(amt), AccountClass: a.class,
			}},
		}
		return tx
	}
	newSnap := func(a *tU2Account, head [32]byte, last, interval, epoch uint64) *Snapshot {
		return &Snapshot{Econ: testEcon,
			Accounts: map[[32]byte]AccountSnap{
				a.id: {Head: head, Balance: 1_000_000, Seq: 1, Class: a.class,
					AuthPubKey: a.pub.Encode(), U2PubKey: a.u2Pub.Encode(), LastGuardedSendEpoch: last},
			},
			FundAccount:                  testFund,
			Epoch:                        epoch,
			GuardedSendMinIntervalEpochs: interval,
		}
	}
	var head, to [32]byte
	head[0], to[0] = 0x6b, 0x6c

	for _, class := range []pb.AccountClass{
		pb.AccountClass_ACCOUNT_CLASS_GUARDED, pb.AccountClass_ACCOUNT_CLASS_VAULT,
	} {
		a := newTU2Account(class, 0x90+byte(class))
		t.Run(class.String(), func(t *testing.T) {
			sign := func(tx *pb.Tx) *pb.Tx {
				if err := crypto.SignTxHybrid(tx, a.priv); err != nil {
					t.Fatal(err)
				}
				return tx
			}
			// Inside the window (last=10, interval=6, epoch=15: 15-10=5 < 6) → reject.
			_, err := ValidateTxAgainstSnapshot(sign(build(a, head, to)), newSnap(a, head, 10, 6, 15))
			wantErrContaining(t, err, "guarded send rate limit", "send inside the rate-limit window")
			// Exactly at the boundary (epoch=16: 16-10=6, not < 6) → accepted.
			if _, err := ValidateTxAgainstSnapshot(sign(build(a, head, to)), newSnap(a, head, 10, 6, 16)); err != nil {
				t.Fatalf("send exactly at the window boundary rejected: %v", err)
			}
			// First send ever (last=0) → always allowed.
			if _, err := ValidateTxAgainstSnapshot(sign(build(a, head, to)), newSnap(a, head, 0, 6, 1)); err != nil {
				t.Fatalf("first guarded send rejected: %v", err)
			}
			// Interval 0 (pre-wiring test snapshots) → no limit.
			if _, err := ValidateTxAgainstSnapshot(sign(build(a, head, to)), newSnap(a, head, 10, 0, 11)); err != nil {
				t.Fatalf("interval-0 snapshot must impose no limit: %v", err)
			}
		})
	}

	t.Run("SPENDING unaffected", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_SPENDING, 0x95)
		snap := newSnap(a, head, 10, 6, 11) // would be inside the window if it applied
		tx := build(a, head, to)
		if err := crypto.SignTxHybrid(tx, a.priv); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateTxAgainstSnapshot(tx, snap); err != nil {
			t.Fatalf("rate limit leaked onto a SPENDING send: %v", err)
		}
	})

	t.Run("D1 donation reject validate", func(t *testing.T) {
		for _, class := range []pb.AccountClass{
			pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED,
			pb.AccountClass_ACCOUNT_CLASS_GUARDED,
			pb.AccountClass_ACCOUNT_CLASS_VAULT,
		} {
			a := newTU2Account(class, 0xa0+byte(class))
			snap := newSnap(a, head, 0, 0, 5)
			tx := build(a, head, testFund) // bare donation: empty staked_for
			if err := crypto.SignTxHybrid(tx, a.priv); err != nil {
				t.Fatal(err)
			}
			_, err := ValidateTxAgainstSnapshot(tx, snap)
			wantErrContaining(t, err, "cannot send directly to the Fund", class.String()+" donation")
		}
	})
}

func TestGuardedApplyStampsAndD1(t *testing.T) {
	t.Run("apply stamps the finalization epoch", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0xb0)
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var head, to [32]byte
		head[0], to[0] = 0x6d, 0x6e
		if err := db.Update(func(tx *bbolt.Tx) error {
			return putAccountRecord(tx, a.id, AccountRecord{
				Head: head, Balance: 1_000_000, Seq: 1, Class: a.class,
				AuthPubKey: a.pub.Encode(), U2PubKey: a.u2Pub.Encode(),
			})
		}); err != nil {
			t.Fatal(err)
		}
		const amt = uint64(100)
		ptx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: a.id[:]},
			Prev: &pb.Hash32{V: head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: to[:]}, Amount: amt, Fee: ExpectedFee(amt), AccountClass: a.class,
			}},
		}
		raw, _ := proto.Marshal(ptx)
		txid := txidFor(a.id, 2)
		if err := db.Update(func(tx *bbolt.Tx) error {
			return ApplyTx(&bboltTxView{tx: tx}, raw, ptx, txid, testFund, testEcon, 42)
		}); err != nil {
			t.Fatalf("apply guarded send: %v", err)
		}
		_ = db.View(func(tx *bbolt.Tx) error {
			rec, _ := getAccountRecord(tx, a.id)
			if rec.LastGuardedSendEpoch != 42 {
				t.Errorf("LastGuardedSendEpoch = %d, want the finalization epoch 42", rec.LastGuardedSendEpoch)
			}
			if len(rec.U2PubKey) == 0 {
				t.Error("guarded record lost its U2 across a send (read-modify-write broken)")
			}
			return nil
		})
	})

	t.Run("apply leaves SPENDING unstamped", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_SPENDING, 0xb1)
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var head, to [32]byte
		head[0], to[0] = 0x6f, 0x70
		if err := db.Update(func(tx *bbolt.Tx) error {
			return putAccountRecord(tx, a.id, AccountRecord{
				Head: head, Balance: 1_000_000, Seq: 1, Class: a.class, AuthPubKey: a.pub.Encode(),
			})
		}); err != nil {
			t.Fatal(err)
		}
		const amt = uint64(100)
		ptx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: a.id[:]},
			Prev: &pb.Hash32{V: head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: to[:]}, Amount: amt, Fee: ExpectedFee(amt), AccountClass: a.class,
			}},
		}
		raw, _ := proto.Marshal(ptx)
		if err := db.Update(func(tx *bbolt.Tx) error {
			return ApplyTx(&bboltTxView{tx: tx}, raw, ptx, txidFor(a.id, 2), testFund, testEcon, 42)
		}); err != nil {
			t.Fatalf("apply spending send: %v", err)
		}
		_ = db.View(func(tx *bbolt.Tx) error {
			rec, _ := getAccountRecord(tx, a.id)
			if rec.LastGuardedSendEpoch != 0 {
				t.Errorf("SPENDING send stamped LastGuardedSendEpoch=%d, want 0", rec.LastGuardedSendEpoch)
			}
			return nil
		})
	})

	t.Run("apply rejects a guarded donation (D1 lockstep)", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0xb2)
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var head [32]byte
		head[0] = 0x71
		if err := db.Update(func(tx *bbolt.Tx) error {
			return putAccountRecord(tx, a.id, AccountRecord{
				Head: head, Balance: 1_000_000, Seq: 1, Class: a.class,
				AuthPubKey: a.pub.Encode(), U2PubKey: a.u2Pub.Encode(),
			})
		}); err != nil {
			t.Fatal(err)
		}
		const amt = uint64(100)
		ptx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: a.id[:]},
			Prev: &pb.Hash32{V: head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: testFund[:]}, Amount: amt, Fee: ExpectedFee(amt), AccountClass: a.class,
			}},
		}
		raw, _ := proto.Marshal(ptx)
		if err := db.Update(func(tx *bbolt.Tx) error {
			return ApplyTx(&bboltTxView{tx: tx}, raw, ptx, txidFor(a.id, 2), testFund, testEcon, 42)
		}); err == nil {
			t.Fatal("ApplyTx accepted a guarded → Fund donation (D1 lockstep broken)")
		}
	})
}

// --- submit gates: judgeAbsentOpening (pure) + bestEffortReleaseCheck (engine) ---

func TestJudgeAbsentOpeningU2Shapes(t *testing.T) {
	var rid [32]byte
	rid[0] = 0x2b

	t.Run("guarded opening with valid U2 defers", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0xc0)
		if err := judgeAbsentOpening(a.opening(t, rid, true, nil), a.id); err != nil {
			t.Fatalf("valid guarded opening rejected at the stateless gate: %v", err)
		}
	})
	t.Run("guarded opening without U2 rejected", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0xc1)
		if err := judgeAbsentOpening(a.opening(t, rid, false, nil), a.id); err == nil {
			t.Fatal("U2-less guarded opening deferred (can never finalize — must reject)")
		}
	})
	t.Run("guarded opening with bad PoP rejected", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0xc2)
		other := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0xc3)
		tx := a.opening(t, rid, true, func(b *pb.TxBodyReceive) {
			m, _ := crypto.U2RegistrationDigest(a.id, a.u2Pub.Encode())
			sig, _ := other.u2Priv.Sign(m)
			b.U2.PopSig = &pb.HybridSig{V: sig.Encode()}
		})
		if err := judgeAbsentOpening(tx, a.id); err == nil {
			t.Fatal("bad-PoP guarded opening deferred (must reject)")
		}
	})
	t.Run("u2 on a SPENDING opening rejected", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_SPENDING, 0xc4)
		if err := judgeAbsentOpening(a.opening(t, rid, true, nil), a.id); err == nil {
			t.Fatal("U2 block on a SPENDING opening deferred (must reject)")
		}
	})
	t.Run("sig2 on an opening rejected", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_SPENDING, 0xc5)
		tx := a.opening(t, rid, false, nil)
		s2, _ := a.u2Priv.Sign([32]byte{0x11})
		tx.Sig2 = &pb.HybridSig{V: s2.Encode()}
		if err := judgeAbsentOpening(tx, a.id); err == nil {
			t.Fatal("sig2 on an opening RECEIVE deferred (must reject)")
		}
	})
}

func TestBestEffortReleaseCheckPathA(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t), newTValidator(t), newTValidator(t)})
	f := newU2ReleaseFixture(t, true, true)

	// Materialize the fixture's chain record at its position in the engine's DB.
	cs := f.snap.Accounts[f.chainID]
	if err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, f.chainID, AccountRecord{
			Head: cs.Head, Balance: cs.Balance, Seq: cs.Seq, Class: cs.Class,
			TransferSource: cs.TransferSource, TransferDest: cs.TransferDest,
			TransferUnlock: cs.TransferUnlock, TransferFlags: cs.TransferFlags,
			AuthPubKey: cs.AuthPubKey, U2PubKey: cs.U2PubKey,
		})
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("valid path (a) defers", func(t *testing.T) {
		tx := f.unsignedDrain(f.dest)
		signPathA(t, tx, f.u1Priv, f.u2Priv)
		if err := e.bestEffortReleaseCheck(tx); err != nil {
			t.Fatalf("legit path (a) release rejected at the gate: %v", err)
		}
	})
	t.Run("swapped-roles path (a) rejected", func(t *testing.T) {
		tx := f.unsignedDrain(f.dest)
		signPathA(t, tx, f.u2Priv, f.u1Priv)
		if err := e.bestEffortReleaseCheck(tx); err == nil {
			t.Fatal("role-swapped path (a) deferred at the gate (never finalizable — must reject)")
		}
	})
	t.Run("wrong-key sig2 rejected", func(t *testing.T) {
		other, _ := crypto.GenerateHybridKeyFromSeed([32]byte{0x9d})
		tx := f.unsignedDrain(f.dest)
		signPathA(t, tx, f.u1Priv, other)
		if err := e.bestEffortReleaseCheck(tx); err == nil {
			t.Fatal("wrong-key sig2 deferred at the gate (must reject)")
		}
	})
	t.Run("sig2 on a cancel rejected", func(t *testing.T) {
		tx := f.unsignedDrain(f.src)
		signPathA(t, tx, f.u1Priv, f.u2Priv)
		if err := e.bestEffortReleaseCheck(tx); err == nil {
			t.Fatal("sig2 on a cancel deferred at the gate (must reject)")
		}
	})
	t.Run("sig2 on a RECEIVE rejected statelessly", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_GUARDED, 0xc6)
		var rid [32]byte
		rid[0] = 0x2c
		tx := a.opening(t, rid, true, nil)
		s2, _ := a.u2Priv.Sign([32]byte{0x12})
		tx.Sig2 = &pb.HybridSig{V: s2.Encode()}
		if err := e.bestEffortReleaseCheck(tx); err == nil {
			t.Fatal("sig2 on a RECEIVE deferred at the gate (must reject)")
		}
	})
	t.Run("not-at-position defers", func(t *testing.T) {
		tx := f.unsignedDrain(f.dest)
		tx.Prev = &pb.Hash32{V: make([]byte, 32)} // wrong prev — the node can't judge
		signPathA(t, tx, f.u1Priv, f.u2Priv)
		if err := e.bestEffortReleaseCheck(tx); err != nil {
			t.Fatalf("not-at-position sig2 release must defer: %v", err)
		}
	})
}
