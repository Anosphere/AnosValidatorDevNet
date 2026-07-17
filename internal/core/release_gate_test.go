package core

// P3.2 GUARDED/VAULT attestor-gated release (spec-18 §3.3/§5.3/§5.4, spec-19 §6.1).
//
// These tests pin the release gate at the ValidateTxAgainstSnapshot level (the consensus
// authority): a release-to-dest of an attestor-gated TRANSFER chain needs the chain's
// controlling-key Tx.sig AND a flat M-of-N Fund Attestor quorum; a return-to-source is never
// gated; an ordinary (flag-unset) release must not carry a multisig; a normal send must not
// carry a multisig. A crypto test pins that the release txid binds BOTH the controlling-key
// Tx.sig and the exact attestor set (order-independently), closing the attestor-set-swap fork.
// The per-class delay table is pinned as pure math. (The flag-set-from-source-class wiring and
// resync determinism are exercised end-to-end by sim-guarded-vault-release + the live harness.)

import (
	"crypto/sha256"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// --- pure: per-class delay table + the attestor-flag predicate ---

func TestDelayForSourceClass(t *testing.T) {
	snap := &Snapshot{Econ: testEcon, DelayEpochs: 6, GuardedDelayEpochs: 8, VaultDelayEpochs: 12}
	cases := []struct {
		c    pb.AccountClass
		want uint64
	}{
		{pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, 6},
		{pb.AccountClass_ACCOUNT_CLASS_GUARDED, 8},
		{pb.AccountClass_ACCOUNT_CLASS_VAULT, 12},
		{pb.AccountClass_ACCOUNT_CLASS_SPENDING, 0},
		{pb.AccountClass_ACCOUNT_CLASS_TRANSFER, 0},
		{pb.AccountClass_ACCOUNT_CLASS_FUND, 0},
		{pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED, 0},
	}
	for _, c := range cases {
		if got := delayForSourceClass(c.c, snap); got != c.want {
			t.Errorf("delayForSourceClass(%v) = %d, want %d", c.c, got, c.want)
		}
	}
	// VAULT > GUARDED > TIMELOCKED is the design invariant (kept a separate class for it).
	if !(snap.VaultDelayEpochs > snap.GuardedDelayEpochs && snap.GuardedDelayEpochs > snap.DelayEpochs) {
		t.Error("fixture must keep VAULT > GUARDED > TIMELOCKED")
	}
}

func TestSourceClassRequiresAttestor(t *testing.T) {
	yes := []pb.AccountClass{pb.AccountClass_ACCOUNT_CLASS_GUARDED, pb.AccountClass_ACCOUNT_CLASS_VAULT}
	no := []pb.AccountClass{
		pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, pb.AccountClass_ACCOUNT_CLASS_SPENDING,
		pb.AccountClass_ACCOUNT_CLASS_FUND, pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
		pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED,
	}
	for _, c := range yes {
		if !sourceClassRequiresAttestor(c) {
			t.Errorf("sourceClassRequiresAttestor(%v) = false, want true", c)
		}
	}
	for _, c := range no {
		if sourceClassRequiresAttestor(c) {
			t.Errorf("sourceClassRequiresAttestor(%v) = true, want false", c)
		}
	}
}

// --- test attestor identity ---

type tAttestor struct {
	priv *crypto.HybridPrivateKey
	pub  *crypto.HybridPubKey
	id   [32]byte
}

func newAttestor(seed byte) *tAttestor {
	priv, pub := crypto.GenerateHybridKeyFromSeed([32]byte{seed, 0xa7})
	id := crypto.BaseAccountID(crypto.AccountTypeByteForClass(pb.AccountClass_ACCOUNT_CLASS_SPENDING), pub.Encode())
	return &tAttestor{priv: priv, pub: pub, id: id}
}

// attestorStake gives `a` an active Attestor-tagged stake of `whoAnos` whole anos (so
// testEcon.IsAttestor(a) iff whoAnos >= 5000).
func attestorStake(a *tAttestor, depositSeed byte, whoAnos uint64) StakeRow {
	return StakeRow{
		DepositTxid: [32]byte{depositSeed, 0xaa},
		StakeRecord: StakeRecord{
			StakerID: a.id, Amount: anosUnits(whoAnos), TimeDelay: oneMonth,
			Status: StakeStatusActive, StakedFor: StakedForAttestor,
		},
	}
}

// attachAttestorMultiSig assembles a HybridMultiSig over the tx digest m and sets tx.MultiSig.
func attachAttestorMultiSig(t *testing.T, tx *pb.Tx, signers ...*tAttestor) {
	t.Helper()
	m, _, err := crypto.MsgHash(tx)
	if err != nil {
		t.Fatalf("msghash: %v", err)
	}
	ms := &pb.HybridMultiSig{}
	for _, a := range signers {
		sig, err := a.priv.Sign(m)
		if err != nil {
			t.Fatalf("attestor sign: %v", err)
		}
		ms.Entries = append(ms.Entries, &pb.HybridSigEntry{
			SignerId: &pb.AccountId{V: append([]byte(nil), a.id[:]...)},
			Sig:      &pb.HybridSig{V: sig.Encode()},
		})
	}
	tx.MultiSig = ms
}

// --- release-gate fixture ---

type releaseFixture struct {
	snap      *Snapshot
	chainPriv *crypto.HybridPrivateKey
	chainID   [32]byte
	src       [32]byte
	dest      [32]byte
	head      [32]byte
	unlock    uint64
	balance   uint64
	a1, a2    *tAttestor // staked attestors (5000 anos each)
	a3        *tAttestor // keyed signer that is NOT an attestor (no stake)
}

// newReleaseFixture builds a TRANSFER chain at its position (seq 1, head h) holding `balance`,
// with the given release_requires_attestor flag, plus two staked attestors and one non-attestor
// keyed signer. The chain's controlling key is chainPriv (its cached AuthPubKey). Snapshot epoch
// == unlock (release allowed); AttestorQuorumM == 2.
func newReleaseFixture(t *testing.T, flagSet bool) *releaseFixture {
	t.Helper()
	chainPriv, chainPub := crypto.GenerateHybridKeyFromSeed([32]byte{0x33, 0x33})
	a1, a2, a3 := newAttestor(1), newAttestor(2), newAttestor(3)

	var chainID, src, dest, head [32]byte
	chainID[0], src[0], dest[0], head[0] = 0xcc, 0x55, 0xdd, 0x71
	const unlock = uint64(20)
	const balance = uint64(1000)

	var flags byte
	if flagSet {
		flags = transferFlagReleaseRequiresAttestor
	}

	snap := &Snapshot{Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			chainID: {
				Head: head, Balance: balance, Seq: 1,
				Class:          pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
				TransferSource: src, TransferDest: dest, TransferUnlock: unlock, TransferFlags: flags,
				AuthPubKey: chainPub.Encode(),
			},
			a1.id: {Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: a1.pub.Encode()},
			a2.id: {Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: a2.pub.Encode()},
			a3.id: {Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: a3.pub.Encode()},
		},
		Receivables:     map[[32]byte]ReceivableSnap{},
		Epoch:           unlock, // at unlock → release allowed
		FundAccount:     testFund,
		AttestorQuorumM: 2,
		FundStakeRows: []StakeRow{
			attestorStake(a1, 0x01, 5_000),
			attestorStake(a2, 0x02, 5_000),
			// a3 has no stake → not an attestor.
		},
	}
	return &releaseFixture{
		snap: snap, chainPriv: chainPriv, chainID: chainID, src: src, dest: dest,
		head: head, unlock: unlock, balance: balance, a1: a1, a2: a2, a3: a3,
	}
}

// releaseTx builds a full-balance zero-fee TRANSFER drain to `to`, signed by the chain's key.
func (f *releaseFixture) releaseTx(t *testing.T, to [32]byte) *pb.Tx {
	t.Helper()
	tx := &pb.Tx{
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
	if err := crypto.SignTxHybrid(tx, f.chainPriv); err != nil {
		t.Fatalf("chain sign: %v", err)
	}
	return tx
}

func TestReleaseAttestorGate(t *testing.T) {
	// Positive: at/after unlock, chain key + M (=2) attestor sigs → accepted.
	t.Run("accept M-of-N at unlock", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		tx := f.releaseTx(t, f.dest)
		attachAttestorMultiSig(t, tx, f.a1, f.a2)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("valid M-of-N release rejected: %v", err)
		}
	})

	// Extra non-attestor signer is harmless (ignored): a1+a2+a3 still counts 2.
	t.Run("non-attestor signer ignored", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		tx := f.releaseTx(t, f.dest)
		attachAttestorMultiSig(t, tx, f.a1, f.a2, f.a3)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("release with an extra non-attestor signer rejected: %v", err)
		}
	})

	// Below threshold: 1 attestor < M=2 → rejected.
	t.Run("reject below M", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		tx := f.releaseTx(t, f.dest)
		attachAttestorMultiSig(t, tx, f.a1)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("release with 1 < M attestor signatures accepted")
		}
	})

	// Only a non-attestor signs (a3): count 0 < M → rejected.
	t.Run("reject non-attestor-only", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		tx := f.releaseTx(t, f.dest)
		attachAttestorMultiSig(t, tx, f.a3)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("release authorized only by a non-attestor accepted")
		}
	})

	// Duplicate attestor entries count once: a1,a1 → 1 < M → rejected.
	t.Run("reject duplicate signer", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		tx := f.releaseTx(t, f.dest)
		attachAttestorMultiSig(t, tx, f.a1, f.a1)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("release with a duplicated attestor counted twice")
		}
	})

	// No multisig at all (only Tx.sig) on a gated release → rejected.
	t.Run("reject missing multisig", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		tx := f.releaseTx(t, f.dest) // no multisig attached
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("gated release with no attestor multisig accepted")
		}
	})

	// Before unlock: even with a full quorum, the lock check rejects first.
	t.Run("reject before unlock", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		f.snap.Epoch = f.unlock - 1
		tx := f.releaseTx(t, f.dest)
		attachAttestorMultiSig(t, tx, f.a1, f.a2)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("gated release accepted before unlock")
		}
	})

	// Return-to-source is NEVER gated: no multisig, any epoch → accepted.
	t.Run("accept return-to-source ungated", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		f.snap.Epoch = 1 // well before unlock — return is always allowed
		tx := f.releaseTx(t, f.src)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("ungated return-to-source rejected: %v", err)
		}
	})

	// A multisig on a return-to-source is not allowed (it would only grind the txid).
	t.Run("reject multisig on return", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		tx := f.releaseTx(t, f.src)
		attachAttestorMultiSig(t, tx, f.a1, f.a2)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Error("return-to-source carrying a multisig accepted")
		}
	})

	// AttestorQuorumM == 0 is treated as 1 defensively: 1 attestor passes, 0 fails.
	t.Run("M=0 defensive floor", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		f.snap.AttestorQuorumM = 0
		ok := f.releaseTx(t, f.dest)
		attachAttestorMultiSig(t, ok, f.a1)
		if _, err := ValidateTxAgainstSnapshot(ok, f.snap); err != nil {
			t.Fatalf("M=0→1 floor rejected a single attestor: %v", err)
		}
		none := f.releaseTx(t, f.dest)
		attachAttestorMultiSig(t, none, f.a3) // non-attestor only
		if _, err := ValidateTxAgainstSnapshot(none, f.snap); err == nil {
			t.Error("M=0→1 floor accepted zero attestor signatures")
		}
	})
}

func TestReleaseFlagUnsetRejectsMultisig(t *testing.T) {
	// An ordinary (flag-unset, TIMELOCKED) release must NOT carry a multisig.
	f := newReleaseFixture(t, false)
	withMS := f.releaseTx(t, f.dest)
	attachAttestorMultiSig(t, withMS, f.a1, f.a2)
	if _, err := ValidateTxAgainstSnapshot(withMS, f.snap); err == nil {
		t.Error("non-gated release carrying a multisig accepted")
	}
	// ... but a plain (no-multisig) release of a flag-unset chain is fine at/after unlock.
	plain := f.releaseTx(t, f.dest)
	if _, err := ValidateTxAgainstSnapshot(plain, f.snap); err != nil {
		t.Fatalf("ordinary timelocked release rejected: %v", err)
	}
}

func TestNormalSendRejectsMultisig(t *testing.T) {
	// A SPENDING account's normal send must not carry a multisig (it would only grind the txid).
	priv, pub := crypto.GenerateHybridKeyFromSeed([32]byte{0x44})
	id := crypto.BaseAccountID(crypto.AccountTypeByteForClass(pb.AccountClass_ACCOUNT_CLASS_SPENDING), pub.Encode())
	var head, to [32]byte
	head[0], to[0] = 0x61, 0x62
	const amt = uint64(100)
	snap := &Snapshot{Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			id: {Head: head, Balance: 1_000_000, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: pub.Encode()},
		},
		FundAccount: testFund,
	}
	a1, a2 := newAttestor(1), newAttestor(2)
	snap.Accounts[a1.id] = AccountSnap{AuthPubKey: a1.pub.Encode()}
	snap.Accounts[a2.id] = AccountSnap{AuthPubKey: a2.pub.Encode()}
	tx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: id[:]},
		Prev:    &pb.Hash32{V: head[:]},
		Seq:     2,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To: &pb.AccountId{V: to[:]}, Amount: amt, Fee: ExpectedFee(amt),
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
		}},
	}
	if err := crypto.SignTxHybrid(tx, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Without a multisig it is a valid send.
	if _, err := ValidateTxAgainstSnapshot(tx, snap); err != nil {
		t.Fatalf("plain normal send rejected: %v", err)
	}
	// Attaching a multisig must make it invalid (re-sign so Tx.sig stays valid over the body).
	attachAttestorMultiSig(t, tx, a1, a2)
	if err := crypto.SignTxHybrid(tx, priv); err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	if _, err := ValidateTxAgainstSnapshot(tx, snap); err == nil {
		t.Error("normal send carrying a multisig accepted")
	}
}

// TestReleaseTxIDBindsSigAndMultisig pins the consensus-critical txid construction for an
// attestor-gated release: the txid binds BOTH the chain's controlling-key Tx.sig AND the exact
// attestor set (order-independently). Without this, two raws with the same body/sig but different
// attestor sets would share a txid → an attestor-set-swap fork (the kickoff's highest-risk item).
func TestReleaseTxIDBindsSigAndMultisig(t *testing.T) {
	f := newReleaseFixture(t, true)
	a1, a2, a3 := f.a1, f.a2, f.a3

	tx := f.releaseTx(t, f.dest)
	attachAttestorMultiSig(t, tx, a1, a2)
	id12, err := crypto.TxID(tx)
	if err != nil {
		t.Fatalf("txid: %v", err)
	}

	// Explicit construction (forquinn §2.3): txid == SHA256(sign_bytes || Tx.sig || frame(sig2)
	// || canonical(multisig)) — sig2 absent on a path-(b) release folds as a zero-length
	// uint32-LE frame.
	sb, err := crypto.SignBytesACTE(tx)
	if err != nil {
		t.Fatalf("signbytes: %v", err)
	}
	dig, err := crypto.FundMultiSigDigest(tx.MultiSig)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	buf := append(append(append([]byte{}, sb...), tx.Sig.V...), make([]byte, 4)...)
	buf = append(buf, dig...)
	want := sha256.Sum256(buf)
	if id12 != want {
		t.Error("release txid != SHA256(sign_bytes || Tx.sig || frame(sig2) || multisig_digest)")
	}

	// Reordering the entries → same txid (canonical sort).
	e := tx.MultiSig.Entries
	e[0], e[1] = e[1], e[0]
	idReordered, _ := crypto.TxID(tx)
	if idReordered != id12 {
		t.Error("release txid must be independent of multisig entry order")
	}

	// Different attestor set (a1,a3) → DIFFERENT txid (binds the set).
	tx13 := f.releaseTx(t, f.dest)
	attachAttestorMultiSig(t, tx13, a1, a3)
	id13, _ := crypto.TxID(tx13)
	if id13 == id12 {
		t.Error("release txid must change when the attestor set changes")
	}

	// Changing the controlling-key Tx.sig → DIFFERENT txid (binds Tx.sig too). Re-sign with a
	// fresh key over the same body, keep the same multisig.
	otherPriv, _ := crypto.GenerateHybridKeyFromSeed([32]byte{0x99})
	txSig := f.releaseTx(t, f.dest)
	attachAttestorMultiSig(t, txSig, a1, a2)
	if err := crypto.SignTxHybrid(txSig, otherPriv); err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	idSig, _ := crypto.TxID(txSig)
	if idSig == id12 {
		t.Error("release txid must change when the controlling-key Tx.sig changes")
	}
}

// TestApplySetsReleaseAttestorFlag pins the consensus-critical flag derivation in ApplyTx (the
// no-revalidation resync path): a TRANSFER chain opened from a GUARDED/VAULT source stores
// release_requires_attestor; a TIMELOCKED source does not. Derived purely from the source's stored
// class, so a resync replay reproduces the identical flag.
func TestApplySetsReleaseAttestorFlag(t *testing.T) {
	cases := []struct {
		class    pb.AccountClass
		wantFlag bool
	}{
		{pb.AccountClass_ACCOUNT_CLASS_GUARDED, true},
		{pb.AccountClass_ACCOUNT_CLASS_VAULT, true},
		{pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, false},
	}
	for _, c := range cases {
		t.Run(c.class.String(), func(t *testing.T) {
			db := newFundTestDB(t)
			fund := testFund
			seedFundRecord(t, db, fund)

			_, srcPub := crypto.GenerateHybridKeyFromSeed([32]byte{0x21, byte(c.class)})
			_, srcBGPub := crypto.GenerateHybridKeyFromSeed([32]byte{0x22, byte(c.class)})
			tb := crypto.AccountTypeByteForClass(c.class)
			srcID := crypto.BaseAccountID(tb, srcPub.Encode())
			srcBG := crypto.BreakglassCommitment(srcBGPub.Encode())

			const fromSeq = uint64(3)
			const amt = uint64(500)
			chainID := crypto.DerivedAccountID(crypto.AccountTypeTransfer, srcPub.Encode(), srcID, fromSeq)
			var srcHead, dest, rid [32]byte
			srcHead[0], dest[0], rid[0] = 0x01, 0xd0, 0x42

			// Seed the funding source (keyed, with its class) and mint the transfer-restricted
			// receivable that the chain's opening RECEIVE claims.
			if err := db.Update(func(tx *bbolt.Tx) error {
				if err := putAccountRecord(tx, srcID, AccountRecord{
					Head: srcHead, Balance: 1_000_000, Seq: fromSeq, Class: c.class,
					AuthPubKey: srcPub.Encode(), BreakglassCommit: srcBG[:],
				}); err != nil {
					return err
				}
				rec := &pb.Receivable{
					Id: &pb.Hash32{V: rid[:]}, From: &pb.AccountId{V: srcID[:]}, To: &pb.AccountId{V: chainID[:]},
					Amount: amt, RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER, FromSeq: fromSeq,
				}
				rr, _ := proto.Marshal(rec)
				return putReceivableRaw(tx, rid, rr)
			}); err != nil {
				t.Fatalf("seed: %v", err)
			}

			// Apply the chain's opening RECEIVE (copies the source's keys + id nonce).
			ptx := &pb.Tx{
				Type:    pb.TxType_TX_TYPE_RECEIVE,
				Account: &pb.AccountId{V: chainID[:]},
				Prev:    &pb.Hash32{V: make([]byte, 32)},
				Seq:     1,
				Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
					ReceivableId:         &pb.Hash32{V: rid[:]},
					AccountClass:         pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
					TransferDestination:  &pb.AccountId{V: dest[:]},
					TransferUnlockEpoch:  100,
					AuthPubkey:           &pb.HybridPubKey{V: srcPub.Encode()},
					BreakglassCommitment: &pb.Hash64{V: srcBG[:]},
				}},
			}
			raw, _ := proto.Marshal(ptx)
			txid := txidFor(chainID, 1)
			if err := db.Update(func(tx *bbolt.Tx) error {
				return ApplyTx(&bboltTxView{tx: tx}, raw, ptx, txid, fund, testEcon, 0)
			}); err != nil {
				t.Fatalf("ApplyTx opening RECEIVE: %v", err)
			}

			var rec AccountRecord
			if err := db.View(func(tx *bbolt.Tx) error {
				r, ok := getAccountRecord(tx, chainID)
				if !ok {
					t.Fatal("chain record missing after apply")
				}
				rec = r
				return nil
			}); err != nil {
				t.Fatalf("read chain: %v", err)
			}
			gotFlag := rec.TransferFlags&transferFlagReleaseRequiresAttestor != 0
			if gotFlag != c.wantFlag {
				t.Errorf("%v source: release_requires_attestor = %v, want %v", c.class, gotFlag, c.wantFlag)
			}
			if rec.TransferSource != srcID || rec.TransferDest != dest || rec.TransferUnlock != 100 {
				t.Error("transfer metadata not stored from committed data")
			}
		})
	}
}

// TestFundSendTxIDByteIdentity pins the CURRENT canonical keyless Fund-SEND txid construction:
// SHA256(sign_bytes || frame(sig2) || multisig_digest). (Pre-forquinn this was byte-identical to
// the pre-P3.2 form; the forquinn §2.3 sig2 fold deliberately inserts an unconditional zero-length
// uint32-LE frame — old txids die at the cutover reset, which is the point.)
func TestFundSendTxIDByteIdentity(t *testing.T) {
	g1, g2 := newGuardian(1), newGuardian(2)
	tx := buildFundSend(testFund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), 100, []*tGuardian{g1, g2})
	got, err := crypto.TxID(tx)
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
	buf := append([]byte{}, sb...)
	buf = append(buf, make([]byte, 4)...) // frame(sig2): absent → zero-length frame
	buf = append(buf, dig...)
	want := sha256.Sum256(buf)
	if got != want {
		t.Error("keyless Fund-SEND txid is not SHA256(sign_bytes || frame(sig2) || multisig_digest)")
	}
}
