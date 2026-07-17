package core

// forquinn phase 3 — the attestor case commitment (forquinn item 2).
//
// Pins the case-field presence matrix at the consensus authority (ValidateTxAgainstSnapshot)
// with the ApplyTx lockstep mirror (resync replays apply WITHOUT validate) and the submit gate:
//   - Path (b) — the flag-set release WITHOUT a sig2, incl. the breakglass hop-2 — REQUIRES
//     both exact-32-byte fields (case_nonce + attestation_hash); contents are opaque.
//   - Both fields are folded into the signed preimage, so m — and therefore the user signature
//     AND every attestor signature — commits to them: stripping them breaks the user sig, and an
//     attestor quorum gathered over different case fields does not verify (m differs).
//   - Content-based reject on every OTHER SEND shape: normal/stake sends, keyless Fund sends,
//     escrow outflows, flag-unset (plain timelocked) releases — completing the shapes phase 2
//     already rejected (cancels, guarded/vault hop-1 sends, path-(a) releases).
//   - A wrong-LENGTH field has no computable preimage/txid anywhere (the D8 hard-length rule in
//     SignBytesACTE), so wrong-length shapes assert the crypto error; only {0, 32} shapes ever
//     reach validate.
//
// The phase-2 rows of the matrix (path (a) + cancel + hop-1 rejects) stay pinned in
// u2_spend_test.go; the breakglass §2.6 row is pinned in breakglass_test.go.

import (
	"bytes"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

// setTestCaseFields stamps a deterministic 32-byte case commitment onto a SEND body. Call it
// BEFORE signing — both fields are folded into the signed preimage (crypto.SignBytesACTE).
func setTestCaseFields(tx *pb.Tx) {
	s := tx.GetSend()
	s.CaseNonce = bytes.Repeat([]byte{0xca}, crypto.CaseFieldSize)
	s.AttestationHash = bytes.Repeat([]byte{0xa4}, crypto.CaseFieldSize)
}

// --- validate: path (b) requires the commitment; every signature commits to it ---

func TestCaseCommitmentPathBValidate(t *testing.T) {
	t.Run("accept path (b) with both fields", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		tx := f.releaseTxCase(t, f.dest)
		attachAttestorMultiSig(t, tx, f.a1, f.a2)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Fatalf("case-carrying path (b) release rejected: %v", err)
		}
	})

	t.Run("reject path (b) without case fields", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		tx := f.releaseTx(t, f.dest) // fieldless
		attachAttestorMultiSig(t, tx, f.a1, f.a2)
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "must carry a 32-byte case_nonce", "path (b) without the case commitment")
	})

	t.Run("reject path (b) with only case_nonce", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		tx := f.unsignedReleaseTx(f.dest)
		tx.GetSend().CaseNonce = bytes.Repeat([]byte{0xca}, crypto.CaseFieldSize) // hash absent
		if err := crypto.SignTxHybrid(tx, f.chainPriv); err != nil {
			t.Fatalf("sign: %v", err)
		}
		attachAttestorMultiSig(t, tx, f.a1, f.a2)
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "must carry a 32-byte case_nonce", "path (b) with only one case field")
	})

	t.Run("reject path (b) with only attestation_hash", func(t *testing.T) {
		f := newReleaseFixture(t, true)
		tx := f.unsignedReleaseTx(f.dest)
		tx.GetSend().AttestationHash = bytes.Repeat([]byte{0xa4}, crypto.CaseFieldSize) // nonce absent
		if err := crypto.SignTxHybrid(tx, f.chainPriv); err != nil {
			t.Fatalf("sign: %v", err)
		}
		attachAttestorMultiSig(t, tx, f.a1, f.a2)
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "must carry a 32-byte case_nonce", "path (b) with only one case field")
	})

	t.Run("attestor quorum over different case fields does not verify", func(t *testing.T) {
		// The commitment property itself: attestors signed m(decoy fields), the submitted release
		// carries different fields → different m → zero verifying attestor signatures → reject.
		// An attestor signature gathered for one moderation case cannot be replayed onto another.
		f := newReleaseFixture(t, true)
		decoy := f.unsignedReleaseTx(f.dest)
		decoy.GetSend().CaseNonce = bytes.Repeat([]byte{0x01}, crypto.CaseFieldSize)
		decoy.GetSend().AttestationHash = bytes.Repeat([]byte{0x02}, crypto.CaseFieldSize)
		attachAttestorMultiSig(t, decoy, f.a1, f.a2) // full quorum — but over m(decoy)

		tx := f.releaseTxCase(t, f.dest) // different fields, valid user sig over m(tx)
		tx.MultiSig = decoy.MultiSig
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Fatal("attestor quorum signed over DIFFERENT case fields accepted (m must commit to them)")
		}
	})

	t.Run("stripped case fields break the user signature", func(t *testing.T) {
		// The fold binding (the P1.2 lesson): the fields are inside the signed preimage, so
		// stripping them in flight invalidates the already-made signatures — not merely the
		// presence rule.
		f := newReleaseFixture(t, true)
		tx := f.releaseTxCase(t, f.dest)
		attachAttestorMultiSig(t, tx, f.a1, f.a2)
		tx.GetSend().CaseNonce = nil
		tx.GetSend().AttestationHash = nil
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Fatal("release with stripped case fields accepted (fold must bind them to the signatures)")
		}
	})

	t.Run("wrong-length case field has no computable preimage", func(t *testing.T) {
		// D8 hard-length rule: a 31-byte field hard-errors SignBytesACTE, so there is no m and no
		// txid anywhere — validate can only reject (it cannot even resolve a signature over it).
		f := newReleaseFixture(t, true)
		tx := f.unsignedReleaseTx(f.dest)
		tx.GetSend().CaseNonce = make([]byte, crypto.CaseFieldSize-1)
		tx.GetSend().AttestationHash = bytes.Repeat([]byte{0xa4}, crypto.CaseFieldSize)
		if _, _, err := crypto.MsgHash(tx); err == nil {
			t.Fatal("MsgHash computed a preimage over a 31-byte case_nonce (D8 hard-length rule broken)")
		}
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Fatal("wrong-length case field accepted at validate")
		}
	})
}

// --- validate: content-based reject on every other SEND shape (the phase-3 rows) ---

func TestCaseFieldsRejectedEverywhereElseValidate(t *testing.T) {
	t.Run("normal send", func(t *testing.T) {
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_SPENDING, 0xd0)
		var head, to [32]byte
		head[0], to[0] = 0x81, 0x82
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
		setTestCaseFields(tx)
		if err := crypto.SignTxHybrid(tx, a.priv); err != nil {
			t.Fatalf("sign: %v", err)
		}
		_, err := ValidateTxAgainstSnapshot(tx, snap)
		wantErrContaining(t, err, "normal send must not carry attestor case fields", "case fields on a normal send")
	})

	t.Run("stake send to the Fund", func(t *testing.T) {
		// An otherwise-VALID direct stake deposit (SPENDING → Fund, tagged, tiered) carrying the
		// fields — proves the reject covers the whole normal-send arm, not just plain payments.
		a := newTU2Account(pb.AccountClass_ACCOUNT_CLASS_SPENDING, 0xd1)
		var head [32]byte
		head[0] = 0x83
		amt := anosUnits(6_000)
		snap := &Snapshot{Econ: testEcon,
			Accounts: map[[32]byte]AccountSnap{
				a.id: {Head: head, Balance: 2 * amt, Seq: 1, Class: a.class, AuthPubKey: a.pub.Encode()},
			},
			FundAccount: testFund,
		}
		tx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: a.id[:]},
			Prev: &pb.Hash32{V: head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: testFund[:]}, Amount: amt, Fee: ExpectedFee(amt), AccountClass: a.class,
				StakedFor: StakedForAttestor, TimeDelay: oneMonth,
			}},
		}
		setTestCaseFields(tx)
		if err := crypto.SignTxHybrid(tx, a.priv); err != nil {
			t.Fatalf("sign: %v", err)
		}
		_, err := ValidateTxAgainstSnapshot(tx, snap)
		wantErrContaining(t, err, "normal send must not carry attestor case fields", "case fields on a stake deposit")
	})

	t.Run("keyless fund send", func(t *testing.T) {
		var head, to [32]byte
		head[0], to[0] = 0x84, 0x85
		snap := &Snapshot{Econ: testEcon,
			Accounts: map[[32]byte]AccountSnap{
				testFund: {Head: head, Balance: 1_000_000, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_FUND},
			},
			FundAccount: testFund,
		}
		signer := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xd2}, [32]byte{0xd3})
		tx := simkit.BuildFundSend(testFund, head, 2, to, 100, 0)
		setTestCaseFields(tx)
		if err := simkit.SignFundSend(tx, []*simkit.Account{signer}); err != nil {
			t.Fatalf("sign fund send: %v", err)
		}
		_, err := ValidateTxAgainstSnapshot(tx, snap)
		wantErrContaining(t, err, "fund send must not carry attestor case fields", "case fields on a keyless Fund send")
	})

	t.Run("escrow outflow", func(t *testing.T) {
		var dest [32]byte
		dest[0] = 0x86
		f := newEscrowOutFixture(t, false, 0)
		tx := f.outflowTx(dest)
		setTestCaseFields(tx)
		attachEscrowMultiSig(t, tx, f.lo, f.hi) // valid 2-of-2 over m (fields folded)
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "escrow outflow must not carry attestor case fields", "case fields on an escrow outflow")
	})

	t.Run("flag-unset timelocked release", func(t *testing.T) {
		f := newReleaseFixture(t, false) // plain TIMELOCKED chain, never attestor-gated
		tx := f.releaseTxCase(t, f.dest)
		_, err := ValidateTxAgainstSnapshot(tx, f.snap)
		wantErrContaining(t, err, "not attestor-gated: must not carry attestor case fields", "case fields on a flag-unset release")
	})
}

// --- ApplyTx lockstep (resync replays apply WITHOUT validate) ---

func TestCaseCommitmentApplyLockstep(t *testing.T) {
	var src, dest [32]byte
	src[0], dest[0] = 0x91, 0x92

	seedChain := func(t *testing.T, db *bbolt.DB, id, head [32]byte, bal uint64, flags byte) {
		t.Helper()
		if err := db.Update(func(tx *bbolt.Tx) error {
			return putAccountRecord(tx, id, AccountRecord{
				Head: head, Balance: bal, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
				TransferSource: src, TransferDest: dest, TransferUnlock: 5, TransferFlags: flags,
			})
		}); err != nil {
			t.Fatalf("seed chain: %v", err)
		}
	}
	buildSend := func(acct, head, to [32]byte, amt, fee uint64, class pb.AccountClass, withCase bool) *pb.Tx {
		tx := &pb.Tx{
			Type: pb.TxType_TX_TYPE_SEND, Account: &pb.AccountId{V: acct[:]},
			Prev: &pb.Hash32{V: head[:]}, Seq: 2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To: &pb.AccountId{V: to[:]}, Amount: amt, Fee: fee, AccountClass: class,
			}},
		}
		if withCase {
			setTestCaseFields(tx)
		}
		return tx
	}
	applyOne := func(t *testing.T, db *bbolt.DB, tx *pb.Tx) error {
		t.Helper()
		raw, _ := proto.Marshal(tx)
		var acct [32]byte
		copy(acct[:], tx.Account.V)
		return db.Update(func(dbtx *bbolt.Tx) error {
			return ApplyTx(&bboltTxView{tx: dbtx}, raw, tx, txidFor(acct, tx.Seq), testFund, testEcon, 9)
		})
	}
	wantApplyReject := func(t *testing.T, err error, frag, what string) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: ApplyTx accepted, want reject containing %q (lockstep broken)", what, frag)
		}
		if !bytes.Contains([]byte(err.Error()), []byte(frag)) {
			t.Fatalf("%s: ApplyTx rejected with %q, want the %q rule", what, err, frag)
		}
	}

	t.Run("path (b) with fields applies clean", func(t *testing.T) {
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var chainID, head [32]byte
		chainID[0], head[0] = 0x93, 0x94
		seedChain(t, db, chainID, head, 1000, transferFlagReleaseRequiresAttestor)
		if err := applyOne(t, db, buildSend(chainID, head, dest, 1000, 0, pb.AccountClass_ACCOUNT_CLASS_TRANSFER, true)); err != nil {
			t.Fatalf("apply case-carrying release: %v", err)
		}
		_ = db.View(func(dbtx *bbolt.Tx) error {
			rec, _ := getAccountRecord(dbtx, chainID)
			if rec.Balance != 0 || rec.Seq != 2 {
				t.Errorf("release did not apply (balance=%d seq=%d)", rec.Balance, rec.Seq)
			}
			return nil
		})
	})

	t.Run("path (b) without fields rejected", func(t *testing.T) {
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var chainID, head [32]byte
		chainID[0], head[0] = 0x95, 0x96
		seedChain(t, db, chainID, head, 1000, transferFlagReleaseRequiresAttestor)
		err := applyOne(t, db, buildSend(chainID, head, dest, 1000, 0, pb.AccountClass_ACCOUNT_CLASS_TRANSFER, false))
		wantApplyReject(t, err, "must carry a 32-byte case_nonce", "fieldless attestor release at apply")
	})

	t.Run("path (b) with one field rejected", func(t *testing.T) {
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var chainID, head [32]byte
		chainID[0], head[0] = 0x97, 0x98
		seedChain(t, db, chainID, head, 1000, transferFlagReleaseRequiresAttestor)
		tx := buildSend(chainID, head, dest, 1000, 0, pb.AccountClass_ACCOUNT_CLASS_TRANSFER, false)
		tx.GetSend().CaseNonce = bytes.Repeat([]byte{0xca}, crypto.CaseFieldSize)
		err := applyOne(t, db, tx)
		wantApplyReject(t, err, "must carry a 32-byte case_nonce", "half-fielded attestor release at apply")
	})

	t.Run("sig2 release with fields rejected as path (a)", func(t *testing.T) {
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var chainID, head [32]byte
		chainID[0], head[0] = 0x99, 0x9a
		seedChain(t, db, chainID, head, 1000, transferFlagReleaseRequiresAttestor)
		tx := buildSend(chainID, head, dest, 1000, 0, pb.AccountClass_ACCOUNT_CLASS_TRANSFER, true)
		tx.Sig2 = &pb.HybridSig{V: make([]byte, crypto.HybridSigSize)}
		err := applyOne(t, db, tx)
		wantApplyReject(t, err, "path (a) release must not carry attestor case fields", "sig2+fields release at apply")
	})

	t.Run("flag-unset release with fields rejected", func(t *testing.T) {
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var chainID, head [32]byte
		chainID[0], head[0] = 0x9b, 0x9c
		seedChain(t, db, chainID, head, 1000, 0)
		err := applyOne(t, db, buildSend(chainID, head, dest, 1000, 0, pb.AccountClass_ACCOUNT_CLASS_TRANSFER, true))
		wantApplyReject(t, err, "must not carry attestor case fields", "flag-unset release with fields at apply")
	})

	t.Run("return-to-source with fields rejected", func(t *testing.T) {
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var chainID, head [32]byte
		chainID[0], head[0] = 0x9d, 0x9e
		seedChain(t, db, chainID, head, 1000, transferFlagReleaseRequiresAttestor)
		err := applyOne(t, db, buildSend(chainID, head, src, 1000, 0, pb.AccountClass_ACCOUNT_CLASS_TRANSFER, true))
		wantApplyReject(t, err, "return-to-source must not carry attestor case fields", "cancel with fields at apply")
	})

	t.Run("normal send with fields rejected", func(t *testing.T) {
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var acct, head, to [32]byte
		acct[0], head[0], to[0] = 0x9f, 0xa0, 0xa1
		seedSpending(t, db, acct, head, 1_000_000, 1)
		const amt = uint64(100)
		err := applyOne(t, db, buildSend(acct, head, to, amt, ExpectedFee(amt), pb.AccountClass_ACCOUNT_CLASS_SPENDING, true))
		wantApplyReject(t, err, "must not carry attestor case fields", "normal send with fields at apply")
	})

	t.Run("guarded send with fields rejected", func(t *testing.T) {
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var acct, head, to [32]byte
		acct[0], head[0], to[0] = 0xa2, 0xa3, 0xa5
		if err := db.Update(func(tx *bbolt.Tx) error {
			return putAccountRecord(tx, acct, AccountRecord{
				Head: head, Balance: 1_000_000, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_GUARDED,
			})
		}); err != nil {
			t.Fatal(err)
		}
		const amt = uint64(100)
		err := applyOne(t, db, buildSend(acct, head, to, amt, ExpectedFee(amt), pb.AccountClass_ACCOUNT_CLASS_GUARDED, true))
		wantApplyReject(t, err, "guarded/vault send must not carry attestor case fields", "guarded hop-1 with fields at apply")
	})

	t.Run("fund send with fields rejected", func(t *testing.T) {
		db := newFundTestDB(t)
		fh := seedFundRecord(t, db, testFund)
		var to [32]byte
		to[0] = 0xa6
		err := applyOne(t, db, buildSend(testFund, fh, to, 0, 0, pb.AccountClass_ACCOUNT_CLASS_FUND, true))
		wantApplyReject(t, err, "must not carry attestor case fields", "fund send with fields at apply")
	})

	t.Run("escrow outflow with fields rejected", func(t *testing.T) {
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var esc, head, to [32]byte
		esc[0], head[0], to[0] = 0xa7, 0xa8, 0xa9
		if err := db.Update(func(tx *bbolt.Tx) error {
			return putAccountRecord(tx, esc, AccountRecord{
				Head: head, Balance: 777, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_ESCROW,
			})
		}); err != nil {
			t.Fatal(err)
		}
		err := applyOne(t, db, buildSend(esc, head, to, 777, 0, pb.AccountClass_ACCOUNT_CLASS_ESCROW, true))
		wantApplyReject(t, err, "must not carry attestor case fields", "escrow outflow with fields at apply")
	})
}

// --- submit gate: the attestor path requires the fields (bestEffortReleaseCheck) ---

func TestBestEffortReleaseCheckPathBCase(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t), newTValidator(t), newTValidator(t)})
	// The gate enforces the CONFIGURED flat M (D11 site 2); run it at the production floor.
	e.cfg.AttestorQuorumM = 2
	f := newReleaseFixture(t, true)

	// Materialize the chain at its position + both resolvable staked attestors (the gate
	// enforces the configured M=2, so a deferring release needs a full quorum resolvable).
	cs := f.snap.Accounts[f.chainID]
	if err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := putAccountRecord(tx, f.chainID, AccountRecord{
			Head: cs.Head, Balance: cs.Balance, Seq: cs.Seq, Class: cs.Class,
			TransferSource: cs.TransferSource, TransferDest: cs.TransferDest,
			TransferUnlock: cs.TransferUnlock, TransferFlags: cs.TransferFlags,
			AuthPubKey: cs.AuthPubKey,
		}); err != nil {
			return err
		}
		for i, a := range []*tAttestor{f.a1, f.a2} {
			if err := putAccountRecord(tx, a.id, AccountRecord{
				Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: a.pub.Encode(),
			}); err != nil {
				return err
			}
			row := attestorStake(a, byte(0x31+i), 5_000)
			if err := putStakeRecord(tx, row.DepositTxid, row.StakeRecord); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("fieldless attestor release rejected", func(t *testing.T) {
		tx := f.releaseTx(t, f.dest)
		attachAttestorMultiSig(t, tx, f.a1)
		err := e.bestEffortReleaseCheck(tx)
		if err == nil {
			t.Fatal("fieldless attestor release deferred at the gate (can never finalize — must reject)")
		}
		if !bytes.Contains([]byte(err.Error()), []byte("must carry a 32-byte case_nonce")) {
			t.Fatalf("gate rejected with %q, want the case-commitment rule", err)
		}
	})

	t.Run("half-fielded release rejected", func(t *testing.T) {
		tx := f.unsignedReleaseTx(f.dest)
		tx.GetSend().CaseNonce = bytes.Repeat([]byte{0xca}, crypto.CaseFieldSize)
		if err := crypto.SignTxHybrid(tx, f.chainPriv); err != nil {
			t.Fatal(err)
		}
		attachAttestorMultiSig(t, tx, f.a1)
		if err := e.bestEffortReleaseCheck(tx); err == nil {
			t.Fatal("half-fielded attestor release deferred at the gate (must reject)")
		}
	})

	t.Run("case-carrying release defers", func(t *testing.T) {
		tx := f.releaseTxCase(t, f.dest)
		attachAttestorMultiSig(t, tx, f.a1, f.a2) // a full configured-M quorum resolvable locally
		if err := e.bestEffortReleaseCheck(tx); err != nil {
			t.Fatalf("legit case-carrying release rejected at the gate: %v", err)
		}
	})

	// D11 site 2: the gate enforces the CONFIGURED M (2), not the old hardcoded N>=1 floor —
	// a single attestor signature no longer squeaks past submit.
	t.Run("sub-M release rejected at the gate", func(t *testing.T) {
		tx := f.releaseTxCase(t, f.dest)
		attachAttestorMultiSig(t, tx, f.a1) // 1 < configured M=2
		err := e.bestEffortReleaseCheck(tx)
		if err == nil {
			t.Fatal("1-of-2 attestor release deferred at the gate (must enforce the configured M)")
		}
		if !bytes.Contains([]byte(err.Error()), []byte("< required 2")) {
			t.Fatalf("gate rejected with %q, want the configured-M threshold", err)
		}
	})

	// D11 site 3 reaches the gate too: an unconfigured (0) M fails closed even with a full
	// valid quorum attached.
	t.Run("unconfigured M fails closed at the gate", func(t *testing.T) {
		saved := e.cfg.AttestorQuorumM
		e.cfg.AttestorQuorumM = 0
		defer func() { e.cfg.AttestorQuorumM = saved }()
		tx := f.releaseTxCase(t, f.dest)
		attachAttestorMultiSig(t, tx, f.a1, f.a2)
		if err := e.bestEffortReleaseCheck(tx); err == nil {
			t.Fatal("M=0 release deferred at the gate (a missing quorum config must fail closed)")
		}
	})

	t.Run("not-at-position defers", func(t *testing.T) {
		tx := f.unsignedReleaseTx(f.dest)
		tx.Prev = &pb.Hash32{V: make([]byte, 32)} // wrong prev — the node can't judge
		if err := crypto.SignTxHybrid(tx, f.chainPriv); err != nil {
			t.Fatal(err)
		}
		attachAttestorMultiSig(t, tx, f.a1)
		if err := e.bestEffortReleaseCheck(tx); err != nil {
			t.Fatalf("not-at-position fieldless release must defer: %v", err)
		}
	})
}
