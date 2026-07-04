package core

// P1.3 copied-key TRANSFER chains: ValidateTxAgainstSnapshot must accept an opening
// RECEIVE that copies the funding source's auth+breakglass keys and carries the
// creation-nonce DerivedAccountID, and reject a wrong nonce, a non-copied auth pubkey,
// a non-copied breakglass commitment, or a missing/unkeyed source (keys-spec §6.2/§6.4).

import (
	"testing"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// transferOpenFixture builds a TIMELOCKED source, a funding TRANSFER receivable, and a
// matching epoch snapshot. It returns the pieces a test needs to construct an opening
// RECEIVE for the derived chain (and to mutate it for the negative cases).
type transferOpenFixture struct {
	snap    *Snapshot
	srcPriv *crypto.HybridPrivateKey
	srcPub  *crypto.HybridPubKey
	srcID   [32]byte
	srcBG   [64]byte
	rid     [32]byte
	dest    [32]byte
	fromSeq uint64
	unlock  uint64
	chainID [32]byte // correct DerivedAccountID for the source keys + fromSeq
}

func newTransferOpenFixture(t *testing.T) *transferOpenFixture {
	t.Helper()
	srcPriv, srcPub := crypto.GenerateHybridKeyFromSeed([32]byte{1})
	_, srcBGPub := crypto.GenerateHybridKeyFromSeed([32]byte{2})
	tb := crypto.AccountTypeByteForClass(pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED)
	srcID := crypto.BaseAccountID(tb, srcPub.Encode())
	srcBG := crypto.BreakglassCommitment(srcBGPub.Encode())

	const fromSeq = uint64(5)
	chainID := crypto.DerivedAccountID(crypto.AccountTypeTransfer, srcPub.Encode(), srcID, fromSeq)

	var rid, dest [32]byte
	rid[0], dest[0] = 0x42, 0x77

	snap := &Snapshot{Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			srcID: {
				Seq:              fromSeq,
				Class:            pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED,
				AuthPubKey:       srcPub.Encode(),
				BreakglassCommit: srcBG[:],
			},
		},
		Receivables: map[[32]byte]ReceivableSnap{
			rid: {From: srcID, To: chainID, Amount: 100, RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER, FromSeq: fromSeq},
		},
		Epoch:       10,
		DelayEpochs: 6,
	}
	return &transferOpenFixture{
		snap: snap, srcPriv: srcPriv, srcPub: srcPub, srcID: srcID, srcBG: srcBG,
		rid: rid, dest: dest, fromSeq: fromSeq, unlock: 10 + 6 + 1, chainID: chainID,
	}
}

// openTx builds an opening RECEIVE for the given chain id, carrying the given auth
// pubkey + breakglass commitment, signed by signPriv.
func (f *transferOpenFixture) openTx(t *testing.T, acct [32]byte, authPub, bgCommit []byte, signPriv *crypto.HybridPrivateKey) *pb.Tx {
	t.Helper()
	tx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: &pb.AccountId{V: append([]byte(nil), acct[:]...)},
		Prev:    &pb.Hash32{V: make([]byte, 32)},
		Seq:     1,
		Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
			ReceivableId:         &pb.Hash32{V: append([]byte(nil), f.rid[:]...)},
			AccountClass:         pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			TransferDestination:  &pb.AccountId{V: append([]byte(nil), f.dest[:]...)},
			TransferUnlockEpoch:  f.unlock,
			AuthPubkey:           &pb.HybridPubKey{V: authPub},
			BreakglassCommitment: &pb.Hash64{V: bgCommit},
		}},
	}
	if err := crypto.SignTxHybrid(tx, signPriv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tx
}

func TestValidateTransferOpenCopiedKeys(t *testing.T) {
	f := newTransferOpenFixture(t)

	// Positive: copied keys + correct nonce id → accepted.
	good := f.openTx(t, f.chainID, f.srcPub.Encode(), f.srcBG[:], f.srcPriv)
	if _, err := ValidateTxAgainstSnapshot(good, f.snap); err != nil {
		t.Fatalf("correctly derived copied-key TRANSFER opening rejected: %v", err)
	}

	// Wrong nonce: chain id derived with a different send seq → rejected.
	wrongID := crypto.DerivedAccountID(crypto.AccountTypeTransfer, f.srcPub.Encode(), f.srcID, f.fromSeq+1)
	wrongNonce := f.openTx(t, wrongID, f.srcPub.Encode(), f.srcBG[:], f.srcPriv)
	if _, err := ValidateTxAgainstSnapshot(wrongNonce, f.snap); err == nil {
		t.Error("wrong-nonce TRANSFER opening accepted (creation nonce not enforced)")
	}

	// Non-copied auth pubkey: attacker's own keys, id self-consistent with them and
	// signed by the attacker — must still be rejected (chain must copy the source key).
	atkPriv, atkPub := crypto.GenerateHybridKeyFromSeed([32]byte{9})
	atkID := crypto.DerivedAccountID(crypto.AccountTypeTransfer, atkPub.Encode(), f.srcID, f.fromSeq)
	atkTx := f.openTx(t, atkID, atkPub.Encode(), f.srcBG[:], atkPriv)
	if _, err := ValidateTxAgainstSnapshot(atkTx, f.snap); err == nil {
		t.Error("TRANSFER opening with a non-copied auth pubkey accepted (key-copy bypass)")
	}

	// Non-copied breakglass commitment: copied auth key + correct id, but a foreign
	// commitment (signed over, so the sig is valid) → rejected on the copy check.
	otherBG := crypto.BreakglassCommitment(atkPub.Encode())
	badBG := f.openTx(t, f.chainID, f.srcPub.Encode(), otherBG[:], f.srcPriv)
	if _, err := ValidateTxAgainstSnapshot(badBG, f.snap); err == nil {
		t.Error("TRANSFER opening with a non-copied breakglass commitment accepted")
	}

	// Missing/unkeyed source: drop the source from the snapshot → cannot derive/enforce
	// the copy → rejected (fail-closed).
	delete(f.snap.Accounts, f.srcID)
	if _, err := ValidateTxAgainstSnapshot(good, f.snap); err == nil {
		t.Error("TRANSFER opening accepted with the funding source absent from the snapshot")
	}
}
