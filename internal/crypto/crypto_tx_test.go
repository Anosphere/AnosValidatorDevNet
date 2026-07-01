package crypto

// Tx-level tests for the P1.2 hybrid signature path: VerifyTxSignature against a
// resolved hybrid pubkey, and the account-opening RECEIVE registration binding
// (auth pubkey + breakglass commitment folded into the signed preimage, so a
// tampered commitment invalidates the signature — keys-spec §8.3 + binding decision).

import (
	"testing"

	pb "anos/internal/proto"
)

func spendID(pub *HybridPubKey) [32]byte {
	return BaseAccountID(byte(pb.AccountClass_ACCOUNT_CLASS_SPENDING), pub.Encode())
}

func TestVerifyTxSignatureHybridSend(t *testing.T) {
	priv, pub := GenerateHybridKeyFromSeed([32]byte{1, 2, 3})
	id := spendID(pub)
	var to [32]byte
	to[0] = 0x09

	tx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: id[:]},
		Prev:    &pb.Hash32{V: make([]byte, 32)},
		Seq:     2,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: to[:]},
			Amount:       100,
			Fee:          1,
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
		}},
	}
	if err := SignTxHybrid(tx, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(tx.Sig.V) != HybridSigSize {
		t.Fatalf("sig size = %d, want %d", len(tx.Sig.V), HybridSigSize)
	}
	if err := VerifyTxSignature(tx, pub.Encode()); err != nil {
		t.Fatalf("good hybrid sig rejected: %v", err)
	}

	// Tampered signature → reject (then restore).
	orig := tx.Sig.V[0]
	tx.Sig.V[0] ^= 0xFF
	if err := VerifyTxSignature(tx, pub.Encode()); err == nil {
		t.Error("tampered signature accepted")
	}
	tx.Sig.V[0] = orig

	// Verification against the wrong pubkey → reject (defeats AND-verify).
	_, wrong := GenerateHybridKeyFromSeed([32]byte{9, 9, 9})
	if err := VerifyTxSignature(tx, wrong.Encode()); err == nil {
		t.Error("signature accepted against the wrong pubkey")
	}

	// A short/garbage pubkey → reject.
	if err := VerifyTxSignature(tx, []byte{0x01, 0x02}); err == nil {
		t.Error("signature accepted against a malformed pubkey")
	}
}

func TestOpeningReceiveRegistrationBinding(t *testing.T) {
	priv, pub := GenerateHybridKeyFromSeed([32]byte{7})
	_, bgPub := GenerateHybridKeyFromSeed([32]byte{8})
	id := spendID(pub)
	commit := BreakglassCommitment(bgPub.Encode())

	rid := make([]byte, 32)
	rid[0] = 0x42
	tx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: &pb.AccountId{V: id[:]},
		Prev:    &pb.Hash32{V: make([]byte, 32)},
		Seq:     1,
		Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
			ReceivableId:         &pb.Hash32{V: rid},
			AccountClass:         pb.AccountClass_ACCOUNT_CLASS_SPENDING,
			AuthPubkey:           &pb.HybridPubKey{V: pub.Encode()},
			BreakglassCommitment: &pb.Hash64{V: commit[:]},
		}},
	}
	if err := SignTxHybrid(tx, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyTxSignature(tx, pub.Encode()); err != nil {
		t.Fatalf("good opening RECEIVE rejected: %v", err)
	}

	// Tampering the breakglass commitment WITHOUT re-signing must invalidate the
	// signature — it is bound into the signed preimage (the whole point of the
	// binding decision: otherwise a peer could swap it and keep a valid sig/txid).
	tx.GetReceive().BreakglassCommitment.V[0] ^= 0xFF
	if err := VerifyTxSignature(tx, pub.Encode()); err == nil {
		t.Error("tampered breakglass_commitment still verified — binding is broken")
	}
	tx.GetReceive().BreakglassCommitment.V[0] ^= 0xFF // restore

	// Likewise tampering the registered auth pubkey breaks the signature.
	tx.GetReceive().AuthPubkey.V[0] ^= 0xFF
	if err := VerifyTxSignature(tx, pub.Encode()); err == nil {
		t.Error("tampered auth_pubkey still verified — binding is broken")
	}
}

// The proto AccountClass → account-id type_byte mapping must match the canonical
// AccountType* constants for every real class, and fail closed for UNSPECIFIED.
func TestAccountTypeByteForClass(t *testing.T) {
	cases := []struct {
		class pb.AccountClass
		want  byte
	}{
		{pb.AccountClass_ACCOUNT_CLASS_SPENDING, AccountTypeSpending},
		{pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, AccountTypeTimelocked},
		{pb.AccountClass_ACCOUNT_CLASS_GUARDED, AccountTypeGuarded},
		{pb.AccountClass_ACCOUNT_CLASS_VAULT, AccountTypeVault},
		{pb.AccountClass_ACCOUNT_CLASS_TRANSFER, AccountTypeTransfer},
		{pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED, 0},
	}
	for _, c := range cases {
		if got := AccountTypeByteForClass(c.class); got != c.want {
			t.Errorf("AccountTypeByteForClass(%v) = %d, want %d", c.class, got, c.want)
		}
	}
}

// Deterministic seed-derivation must be stable: the same seed yields the same
// pubkey (so the genesis pubkey a validator pins matches what the signer derives).
func TestGenerateHybridKeyFromSeedDeterministic(t *testing.T) {
	_, a := GenerateHybridKeyFromSeed([32]byte{5, 5, 5})
	_, b := GenerateHybridKeyFromSeed([32]byte{5, 5, 5})
	if string(a.Encode()) != string(b.Encode()) {
		t.Error("seed-derived pubkey is not deterministic")
	}
	_, c := GenerateHybridKeyFromSeed([32]byte{6, 6, 6})
	if string(a.Encode()) == string(c.Encode()) {
		t.Error("different seeds produced the same pubkey")
	}
}
