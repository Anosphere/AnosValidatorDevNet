package simkit

// Phase-1 round-trip of the new U2 / case-commitment helpers: a guarded opening built by
// BuildGuardedOpeningReceive signs and verifies with a well-formed PoP; the U2 keypair follows
// derived TRANSFER chains (the D2 copy); SignPathARelease produces a U1 Tx.sig + U2 sig2 that
// both verify over the same digest; SetCaseCommitment sets fold-ready 32-byte fields.

import (
	"bytes"
	"testing"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

func TestGuardedOpeningWithU2RoundTrip(t *testing.T) {
	acct := NewAccount(pb.AccountClass_ACCOUNT_CLASS_GUARDED, [32]byte{1}, [32]byte{2}).AttachU2([32]byte{3})
	if !acct.HasU2() || len(acct.U2PubKeyBytes()) != crypto.HybridPubKeySize {
		t.Fatal("AttachU2 did not attach a well-formed U2 keypair")
	}

	var rid [32]byte
	rid[0] = 0x42
	tx, err := BuildGuardedOpeningReceive(acct, rid)
	if err != nil {
		t.Fatalf("BuildGuardedOpeningReceive: %v", err)
	}
	acct.MustSign(tx) // openings are U1-signed
	if err := crypto.VerifyTxSignature(tx, acct.AuthPubKeyBytes()); err != nil {
		t.Fatalf("U1 signature on the guarded opening rejected: %v", err)
	}

	// The carried registration block is well-formed and its PoP verifies over m_u2 —
	// exactly what validate/apply will require in phase 2.
	u2 := tx.GetReceive().GetU2()
	if !bytes.Equal(u2.GetPubkey().GetV(), acct.U2PubKeyBytes()) {
		t.Fatal("opening carries the wrong U2 pubkey")
	}
	m, err := crypto.U2RegistrationDigest(acct.ID, u2.GetPubkey().GetV())
	if err != nil {
		t.Fatalf("U2RegistrationDigest: %v", err)
	}
	pub, err := crypto.ParseHybridPubKey(u2.GetPubkey().GetV())
	if err != nil {
		t.Fatalf("parse carried U2: %v", err)
	}
	sig, err := crypto.ParseHybridSig(u2.GetPopSig().GetV())
	if err != nil {
		t.Fatalf("parse carried PoP: %v", err)
	}
	if !crypto.HybridVerify(pub, m, sig) {
		t.Fatal("carried PoP does not verify over U2RegistrationDigest")
	}

	// Without an attached U2 the builder refuses (a guarded opening REQUIRES one post-cutover).
	bare := NewAccount(pb.AccountClass_ACCOUNT_CLASS_VAULT, [32]byte{7}, [32]byte{8})
	if _, err := BuildGuardedOpeningReceive(bare, rid); err == nil {
		t.Fatal("BuildGuardedOpeningReceive accepted an account with no U2")
	}
}

func TestPathAReleaseSignsBothKeys(t *testing.T) {
	src := NewAccount(pb.AccountClass_ACCOUNT_CLASS_GUARDED, [32]byte{11}, [32]byte{12}).AttachU2([32]byte{13})
	chain := DerivedTransferAccount(src, 2)
	if !chain.HasU2() || !bytes.Equal(chain.U2PubKeyBytes(), src.U2PubKeyBytes()) {
		t.Fatal("derived transfer chain did not copy the source's U2 (D2)")
	}

	var dest [32]byte
	dest[0] = 0x99
	tx := BuildSend(chain, [32]byte{0xAA}, 2, dest, 500, 0)
	if err := SignPathARelease(tx, chain); err != nil {
		t.Fatalf("SignPathARelease: %v", err)
	}

	// Fixed roles (D5): Tx.sig verifies under U1 (the chain's copied auth key)...
	if err := crypto.VerifyTxSignature(tx, chain.AuthPubKeyBytes()); err != nil {
		t.Fatalf("path-(a) Tx.sig does not verify under U1: %v", err)
	}
	// ...and sig2 verifies under U2 over the SAME digest m.
	m, _, err := crypto.MsgHash(tx)
	if err != nil {
		t.Fatalf("MsgHash: %v", err)
	}
	pub2, err := crypto.ParseHybridPubKey(chain.U2PubKeyBytes())
	if err != nil {
		t.Fatalf("parse U2: %v", err)
	}
	s2, err := crypto.ParseHybridSig(tx.GetSig2().GetV())
	if err != nil {
		t.Fatalf("parse sig2: %v", err)
	}
	if !crypto.HybridVerify(pub2, m, s2) {
		t.Fatal("sig2 does not verify under U2 over m")
	}
	// sig2 must NOT verify under U1 (distinct keys, distinct roles).
	pub1, _ := crypto.ParseHybridPubKey(chain.AuthPubKeyBytes())
	if crypto.HybridVerify(pub1, m, s2) {
		t.Fatal("sig2 verified under U1 — U1 and U2 are not distinct")
	}

	// A chain from a U2-less source cannot sign path (a).
	plain := NewAccount(pb.AccountClass_ACCOUNT_CLASS_GUARDED, [32]byte{21}, [32]byte{22})
	if err := SignPathARelease(BuildSend(DerivedTransferAccount(plain, 2), [32]byte{0xAB}, 2, dest, 1, 0), DerivedTransferAccount(plain, 2)); err == nil {
		t.Fatal("SignPathARelease accepted a chain with no U2")
	}
}

func TestSetCaseCommitment(t *testing.T) {
	acct := NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{31}, [32]byte{32})
	var to, nonce, hash [32]byte
	to[0], nonce[0], hash[0] = 1, 2, 3
	tx := BuildSend(acct, [32]byte{}, 2, to, 10, 1000)
	SetCaseCommitment(tx, nonce, hash)
	s := tx.GetSend()
	if !bytes.Equal(s.GetCaseNonce(), nonce[:]) || !bytes.Equal(s.GetAttestationHash(), hash[:]) {
		t.Fatal("SetCaseCommitment did not set both 32-byte fields")
	}
	// Set BEFORE signing: the fields are folded, so the signed tx verifies as built.
	acct.MustSign(tx)
	if err := crypto.VerifyTxSignature(tx, acct.AuthPubKeyBytes()); err != nil {
		t.Fatalf("case-committed send rejected: %v", err)
	}
}
