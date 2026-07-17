package crypto

// Phase-1 (forquinn foundation) tests for the new preimage folds and the TxID sig2 fold:
//
//   - the §2.3 {sig, sig2, multisig} presence matrix produces pairwise-distinct txids (the
//     anti-P1.2 alias/grind regression net);
//   - the D8 hard-length rule: SignBytesACTE/TxID hard-error on every off-size field, so an
//     absorb-shape raw (e.g. a 2689-byte auth_pubkey equal to real_auth‖real_bg) has NO
//     computable preimage/txid instead of aliasing a victim's valid opening;
//   - the U2 registration block and the attestor case commitment are bound to the signature
//     (tamper → verify fails) — the fold-into-preimage discipline;
//   - U2RegistrationDigest (D12) is deterministic, binding, and fail-closed on length.

import (
	"bytes"
	"errors"
	"testing"

	pb "anos/internal/proto"
)

// fill returns n deterministic non-zero bytes seeded by tag (filler signatures/ids: TxID and
// FundMultiSigDigest enforce lengths only, so the matrix does not need verifiable signatures).
func fill(tag byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = tag ^ byte(i*7+1)
	}
	return out
}

func baseMatrixSend() *pb.Tx {
	var acct, to [32]byte
	acct[0], to[0] = 0xA1, 0xB2
	return &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: acct[:]},
		Prev:    &pb.Hash32{V: make([]byte, 32)},
		Seq:     2,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: to[:]},
			Amount:       100,
			Fee:          1000,
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
		}},
	}
}

// TestTxIDPresenceMatrixDistinct pins the §2.3 rule: with an IDENTICAL signed body, every
// {sig, sig2, multisig} presence combination — including the junk rows validate will reject —
// folds to a DISTINCT txid, so no variant can alias another (a swap/strip/attach is always a
// different txid, each independently verifiable; the conflict resolver picks one winner).
func TestTxIDPresenceMatrixDistinct(t *testing.T) {
	sig := &pb.HybridSig{V: fill(0x11, HybridSigSize)}
	sig2 := &pb.HybridSig{V: fill(0x22, HybridSigSize)}
	ms := &pb.HybridMultiSig{Entries: []*pb.HybridSigEntry{{
		SignerId: &pb.AccountId{V: fill(0x33, 32)},
		Sig:      &pb.HybridSig{V: fill(0x44, HybridSigSize)},
	}}}

	shapes := []struct {
		name string
		mut  func(tx *pb.Tx)
	}{
		{"single-sig", func(tx *pb.Tx) { tx.Sig = sig }},
		{"path-a: sig+sig2", func(tx *pb.Tx) { tx.Sig, tx.Sig2 = sig, sig2 }},
		{"path-b: sig+ms", func(tx *pb.Tx) { tx.Sig, tx.MultiSig = sig, ms }},
		{"keyless+ms", func(tx *pb.Tx) { tx.MultiSig = ms }},
		{"junk: sig+sig2+ms", func(tx *pb.Tx) { tx.Sig, tx.Sig2, tx.MultiSig = sig, sig2, ms }},
		{"junk: keyless+sig2", func(tx *pb.Tx) { tx.Sig2 = sig2 }},
		{"junk: keyless+sig2+ms", func(tx *pb.Tx) { tx.Sig2, tx.MultiSig = sig2, ms }},
	}

	seen := make(map[[32]byte]string, len(shapes))
	for _, s := range shapes {
		tx := baseMatrixSend()
		s.mut(tx)
		id, err := TxID(tx)
		if err != nil {
			t.Fatalf("%s: TxID: %v", s.name, err)
		}
		if prev, dup := seen[id]; dup {
			t.Errorf("txid alias: %q and %q share %x", prev, s.name, id[:8])
		}
		seen[id] = s.name
	}

	// The same-sb rule holds on a RECEIVE too: attaching sig2 to a signed RECEIVE is a
	// different txid (a third party attaching one can never squat the original).
	rcv := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: &pb.AccountId{V: fill(0x55, 32)},
		Prev:    &pb.Hash32{V: make([]byte, 32)},
		Seq:     3,
		Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
			ReceivableId: &pb.Hash32{V: fill(0x66, 32)},
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
		}},
		Sig: sig,
	}
	plain, err := TxID(rcv)
	if err != nil {
		t.Fatalf("receive TxID: %v", err)
	}
	rcv.Sig2 = sig2
	withSig2, err := TxID(rcv)
	if err != nil {
		t.Fatalf("receive+sig2 TxID: %v", err)
	}
	if plain == withSig2 {
		t.Error("attaching sig2 to a RECEIVE did not change its txid")
	}
}

// TestTxIDSig2HardLength pins the {0, 4691} rule: an off-size sig2 has no computable txid.
func TestTxIDSig2HardLength(t *testing.T) {
	for _, n := range []int{1, HybridSigSize - 1, HybridSigSize + 1} {
		tx := baseMatrixSend()
		tx.Sig = &pb.HybridSig{V: fill(0x11, HybridSigSize)}
		tx.Sig2 = &pb.HybridSig{V: fill(0x22, n)}
		if _, err := TxID(tx); !errors.Is(err, ErrBadLength) {
			t.Errorf("sig2 len %d: TxID err = %v, want ErrBadLength", n, err)
		}
	}
	// Present-but-empty sig2 message == absent (content-based, matching the folds).
	tx := baseMatrixSend()
	tx.Sig = &pb.HybridSig{V: fill(0x11, HybridSigSize)}
	base, err := TxID(tx)
	if err != nil {
		t.Fatalf("TxID: %v", err)
	}
	tx.Sig2 = &pb.HybridSig{}
	emptyMsg, err := TxID(tx)
	if err != nil {
		t.Fatalf("TxID with empty sig2 message: %v", err)
	}
	if base != emptyMsg {
		t.Error("a present-but-empty sig2 message changed the txid (must classify as absent)")
	}
}

// openingReceive builds a minimal opening RECEIVE carrying the given registration fields
// (any of which may be nil to omit).
func openingReceive(auth, bg, u2pub, u2pop []byte) *pb.Tx {
	body := &pb.TxBodyReceive{
		ReceivableId: &pb.Hash32{V: fill(0x42, 32)},
		AccountClass: pb.AccountClass_ACCOUNT_CLASS_GUARDED,
	}
	if auth != nil {
		body.AuthPubkey = &pb.HybridPubKey{V: auth}
	}
	if bg != nil {
		body.BreakglassCommitment = &pb.Hash64{V: bg}
	}
	if u2pub != nil || u2pop != nil {
		body.U2 = &pb.U2Registration{}
		if u2pub != nil {
			body.U2.Pubkey = &pb.HybridPubKey{V: u2pub}
		}
		if u2pop != nil {
			body.U2.PopSig = &pb.HybridSig{V: u2pop}
		}
	}
	return &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: &pb.AccountId{V: fill(0x77, 32)},
		Prev:    &pb.Hash32{V: make([]byte, 32)},
		Seq:     1,
		Body:    &pb.Tx_Receive{Receive: body},
	}
}

// TestSignBytesHardLengthsReceive pins the D8 rule on the RECEIVE branch: auth_pubkey must be
// {0, 2625}, breakglass_commitment {0, 64}, u2.pubkey {0, 2625}, u2.pop_sig {0, 4691} — anything
// else has no computable preimage. In particular the ABSORB SHAPE — a 2689-byte auth_pubkey equal
// to real_auth‖real_bg, which pre-D8 produced a preimage byte-identical to the victim's valid
// opening (a txid-squat) — now hard-errors.
func TestSignBytesHardLengthsReceive(t *testing.T) {
	auth := fill(0x01, HybridPubKeySize)
	bg := fill(0x02, BreakglassCommitmentSize)
	u2pub := fill(0x03, HybridPubKeySize)
	u2pop := fill(0x04, HybridSigSize)

	// The valid shape computes.
	valid, err := SignBytesACTE(openingReceive(auth, bg, u2pub, u2pop))
	if err != nil {
		t.Fatalf("valid opening preimage: %v", err)
	}

	// The absorb shape: auth' = real_auth‖real_bg (2689 B), no separate bg. Pre-D8 its raw
	// concatenation aliased the victim's bytes; now it must have NO preimage at all.
	absorb := append(append([]byte(nil), auth...), bg...)
	if _, err := SignBytesACTE(openingReceive(absorb, nil, u2pub, u2pop)); !errors.Is(err, ErrBadLength) {
		t.Errorf("absorb-shape auth_pubkey (2689 B): err = %v, want ErrBadLength", err)
	}

	bad := []struct {
		name string
		tx   *pb.Tx
	}{
		{"auth short", openingReceive(auth[:HybridPubKeySize-1], bg, nil, nil)},
		{"auth long", openingReceive(append(append([]byte(nil), auth...), 0xEE), bg, nil, nil)},
		{"bg short", openingReceive(auth, bg[:BreakglassCommitmentSize-1], nil, nil)},
		{"bg long", openingReceive(auth, append(append([]byte(nil), bg...), 0xEE), nil, nil)},
		{"u2 pubkey short", openingReceive(auth, bg, u2pub[:HybridPubKeySize-1], u2pop)},
		{"u2 pubkey long", openingReceive(auth, bg, append(append([]byte(nil), u2pub...), 0xEE), u2pop)},
		{"u2 pop short", openingReceive(auth, bg, u2pub, u2pop[:HybridSigSize-1])},
		{"u2 pop long", openingReceive(auth, bg, u2pub, append(append([]byte(nil), u2pop...), 0xEE))},
	}
	for _, c := range bad {
		if _, err := SignBytesACTE(c.tx); !errors.Is(err, ErrBadLength) {
			t.Errorf("%s: err = %v, want ErrBadLength", c.name, err)
		}
	}

	// The U2 fold is unconditional: a RECEIVE without a U2 block still folds two empty frames,
	// and one WITH a U2 block yields different bytes (present vs absent never alias).
	without, err := SignBytesACTE(openingReceive(auth, bg, nil, nil))
	if err != nil {
		t.Fatalf("no-U2 preimage: %v", err)
	}
	if bytes.Equal(valid, without) {
		t.Error("preimage with a U2 block equals the preimage without one")
	}
}

// TestSignBytesHardLengthsSendCaseFields pins the D8 rule on the SEND branch's case commitment:
// case_nonce / attestation_hash must be {0, 32}; both-present computes and differs from absent.
func TestSignBytesHardLengthsSendCaseFields(t *testing.T) {
	mk := func(nonce, hash []byte) *pb.Tx {
		tx := baseMatrixSend()
		tx.GetSend().CaseNonce = nonce
		tx.GetSend().AttestationHash = hash
		return tx
	}
	nonce := fill(0x0A, CaseFieldSize)
	hash := fill(0x0B, CaseFieldSize)

	absent, err := SignBytesACTE(mk(nil, nil))
	if err != nil {
		t.Fatalf("absent case fields: %v", err)
	}
	present, err := SignBytesACTE(mk(nonce, hash))
	if err != nil {
		t.Fatalf("present case fields: %v", err)
	}
	if bytes.Equal(absent, present) {
		t.Error("case fields did not change the preimage")
	}
	// Swapping the two 32-byte values must change the bytes (frames keep positions fixed, the
	// values differ) — a nonce can never stand in for the attestation hash.
	swapped, err := SignBytesACTE(mk(hash, nonce))
	if err != nil {
		t.Fatalf("swapped case fields: %v", err)
	}
	if bytes.Equal(present, swapped) {
		t.Error("swapping case_nonce and attestation_hash left the preimage unchanged")
	}

	for _, c := range []struct {
		name        string
		nonce, hash []byte
	}{
		{"nonce short", nonce[:CaseFieldSize-1], hash},
		{"nonce long", append(append([]byte(nil), nonce...), 0xEE), hash},
		{"hash short", nonce, hash[:CaseFieldSize-1]},
		{"hash long", nonce, append(append([]byte(nil), hash...), 0xEE)},
	} {
		if _, err := SignBytesACTE(mk(c.nonce, c.hash)); !errors.Is(err, ErrBadLength) {
			t.Errorf("%s: err = %v, want ErrBadLength", c.name, err)
		}
	}
}

// TestU2RegistrationBindsToSignature is the phase-1 signing round-trip: a guarded opening
// carrying a real U2 registration signs and verifies, the PoP verifies over
// U2RegistrationDigest, and tampering EITHER half of the U2 block without re-signing
// invalidates the U1 signature (the fold-into-preimage discipline — a stripped/swapped U2
// changes the bytes U1 signed).
func TestU2RegistrationBindsToSignature(t *testing.T) {
	u1priv, u1pub := GenerateHybridKeyFromSeed([32]byte{0xD1})
	u2priv, u2pub := GenerateHybridKeyFromSeed([32]byte{0xD2})
	_, bgPub := GenerateHybridKeyFromSeed([32]byte{0xD3})
	id := BaseAccountID(AccountTypeGuarded, u1pub.Encode())
	commit := BreakglassCommitment(bgPub.Encode())

	mU2, err := U2RegistrationDigest(id, u2pub.Encode())
	if err != nil {
		t.Fatalf("U2RegistrationDigest: %v", err)
	}
	pop, err := u2priv.Sign(mU2)
	if err != nil {
		t.Fatalf("PoP sign: %v", err)
	}

	tx := openingReceive(u1pub.Encode(), commit[:], u2pub.Encode(), pop.Encode())
	tx.Account = &pb.AccountId{V: id[:]}
	if err := SignTxHybrid(tx, u1priv); err != nil {
		t.Fatalf("sign opening: %v", err)
	}
	if err := VerifyTxSignature(tx, u1pub.Encode()); err != nil {
		t.Fatalf("good guarded opening rejected: %v", err)
	}

	// The PoP verifies against U2 over m_u2 (what validate/apply will check in phase 2).
	pub2, err := ParseHybridPubKey(u2pub.Encode())
	if err != nil {
		t.Fatalf("parse u2: %v", err)
	}
	sig2, err := ParseHybridSig(pop.Encode())
	if err != nil {
		t.Fatalf("parse pop: %v", err)
	}
	if !HybridVerify(pub2, mU2, sig2) {
		t.Fatal("U2 PoP does not verify over U2RegistrationDigest")
	}

	// Tamper the registered U2 pubkey → the opening signature dies.
	tx.GetReceive().U2.Pubkey.V[0] ^= 0xFF
	if err := VerifyTxSignature(tx, u1pub.Encode()); err == nil {
		t.Error("tampered u2.pubkey still verified — the fold is broken")
	}
	tx.GetReceive().U2.Pubkey.V[0] ^= 0xFF

	// Tamper the PoP → the opening signature dies (the PoP bytes are folded too).
	tx.GetReceive().U2.PopSig.V[0] ^= 0xFF
	if err := VerifyTxSignature(tx, u1pub.Encode()); err == nil {
		t.Error("tampered u2.pop_sig still verified — the fold is broken")
	}
	tx.GetReceive().U2.PopSig.V[0] ^= 0xFF

	// Strip the whole block → the signature dies (absent folds as empty frames ≠ present).
	saved := tx.GetReceive().U2
	tx.GetReceive().U2 = nil
	if err := VerifyTxSignature(tx, u1pub.Encode()); err == nil {
		t.Error("stripped U2 block still verified — the fold is broken")
	}
	tx.GetReceive().U2 = saved
}

// TestCaseCommitmentBindsToSignature: every signature over a SEND (the user's and — in phase 3 —
// each attestor's, all over the same m) commits to the case fields: tampering or stripping them
// without re-signing invalidates the signature.
func TestCaseCommitmentBindsToSignature(t *testing.T) {
	priv, pub := GenerateHybridKeyFromSeed([32]byte{0xC1})
	id := BaseAccountID(AccountTypeSpending, pub.Encode())

	tx := baseMatrixSend()
	tx.Account = &pb.AccountId{V: id[:]}
	tx.GetSend().CaseNonce = fill(0x0A, CaseFieldSize)
	tx.GetSend().AttestationHash = fill(0x0B, CaseFieldSize)
	if err := SignTxHybrid(tx, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyTxSignature(tx, pub.Encode()); err != nil {
		t.Fatalf("good case-committed send rejected: %v", err)
	}

	tx.GetSend().CaseNonce[0] ^= 0xFF
	if err := VerifyTxSignature(tx, pub.Encode()); err == nil {
		t.Error("tampered case_nonce still verified — the fold is broken")
	}
	tx.GetSend().CaseNonce[0] ^= 0xFF

	saved := tx.GetSend().AttestationHash
	tx.GetSend().AttestationHash = nil
	if err := VerifyTxSignature(tx, pub.Encode()); err == nil {
		t.Error("stripped attestation_hash still verified — the fold is broken")
	}
	tx.GetSend().AttestationHash = saved
}

// TestU2RegistrationDigestVector pins determinism, binding, and the length guard.
func TestU2RegistrationDigestVector(t *testing.T) {
	var idA, idB [32]byte
	idA[0], idB[0] = 1, 2
	pubA := fill(0x51, HybridPubKeySize)
	pubB := fill(0x52, HybridPubKeySize)

	d1, err := U2RegistrationDigest(idA, pubA)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	d2, _ := U2RegistrationDigest(idA, pubA)
	if d1 != d2 {
		t.Error("U2RegistrationDigest is not deterministic")
	}
	dOtherID, _ := U2RegistrationDigest(idB, pubA)
	if d1 == dOtherID {
		t.Error("digest does not bind the account id (PoP would be replayable across accounts)")
	}
	dOtherPub, _ := U2RegistrationDigest(idA, pubB)
	if d1 == dOtherPub {
		t.Error("digest does not bind the U2 pubkey")
	}
	if _, err := U2RegistrationDigest(idA, pubA[:HybridPubKeySize-1]); !errors.Is(err, ErrBadLength) {
		t.Errorf("short pubkey: err = %v, want ErrBadLength", err)
	}
}
