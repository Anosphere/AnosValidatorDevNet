package crypto

// White-box tests for the P0.1 hybrid crypto primitives (keys-spec §5). They are
// in `package crypto` (not `crypto_test`) so they can reach unexported helpers
// and struct fields to corrupt individual halves and forge high-S signatures.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func digest(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func mustKey(t *testing.T) (*HybridPrivateKey, *HybridPubKey) {
	t.Helper()
	priv, pub, err := GenerateHybridKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateHybridKey: %v", err)
	}
	return priv, pub
}

// --- Sizes: the cross-system contract pins exact widths (keys-spec §11). ---

func TestPinnedSizes(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"mldsaPublicKeySize", mldsaPublicKeySize, 2592},
		{"mldsaSignatureSize", mldsaSignatureSize, 4627},
		{"mldsaPrivateKeySize", mldsaPrivateKeySize, 4896},
		{"mldsaSeedSize", mldsaSeedSize, 32},
		{"P256CompressedPubKeySize", P256CompressedPubKeySize, 33},
		{"P256RawSigSize", P256RawSigSize, 64},
		{"HybridPubKeySize", HybridPubKeySize, 2625},
		{"HybridSigSize", HybridSigSize, 4691},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestEncodedLengths(t *testing.T) {
	priv, pub := mustKey(t)
	if got := len(pub.Encode()); got != HybridPubKeySize {
		t.Errorf("pub.Encode len = %d, want %d", got, HybridPubKeySize)
	}
	sig, err := priv.Sign(digest("m"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := len(sig.Encode()); got != HybridSigSize {
		t.Errorf("sig.Encode len = %d, want %d", got, HybridSigSize)
	}
}

// --- Round-trips: encode then decode is the identity on the canonical bytes. ---

func TestHybridPubKeyRoundTrip(t *testing.T) {
	_, pub := mustKey(t)
	enc := pub.Encode()
	parsed, err := ParseHybridPubKey(enc)
	if err != nil {
		t.Fatalf("ParseHybridPubKey: %v", err)
	}
	if !bytes.Equal(enc, parsed.Encode()) {
		t.Error("pubkey round-trip changed bytes")
	}
	// ML-DSA first, P-256 compressed last (33 B, 0x02/0x03 parity prefix).
	if pfx := enc[mldsaPublicKeySize]; pfx != 0x02 && pfx != 0x03 {
		t.Errorf("p256 compressed prefix = 0x%02x, want 0x02/0x03", pfx)
	}
}

func TestHybridSigRoundTrip(t *testing.T) {
	priv, _ := mustKey(t)
	sig, err := priv.Sign(digest("round-trip"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	enc := sig.Encode()
	parsed, err := ParseHybridSig(enc)
	if err != nil {
		t.Fatalf("ParseHybridSig: %v", err)
	}
	if !bytes.Equal(enc, parsed.Encode()) {
		t.Error("sig round-trip changed bytes")
	}
}

// --- Happy path. ---

func TestHybridVerifyAcceptsGoodSig(t *testing.T) {
	priv, pub := mustKey(t)
	m := digest("hello anos")
	sig, err := priv.Sign(m)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !HybridVerify(pub, m, sig) {
		t.Fatal("HybridVerify rejected a valid signature")
	}
	// A signature must survive an encode/decode hop and still verify.
	enc := sig.Encode()
	reparsed, err := ParseHybridSig(enc)
	if err != nil {
		t.Fatalf("ParseHybridSig: %v", err)
	}
	repub, err := ParseHybridPubKey(pub.Encode())
	if err != nil {
		t.Fatalf("ParseHybridPubKey: %v", err)
	}
	if !HybridVerify(repub, m, reparsed) {
		t.Fatal("HybridVerify rejected a re-parsed valid signature")
	}
}

// --- AND semantics: BOTH halves are required (keys-spec §5.4). ---

func TestHybridVerifyRejectsCorruptedMLDSAHalf(t *testing.T) {
	priv, pub := mustKey(t)
	m := digest("corrupt-mldsa")
	sig, _ := priv.Sign(m)
	sig.mldsa[10] ^= 0xFF // flip a byte in the ML-DSA half; P-256 half untouched
	if HybridVerify(pub, m, sig) {
		t.Fatal("accepted a sig with a corrupted ML-DSA half (AND rule violated)")
	}
}

func TestHybridVerifyRejectsCorruptedP256Half(t *testing.T) {
	priv, pub := mustKey(t)
	m := digest("corrupt-p256")
	sig, _ := priv.Sign(m)
	sig.p256[0] ^= 0xFF // flip a byte in the P-256 half; ML-DSA half untouched
	if HybridVerify(pub, m, sig) {
		t.Fatal("accepted a sig with a corrupted P-256 half (AND rule violated)")
	}
}

// Mix-and-match: a valid ML-DSA half from key A with a valid P-256 half from key
// B must NOT verify against either key — proving it is an AND, not an OR.
func TestHybridVerifyRejectsMixedHalves(t *testing.T) {
	m := digest("mixed")
	privA, pubA := mustKey(t)
	privB, pubB := mustKey(t)
	sigA, _ := privA.Sign(m)
	sigB, _ := privB.Sign(m)

	frankenAB := &HybridSig{mldsa: sigA.mldsa, p256: sigB.p256}
	if HybridVerify(pubA, m, frankenAB) {
		t.Fatal("accepted ML-DSA(A)+P256(B) against key A")
	}
	if HybridVerify(pubB, m, frankenAB) {
		t.Fatal("accepted ML-DSA(A)+P256(B) against key B")
	}
	_ = privB
}

func TestHybridVerifyRejectsWrongDigest(t *testing.T) {
	priv, pub := mustKey(t)
	sig, _ := priv.Sign(digest("signed-message"))
	if HybridVerify(pub, digest("other-message"), sig) {
		t.Fatal("accepted a signature over the wrong digest")
	}
}

func TestHybridVerifyRejectsWrongKey(t *testing.T) {
	priv, _ := mustKey(t)
	_, otherPub := mustKey(t)
	m := digest("x")
	sig, _ := priv.Sign(m)
	if HybridVerify(otherPub, m, sig) {
		t.Fatal("accepted a signature under an unrelated public key")
	}
}

// --- Low-S malleability: a high-S P-256 half must be rejected (keys-spec §5.3).
func TestHybridVerifyRejectsHighS(t *testing.T) {
	priv, pub := mustKey(t)
	m := digest("malleable")
	sig, _ := priv.Sign(m)

	// The signer always emits low-S. Forge the malleable twin s' = n - s.
	n := elliptic.P256().Params().N
	r := new(big.Int).SetBytes(sig.p256[:32])
	sLow := new(big.Int).SetBytes(sig.p256[32:])
	if sLow.Cmp(p256HalfOrder) > 0 {
		t.Fatal("signer produced a high-S signature (low-S normalization failed)")
	}
	sHigh := new(big.Int).Sub(n, sLow)
	if sHigh.Cmp(p256HalfOrder) <= 0 {
		t.Fatal("forged twin is not high-S")
	}

	var highRaw [64]byte
	copy(highRaw[:32], sig.p256[:32])
	sHigh.FillBytes(highRaw[32:])

	// The high-S twin is a MATHEMATICALLY VALID ECDSA signature...
	if !ecdsa.Verify(pub.p256, m[:], r, sHigh) {
		t.Fatal("sanity: high-S twin should still satisfy raw ECDSA verification")
	}
	// ...but our canonical verifier must reject it for being non-canonical.
	if verifyP256RawLowS(pub.p256, m, highRaw) {
		t.Fatal("verifyP256RawLowS accepted a high-S signature")
	}
	highSig := &HybridSig{mldsa: sig.mldsa, p256: highRaw}
	if HybridVerify(pub, m, highSig) {
		t.Fatal("HybridVerify accepted a high-S P-256 half")
	}
}

// Every signature the signer emits is low-S over many runs.
func TestSignAlwaysLowS(t *testing.T) {
	priv, _ := mustKey(t)
	for i := 0; i < 64; i++ {
		raw, err := signP256RawLowS(priv.p256, digest(string(rune(i))+"salt"), rand.Reader)
		if err != nil {
			t.Fatalf("signP256RawLowS: %v", err)
		}
		s := new(big.Int).SetBytes(raw[32:])
		if s.Sign() == 0 || s.Cmp(p256HalfOrder) > 0 {
			t.Fatalf("iteration %d: s not in (0, n/2]", i)
		}
	}
}

// --- Structural decode validation. ---

func TestParseRejectsBadLengths(t *testing.T) {
	if _, err := ParseHybridPubKey(make([]byte, HybridPubKeySize-1)); err == nil {
		t.Error("ParseHybridPubKey accepted a short buffer")
	}
	if _, err := ParseHybridPubKey(make([]byte, HybridPubKeySize+1)); err == nil {
		t.Error("ParseHybridPubKey accepted a long buffer")
	}
	if _, err := ParseHybridSig(make([]byte, HybridSigSize-1)); err == nil {
		t.Error("ParseHybridSig accepted a short buffer")
	}
	if _, err := ParseHybridSig(make([]byte, HybridSigSize+1)); err == nil {
		t.Error("ParseHybridSig accepted a long buffer")
	}
}

func TestParseHybridPubKeyRejectsOffCurveP256(t *testing.T) {
	_, pub := mustKey(t)
	enc := pub.Encode()
	bad := make([]byte, len(enc))
	copy(bad, enc)
	// Keep a valid ML-DSA half; replace the P-256 compressed half with a
	// 0x02-prefixed X = all-0xFF (≥ field prime ⇒ not a curve point).
	bad[mldsaPublicKeySize] = 0x02
	for i := mldsaPublicKeySize + 1; i < len(bad); i++ {
		bad[i] = 0xFF
	}
	if _, err := ParseHybridPubKey(bad); err == nil {
		t.Error("ParseHybridPubKey accepted an off-curve P-256 point")
	}
}

// The ML-DSA half is length-only structural: circl validates length, not
// content (an ML-DSA public key has no rejectable content invariant), so a
// garbage-but-correct-length ML-DSA head paired with a VALID P-256 tail must
// PARSE. Rejection of a corrupted ML-DSA key happens at verify time
// (TestHybridVerifyRejectsCorruptedMLDSAHalf), not at parse time. This pins the
// honest decode contract and catches a wrong split offset between the halves.
func TestParseHybridPubKeyMLDSAHalfIsContentUnvalidated(t *testing.T) {
	_, pub := mustKey(t)
	enc := pub.Encode()
	b := make([]byte, len(enc))
	copy(b, enc)
	for i := 0; i < mldsaPublicKeySize; i++ {
		b[i] = 0xAB // clobber the ML-DSA half; keep the valid P-256 compressed tail
	}
	if _, err := ParseHybridPubKey(b); err != nil {
		t.Errorf("ParseHybridPubKey rejected a length-valid ML-DSA half: %v (decode is length-only)", err)
	}
}

// The verify/sign entrypoints guard against nil and malformed structs so a
// caller that hand-builds them from partially-decoded wire data gets a clean
// false/error, never a nil-pointer panic. A regression dropping any guard would
// crash the verify path (a DoS surface), so pin them.
func TestVerifyGuardsRejectMalformedInputs(t *testing.T) {
	priv, pub := mustKey(t)
	m := digest("guards")
	sig, _ := priv.Sign(m)

	if HybridVerify(nil, m, sig) {
		t.Error("HybridVerify accepted a nil public key")
	}
	if HybridVerify(pub, m, nil) {
		t.Error("HybridVerify accepted a nil signature")
	}
	short := &HybridSig{mldsa: make([]byte, mldsaSignatureSize-1), p256: sig.p256}
	if HybridVerify(pub, m, short) {
		t.Error("HybridVerify accepted a wrong-length ML-DSA half")
	}
	if verifyP256RawLowS(nil, m, sig.p256) {
		t.Error("verifyP256RawLowS accepted a nil P-256 public key")
	}
	if verifyP256RawLowS(&ecdsa.PublicKey{}, m, sig.p256) {
		t.Error("verifyP256RawLowS accepted a zero-Curve P-256 public key")
	}
	if _, err := signP256RawLowS(nil, m, rand.Reader); err == nil {
		t.Error("signP256RawLowS signed with a nil private key")
	}
}

// --- Deterministic ML-DSA from a seed underpins reproducible KAT vectors. ---

func TestMLDSASeedDeterminism(t *testing.T) {
	var seed [mldsaSeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	pub1, priv1 := mldsaKeyFromSeed(&seed)
	pub2, _ := mldsaKeyFromSeed(&seed)
	if !bytes.Equal(pub1.bytes(), pub2.bytes()) {
		t.Fatal("same seed produced different ML-DSA public keys")
	}
	// Deterministic (randomized=false) signing is reproducible for KATs.
	m := digest("kat")
	s1, err := mldsaSign(priv1, m[:], false)
	if err != nil {
		t.Fatalf("mldsaSign: %v", err)
	}
	s2, _ := mldsaSign(priv1, m[:], false)
	if !bytes.Equal(s1, s2) {
		t.Fatal("deterministic ML-DSA signing was not reproducible")
	}
	if !mldsaVerify(pub1, m[:], s1) {
		t.Fatal("seed-derived ML-DSA signature failed to verify")
	}
}

// The public half derived from a private key matches the generated public key.
func TestHybridPublicMatchesPrivate(t *testing.T) {
	priv, pub := mustKey(t)
	if !bytes.Equal(priv.Public().Encode(), pub.Encode()) {
		t.Fatal("HybridPrivateKey.Public() disagrees with the generated public key")
	}
}
