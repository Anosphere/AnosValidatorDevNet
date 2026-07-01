package crypto

// hybrid.go implements Anos namespace-A (account auth) and namespace-B
// (breakglass) keys: a post-quantum HYBRID of ML-DSA-87 and ECDSA-P-256 whose
// signatures verify under the AND rule, so an account survives a complete break
// of EITHER algorithm. See "Anos Keys, Signatures & Account-ID Spec" §5.
//
// Canonical encodings (keys-spec §5.2/§5.3, sizes §11), bare concatenation with
// ML-DSA first and no framing (both components are fixed-length):
//
//	HybridPubKey = mldsa87_pub(2592) ‖ p256_pub_compressed(33)        = 2625 B
//	HybridSig    = mldsa87_sig(4627)  ‖ p256_sig_raw(64, low-S r‖s)   = 4691 B
//
// The P-256 signature half is a FIXED-WIDTH, LOW-S-CANONICAL raw r‖s — not DER.
// This removes both length-variability and S-malleability, which matters because
// txid = SHA-256(sign_bytes ‖ sig): a malleable signature would yield a second
// valid txid for the same logical tx (keys-spec §5.3). Verifiers MUST reject
// non-canonical (high-S) signatures; HybridVerify does.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"
)

// Public-key / signature half sizes and the hybrid totals (keys-spec §11).
const (
	P256CompressedPubKeySize = 33 // SEC1 compressed point (CompressP256PublicKey)
	P256RawSigSize           = 64 // r(32 BE) ‖ s(32 BE), low-S canonical

	HybridPubKeySize = mldsaPublicKeySize + P256CompressedPubKeySize // 2625
	HybridSigSize    = mldsaSignatureSize + P256RawSigSize           // 4691
)

// ErrNotOnCurve is returned when a compressed P-256 point fails to decompress to
// a valid curve point.
var ErrNotOnCurve = errors.New("p256 public key point is not on curve")

// p256HalfOrder = floor(N/2). Low-S canonical requires s ≤ p256HalfOrder
// (keys-spec §5.3); a signature with s above it is rejected as non-canonical.
var p256HalfOrder = new(big.Int).Rsh(elliptic.P256().Params().N, 1)

// HybridPubKey is an account auth or breakglass public key (namespace A / B):
// an ML-DSA-87 public key paired with a compressed P-256 public key.
type HybridPubKey struct {
	mldsa mldsaPublicKey
	p256  *ecdsa.PublicKey
}

// HybridSig is an account signature: an ML-DSA-87 signature paired with a
// fixed-width low-S raw P-256 signature, both over the same 32-byte digest.
type HybridSig struct {
	mldsa []byte   // mldsaSignatureSize bytes
	p256  [64]byte // r‖s, low-S canonical
}

// HybridPrivateKey holds both secret halves. ML-DSA cannot be enclave-backed, so
// the hybrid secret is software-resident (keys-spec §10); only the P-256 half
// could be hardware-backed in a later integration.
type HybridPrivateKey struct {
	mldsa mldsaPrivateKey
	p256  *ecdsa.PrivateKey
}

// --------------------
// Key generation
// --------------------

// GenerateHybridKey draws a fresh hybrid keypair (ML-DSA-87 + ECDSA-P-256) from
// rng. Pass crypto/rand.Reader in production.
func GenerateHybridKey(rng io.Reader) (*HybridPrivateKey, *HybridPubKey, error) {
	mlPub, mlPriv, err := mldsaGenerateKey(rng)
	if err != nil {
		return nil, nil, err
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rng)
	if err != nil {
		return nil, nil, err
	}
	priv := &HybridPrivateKey{mldsa: mlPriv, p256: ecPriv}
	pub := &HybridPubKey{mldsa: mlPub, p256: &ecPriv.PublicKey}
	return priv, pub, nil
}

// Public returns the public half of a hybrid private key.
func (k *HybridPrivateKey) Public() *HybridPubKey {
	return &HybridPubKey{mldsa: k.mldsa.public(), p256: &k.p256.PublicKey}
}

// GenerateHybridKeyFromSeed deterministically derives a hybrid keypair from a
// 32-byte seed. Both halves are reproducible from the seed alone: the ML-DSA-87
// half via FIPS 204 seed expansion, and the P-256 half via a domain-separated
// scalar reduced from a full SHA-512 digest. This lets reproducible bootstrap and
// test material (the genesis distribution key, simulator accounts, breakglass
// keys) be pinned by a small 32-byte seed rather than a multi-KB private-key blob:
// the public half is re-derived identically wherever the seed is known.
// Production account keys use GenerateHybridKey (fresh entropy); this is bootstrap
// / test only — anyone holding the seed holds the private key.
func GenerateHybridKeyFromSeed(seed [32]byte) (*HybridPrivateKey, *HybridPubKey) {
	var mlSeed [mldsaSeedSize]byte
	mlExpand := sha512.Sum512(append([]byte("ANOSv2-HybridSeed-MLDSA\x00"), seed[:]...))
	copy(mlSeed[:], mlExpand[:mldsaSeedSize])
	mlPub, mlPriv := mldsaKeyFromSeed(&mlSeed)

	ecPriv := p256PrivateKeyFromSeed(seed, "ANOSv2-HybridSeed-P256\x00")

	priv := &HybridPrivateKey{mldsa: mlPriv, p256: ecPriv}
	pub := &HybridPubKey{mldsa: mlPub, p256: &ecPriv.PublicKey}
	return priv, pub
}

// p256PrivateKeyFromSeed derives a deterministic P-256 private key: the scalar
// d = (SHA-512(domain ‖ seed) mod (n-1)) + 1, which guarantees d ∈ [1, n-1].
// Reducing a 512-bit digest modulo the 256-bit group order leaves only negligible
// modulo bias. Deterministic and Go-version-independent (it does not rely on
// ecdsa.GenerateKey's internal rejection sampling).
func p256PrivateKeyFromSeed(seed [32]byte, domain string) *ecdsa.PrivateKey {
	curve := elliptic.P256()
	n := curve.Params().N
	full := sha512.Sum512(append([]byte(domain), seed[:]...))
	d := new(big.Int).SetBytes(full[:])
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = d
	priv.PublicKey.Curve = curve
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	return priv
}

// --------------------
// HybridPubKey encode / decode
// --------------------

// Encode returns the canonical HybridPubKeySize-byte form (ML-DSA pub ‖ P-256
// compressed pub). This exact byte string is the `keyblob` hashed into the
// account-id (keys-spec §6) and registered/cached on the account's first block.
func (h *HybridPubKey) Encode() []byte {
	out := make([]byte, 0, HybridPubKeySize)
	out = append(out, h.mldsa.bytes()...)
	comp := CompressP256PublicKey(h.p256)
	out = append(out, comp[:]...)
	return out
}

// ParseHybridPubKey decodes a canonical HybridPubKey. The ML-DSA half is
// length-checked and structurally unpacked — circl validates length only, since
// an ML-DSA public key has no content invariant to reject (any correct-length
// blob unpacks); a malformed ML-DSA key is caught at verify time, not here. The
// P-256 half is decompressed and validated to be on-curve. A wrong total length,
// or an off-curve / malformed P-256 point, is rejected.
func ParseHybridPubKey(b []byte) (*HybridPubKey, error) {
	if len(b) != HybridPubKeySize {
		return nil, ErrBadLength
	}
	mlPub, err := mldsaPublicKeyFromBytes(b[:mldsaPublicKeySize])
	if err != nil {
		return nil, err
	}
	ecPub, err := decompressP256(b[mldsaPublicKeySize:])
	if err != nil {
		return nil, err
	}
	return &HybridPubKey{mldsa: mlPub, p256: ecPub}, nil
}

// --------------------
// HybridSig encode / decode
// --------------------

// Encode returns the canonical HybridSigSize-byte form (ML-DSA sig ‖ raw P-256
// sig). This is the `sig` consumed by txid = SHA-256(sign_bytes ‖ sig).
func (s *HybridSig) Encode() []byte {
	out := make([]byte, 0, HybridSigSize)
	out = append(out, s.mldsa...)
	out = append(out, s.p256[:]...)
	return out
}

// ParseHybridSig decodes a canonical HybridSig. This is a STRUCTURAL decode
// only: low-S canonicalization is a verification rule, enforced in HybridVerify
// (keys-spec §5.3/§5.4), not at parse time.
func ParseHybridSig(b []byte) (*HybridSig, error) {
	if len(b) != HybridSigSize {
		return nil, ErrBadLength
	}
	s := &HybridSig{mldsa: make([]byte, mldsaSignatureSize)}
	copy(s.mldsa, b[:mldsaSignatureSize])
	copy(s.p256[:], b[mldsaSignatureSize:])
	return s, nil
}

// --------------------
// Sign / verify
// --------------------

// Sign produces a HybridSig over the 32-byte message digest m (keys-spec §5.3,
// §8.2): an ML-DSA-87 signature plus a low-S raw P-256 signature, both over the
// SAME m. The ML-DSA half is deterministic (FIPS 204); the P-256 half draws its
// nonce from crypto/rand.
func (k *HybridPrivateKey) Sign(m [32]byte) (*HybridSig, error) {
	mlSig, err := mldsaSign(k.mldsa, m[:], false)
	if err != nil {
		return nil, err
	}
	rawP256, err := signP256RawLowS(k.p256, m, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &HybridSig{mldsa: mlSig, p256: rawP256}, nil
}

// HybridVerify implements the hybrid-AND rule (keys-spec §5.4): the signature is
// valid IFF BOTH halves verify over the same 32-byte digest m —
//
//	1. ML-DSA-87.Verify(pub.mldsa, m, sig.mldsa), AND
//	2. ECDSA-P-256.Verify(pub.p256, m, sig.p256) with s ≤ n/2 (low-S).
//
// Either half failing — or a high-S P-256 half — rejects the whole signature.
func HybridVerify(pub *HybridPubKey, m [32]byte, sig *HybridSig) bool {
	if pub == nil || sig == nil || len(sig.mldsa) != mldsaSignatureSize {
		return false
	}
	if !mldsaVerify(pub.mldsa, m[:], sig.mldsa) {
		return false
	}
	if !verifyP256RawLowS(pub.p256, m, sig.p256) {
		return false
	}
	return true
}

// --------------------
// P-256 raw low-S helpers (the classical half)
// --------------------

// signP256RawLowS signs digest and returns a fixed 64-byte r‖s with s normalized
// to low-S canonical form (s ≤ n/2), big-endian, zero-padded (keys-spec §5.3).
func signP256RawLowS(priv *ecdsa.PrivateKey, digest [32]byte, rng io.Reader) ([64]byte, error) {
	var out [64]byte
	if priv == nil {
		return out, ErrMissingField
	}
	r, s, err := ecdsa.Sign(rng, priv, digest[:])
	if err != nil {
		return out, err
	}
	if s.Cmp(p256HalfOrder) > 0 {
		// Flip to the equivalent low-S value: s -> n - s.
		s = new(big.Int).Sub(priv.Curve.Params().N, s)
	}
	r.FillBytes(out[:32]) // r,s < n < 2^256 ⇒ fit in 32 bytes
	s.FillBytes(out[32:])
	return out, nil
}

// verifyP256RawLowS verifies a fixed 64-byte r‖s P-256 signature over digest and
// REJECTS non-canonical (high-S) or out-of-range signatures (keys-spec §5.4).
func verifyP256RawLowS(pub *ecdsa.PublicKey, digest [32]byte, sig [64]byte) bool {
	if pub == nil || pub.Curve == nil {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	n := pub.Curve.Params().N
	// r,s must be in [1, n-1].
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	// Low-S canonical: reject s > n/2.
	if s.Cmp(p256HalfOrder) > 0 {
		return false
	}
	return ecdsa.Verify(pub, digest[:], r, s)
}

// decompressP256 parses a 33-byte SEC1 compressed point into a P-256 public key,
// validating that it lies on the curve.
func decompressP256(comp []byte) (*ecdsa.PublicKey, error) {
	if len(comp) != P256CompressedPubKeySize {
		return nil, ErrBadLength
	}
	// elliptic.UnmarshalCompressed validates the point is on the P-256 curve and
	// returns nil X for any invalid/identity encoding.
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), comp)
	if x == nil {
		return nil, ErrNotOnCurve
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
