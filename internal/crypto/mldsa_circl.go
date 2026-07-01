package crypto

// mldsa_circl.go is the ONLY file in this package that references the Cloudflare
// circl ML-DSA-87 implementation. Everything else (hybrid.go, account_id.go, the
// ledger) talks to ML-DSA through the thin in-house surface defined here — the
// mldsa* opaque types and functions. Swapping to a future importable stdlib
// crypto/mldsa is therefore a one-file change: re-implement these declarations
// against the new backend and nothing else in the tree moves.
//
// Spec: "Anos Keys, Signatures & Account-ID Spec" §5.1 — ML-DSA-87 = FIPS 204
// ML-DSA, parameter set 87 (NIST security category 5). ML-DSA is a *software*
// key (secure enclaves do not implement it — keys-spec §10).

import (
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// ML-DSA-87 fixed sizes (bytes). Mirrored from the backend so other files in
// this package never import circl just to read a size. Pinned (keys-spec §11):
// public 2592, signature 4627, secret 4896, seed 32.
const (
	mldsaPublicKeySize  = mldsa87.PublicKeySize  // 2592
	mldsaSignatureSize  = mldsa87.SignatureSize  // 4627
	mldsaPrivateKeySize = mldsa87.PrivateKeySize // 4896
	mldsaSeedSize       = mldsa87.SeedSize       // 32
)

// mldsaPublicKey / mldsaPrivateKey are opaque handles over the backend key
// types. Callers in this package pass them around as values; only this file
// knows the concrete type, which keeps the circl dependency contained.
type mldsaPublicKey struct{ pk *mldsa87.PublicKey }
type mldsaPrivateKey struct{ sk *mldsa87.PrivateKey }

// mldsaGenerateKey draws a fresh ML-DSA-87 keypair from rand.
func mldsaGenerateKey(rand io.Reader) (mldsaPublicKey, mldsaPrivateKey, error) {
	pk, sk, err := mldsa87.GenerateKey(rand)
	if err != nil {
		return mldsaPublicKey{}, mldsaPrivateKey{}, err
	}
	return mldsaPublicKey{pk}, mldsaPrivateKey{sk}, nil
}

// mldsaKeyFromSeed deterministically derives a keypair from a fixed 32-byte
// seed. Used to make known-answer test vectors reproducible (build-plan P0.2).
func mldsaKeyFromSeed(seed *[mldsaSeedSize]byte) (mldsaPublicKey, mldsaPrivateKey) {
	pk, sk := mldsa87.NewKeyFromSeed(seed)
	return mldsaPublicKey{pk}, mldsaPrivateKey{sk}
}

// mldsaSign signs msg with the ML-DSA-87 secret key using an EMPTY context
// (keys-spec §5.4: both hybrid halves sign the same 32-byte digest m, no
// per-half context — domain separation lives in the preimage that produced m).
// randomized=false selects FIPS 204 deterministic mode (reproducible);
// randomized=true mixes fresh entropy (hedged). Returns a freshly-allocated
// mldsaSignatureSize signature.
func mldsaSign(sk mldsaPrivateKey, msg []byte, randomized bool) ([]byte, error) {
	if sk.sk == nil {
		return nil, ErrMissingField
	}
	sig := make([]byte, mldsaSignatureSize)
	if err := mldsa87.SignTo(sk.sk, msg, nil, randomized, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// mldsaVerify reports whether sig is a valid ML-DSA-87 signature over msg under
// the empty context (matching mldsaSign).
func mldsaVerify(pk mldsaPublicKey, msg, sig []byte) bool {
	if pk.pk == nil || len(sig) != mldsaSignatureSize {
		return false
	}
	return mldsa87.Verify(pk.pk, msg, nil, sig)
}

// bytes returns the canonical mldsaPublicKeySize-byte packing of the public key.
func (pk mldsaPublicKey) bytes() []byte {
	if pk.pk == nil {
		return nil
	}
	return pk.pk.Bytes()
}

// mldsaPublicKeyFromBytes parses a canonical mldsaPublicKeySize-byte public key.
func mldsaPublicKeyFromBytes(b []byte) (mldsaPublicKey, error) {
	if len(b) != mldsaPublicKeySize {
		return mldsaPublicKey{}, ErrBadLength
	}
	pk := new(mldsa87.PublicKey)
	if err := pk.UnmarshalBinary(b); err != nil {
		return mldsaPublicKey{}, err
	}
	return mldsaPublicKey{pk}, nil
}

// public derives the public half of a secret key (keygen / test helper).
func (sk mldsaPrivateKey) public() mldsaPublicKey {
	return mldsaPublicKey{sk.sk.Public().(*mldsa87.PublicKey)}
}
