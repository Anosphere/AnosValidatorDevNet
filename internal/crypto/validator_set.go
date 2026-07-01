package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

func ParseValidatorSetCSV(csv string) (map[[33]byte]*ecdsa.PublicKey, error) {
	parts := strings.Split(csv, ",")
	out := make(map[[33]byte]*ecdsa.PublicKey, len(parts))
	curve := elliptic.P256()

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		b, err := hex.DecodeString(p)
		if err != nil {
			return nil, err
		}
		if len(b) != 33 {
			return nil, errors.New("each validator pubkey must be 33 bytes compressed")
		}
		var id [33]byte
		copy(id[:], b)

		pub, err := parseCompressedP256(curve, id)
		if err != nil {
			return nil, err
		}
		out[id] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("empty validator set")
	}
	return out, nil
}

// ParseCompressedP256 parses one 33-byte compressed P-256 public key into an *ecdsa.PublicKey
// (on-curve checked), the single-key analogue of ParseValidatorSetCSV. The P4.3 list→Fund flip
// uses it to turn a Fund-derived validator descriptor's consensus_key into a verifying pubkey for
// the per-epoch validator set. Pure → identical on every validator.
func ParseCompressedP256(id [33]byte) (*ecdsa.PublicKey, error) {
	return parseCompressedP256(elliptic.P256(), id)
}

// ValidCompressedP256 reports whether b is a valid 33-byte compressed P-256 public key (a point on
// the curve). Used by the P4.1 Banker descriptor projection to decide set-eligibility: a banker
// stake whose carried consensus_pubkey is absent/malformed is recorded but NOT set-eligible
// (membership-not-rejection). Pure → identical on every validator.
func ValidCompressedP256(b []byte) bool {
	if len(b) != 33 {
		return false
	}
	var id [33]byte
	copy(id[:], b)
	_, err := parseCompressedP256(elliptic.P256(), id)
	return err == nil
}

// Uses stdlib elliptic.UnmarshalCompressed (Go 1.20+). If your Go is older, tell me and I’ll swap in a pure-math fallback.
func parseCompressedP256(curve elliptic.Curve, id [33]byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(curve, id[:])
	if x == nil || y == nil {
		return nil, errors.New("invalid compressed pubkey")
	}
	// sanity: on-curve
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("pubkey not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// (import big only to keep file self-contained; removed if unused by your compiler)
var _ = big.NewInt
