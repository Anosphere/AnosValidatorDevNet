package crypto

// account_id.go implements the Anos account-id and the breakglass commitment
// (build-plan P0.2), per "Anos Keys, Signatures & Account-ID Spec" §3, §6, §7.
// These are the cross-system interop primitives: the app, keyholder/recovery
// software, attestors, and Guardians must all derive byte-identical ids and
// commitments. The known-answer vectors in testdata/ are the frozen contract.
//
// Pure functions over canonical HybridPubKey bytes (§5.2) — no ledger wiring;
// validator-side enforcement of the derivation lands in P1.

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
)

// Account-type discriminants (keys-spec §6.3). They mirror the proto AccountClass
// enum values (anos.proto:30-34), extended with ESCROW=6 (a spec-18 type not yet
// present in the proto). Used as the 1-byte type discriminant inside the
// account-id and breakglass-commitment preimages, which gives per-type domain
// separation: the same hybrid keys under two type bytes yield different ids.
const (
	AccountTypeSpending   byte = 1
	AccountTypeTimelocked byte = 2
	AccountTypeGuarded    byte = 3
	AccountTypeVault      byte = 4
	AccountTypeTransfer   byte = 5
	AccountTypeEscrow     byte = 6
)

// New account/tag-layer domain tags (keys-spec §4): NUL-terminated ASCII with no
// length prefix, matching the existing domainTxSignable convention in crypto.go.
var (
	domainAccountID  = []byte("ANOSv2-AcctID\x00")
	domainBreakglass = []byte("ANOSv2-Breakglass\x00")
)

// SHA512_32 returns the leftmost 32 bytes of the full SHA-512 digest of b
// (keys-spec §3). This is plain left-truncation of SHA-512 — deliberately NOT the
// SHA-512/256 variant, which uses a different IV and yields different bytes.
func SHA512_32(b []byte) [32]byte {
	full := sha512.Sum512(b)
	var out [32]byte
	copy(out[:], full[:32])
	return out
}

// BaseAccountID derives the account-id of a base (sole-owner) account — SPENDING,
// TIMELOCKED, GUARDED, VAULT — from its canonical HybridPubKey bytes (keys-spec
// §6.1, §6.2). Base accounts have freshly-generated keys, so there is no nonce:
//
//	id = SHA512_32( domainAccountID ‖ type_byte ‖ keyblob )
func BaseAccountID(typeByte byte, keyblob []byte) [32]byte {
	return SHA512_32(accountIDPreimage(typeByte, keyblob, false, [32]byte{}, 0))
}

// DerivedAccountID derives the account-id of a key-copying account — TRANSFER and
// ESCROW — which copy their controlling keys from a funding source and therefore
// need the creation nonce to disambiguate two children of the same source under
// the same type (keys-spec §6.1, §6.2):
//
//	id = SHA512_32( domainAccountID ‖ type_byte ‖ keyblob ‖ creator_id(32) ‖ creator_seq(8 LE) )
//
// creatorID is the funder's account-id; creatorSeq is the seq of the creating
// SEND, encoded little-endian. For ESCROW, keyblob = EscrowKeyblob(a, b) and
// creatorID is the funder.
func DerivedAccountID(typeByte byte, keyblob []byte, creatorID [32]byte, creatorSeq uint64) [32]byte {
	return SHA512_32(accountIDPreimage(typeByte, keyblob, true, creatorID, creatorSeq))
}

func accountIDPreimage(typeByte byte, keyblob []byte, derived bool, creatorID [32]byte, creatorSeq uint64) []byte {
	size := len(domainAccountID) + 1 + len(keyblob)
	if derived {
		size += 32 + 8
	}
	out := make([]byte, 0, size)
	out = append(out, domainAccountID...)
	out = append(out, typeByte)
	out = append(out, keyblob...)
	if derived {
		out = append(out, creatorID[:]...)
		var seq [8]byte
		binary.LittleEndian.PutUint64(seq[:], creatorSeq)
		out = append(out, seq[:]...)
	}
	return out
}

// EscrowKeyblob returns the canonical two-party escrow keyblob (keys-spec §6.2):
// the two participants' canonical HybridPubKey encodings concatenated in
// ascending lexicographic byte order (low ‖ high), so both parties derive the
// identical id regardless of who funds. Each input must be a HybridPubKey
// (HybridPubKey.Encode(), 2625 B).
func EscrowKeyblob(a, b []byte) []byte {
	lo, hi := a, b
	if bytes.Compare(a, b) > 0 {
		lo, hi = b, a
	}
	out := make([]byte, 0, len(lo)+len(hi))
	out = append(out, lo...)
	out = append(out, hi...)
	return out
}

// BreakglassCommitment returns the 64-byte SHA-512 commitment to a breakglass
// HybridPubKey (keys-spec §7.2). The FULL digest is stored (no truncation): this
// is the security-relevant commitment that hides the long-dormant backup key
// from a future quantum adversary until it is first exercised.
//
//	commitment = SHA-512( domainBreakglass ‖ HybridPubKey_breakglass )
//
// The commitment carries NO account-type byte (P5.2, 2026-06-30). Unlike the
// account-id (which re-derives its own type byte at creation, so it never travels),
// the commitment is the ONE value that transfer/escrow CHILDREN copy verbatim from
// their source: a type byte here would force every reveal-check to "look back" to
// the source's original class (the wall behind escrow option-B and the
// return-stake-source-is-the-Fund problem). Dropping it is safe — security rests on
// preimage-resistance + holding the private key, and the signature that exercises
// the key binds the specific tx/account-id, so there is no cross-account replay.
//
// The commitment is intentionally NOT part of the account-id (§6 binds only the
// auth keys), so the id is verifiable without revealing the dormant breakglass
// pubkey. For derived accounts the breakglass keys are copied from the source, so
// the child's commitment equals the source's (now byte-identical, no re-derivation).
func BreakglassCommitment(breakglassPub []byte) [64]byte {
	buf := make([]byte, 0, len(domainBreakglass)+len(breakglassPub))
	buf = append(buf, domainBreakglass...)
	buf = append(buf, breakglassPub...)
	return sha512.Sum512(buf)
}

// VerifyBreakglassReveal reports whether revealedPub is the breakglass key committed to by
// storedCommit (keys-spec §7.3, the breakglass reveal-on-use check, P5.1; class-independent since
// P5.2). It re-derives BreakglassCommitment(revealedPub) and compares it to the stored 64-byte
// commitment. A wrong-length stored commitment is a non-match (fail-closed). The values are public
// (both the commitment and the revealed key are on-chain by this point), so a plain comparison is
// sufficient.
func VerifyBreakglassReveal(revealedPub, storedCommit []byte) bool {
	if len(storedCommit) != 64 {
		return false
	}
	got := BreakglassCommitment(revealedPub)
	return bytes.Equal(got[:], storedCommit)
}
