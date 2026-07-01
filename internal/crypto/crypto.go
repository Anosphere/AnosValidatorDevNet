package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	pb "anos/internal/proto"
)

var (
	ErrMissingField = errors.New("missing required field")
	ErrBadLength    = errors.New("bad byte length")
)

// Domain tags (ASCII, includes trailing null byte)
var (
	domainTxSignable     = []byte("ANOSv2-TxSignable\x00")
	domainReceivable     = []byte("ANOSv2-Receivable\x00")
	domainFeeReceivable  = []byte("ANOSv2-FeeReceivable\x00")
	domainCandidates     = []byte("ANOSv2-Candidates\x00")
	domainStakeOwnerAuth = []byte("ANOSv2-StakeOwnerAuth\x00")
)

// StakeOwnerAuth op discriminants (P5.4): the current stake owner signs over the exact operation, so a
// signature authorizing a return cannot be replayed as a re-attribution (or vice versa). The validator
// infers the op from the Fund SEND's destination (to == Fund id ⇒ re-attribution, else ⇒ return) and
// recomputes the digest with it, so a sig for the other op fails to verify.
const (
	StakeOwnerAuthOpReturn      byte = 1 // C2 generalized return (to != Fund id)
	StakeOwnerAuthOpReattribute byte = 2 // C1 re-attribution (to == Fund id)
)

// StakeOwnerAuthDigest returns the 32-byte digest a stake owner signs to authorize REDIRECTING a stake
// to a new beneficiary B (P5.4, working notes §3.4). Binding the deposit_txid + B + op makes the
// authorization self-contained and non-replayable: it names exactly which stake, to whom, and in which
// mode. The owner's HybridSig (or a revealed breakglass key) is verified against this digest.
//
//	m_owner = SHA256( domainStakeOwnerAuth ‖ op(1) ‖ deposit_txid(32) ‖ beneficiary(32) )
func StakeOwnerAuthDigest(op byte, depositTxid, beneficiary [32]byte) [32]byte {
	buf := make([]byte, 0, len(domainStakeOwnerAuth)+1+32+32)
	buf = append(buf, domainStakeOwnerAuth...)
	buf = append(buf, op)
	buf = append(buf, depositTxid[:]...)
	buf = append(buf, beneficiary[:]...)
	return sha256.Sum256(buf)
}

// Hash32 returns SHA256(b).
func Hash32(b []byte) [32]byte { return sha256.Sum256(b) }

// AccountTypeByteForClass maps a proto AccountClass to the 1-byte account-id type
// discriminant (keys-spec §6.3). The proto enum values and the AccountType*
// constants coincide by design, but routing through this switch links the two
// namespaces so a future proto class is a deliberate edit here rather than a
// silent wrong-id. UNSPECIFIED / unknown (incl. the keyless FUND, which is never
// key-derived) returns 0, which cannot match any §6.1-derived id — fail-closed.
func AccountTypeByteForClass(c pb.AccountClass) byte {
	switch c {
	case pb.AccountClass_ACCOUNT_CLASS_SPENDING:
		return AccountTypeSpending
	case pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED:
		return AccountTypeTimelocked
	case pb.AccountClass_ACCOUNT_CLASS_GUARDED:
		return AccountTypeGuarded
	case pb.AccountClass_ACCOUNT_CLASS_VAULT:
		return AccountTypeVault
	case pb.AccountClass_ACCOUNT_CLASS_TRANSFER:
		return AccountTypeTransfer
	case pb.AccountClass_ACCOUNT_CLASS_ESCROW:
		return AccountTypeEscrow
	default:
		return 0
	}
}

// --------------------
// ACTE v1 signing bytes
// --------------------

// SignBytesACTE constructs the canonical signing preimage for the given Tx, per ACTE v1.
// IMPORTANT (v1): For SEND, the receivable_id portion is treated as 32 zero bytes because
// receivable_id is deterministically derived from txid (which depends on the signature).
func SignBytesACTE(tx *pb.Tx) ([]byte, error) {
	if tx == nil {
		return nil, ErrMissingField
	}
	if tx.Account == nil || len(tx.Account.V) != 32 {
		return nil, ErrBadLength
	}

	var prev32 [32]byte
	if tx.Prev != nil && len(tx.Prev.V) == 32 {
		copy(prev32[:], tx.Prev.V)
	} // else keep zeros

	// type byte
	var tbyte byte
	switch tx.Type {
	case pb.TxType_TX_TYPE_SEND:
		tbyte = 0x01
	case pb.TxType_TX_TYPE_RECEIVE:
		tbyte = 0x02
	default:
		tbyte = 0x00
	}

	// base = tag || type || account || prev || seq
	out := make([]byte, 0, len(domainTxSignable)+1+32+32+8+1+32+8+8+32)
	out = append(out, domainTxSignable...)
	out = append(out, tbyte)
	out = append(out, tx.Account.V...)
	out = append(out, prev32[:]...)

	var u64 [8]byte
	var u32 [4]byte
	binary.LittleEndian.PutUint64(u64[:], tx.Seq)
	out = append(out, u64[:]...)

	// body tag + body
	switch tx.Type {
	case pb.TxType_TX_TYPE_SEND:
		sb, ok := tx.Body.(*pb.Tx_Send)
		if !ok || sb.Send == nil || sb.Send.To == nil || len(sb.Send.To.V) != 32 {
			return nil, ErrMissingField
		}
		out = append(out, 0x01) // body_tag SEND
		out = append(out, sb.Send.To.V...)

		binary.LittleEndian.PutUint64(u64[:], sb.Send.Amount)
		out = append(out, u64[:]...)
		binary.LittleEndian.PutUint64(u64[:], sb.Send.Fee)
		out = append(out, u64[:]...)

		// receivable_id is derived from txid => encode as 32 zero bytes for signing/txid
		out = append(out, make([]byte, 32)...)

		binary.LittleEndian.PutUint32(u32[:], uint32(sb.Send.AccountClass))
		out = append(out, u32[:]...)

		// Stake-deposit metadata (P2.2). Folded into the signed preimage so staked_for /
		// time_delay / proof_pointer are bound to the txid (tamper-evident), mirroring how
		// the RECEIVE branch folds transfer/key fields. Appended UNCONDITIONALLY and
		// length-framed (an ordinary non-stake send carries an empty tag, tier 0, and an
		// empty pointer), so the bytes are byte-identical across nodes for every SEND. The
		// preimage is only ever hashed (never parsed), but the explicit length prefixes keep
		// the variable-length fields unambiguous so two distinct sends cannot alias.
		sf := []byte(sb.Send.GetStakedFor())
		binary.LittleEndian.PutUint32(u32[:], uint32(len(sf)))
		out = append(out, u32[:]...)
		out = append(out, sf...)

		binary.LittleEndian.PutUint32(u32[:], uint32(sb.Send.GetTimeDelay()))
		out = append(out, u32[:]...)

		pp := sb.Send.GetProofPointer()
		binary.LittleEndian.PutUint32(u32[:], uint32(len(pp)))
		out = append(out, u32[:]...)
		out = append(out, pp...)

		// Fund-SEND activation epoch (P2.3, spec-19 §6.2). Folded in UNCONDITIONALLY (0 on a
		// non-Fund send) so it is byte-identical across nodes and bound to the txid/signature.
		// On a Fund SEND the Guardian signers co-sign this digest, so the epoch they vouch for
		// (which becomes each signer's lastActive on apply) cannot be altered in flight.
		binary.LittleEndian.PutUint64(u64[:], sb.Send.GetFundSendEpoch())
		out = append(out, u64[:]...)

		// Return/kick target deposit_txid (P2.3b). Length-framed + folded unconditionally (empty on
		// an ordinary send) so the Guardians co-sign WHICH stake a Fund SEND returns or kicks.
		rdt := sb.Send.GetReturnDepositTxid().GetV()
		binary.LittleEndian.PutUint32(u32[:], uint32(len(rdt)))
		out = append(out, u32[:]...)
		out = append(out, rdt...)

		// Banker validator descriptor (P4.1): the consensus pubkey + endpoint a banker stake/rotation
		// deposit carries. Folded UNCONDITIONALLY + length-framed (both empty on a non-banker send) so
		// they are byte-identical across nodes and bound to the txid/signature — making the descriptor
		// update self-attributed (signed by the banker's identity, so it can only update its own record).
		cpk := sb.Send.GetConsensusPubkey()
		binary.LittleEndian.PutUint32(u32[:], uint32(len(cpk)))
		out = append(out, u32[:]...)
		out = append(out, cpk...)

		ep := []byte(sb.Send.GetEndpoint())
		binary.LittleEndian.PutUint32(u32[:], uint32(len(ep)))
		out = append(out, u32[:]...)
		out = append(out, ep...)

		// Revealed breakglass pubkey (P5.1, keys-spec §7.3): folded UNCONDITIONALLY + length-framed
		// (empty on every non-breakglass SEND) so a breakglass move's revealed key is bound to BOTH the
		// signature and the txid. A hop-1 source-drain SEND or a hop-2 release SEND carries it; binding
		// it into the preimage (not just the txid) closes the P1.2 malleability gap — a stripped/swapped
		// reveal changes the bytes the breakglass key signed, so the signature no longer verifies.
		out = appendRevealedBreakglass(out, tx, u32)

		// In-Fund stake recovery (P5.4): recovery_beneficiary, return_delay_epochs, and the owner_auth
		// block (sig + revealed breakglass pubkey). Folded UNCONDITIONALLY + length-framed (empty frames /
		// 0 on every non-recovery SEND) so they are byte-identical across nodes and bound to BOTH the
		// signature and the txid. Binding recovery_beneficiary/return_delay_epochs makes two returns to
		// different B or with different delays distinct txids; binding owner_auth makes a stripped/swapped
		// owner authorization a distinct txid (so a junk-owner-auth variant can never alias the valid
		// tx's txid — the P1.2/P5.1 fork-closure rule). owner_auth is NOT the Guardian multisig (which is
		// folded separately in TxID), so it lives here with the other SEND-body fields.
		out = appendStakeRecovery(out, sb.Send, u32)

		return out, nil

	case pb.TxType_TX_TYPE_RECEIVE:
		rb, ok := tx.Body.(*pb.Tx_Receive)
		if !ok || rb.Receive == nil || rb.Receive.ReceivableId == nil || len(rb.Receive.ReceivableId.V) != 32 {
			return nil, ErrMissingField
		}
		out = append(out, 0x02) // body_tag RECEIVE
		out = append(out, rb.Receive.ReceivableId.V...)

		binary.LittleEndian.PutUint32(u32[:], uint32(rb.Receive.AccountClass))
		out = append(out, u32[:]...)

		// Transfer-chain creation: when this RECEIVE opens a TRANSFER chain, the
		// destination and unlock epoch are part of the signed bytes, so they are
		// committed to consensus via the chain head (txid). Appended only for the
		// TRANSFER class, so SPENDING/TIMELOCKED/etc. receives keep their exact bytes.
		if rb.Receive.AccountClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			if rb.Receive.TransferDestination == nil || len(rb.Receive.TransferDestination.V) != 32 {
				return nil, ErrMissingField
			}
			out = append(out, rb.Receive.TransferDestination.V...)
			binary.LittleEndian.PutUint64(u64[:], rb.Receive.TransferUnlockEpoch)
			out = append(out, u64[:]...)
		}

		// Escrow opening (P3.3, spec-18 §5.6.3): when this RECEIVE opens an ESCROW, BOTH parties'
		// key material + breakglass commitments, the attestation_trigger_epoch, and the attested
		// flag are folded into the SIGNED preimage. This is consensus-critical (same reason as the
		// breakglass commitment below): without it those fields are bound to neither the signature
		// nor the txid (txid = SHA256(sign_bytes‖sig)), so a peer could flip the attested flag, lower
		// the trigger epoch, or swap a stored breakglass commitment in flight — and, worse, two
		// openings differing ONLY in escrow_open would share a txid → divergent ESCROW_META under one
		// txid → a fork (the heads-only frontier root cannot see the difference). The two party
		// pubkeys are additionally pinned by the account-id re-derivation, but binding-into-the-txid
		// alone is insufficient (the P1.2 lesson), so everything is folded here. Appended only for the
		// ESCROW class; the fields are fixed-width so raw concatenation is unambiguous (the preimage is
		// only ever hashed, never parsed).
		if rb.Receive.AccountClass == pb.AccountClass_ACCOUNT_CLASS_ESCROW {
			eo := rb.Receive.GetEscrowOpen()
			if eo == nil || len(eo.GetPartyLoPubkey().GetV()) == 0 || len(eo.GetPartyHiPubkey().GetV()) == 0 ||
				len(eo.GetPartyLoBreakglassCommit().GetV()) == 0 || len(eo.GetPartyHiBreakglassCommit().GetV()) == 0 {
				return nil, ErrMissingField
			}
			out = append(out, eo.GetPartyLoPubkey().GetV()...)
			out = append(out, eo.GetPartyLoBreakglassCommit().GetV()...)
			out = append(out, eo.GetPartyHiPubkey().GetV()...)
			out = append(out, eo.GetPartyHiBreakglassCommit().GetV()...)
			binary.LittleEndian.PutUint64(u64[:], eo.GetAttestationTriggerEpoch())
			out = append(out, u64[:]...)
			var attested byte
			if eo.GetAttested() {
				attested = 1
			}
			out = append(out, attested)
		}

		// First-block key registration (keys-spec §8.3): on an account-opening RECEIVE the
		// auth pubkey and breakglass commitment are folded into the SIGNED preimage so they
		// cannot be tampered in flight. Without this, breakglass_commitment would be bound to
		// neither the signature nor the txid (txid = SHA256(sign_bytes‖sig)), letting a peer
		// swap it and leaving nodes with divergent commitments invisible to the heads-only
		// frontier root. Appended only when present; verify_apply requires both on opening
		// blocks and forbids them on non-opening blocks, mirroring the TRANSFER-fields pattern
		// above. The preimage is only ever hashed (never parsed), so raw concatenation of the
		// fixed-width fields is unambiguous.
		if rb.Receive.AuthPubkey != nil && len(rb.Receive.AuthPubkey.V) > 0 {
			out = append(out, rb.Receive.AuthPubkey.V...)
		}
		if rb.Receive.BreakglassCommitment != nil && len(rb.Receive.BreakglassCommitment.V) > 0 {
			out = append(out, rb.Receive.BreakglassCommitment.V...)
		}

		// Revealed breakglass pubkey (P5.1): a breakglass move's TRANSFER-chain OPENING RECEIVE is
		// signed by the revealed breakglass key (not the copied source auth key, which the recoverer
		// has lost). Folded UNCONDITIONALLY + length-framed at the end of the RECEIVE preimage, exactly
		// like the SEND branch, so it binds to both the signature and the txid.
		out = appendRevealedBreakglass(out, tx, u32)

		return out, nil

	default:
		// No body
		out = append(out, 0x00)
		return out, nil
	}
}

// appendRevealedBreakglass folds tx.revealed_breakglass_pubkey into the signing preimage,
// length-framed (uint32 LE) and UNCONDITIONALLY (a zero-length frame when absent), matching the
// SEND branch's other variable-length fields. Folding the revealed key into the SIGNED bytes (not
// only the txid) binds it to the signature: the breakglass key signs over its own revealed pubkey,
// so a relay cannot strip or swap it without invalidating the signature, and two breakglass moves
// that differ only in the revealed key produce different preimages → different txids (the P1.2
// fork-closure rule). The scratch buffer is passed in to avoid a per-call allocation.
func appendRevealedBreakglass(out []byte, tx *pb.Tx, u32 [4]byte) []byte {
	rb := tx.GetRevealedBreakglassPubkey().GetV()
	binary.LittleEndian.PutUint32(u32[:], uint32(len(rb)))
	out = append(out, u32[:]...)
	out = append(out, rb...)
	return out
}

// appendStakeRecovery folds the P5.4 in-Fund-stake-recovery SEND fields into the signing preimage:
// recovery_beneficiary, return_delay_epochs, and the owner_auth block (its HybridSig and any revealed
// breakglass pubkey). All are appended UNCONDITIONALLY and length-framed (uint32 LE) — an empty frame /
// 0 on every non-recovery SEND — so the bytes are byte-identical across nodes for every SEND and each
// variable-length field is self-delimiting (two distinct sends cannot alias). Folding binds them to the
// signature AND the txid (the preimage feeds crypto.TxID): a swapped beneficiary, a changed delay, or a
// stripped/altered owner authorization all yield a different preimage → a different txid, so a junk
// variant can never share the valid tx's txid (the P1.2/P5.1 fork-closure rule). Mirrors the other
// length-framed SEND folds; the scratch buffer avoids a per-call allocation.
func appendStakeRecovery(out []byte, s *pb.TxBodySend, u32 [4]byte) []byte {
	rb := s.GetRecoveryBeneficiary().GetV()
	binary.LittleEndian.PutUint32(u32[:], uint32(len(rb)))
	out = append(out, u32[:]...)
	out = append(out, rb...)

	var u64 [8]byte
	binary.LittleEndian.PutUint64(u64[:], s.GetReturnDelayEpochs())
	out = append(out, u64[:]...)

	oa := s.GetOwnerAuth()
	sig := oa.GetSig().GetV()
	binary.LittleEndian.PutUint32(u32[:], uint32(len(sig)))
	out = append(out, u32[:]...)
	out = append(out, sig...)

	obg := oa.GetRevealedBreakglassPubkey().GetV()
	binary.LittleEndian.PutUint32(u32[:], uint32(len(obg)))
	out = append(out, u32[:]...)
	out = append(out, obg...)
	return out
}

// MsgHash returns SHA256(SignBytesACTE(tx)) and the sign bytes.
func MsgHash(tx *pb.Tx) ([32]byte, []byte, error) {
	sb, err := SignBytesACTE(tx)
	if err != nil {
		return [32]byte{}, nil, err
	}
	h := sha256.Sum256(sb)
	return h, sb, nil
}

// VerifyTxSignature verifies cryptographic validity of the signatures on a tx.
//
// For regular account txs (SEND/RECEIVE) the signature is the post-quantum hybrid
// AND-signature (ML-DSA-87 + low-S P-256, keys-spec §5.4), verified against
// authPubKey — the account's canonical 2625-byte HybridPubKey. Because the bulky
// pubkey is cached on-chain and not repeated per-tx (keys-spec §5.5), the CALLER
// must resolve and supply it: from the opening RECEIVE's carried field for an
// account-creating block, or from the cached account record for everything else.
// The caller (not this function) decides which is authoritative, which is what
// blocks a non-opening block from smuggling in a substitute pubkey.
//
// A keyless Fund SEND carries no Tx.sig (its authorization is the HybridMultiSig,
// verified separately against the reference table in verify_apply.go); the caller
// skips this function for it.
func VerifyTxSignature(tx *pb.Tx, authPubKey []byte) error {
	if tx == nil || tx.Account == nil || len(tx.Account.V) != 32 {
		return ErrBadLength
	}
	h, _, err := MsgHash(tx)
	if err != nil {
		return err
	}
	if tx.Sig == nil || len(tx.Sig.V) != HybridSigSize {
		return ErrMissingField
	}
	pub, err := ParseHybridPubKey(authPubKey)
	if err != nil {
		return fmt.Errorf("auth pubkey: %w", err)
	}
	sig, err := ParseHybridSig(tx.Sig.V)
	if err != nil {
		return err
	}
	if !HybridVerify(pub, h, sig) {
		return errors.New("invalid signature")
	}
	return nil
}

// SignTxHybrid signs tx with the hybrid private key and sets tx.Sig (keys-spec
// §5/§8.2). Helper for clients/simulators; mirrors the old ed25519 signTx helpers.
func SignTxHybrid(tx *pb.Tx, priv *HybridPrivateKey) error {
	m, _, err := MsgHash(tx)
	if err != nil {
		return err
	}
	sig, err := priv.Sign(m)
	if err != nil {
		return err
	}
	tx.Sig = &pb.HybridSig{V: sig.Encode()}
	return nil
}

// TxID computes txid = SHA256(sign_bytes || sig) for regular single-sig txs.
//
// A SEND that carries a HybridMultiSig folds the canonical (sorted) multisig digest into the txid
// (see FundMultiSigDigest), so the txid pins the EXACT signature set. This covers two cases:
//
//   - Keyless Fund SEND (no Tx.sig): SHA256(sign_bytes || multisig_digest). The multisig is the
//     whole authorization. BYTE-IDENTICAL to the pre-P3.2 form (Tx.sig is nil, so nothing is
//     appended between sign_bytes and the digest).
//   - Attestor-gated TRANSFER release-to-dest (Tx.sig present AND a multisig present, P3.2): the
//     release is authorized by BOTH the chain's controlling-key Tx.sig AND the flat M-of-N
//     attestor quorum, so BOTH are folded: SHA256(sign_bytes || Tx.sig || multisig_digest).
//
// Binding the multisig into the txid is consensus-critical: the txid is the chain head committed
// to the frontier root and the BTxs key, so without folding, two raws with the same body/sig but
// DIFFERENT attestor sets would share a txid — a peer could swap the attestor set under one txid
// and nodes holding different raws would validate it differently → a fork. Sorting (in
// FundMultiSigDigest) makes the result independent of entry/submission order; two assemblies with
// different signer sets are distinct txids, each independently verifiable, and the conflict
// resolver (account, prev, seq) picks one winner.
//
// Because ANY SEND with a multisig becomes txid-grindable (an attacker can attach length-valid
// junk entries to vary the txid), the validate path rejects a multisig on any SEND that is neither
// a Fund SEND nor an attestor-gated release, and the submit/gossip gate (bestEffortReleaseCheck)
// keeps a junk-multisig variant out of the conflict pool.
func TxID(tx *pb.Tx) ([32]byte, error) {
	_, sb, err := MsgHash(tx)
	if err != nil {
		return [32]byte{}, err
	}
	hasMultiSig := tx.MultiSig != nil && len(tx.MultiSig.Entries) > 0
	if tx.Type == pb.TxType_TX_TYPE_SEND && (tx.Sig == nil || hasMultiSig) {
		ms, err := FundMultiSigDigest(tx.MultiSig)
		if err != nil {
			return [32]byte{}, err
		}
		buf := make([]byte, 0, len(sb)+HybridSigSize+len(ms))
		buf = append(buf, sb...)
		// A keyless Fund SEND has no Tx.sig (nothing appended here — byte-identical to the
		// pre-P3.2 txid). An attestor-gated release ALSO carries the chain's controlling-key
		// Tx.sig, which is folded in (a single-sig txid binds Tx.sig) so the txid binds both
		// the controlling signature and the attestor set.
		if tx.Sig != nil {
			if len(tx.Sig.V) != HybridSigSize {
				return [32]byte{}, ErrBadLength
			}
			buf = append(buf, tx.Sig.V...)
		}
		buf = append(buf, ms...)
		return sha256.Sum256(buf), nil
	}
	if tx.Sig == nil || len(tx.Sig.V) != HybridSigSize {
		return [32]byte{}, ErrMissingField
	}
	buf := make([]byte, 0, len(sb)+HybridSigSize)
	buf = append(buf, sb...)
	buf = append(buf, tx.Sig.V...)
	return sha256.Sum256(buf), nil
}

// FundMultiSigDigest returns the canonical byte serialization of a HybridMultiSig used inside
// the txid of a Fund (multisig-authorized) SEND: each well-formed entry as signer_id(32) ‖
// sig(4691), sorted lexicographically by that concatenation, then concatenated. Sorting makes
// the result independent of entry order; a malformed entry (wrong-length id or sig) is a hard
// error so a tampered multisig cannot silently change the txid. An empty/nil multisig yields an
// empty digest (the resulting txid will still be rejected at verify for lacking a quorum).
func FundMultiSigDigest(ms *pb.HybridMultiSig) ([]byte, error) {
	if ms == nil || len(ms.Entries) == 0 {
		return nil, nil
	}
	rows := make([][]byte, 0, len(ms.Entries))
	for _, e := range ms.Entries {
		if e == nil || e.SignerId == nil || len(e.SignerId.V) != 32 ||
			e.Sig == nil || len(e.Sig.V) != HybridSigSize {
			return nil, ErrBadLength
		}
		// Revealed breakglass pubkey for an escrow breakglass-slot entry (P5.1). LENGTH-FRAMED so each
		// row is self-delimiting: without the explicit length, a row carrying a 2625-B revealed key
		// could alias against two ordinary rows under the sorted concatenation → two distinct multisigs
		// sharing a txid (a fork). When present it MUST be exactly HybridPubKeySize — a malformed reveal
		// is a hard error so it can never silently change the txid (mirrors the strict signer/sig check).
		// Folded UNCONDITIONALLY (zero length when absent) so the digest is unambiguous for every entry;
		// every Fund SEND / attestor-release entry carries a zero-length frame here.
		rbg := e.GetRevealedBreakglassPubkey().GetV()
		if len(rbg) != 0 && len(rbg) != HybridPubKeySize {
			return nil, ErrBadLength
		}
		row := make([]byte, 0, 32+HybridSigSize+4+len(rbg))
		row = append(row, e.SignerId.V...)
		row = append(row, e.Sig.V...)
		var rl [4]byte
		binary.BigEndian.PutUint32(rl[:], uint32(len(rbg)))
		row = append(row, rl[:]...)
		row = append(row, rbg...)
		rows = append(rows, row)
	}
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && bytes.Compare(rows[j], rows[j-1]) < 0; j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
	out := make([]byte, 0, len(rows)*(32+HybridSigSize))
	for _, r := range rows {
		out = append(out, r...)
	}
	return out, nil
}

// ReceivableIDFromTxID computes receivable_id = SHA256("ANOSv2-Receivable\0" || txid).
func ReceivableIDFromTxID(txid [32]byte) [32]byte {
	buf := make([]byte, 0, len(domainReceivable)+32)
	buf = append(buf, domainReceivable...)
	buf = append(buf, txid[:]...)
	return sha256.Sum256(buf)
}

// FeeReceivableIDFromTxID computes fee_receivable_id = SHA256("ANOSv2-FeeReceivable\0" || txid).
func FeeReceivableIDFromTxID(txid [32]byte) [32]byte {
	buf := make([]byte, 0, len(domainFeeReceivable)+32)
	buf = append(buf, domainFeeReceivable...)
	buf = append(buf, txid[:]...)
	return sha256.Sum256(buf)
}

// --------------------
// Candidate list hashing/signing
// --------------------

// CandidatesListHash returns SHA256(concat(sorted_txids)).
func CandidatesListHash(sortedTxIDs [][32]byte) [32]byte {
	h := sha256.New()
	for _, id := range sortedTxIDs {
		h.Write(id[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// CandidatesSignBytes returns bytes to sign: domain || epoch(u64 LE) || validatorID(32) || listHash(32).
func CandidatesSignBytes(epoch uint64, validatorID [32]byte, listHash [32]byte) []byte {
	buf := make([]byte, 0, len(domainCandidates)+8+32+32)
	buf = append(buf, domainCandidates...)
	var u64 [8]byte
	binary.LittleEndian.PutUint64(u64[:], epoch)
	buf = append(buf, u64[:]...)
	buf = append(buf, validatorID[:]...)
	buf = append(buf, listHash[:]...)
	return buf
}

// VerifyCandidatesSig verifies candidate list signature.
func VerifyCandidatesSig(pub ed25519.PublicKey, epoch uint64, validatorID [32]byte, listHash [32]byte, sig []byte) bool {
	if len(pub) != 32 || len(sig) != 64 {
		return false
	}
	sb := CandidatesSignBytes(epoch, validatorID, listHash)
	h := Hash32(sb)
	return ed25519.Verify(pub, h[:], sig)
}

// SignCandidates signs candidate list payload.
func SignCandidates(priv ed25519.PrivateKey, epoch uint64, validatorID [32]byte, listHash [32]byte) []byte {
	sb := CandidatesSignBytes(epoch, validatorID, listHash)
	h := Hash32(sb)
	return ed25519.Sign(priv, h[:])
}

// LexSortTxIDs sorts txids lexicographically in-place.
func LexSortTxIDs(ids [][32]byte) {
	sortFn := func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 }
	// local simple insertion sort to avoid importing sort in this package
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && sortFn(j, j-1); j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}
