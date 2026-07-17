package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"

	"go.etcd.io/bbolt"

	pb "anos/internal/proto"
)

var (
	BMeta           = []byte("meta")
	BAccounts       = []byte("accounts")
	BTxs            = []byte("txs")
	BRecv           = []byte("recv")
	BEpochFrontiers = []byte("epoch_frontiers")
	BFinalizations  = []byte("finalizations")
	// BFundStakes is the derived stake reference table (build-plan §P2.2, spec-18 §7,
	// spec-19 §5): key = deposit_txid(32) -> packed StakeRecord (fund_table.go). It is a
	// DERIVED CACHE — like the Fund balance it is rebuilt purely by replaying every
	// sender's to==Fund stake SEND through ApplyTx, and it is NOT carried in any consensus
	// hash (ComputeFrontiersRoot hashes only account‖head). Wiped+rebuilt on resync.
	BFundStakes = []byte("fund_stakes")
	// BGuardianActive is the derived Guardian-activity projection (build-plan §P2.3,
	// spec-19 §6.2): key = guardian_id(32) -> lastActiveEpoch(8 BE). A Guardian becomes
	// "active" by contributing a verifying signature to a Fund SEND; the trailing-window
	// active set is the quorum DENOMINATOR. Like BFundStakes it is a DERIVED CACHE rebuilt
	// purely by replaying Fund SENDs through ApplyTx (the activation epoch is read off the
	// signed tx, fund_send_epoch, so replay is deterministic), and is NOT in any consensus
	// hash. Wiped+rebuilt on resync.
	BGuardianActive = []byte("guardian_active")
	// BBankerInfo is the derived Banker validator-descriptor projection (build-plan §P4.1,
	// spec-18 §3.7): key = banker_identity(32) -> packed {consensus_key(33), endpoint, send_seq}.
	// A Banker stake/rotation deposit carries the validator's consensus P-256 key + endpoint; this
	// projection resolves them per-identity LAST-WRITE-WINS by the deposit's send-seq (keep-max,
	// like BGuardianActive). It is a DERIVED CACHE rebuilt purely by replaying every banker deposit
	// through ApplyTx (the send-seq is on the signed tx, so replay is deterministic), and is NOT in
	// any consensus hash. Wiped+rebuilt on resync. The Fund-derived validator set (Banker membership
	// AND a valid-key descriptor) reads it; in P4.1 it is exposed read-only (the env list still
	// drives live consensus until the P4.3 list→Fund flip).
	BBankerInfo = []byte("banker_info")
	// BFlipState holds the P4.3 list→Fund activation latch: the single key flipEpochKey -> the
	// epoch(8 BE) at which the Fund-derived Banker set FIRST exactly matched the manifest
	// validator list (working notes §3.9). UNLIKE the derived caches above this is CONSENSUS-
	// CRITICAL latched state: once set it is never cleared (one-way), so a later kick that drops
	// the Fund set below the list does NOT revert a node to list mode. It persists across a normal
	// restart (crash recovery). It IS wiped on resync and re-established from the rebuilt tip (P4.3a
	// interim, devnet-safe); the rigorous chain-verified recovery is P4.3b.
	BFlipState = []byte("flip_state")
)

// flipEpochKey is the single key under BFlipState holding the latched activation epoch.
var flipEpochKey = []byte("flip_epoch")

var (
	ErrNotFound = errors.New("not found")
)

func ensureBuckets(tx *bbolt.Tx) error {
	for _, b := range [][]byte{BMeta, BAccounts, BTxs, BRecv, BEpochFrontiers, BFinalizations, BFundStakes, BGuardianActive, BBankerInfo, BFlipState} {
		if _, err := tx.CreateBucketIfNotExists(b); err != nil {
			return err
		}
	}
	return nil
}

// getFlipEpoch reads the P4.3 list→Fund activation epoch (0 == not yet flipped). The validator-set
// source for epoch E is the manifest list while flipEpoch == 0 or E <= flipEpoch, and the
// Fund-derived set once E > flipEpoch (the flip takes effect the epoch AFTER the match, by which
// point the Fund set == the list, so the cutover is byte-identical / seamless).
func getFlipEpoch(tx *bbolt.Tx) uint64 {
	b := tx.Bucket(BFlipState)
	if b == nil {
		return 0
	}
	v := b.Get(flipEpochKey)
	if len(v) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

// setFlipEpoch latches the activation epoch ONE-WAY: it writes only if no epoch is recorded yet, so
// the flip can never be un-set or moved (a later kick that drops the Fund set below the list must
// not revert a node to list mode — working notes §3.9). Idempotent. Fails closed if the bucket is
// missing (ensureBuckets creates it on every boot and resync).
func setFlipEpoch(tx *bbolt.Tx, epoch uint64) error {
	b := tx.Bucket(BFlipState)
	if b == nil {
		return ErrNotFound
	}
	if v := b.Get(flipEpochKey); len(v) == 8 {
		return nil // already latched — one-way
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], epoch)
	return b.Put(flipEpochKey, buf[:])
}

// AccountRecord is the live state of one account chain. The base fields
// (head, balance, seq, class) exist for every account. Class-specific metadata
// lives in a self-describing TLV blob after the base (spec-18 §3); for now only
// TRANSFER chains carry one (TRANSFER_META). The cached hybrid auth pubkey and
// breakglass commitment (AUTH_PUBKEY / BREAKGLASS_COMMIT) join the blob in P1.2;
// ESCROW_META in P3.3.
//
// On-disk layout (big-endian):
//
//	head(32) | balance(8) | seq(8) | class(4)   // base = 52 bytes (UNCHANGED; head stays v[0:32])
//	metadata_len(2)                              // byte length of the TLV blob that follows
//	metadata_blob                                // metadata_len bytes of TLV fields, each:
//	                                             //   field_tag(1) | field_len(2) | value(field_len)
//
// metadata_len == 0 is a bare base record (genesis account, Fund). Unknown TLV
// tags are skipped on read, so the format is forward-compatible.
type AccountRecord struct {
	Head    [32]byte
	Balance uint64
	Seq     uint64
	Class   pb.AccountClass

	// Transfer-chain metadata (TRANSFER_META TLV); only meaningful when
	// Class == ACCOUNT_CLASS_TRANSFER.
	TransferSource [32]byte // the account that funded this transfer (return target)
	TransferDest   [32]byte // the release target (allowed only at/after TransferUnlock)
	TransferUnlock uint64   // epoch at/after which release-to-dest is permitted
	TransferFlags  byte     // bit 0 = release_requires_attestor (set in P3.2; 0 here)
	// TransferReturnDepositTxid threads the original stake row's deposit_txid onto a Fund-sourced
	// RETURN-STAKE chain (TRANSFER_RETURN_DEPOSIT TLV, P5.5). Set only on a return-stake chain
	// (copied from the funding receivable's return_deposit_txid at chain-open, immutable); zero on
	// every ordinary transfer chain. A later breakglass-RETURN of the chain to the (keyless) Fund
	// reads it to mark the BFundStakes row Reverted. Derived purely from committed data (resync-safe).
	TransferReturnDepositTxid [32]byte

	// Cached hybrid auth pubkey (AUTH_PUBKEY TLV) and breakglass commitment
	// (BREAKGLASS_COMMIT TLV), registered on the account's opening block and
	// immutable thereafter (keys-spec §5.5, §7.2). Present on every normal
	// single-owner account and on the genesis account (seeded at boot); absent
	// (nil) on the keyless Fund and on a keyless ESCROW. AuthPubKey is the 2625-B
	// HybridPubKey the verifier loads to check per-tx hybrid signatures without the
	// bulky key travelling.
	AuthPubKey       []byte // 2625 B canonical HybridPubKey, or nil
	BreakglassCommit []byte // 64 B SHA-512 commitment, or nil

	// U2PubKey is the cached second user key (U2_PUBKEY TLV, forquinn item 1): registered on a
	// GUARDED/VAULT account's opening RECEIVE (PoP-verified) and immutable thereafter, or COPIED
	// from the key source's stored record when a TRANSFER chain is created (the D2 derived copy —
	// never carried on a chain opening, so nothing is strippable). A single user signature then
	// verifies under AuthPubKey (U1) OR U2PubKey; the attestor-free release path (a) needs both.
	// nil on every other class and on pre-U2 records.
	U2PubKey []byte // 2625 B canonical HybridPubKey, or nil

	// LastGuardedSendEpoch is the finalization epoch of this account's most recent SEND
	// (GUARDED_LAST_SEND TLV, forquinn confirm-item 2) — meaningful only on GUARDED/VAULT
	// accounts, stamped by ApplyTx from the epoch parameter (committed data, resync-deterministic).
	// The hop-1 rate limit rejects a SEND while epoch - this < GuardedSendMinIntervalEpochs.
	// 0 == never sent (first send always allowed).
	LastGuardedSendEpoch uint64

	// Escrow two-party metadata (ESCROW_META TLV, spec-18 §5.6.2); only meaningful
	// when Class == ACCOUNT_CLASS_ESCROW. The two parties' hybrid pubkeys + breakglass
	// commitments are stored BY VALUE in canonical order (PartyLoPub < PartyHiPub
	// lexicographically — the same order crypto.EscrowKeyblob uses for the id), so the
	// keyless escrow's 2-of-2 outflow verify reads them straight off the record. The
	// escrow account itself carries no AUTH_PUBKEY/BREAKGLASS_COMMIT TLV.
	EscrowPartyLoPub []byte // 2625 B canonical HybridPubKey of the lexicographically-smaller party
	EscrowPartyLoBG  []byte // 64 B breakglass commitment of party lo
	EscrowPartyHiPub []byte // 2625 B canonical HybridPubKey of the lexicographically-larger party
	EscrowPartyHiBG  []byte // 64 B breakglass commitment of party hi
	EscrowTrigger    uint64 // attestation_trigger_epoch: at/after this a 1-of-2 → Fund trigger is allowed (attested only)
	EscrowFlags      byte   // bit 0 = attested-escrow
}

const (
	accountBaseLen = 32 + 8 + 8 + 4 // 52: head|balance|seq|class
	metadataLenLen = 2              // metadata_len prefix (BE uint16)
	tlvHeaderLen   = 3              // field_tag(1) | field_len(2 BE)
)

// Account-record TLV field tags (spec-18 §3.3). AUTH_PUBKEY / BREAKGLASS_COMMIT
// populated in P1.2; ESCROW_META in P3.3.
const (
	tlvAuthPubkey          byte = 0x01 // 2625 B HybridPubKey
	tlvBreakglassCommit    byte = 0x02 // 64 B SHA-512 commitment
	tlvU2Pubkey            byte = 0x03 // 2625 B HybridPubKey — second user key U2 (guarded/vault + derived-copy transfer chains)
	tlvGuardedLastSend     byte = 0x04 // 8 B BE finalization epoch of the last guarded/vault SEND (rate limit)
	tlvTransferMeta        byte = 0x10 // source(32)|dest(32)|unlock(8 BE)|flags(1)
	tlvTransferReturnDepos byte = 0x11 // return_deposit_txid(32) — return-stake chains only (P5.5)
	tlvEscrowMeta          byte = 0x20 // partyLo_pub|partyLo_bg|partyHi_pub|partyHi_bg|trigger(8 BE)|flags(1)
)

const (
	transferMetaLen        = 32 + 32 + 8 + 1 // 73
	transferReturnDeposLen = 32              // return_deposit_txid (P5.5)
	authPubkeyLen          = 2625            // crypto.HybridPubKeySize: mldsa87_pub(2592)+p256_compressed(33)
	breakglassCommitLen    = 64              // full SHA-512 breakglass commitment (keys-spec §7.2)
	// escrowMetaLen is the fixed ESCROW_META value length (spec-18 §5.6.2):
	// partyLo_pub(2625) | partyLo_bg(64) | partyHi_pub(2625) | partyHi_bg(64) | trigger(8 BE) | flags(1).
	escrowMetaLen = authPubkeyLen + breakglassCommitLen + authPubkeyLen + breakglassCommitLen + 8 + 1 // 5387
)

// ESCROW_META flags byte bits (spec-18 §5.6.2/§5.6.4). Stored in AccountRecord.EscrowFlags.
const (
	// escrowFlagAttested (bit 0): set for an attested escrow — charges ATTESTED_ESCROW_FEE at
	// funding and is the gate for the 1-of-2 → Fund attestation trigger (spec-19 §6.3). A plain
	// escrow has the bit clear and NO trigger (a 1-of-2 → Fund on a plain escrow is rejected).
	escrowFlagAttested byte = 0x01
)

// TRANSFER_META flags byte bits (spec-18 §3.3). Stored in AccountRecord.TransferFlags and
// round-tripped through buildMetadataBlob/parseMetadataBlob.
const (
	// transferFlagReleaseRequiresAttestor (bit 0): set on a TRANSFER chain spawned by a
	// GUARDED/VAULT source (P3.2) — or a breakglass move (P5.1). When set, a release-to-dest
	// requires the flat M-of-N Fund Attestor quorum IN ADDITION to the chain's controlling-key
	// Tx.sig (spec-19 §6.1); a return-to-source is never attestor-gated. Derived from the funding
	// source's class at chain creation (ApplyTx) and stored immutably, so it is resync-safe — a
	// replay re-derives the identical flag from committed data, exactly like dest/unlock.
	transferFlagReleaseRequiresAttestor byte = 0x01

	// transferFlagBreakglassOrigin (bit 1): set on a TRANSFER chain opened by a BREAKGLASS move
	// (P5.1, spec-19 §6.4) — derived from the funding receivable's from_breakglass marker at chain
	// creation (ApplyTx), stored immutably (resync-safe). It distinguishes a breakglass chain from a
	// plain GUARDED/VAULT chain (both carry bit 0): a breakglass chain's controlling-key Tx.sig on an
	// OUTBOUND (release OR return) may be the copied auth key OR the REVEALED breakglass key
	// (commitment-checked), so a recoverer who lost the auth key can still complete the release. A
	// plain chain accepts the auth key only. Bit 1 also records that the chain's unlock already
	// included BREAKGLASS_EXTRA_EPOCHS (enforced at the opening RECEIVE).
	transferFlagBreakglassOrigin byte = 0x02
)

func packAccountRecord(r AccountRecord) []byte {
	blob := buildMetadataBlob(r)
	out := make([]byte, accountBaseLen+metadataLenLen+len(blob))
	copy(out[:32], r.Head[:])
	binary.BigEndian.PutUint64(out[32:40], r.Balance)
	binary.BigEndian.PutUint64(out[40:48], r.Seq)
	binary.BigEndian.PutUint32(out[48:52], uint32(r.Class))
	binary.BigEndian.PutUint16(out[52:54], uint16(len(blob)))
	copy(out[accountBaseLen+metadataLenLen:], blob)
	return out
}

// buildMetadataBlob assembles the class-specific TLV blob for a record. Fields are
// emitted in a fixed tag order (AUTH_PUBKEY, BREAKGLASS_COMMIT, U2_PUBKEY,
// GUARDED_LAST_SEND, then TRANSFER/ESCROW meta) so the packed record is
// byte-deterministic across nodes — important for resync rebuilding byte-identical
// records (the consensus frontier root hashes only the head, but the local DB
// should still converge).
func buildMetadataBlob(r AccountRecord) []byte {
	var blob []byte
	if len(r.AuthPubKey) > 0 {
		blob = appendTLV(blob, tlvAuthPubkey, r.AuthPubKey)
	}
	if len(r.BreakglassCommit) > 0 {
		blob = appendTLV(blob, tlvBreakglassCommit, r.BreakglassCommit)
	}
	if len(r.U2PubKey) > 0 {
		blob = appendTLV(blob, tlvU2Pubkey, r.U2PubKey)
	}
	// GUARDED_LAST_SEND is emitted only when non-zero, so an account that never sent (and every
	// record written before its first guarded send) stays byte-identical to a record without the tag.
	if r.LastGuardedSendEpoch != 0 {
		var v [8]byte
		binary.BigEndian.PutUint64(v[:], r.LastGuardedSendEpoch)
		blob = appendTLV(blob, tlvGuardedLastSend, v[:])
	}
	if r.Class == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
		var v [transferMetaLen]byte
		copy(v[0:32], r.TransferSource[:])
		copy(v[32:64], r.TransferDest[:])
		binary.BigEndian.PutUint64(v[64:72], r.TransferUnlock)
		v[72] = r.TransferFlags
		blob = appendTLV(blob, tlvTransferMeta, v[:])
		// TRANSFER_RETURN_DEPOSIT (P5.5): emitted ONLY for a Fund-sourced return-stake chain (the
		// deposit_txid is non-zero), so an ordinary transfer chain's record is byte-identical to
		// pre-P5.5. Kept as a separate optional tag (not baked into TRANSFER_META) so ordinary chains
		// are not bloated and the fixed TRANSFER_META layout is untouched.
		if r.TransferReturnDepositTxid != ([32]byte{}) {
			blob = appendTLV(blob, tlvTransferReturnDepos, r.TransferReturnDepositTxid[:])
		}
	}
	if r.Class == pb.AccountClass_ACCOUNT_CLASS_ESCROW &&
		len(r.EscrowPartyLoPub) == authPubkeyLen && len(r.EscrowPartyLoBG) == breakglassCommitLen &&
		len(r.EscrowPartyHiPub) == authPubkeyLen && len(r.EscrowPartyHiBG) == breakglassCommitLen {
		var v [escrowMetaLen]byte
		o := 0
		o += copy(v[o:], r.EscrowPartyLoPub)
		o += copy(v[o:], r.EscrowPartyLoBG)
		o += copy(v[o:], r.EscrowPartyHiPub)
		o += copy(v[o:], r.EscrowPartyHiBG)
		binary.BigEndian.PutUint64(v[o:o+8], r.EscrowTrigger)
		o += 8
		v[o] = r.EscrowFlags
		blob = appendTLV(blob, tlvEscrowMeta, v[:])
	}
	return blob
}

// appendTLV appends one field_tag(1) | field_len(2 BE) | value record.
func appendTLV(dst []byte, tag byte, value []byte) []byte {
	var hdr [tlvHeaderLen]byte
	hdr[0] = tag
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(value)))
	dst = append(dst, hdr[:]...)
	return append(dst, value...)
}

// unpackAccountRecord parses an account record (spec-18 §3). The base is always
// the first 52 bytes (so head = v[0:32] stays cheap for the frontier hot path);
// the 2-byte metadata_len then frames a TLV blob whose known fields are decoded
// and whose unknown tags are skipped.
func unpackAccountRecord(v []byte) (AccountRecord, bool) {
	if len(v) < accountBaseLen+metadataLenLen {
		return AccountRecord{}, false
	}
	var r AccountRecord
	copy(r.Head[:], v[:32])
	r.Balance = binary.BigEndian.Uint64(v[32:40])
	r.Seq = binary.BigEndian.Uint64(v[40:48])
	r.Class = pb.AccountClass(binary.BigEndian.Uint32(v[48:52]))

	mlen := int(binary.BigEndian.Uint16(v[52:54]))
	blob := v[accountBaseLen+metadataLenLen:]
	if len(blob) < mlen {
		return AccountRecord{}, false
	}
	if !parseMetadataBlob(&r, blob[:mlen]) {
		return AccountRecord{}, false
	}
	return r, true
}

// parseMetadataBlob walks the TLV fields, decoding known tags and skipping
// unknown ones. It fails closed on a truncated or over-long field.
func parseMetadataBlob(r *AccountRecord, blob []byte) bool {
	for i := 0; i < len(blob); {
		if i+tlvHeaderLen > len(blob) {
			return false
		}
		tag := blob[i]
		flen := int(binary.BigEndian.Uint16(blob[i+1 : i+3]))
		i += tlvHeaderLen
		if i+flen > len(blob) {
			return false
		}
		val := blob[i : i+flen]
		i += flen

		switch tag {
		case tlvAuthPubkey:
			if flen != authPubkeyLen {
				return false
			}
			// Copy out of the bbolt mmap-backed value (valid only for this tx).
			r.AuthPubKey = append([]byte(nil), val...)
		case tlvBreakglassCommit:
			if flen != breakglassCommitLen {
				return false
			}
			r.BreakglassCommit = append([]byte(nil), val...)
		case tlvU2Pubkey:
			if flen != authPubkeyLen {
				return false
			}
			r.U2PubKey = append([]byte(nil), val...)
		case tlvGuardedLastSend:
			if flen != 8 {
				return false
			}
			r.LastGuardedSendEpoch = binary.BigEndian.Uint64(val)
		case tlvTransferMeta:
			if flen != transferMetaLen {
				return false
			}
			copy(r.TransferSource[:], val[0:32])
			copy(r.TransferDest[:], val[32:64])
			r.TransferUnlock = binary.BigEndian.Uint64(val[64:72])
			r.TransferFlags = val[72]
		case tlvTransferReturnDepos:
			if flen != transferReturnDeposLen {
				return false
			}
			copy(r.TransferReturnDepositTxid[:], val[0:32])
		case tlvEscrowMeta:
			if flen != escrowMetaLen {
				return false
			}
			// Copy each field out of the bbolt mmap-backed value (valid only for this tx).
			o := 0
			r.EscrowPartyLoPub = append([]byte(nil), val[o:o+authPubkeyLen]...)
			o += authPubkeyLen
			r.EscrowPartyLoBG = append([]byte(nil), val[o:o+breakglassCommitLen]...)
			o += breakglassCommitLen
			r.EscrowPartyHiPub = append([]byte(nil), val[o:o+authPubkeyLen]...)
			o += authPubkeyLen
			r.EscrowPartyHiBG = append([]byte(nil), val[o:o+breakglassCommitLen]...)
			o += breakglassCommitLen
			r.EscrowTrigger = binary.BigEndian.Uint64(val[o : o+8])
			o += 8
			r.EscrowFlags = val[o]
		default:
			// Unknown tag — skip (forward-compatible).
		}
	}
	return true
}

func getAccountRecord(tx *bbolt.Tx, acct [32]byte) (AccountRecord, bool) {
	b := tx.Bucket(BAccounts)
	if b == nil {
		return AccountRecord{}, false
	}
	v := b.Get(acct[:])
	if v == nil {
		return AccountRecord{}, false
	}
	return unpackAccountRecord(v)
}

func putAccountRecord(tx *bbolt.Tx, acct [32]byte, r AccountRecord) error {
	return tx.Bucket(BAccounts).Put(acct[:], packAccountRecord(r))
}

// --- Base-field wrappers ---
// These preserve the original signatures for callers that do not care about transfer
// metadata (genesis, resync, frontier/head extraction, snapshot base fields). For
// non-TRANSFER accounts they are exact equivalents of the old fixed-52-byte functions.
// NOTE: putAccount writes NO transfer metadata, so it must never be used to write a
// TRANSFER account — those go through putAccountRecord (read-modify-write preserves meta).

func packAccount(head [32]byte, balance uint64, seq uint64, class pb.AccountClass) []byte {
	return packAccountRecord(AccountRecord{Head: head, Balance: balance, Seq: seq, Class: class})
}

func unpackAccount(v []byte) (head [32]byte, bal uint64, seq uint64, class pb.AccountClass, ok bool) {
	r, k := unpackAccountRecord(v)
	if !k {
		return [32]byte{}, 0, 0, 0, false
	}
	return r.Head, r.Balance, r.Seq, r.Class, true
}

func getAccount(tx *bbolt.Tx, acct [32]byte) (head [32]byte, bal uint64, seq uint64, class pb.AccountClass) {
	r, ok := getAccountRecord(tx, acct)
	if !ok {
		return [32]byte{}, 0, 0, 0
	}
	return r.Head, r.Balance, r.Seq, r.Class
}

func putAccount(tx *bbolt.Tx, acct [32]byte, head [32]byte, bal uint64, seq uint64, class pb.AccountClass) error {
	return putAccountRecord(tx, acct, AccountRecord{Head: head, Balance: bal, Seq: seq, Class: class})
}

func putTxRaw(tx *bbolt.Tx, txid [32]byte, raw []byte) error {
	return tx.Bucket(BTxs).Put(txid[:], raw)
}

func getTxRaw(tx *bbolt.Tx, txid [32]byte) ([]byte, error) {
	v := tx.Bucket(BTxs).Get(txid[:])
	if v == nil {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func hasTx(tx *bbolt.Tx, txid [32]byte) bool {
	return tx.Bucket(BTxs).Get(txid[:]) != nil
}

func putReceivableRaw(tx *bbolt.Tx, rid [32]byte, raw []byte) error {
	return tx.Bucket(BRecv).Put(rid[:], raw)
}

func getReceivableRaw(tx *bbolt.Tx, rid [32]byte) ([]byte, error) {
	v := tx.Bucket(BRecv).Get(rid[:])
	if v == nil {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func hasReceivable(tx *bbolt.Tx, rid [32]byte) bool {
	return tx.Bucket(BRecv).Get(rid[:]) != nil
}

func bytesEq32(a []byte, b [32]byte) bool { return len(a) == 32 && bytes.Equal(a, b[:]) }

type AccountHeadRow struct {
	Account [32]byte
	Head    [32]byte
	Balance uint64
	Seq     uint64
	Class   pb.AccountClass

	// Transfer-chain metadata; only meaningful when Class == ACCOUNT_CLASS_TRANSFER.
	TransferSource            [32]byte
	TransferDest              [32]byte
	TransferUnlock            uint64
	TransferFlags             byte     // bit 0 = release_requires_attestor (P3.2)
	TransferReturnDepositTxid [32]byte // P5.5: return-stake chains only (else zero)

	// Escrow metadata; only meaningful when Class == ACCOUNT_CLASS_ESCROW (P3.3).
	EscrowTrigger uint64
	EscrowFlags   byte // bit 0 = attested-escrow
}

// ListAllAccountHeads reads the current heads for all accounts from the DB.
// It returns one row per account in the BAccounts bucket.
func ListAllAccountHeads(db *bbolt.DB) ([]AccountHeadRow, error) {
	var out []AccountHeadRow

	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BAccounts)
		if b == nil {
			// If buckets weren’t created yet, treat as empty.
			return nil
		}

		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(k) != 32 {
				continue
			}
			r, ok := unpackAccountRecord(v)
			if !ok {
				continue
			}

			var acct [32]byte
			copy(acct[:], k)

			out = append(out, AccountHeadRow{
				Account:                   acct,
				Head:                      r.Head,
				Balance:                   r.Balance,
				Seq:                       r.Seq,
				Class:                     r.Class,
				TransferSource:            r.TransferSource,
				TransferDest:              r.TransferDest,
				TransferUnlock:            r.TransferUnlock,
				TransferFlags:             r.TransferFlags,
				TransferReturnDepositTxid: r.TransferReturnDepositTxid,
				EscrowTrigger:             r.EscrowTrigger,
				EscrowFlags:               r.EscrowFlags,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Stable ordering (helpful for debugging / diffing)
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].Account[:], out[j].Account[:]) < 0
	})

	return out, nil
}

// --- Finalizations ---

func finalKey(epoch uint64, validatorID [33]byte) []byte {
	k := make([]byte, 8+33)
	binary.BigEndian.PutUint64(k[:8], epoch)
	copy(k[8:], validatorID[:])
	return k
}

func PutFinalization(tx *bbolt.Tx, epoch uint64, validatorID [33]byte, raw []byte) error {
	return tx.Bucket(BFinalizations).Put(finalKey(epoch, validatorID), raw)
}

func GetFinalizations(db *bbolt.DB, epoch uint64) ([][]byte, error) {
	var out [][]byte
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BFinalizations)
		if b == nil {
			return ErrNotFound
		}
		prefix := make([]byte, 8)
		binary.BigEndian.PutUint64(prefix, epoch)

		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			out = append(out, append([]byte(nil), v...))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// --- Epoch frontiers (acct->head snapshot after apply) ---

func epochFrontierKey(epoch uint64, acct [32]byte) []byte {
	k := make([]byte, 8+32)
	binary.BigEndian.PutUint64(k[:8], epoch)
	copy(k[8:], acct[:])
	return k
}

// SaveEpochFrontiers snapshots the current post-state BAccounts heads into BEpochFrontiers
// for this epoch. Call this immediately after applying winners (post-state). The live epoch loop
// no longer calls this db-level form — its commit runs saveEpochFrontiersInTx inside the SAME
// transaction as the winner apply (P7.6 commitEpoch, atomicity); resync and tests still use this.
func SaveEpochFrontiers(db *bbolt.DB, epoch uint64) error {
	return db.Update(func(tx *bbolt.Tx) error {
		return saveEpochFrontiersInTx(tx, epoch)
	})
}

// saveEpochFrontiersInTx is the transaction-scoped body of SaveEpochFrontiers: inside an Update
// it sees the transaction's own uncommitted writes, so the snapshot taken by commitEpoch is over
// exactly the just-applied state.
func saveEpochFrontiersInTx(tx *bbolt.Tx, epoch uint64) error {
	if err := ensureBuckets(tx); err != nil {
		return err
	}
	acc := tx.Bucket(BAccounts)
	out := tx.Bucket(BEpochFrontiers)

	c := acc.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if len(k) != 32 {
			continue
		}
		head, _, _, _, ok := unpackAccount(v)
		if !ok {
			continue
		}
		var acct [32]byte
		copy(acct[:], k)
		if err := out.Put(epochFrontierKey(epoch, acct), head[:]); err != nil {
			return err
		}
	}

	return nil
}

type FrontierEntry struct {
	AccountID [32]byte
	HeadHash  [32]byte
}

func IterEpochFrontiers(db *bbolt.DB, epoch uint64, cursor [32]byte, limit int) ([]FrontierEntry, *[32]byte, error) {
	if limit <= 0 {
		limit = 1000
	}
	var entries []FrontierEntry
	var next *[32]byte

	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BEpochFrontiers)
		if b == nil {
			return ErrNotFound
		}
		prefix := make([]byte, 8)
		binary.BigEndian.PutUint64(prefix, epoch)

		seek := prefix
		if cursor != ([32]byte{}) {
			seek = epochFrontierKey(epoch, cursor)
		}

		c := b.Cursor()
		for k, v := c.Seek(seek); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if len(k) != 8+32 || len(v) != 32 {
				continue
			}
			var acct [32]byte
			copy(acct[:], k[8:40])
			var head [32]byte
			copy(head[:], v)

			entries = append(entries, FrontierEntry{AccountID: acct, HeadHash: head})
			if len(entries) >= limit {
				// next cursor is the next account id (if any)
				nk, _ := c.Next()
				if nk != nil && bytes.HasPrefix(nk, prefix) && len(nk) >= 40 {
					var nc [32]byte
					copy(nc[:], nk[8:40])
					next = &nc
				}
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return entries, next, nil
}

// ComputeFrontiersRoot computes SHA256 of concat(sorted(account||head)) for epoch frontiers.
func ComputeFrontiersRoot(db *bbolt.DB, epoch uint64) ([32]byte, error) {
	var out [32]byte
	err := db.View(func(tx *bbolt.Tx) error {
		r, rerr := computeFrontiersRootInTx(tx, epoch)
		if rerr != nil {
			return rerr
		}
		out = r
		return nil
	})
	if err != nil {
		return [32]byte{}, err
	}
	return out, nil
}

// computeFrontiersRootInTx is the transaction-scoped body of ComputeFrontiersRoot, so the
// invariant audit (invariants.go) can recompute an epoch's root inside the SAME read View as
// its other checks — one MVCC-consistent snapshot, never racing a commit.
func computeFrontiersRootInTx(tx *bbolt.Tx, epoch uint64) ([32]byte, error) {
	b := tx.Bucket(BEpochFrontiers)
	if b == nil {
		return [32]byte{}, ErrNotFound
	}
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint64(prefix, epoch)

	var rows []FrontierEntry
	c := b.Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		if len(k) != 8+32 || len(v) != 32 {
			continue
		}
		var acct [32]byte
		copy(acct[:], k[8:40])
		var head [32]byte
		copy(head[:], v)
		rows = append(rows, FrontierEntry{AccountID: acct, HeadHash: head})
	}

	sort.Slice(rows, func(i, j int) bool {
		return bytes.Compare(rows[i].AccountID[:], rows[j].AccountID[:]) < 0
	})

	h := sha256.New()
	var buf [64]byte
	for _, r := range rows {
		copy(buf[:32], r.AccountID[:])
		copy(buf[32:], r.HeadHash[:])
		_, _ = h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// ComputeDryRunFrontiersRoot computes what the frontiers root would be if the
// given winners were applied, without actually writing to the DB.
// winners maps account -> txid (the new head after apply).
// ComputeDryRunFrontiersRoot computes what the frontiers root would be if the
// given winners were applied, without actually writing to the DB.
// winners maps account -> txid (the new head after apply).
func ComputeDryRunFrontiersRoot(db *bbolt.DB, winners map[[32]byte][32]byte) ([32]byte, error) {
	// 1. Read all current frontier heads from DB.
	frontiers := make(map[[32]byte][32]byte)
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BAccounts)
		if b != nil {
			c := b.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				if len(k) != 32 {
					continue
				}
				head, _, _, _, ok := unpackAccount(v)
				if !ok {
					continue
				}
				var acct [32]byte
				copy(acct[:], k)
				frontiers[acct] = head
			}
		}

		return nil
	})
	if err != nil {
		return [32]byte{}, err
	}

	// 2. Overlay winners: for each winner, new head = txid
	for acct, txid := range winners {
		frontiers[acct] = txid
	}

	// 3. Sort and hash (same algorithm as ComputeFrontiersRoot)
	rows := make([]FrontierEntry, 0, len(frontiers))
	for acct, head := range frontiers {
		rows = append(rows, FrontierEntry{AccountID: acct, HeadHash: head})
	}
	sort.Slice(rows, func(i, j int) bool {
		return bytes.Compare(rows[i].AccountID[:], rows[j].AccountID[:]) < 0
	})

	h := sha256.New()
	var buf [64]byte
	for _, r := range rows {
		copy(buf[:32], r.AccountID[:])
		copy(buf[32:], r.HeadHash[:])
		_, _ = h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
