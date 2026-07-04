package core

// The Fund stake reference table (build-plan §P2.2, spec-18 §7, spec-19 §5, working
// notes §3.6).
//
// Staking = a SEND whose destination is the Fund id carrying a non-empty `staked_for`
// tag (the stake amount is the SEND's amount, credited to the one Fund pool via Alt A in
// P2.1). Each such deposit is recorded here, keyed by its deposit_txid, in the BFundStakes
// bucket. This table is a DERIVED CACHE: it is maintained as a side-effect of ApplyTx
// (recordStakeDeposit, called from the SEND-to-Fund apply path) and therefore rebuilt
// deterministically by replaying every sender's chain — exactly like the Fund balance
// (creditFund). It is NOT carried in any consensus hash (ComputeFrontiersRoot hashes only
// account‖head), so it adds zero consensus-root risk; it is wiped+rebuilt on resync.
//
// All role/weight derivations below are PURE functions over the table rows so they are
// order-independent and trivially testable. P2.2 has no consensus consumer of them yet
// (the Guardian quorum is P2.3, the attestor gate P3.2, the validator set P4); they back
// the read API and unit tests now and are read off a finalized table snapshot by those
// later chunks. They are implemented as scans for simplicity — the table is small (one
// row per stake) and there is no hot-path caller yet; if profiling later shows the scans
// are hot, P2.3/P4 can add composite-key index buckets (the rows are the source of truth).

import (
	"bytes"
	"encoding/binary"
	"sort"

	"go.etcd.io/bbolt"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// StakeStatus is a stake's lifecycle state. P2.2 only ever records ACTIVE inflow;
// RETURNED (a Guardian-signed return-stake) and KICKED (a Guardian-signed kick) arrive
// with the Fund-spend path in P2.3. P5.5 adds two en-route-recovery states: REVERTED (a
// returned stake whose Fund-sourced return chain was breakglass-RETURNED back to the Fund —
// the value is in the pool again but unattributed, awaiting Guardian recovery) and RECOVERED
// (the TERMINAL state a C2 generalized return flips a Reverted row to, so the recovered value
// can never be paid out twice). Only ACTIVE rows confer role/Guardian weight; every other
// status is inert to the role predicates below.
type StakeStatus uint8

const (
	StakeStatusActive    StakeStatus = 0
	StakeStatusReturned  StakeStatus = 1
	StakeStatusKicked    StakeStatus = 2
	StakeStatusReverted  StakeStatus = 3 // P5.5: return chain bg-returned to the Fund; awaiting recovery
	StakeStatusRecovered StakeStatus = 4 // P5.5: TERMINAL — a Reverted row paid out to a new owner via C2
)

// Anos-interpreted role tags. staked_for is otherwise an open namespace — these two are
// the ONLY values Anos interprets for its own validation (Banker → validator set in P4;
// Attestor → GUARDED/VAULT/escrow release quorum in P3.2). Guardian and DAO-voting weight
// are DERIVED from the lock tier and need no tag.
const (
	StakedForBanker   = "banker"
	StakedForAttestor = "attestor"
)

// The Anos-side stake floors (banker 50k / attestor 5k), the Guardian derivation divisor
// (2000), the Fund-SEND pass threshold (7000 bps = 70%), and the fund-send epoch slack (8) are
// consensus-critical governance scalars. They are NOT deposit-acceptance gates — a sub-floor or
// unknown-tag stake is stored, never rejected — but INTERPRETATION thresholds applied when
// deriving roles from the table (amounts in whole anos, scaled by UnitsPerAnos at comparison).
// P7.2 moved them out of Go consts and INTO the network manifest: they now live on the Economics
// value carried by the Snapshot / EngineConfig, so a differently-tuned network is a different
// network_id rather than a silent fork. The role derivations below are therefore methods on
// Economics (they read ec.BankerStakeFloorAnos etc.), and the fund-send slack is read off
// snap.Econ.GuardianFundSendEpochSlackEpochs in the validator.

// StakeRecord is one stake deposit in the reference table (the value stored under a
// deposit_txid key). StakerID is the staking IDENTITY — the original owner. For a stake
// that routed through a TRANSFER chain (a restricted-class account staking, the only way
// it can per the 2026-06-29 require-routing decision) this is the chain's recorded source,
// resolved by the apply path, NOT the chain's own id — so per-identity aggregation
// (Guardian weight) credits the real owner. For a direct SPENDING stake it is the sender.
type StakeRecord struct {
	StakerID  [32]byte
	Amount    uint64 // base units, == the SEND's amount credited to the Fund pool
	TimeDelay pb.StakeTimeDelay
	Status    StakeStatus
	StakedFor string // open/free-form tag, stored verbatim
}

// StakeRow is a StakeRecord plus its deposit_txid key (for enumeration / read API).
type StakeRow struct {
	DepositTxid [32]byte
	StakeRecord
}

// On-disk StakeRecord layout (big-endian, mirroring packAccountRecord's hand-rolled style):
//
//	staker_id(32) | amount(8) | time_delay(4) | status(1) | staked_for_len(4) | staked_for
//
// The staked_for length is a uint32, matching the uint32 framing SignBytesACTE uses for the
// same field — so any tag the signed preimage admits round-trips on disk (the open namespace
// imposes no length cap). bbolt ingress already bounds tx size, so this never overflows.
const stakeRecordFixedLen = 32 + 8 + 4 + 1 + 4 // 49

func packStakeRecord(r StakeRecord) []byte {
	sf := []byte(r.StakedFor)
	out := make([]byte, stakeRecordFixedLen+len(sf))
	copy(out[:32], r.StakerID[:])
	binary.BigEndian.PutUint64(out[32:40], r.Amount)
	binary.BigEndian.PutUint32(out[40:44], uint32(r.TimeDelay))
	out[44] = byte(r.Status)
	binary.BigEndian.PutUint32(out[45:49], uint32(len(sf)))
	copy(out[stakeRecordFixedLen:], sf)
	return out
}

func unpackStakeRecord(v []byte) (StakeRecord, bool) {
	if len(v) < stakeRecordFixedLen {
		return StakeRecord{}, false
	}
	var r StakeRecord
	copy(r.StakerID[:], v[:32])
	r.Amount = binary.BigEndian.Uint64(v[32:40])
	r.TimeDelay = pb.StakeTimeDelay(binary.BigEndian.Uint32(v[40:44]))
	r.Status = StakeStatus(v[44])
	sfLen := int(binary.BigEndian.Uint32(v[45:49]))
	if stakeRecordFixedLen+sfLen != len(v) {
		return StakeRecord{}, false
	}
	r.StakedFor = string(v[stakeRecordFixedLen : stakeRecordFixedLen+sfLen])
	return r, true
}

// putStakeRecord writes a stake row keyed by its deposit_txid. Keying by deposit_txid
// makes the write idempotent: a resync re-apply of the same SEND overwrites the identical
// row, so the table rebuilds byte-identically. Fails closed if the bucket is missing
// (ensureBuckets creates it on every boot and resync, so absence is an invariant
// violation, like creditFund's missing-Fund guard).
func putStakeRecord(tx *bbolt.Tx, depositTxid [32]byte, r StakeRecord) error {
	b := tx.Bucket(BFundStakes)
	if b == nil {
		return ErrNotFound
	}
	return b.Put(depositTxid[:], packStakeRecord(r))
}

// listStakesInTx enumerates the reference table within an existing read/write tx, sorted by
// deposit_txid (stable for diffing / snapshots). buildSnapshot uses it to load a finalized
// view of the rows that the Fund-SEND quorum + role derivations read.
func listStakesInTx(tx *bbolt.Tx) []StakeRow {
	b := tx.Bucket(BFundStakes)
	if b == nil {
		return nil
	}
	var out []StakeRow
	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if len(k) != 32 {
			continue
		}
		r, ok := unpackStakeRecord(v)
		if !ok {
			continue
		}
		var id [32]byte
		copy(id[:], k)
		out = append(out, StakeRow{DepositTxid: id, StakeRecord: r})
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].DepositTxid[:], out[j].DepositTxid[:]) < 0
	})
	return out
}

// getStakeRecord reads one stake row by deposit_txid from the DB (apply path). ok=false if the
// bucket or row is absent — the caller (a return/kick Fund SEND) treats absence as retryable
// (ErrUnknownStake) so resync can defer until the staker's deposit chain replays.
func getStakeRecord(tx *bbolt.Tx, depositTxid [32]byte) (StakeRecord, bool) {
	b := tx.Bucket(BFundStakes)
	if b == nil {
		return StakeRecord{}, false
	}
	v := b.Get(depositTxid[:])
	if v == nil {
		return StakeRecord{}, false
	}
	return unpackStakeRecord(v)
}

// findStakeRow looks up one stake by deposit_txid in a finalized snapshot slice (validate path).
func findStakeRow(rows []StakeRow, depositTxid [32]byte) (StakeRecord, bool) {
	for _, r := range rows {
		if r.DepositTxid == depositTxid {
			return r.StakeRecord, true
		}
	}
	return StakeRecord{}, false
}

// ListAllStakes returns every stake in the reference table, sorted by deposit_txid (stable
// for diffing / read APIs).
func ListAllStakes(db *bbolt.DB) ([]StakeRow, error) {
	var out []StakeRow
	err := db.View(func(tx *bbolt.Tx) error {
		out = listStakesInTx(tx)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// --- Pure role / weight derivations over a set of stake rows (spec-19 §5) ---
//
// These take the rows explicitly so they are pure and testable, and so P2.3/P4 can pass a
// finalized-snapshot view rather than the live table.

// roleEligible reports whether identity `id` holds at least one ACTIVE stake tagged
// `tag` whose amount meets `floorAnos` (the membership predicate — NOT a deposit gate).
func roleEligible(rows []StakeRow, id [32]byte, tag string, floorAnos uint64) bool {
	floorUnits := floorAnos * UnitsPerAnos
	for _, s := range rows {
		if s.Status == StakeStatusActive && s.StakerID == id && s.StakedFor == tag && s.Amount >= floorUnits {
			return true
		}
	}
	return false
}

// IsAttestor reports whether `id` is a current Attestor: ≥1 active Attestor-tagged stake
// ≥ the manifest attestor floor (5,000 anos on the current net; spec-19 §5, §6.1).
func (ec Economics) IsAttestor(rows []StakeRow, id [32]byte) bool {
	return roleEligible(rows, id, StakedForAttestor, ec.AttestorStakeFloorAnos)
}

// IsBanker reports whether `id` is a current Banker: ≥1 active Banker-tagged stake ≥ the
// manifest banker floor (50,000 anos on the current net; the validator-set membership
// predicate; consensus key + endpoint are mutable attributes layered on in P4).
func (ec Economics) IsBanker(rows []StakeRow, id [32]byte) bool {
	return roleEligible(rows, id, StakedForBanker, ec.BankerStakeFloorAnos)
}

// GuardianWeight returns floor(Σ id's ACTIVE 1-year stake / divisor) — the number of Guardian
// signatures the identity contributes toward a Fund SEND (spec-19 §5, §6.2; divisor = 2000 anos
// on the current net). Any stake locked for one year counts toward the sum regardless of its
// staked_for tag; 1-month stakes confer none. ≥1 ⇒ the identity is a Guardian.
func (ec Economics) GuardianWeight(rows []StakeRow, id [32]byte) uint64 {
	var sumUnits uint64
	for _, s := range rows {
		if s.Status == StakeStatusActive && s.StakerID == id &&
			s.TimeDelay == pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR {
			sumUnits += s.Amount
		}
	}
	return sumUnits / (ec.GuardianDivisorAnos * UnitsPerAnos)
}

// StakesByRole returns every active stake carrying the given tag (the enumerate-by-role
// scan — e.g. all Attestor or Banker stakes). The floor is NOT applied here (callers that
// want role membership use IsAttestor/IsBanker); this is the raw tag enumeration.
func StakesByRole(rows []StakeRow, tag string) []StakeRow {
	var out []StakeRow
	for _, s := range rows {
		if s.Status == StakeStatusActive && s.StakedFor == tag {
			out = append(out, s)
		}
	}
	return out
}

// BankerIdentities is the validator-descriptor projection skeleton (build-plan §P2.2 /
// §P4.1): the distinct identities that currently qualify as Bankers (active Banker stake
// ≥ floor), sorted. P4 resolves each identity's mutable consensus key + endpoint and
// deterministic activation; P2.2 only projects membership.
func (ec Economics) BankerIdentities(rows []StakeRow) [][32]byte {
	seen := make(map[[32]byte]struct{})
	var out [][32]byte
	floorUnits := ec.BankerStakeFloorAnos * UnitsPerAnos
	for _, s := range rows {
		if s.Status != StakeStatusActive || s.StakedFor != StakedForBanker || s.Amount < floorUnits {
			continue
		}
		if _, ok := seen[s.StakerID]; ok {
			continue
		}
		seen[s.StakerID] = struct{}{}
		out = append(out, s.StakerID)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}

// --- Guardian activity projection (BGuardianActive, spec-19 §6.2) ---
//
// Activeness backs the quorum DENOMINATOR for Fund SENDs: M = total weight of Guardians who
// signed a Fund SEND within the trailing GUARDIAN_ACTIVE_WINDOW_EPOCHS. The projection maps
// guardian_id -> the latest epoch the identity contributed a verifying signature to a Fund
// SEND. It is derived (rebuilt from replay, never in a consensus hash), keyed so writes are
// idempotent, and the recorded epoch comes from the signed tx (fund_send_epoch) so live apply
// and resync replay record the identical value.

// GuardianActiveRow is one BGuardianActive entry (guardian_id -> last active epoch).
type GuardianActiveRow struct {
	GuardianID      [32]byte
	LastActiveEpoch uint64
}

// putGuardianActive records that `id` was active at `epoch`, keeping the MAXIMUM seen epoch
// (monotonic, so the write is order-independent across replay paths — mirroring creditFund's
// commutative += and putStakeRecord's idempotent keying). Fails closed if the bucket is
// missing (ensureBuckets creates it on every boot and resync).
func putGuardianActive(tx *bbolt.Tx, id [32]byte, epoch uint64) error {
	b := tx.Bucket(BGuardianActive)
	if b == nil {
		return ErrNotFound
	}
	if v := b.Get(id[:]); len(v) == 8 {
		if cur := binary.BigEndian.Uint64(v); cur >= epoch {
			return nil // already at or beyond this epoch — keep the max
		}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], epoch)
	return b.Put(id[:], buf[:])
}

// listGuardianActiveInTx enumerates the projection within an existing read/write tx (used by
// buildSnapshot, which already holds a View tx).
func listGuardianActiveInTx(tx *bbolt.Tx) []GuardianActiveRow {
	b := tx.Bucket(BGuardianActive)
	if b == nil {
		return nil
	}
	var out []GuardianActiveRow
	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if len(k) != 32 || len(v) != 8 {
			continue
		}
		var id [32]byte
		copy(id[:], k)
		out = append(out, GuardianActiveRow{GuardianID: id, LastActiveEpoch: binary.BigEndian.Uint64(v)})
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].GuardianID[:], out[j].GuardianID[:]) < 0 })
	return out
}

// ListGuardianActive returns the whole projection, sorted by id (read API / diffing).
func ListGuardianActive(db *bbolt.DB) ([]GuardianActiveRow, error) {
	var out []GuardianActiveRow
	err := db.View(func(tx *bbolt.Tx) error {
		out = listGuardianActiveInTx(tx)
		return nil
	})
	return out, err
}

// isGuardianActive reports whether a Guardian last active at `lastActive` still falls inside
// the trailing `window` epochs at `epoch`. Overflow-safe (lastActive can equal epoch). A
// window of 0 means "must be active this very epoch".
func isGuardianActive(lastActive, epoch, window uint64) bool {
	if lastActive >= epoch {
		return true
	}
	return epoch-lastActive <= window
}

// ActiveGuardianWeight computes the quorum DENOMINATOR M (spec-19 §6.2): the summed CURRENT
// GuardianWeight of every identity in `active` whose last-active epoch is within the trailing
// `window` at `epoch`. Weight is recomputed from `rows` each call, so a Guardian whose 1-yr
// stake later dropped below the floor (weight 0) stops contributing even while still "active".
// Pure over its inputs → identical on every validator that built the same finalized snapshot.
func (ec Economics) ActiveGuardianWeight(rows []StakeRow, active []GuardianActiveRow, epoch, window uint64) uint64 {
	var sum uint64
	for _, g := range active {
		if !isGuardianActive(g.LastActiveEpoch, epoch, window) {
			continue
		}
		sum += ec.GuardianWeight(rows, g.GuardianID)
	}
	return sum
}

// GuardianQuorumThreshold returns the minimum approved weight a Fund SEND needs:
// ceil(GuardianSendThresholdBps/10000 * activeWeight) (spec-19 §6.2 step 3). When the active
// weight is 0 (genesis / fully-dormant window) this is 0, so the separate N>=1 floor in the
// verifier governs — the first Fund SEND is authorized by any single eligible Guardian
// (self-bootstrapping; no genesis seed).
func (ec Economics) GuardianQuorumThreshold(activeWeight uint64) uint64 {
	return (activeWeight*ec.GuardianSendThresholdBps + 9_999) / 10_000
}

// --- Banker validator-descriptor projection (BBankerInfo, spec-18 §3.7, build-plan §P4.1) ---
//
// The consensus validator set is read from the Banker tag keyed by IDENTITY (the durable PQ
// account-id that staked Banker), with the consensus P-256 key + endpoint as mutable attributes
// resolved per-identity LAST-WRITE-WINS in Fund order. A banker rotates by sending a fresh signed
// additive deposit (P4.2). This projection maps banker_identity -> the latest carried descriptor,
// keyed so writes are idempotent and ordered by the deposit's send-seq (keep-max), so live apply and
// resync replay produce byte-identical state. The projected validator set additionally requires
// active Banker membership (>= the 50k floor); a descriptor without it is just a recorded hint.

// BankerInfo is one BBankerInfo entry: the latest consensus descriptor for a banker identity.
type BankerInfo struct {
	Identity     [32]byte
	ConsensusKey []byte // 33-byte compressed P-256 validator id (consensus-load-bearing)
	Endpoint     string // reachability hint (loose / liveness-only)
	SendSeq      uint64 // the deposit send-seq that last wrote this descriptor (last-write-wins key)
}

// On-disk BBankerInfo value layout (big-endian, mirroring packStakeRecord's hand-rolled style):
//
//	consensus_key(33) | send_seq(8) | endpoint_len(4) | endpoint
const bankerInfoFixedLen = 33 + 8 + 4 // 45

func packBankerInfo(consensusKey []byte, endpoint string, seq uint64) []byte {
	ep := []byte(endpoint)
	out := make([]byte, bankerInfoFixedLen+len(ep))
	copy(out[:33], consensusKey)
	binary.BigEndian.PutUint64(out[33:41], seq)
	binary.BigEndian.PutUint32(out[41:45], uint32(len(ep)))
	copy(out[bankerInfoFixedLen:], ep)
	return out
}

func unpackBankerInfo(v []byte) (BankerInfo, bool) {
	if len(v) < bankerInfoFixedLen {
		return BankerInfo{}, false
	}
	var bi BankerInfo
	bi.ConsensusKey = append([]byte(nil), v[:33]...)
	bi.SendSeq = binary.BigEndian.Uint64(v[33:41])
	epLen := int(binary.BigEndian.Uint32(v[41:45]))
	if bankerInfoFixedLen+epLen != len(v) {
		return BankerInfo{}, false
	}
	bi.Endpoint = string(v[bankerInfoFixedLen : bankerInfoFixedLen+epLen])
	return bi, true
}

// putBankerInfo records identity's descriptor at send-seq `seq`, keeping the entry with the MAXIMUM
// seq (last-write-wins; order-independent across replay, mirroring putGuardianActive's keep-max).
// recordBankerInfo only ever calls this for a DIRECT SPENDING banker deposit, so the identity's
// banker deposits all share its single monotonic chain → the seqs strictly increase and max-seq is
// unambiguously the latest (no equal-seq tie, which would be replay-order-dependent). A routed
// (transfer-chain) banker deposit — whose drain is always seq 2 — is excluded at the call site
// precisely to keep this invariant.
func putBankerInfo(tx *bbolt.Tx, identity [32]byte, consensusKey []byte, endpoint string, seq uint64) error {
	b := tx.Bucket(BBankerInfo)
	if b == nil {
		return ErrNotFound
	}
	if v := b.Get(identity[:]); len(v) >= bankerInfoFixedLen {
		if cur := binary.BigEndian.Uint64(v[33:41]); cur >= seq {
			return nil // already at or beyond this deposit — keep the latest descriptor
		}
	}
	return b.Put(identity[:], packBankerInfo(consensusKey, endpoint, seq))
}

// recordBankerInfo updates BBankerInfo for a Banker descriptor write. It has two callers, both keeping
// the keep-max send-seq ordering well-defined (spec-18 §3.7):
//   - a DIRECT SPENDING Banker stake/rotation deposit (P4.1), passing the deposit's own send-seq (>= 2)
//     — the caller gates on existingClass == SPENDING so all of an identity's descriptor writes share
//     its single monotonic chain (a routed transfer-chain banker stake records no descriptor);
//   - a P5.4b RE-ATTRIBUTION inheriting a descriptor onto beneficiary B, passing the SENTINEL seq 0 —
//     a global floor below every real deposit seq, so it is comparable with (and always loses to) B's
//     own deposits, keeping keep-max order-independent even though it originates on the Fund chain.
//
// The key is recorded ONLY if it is a valid 33-byte compressed P-256 point — else the write is a no-op
// (membership-not-rejection), and any previously-recorded valid descriptor for the identity is left
// untouched (a malformed deposit can't silently kick a banker out). Pure function of the signed tx
// (key/endpoint/seq), so live apply and resync replay produce the identical projection.
func recordBankerInfo(tx *bbolt.Tx, identity [32]byte, consensusKey []byte, endpoint string, seq uint64) error {
	if !crypto.ValidCompressedP256(consensusKey) {
		return nil
	}
	return putBankerInfo(tx, identity, consensusKey, endpoint, seq)
}

// listBankerInfoInTx enumerates the projection within an existing tx, sorted by identity (stable for
// diffing / the finalized-snapshot view the validator-set derivation reads).
func listBankerInfoInTx(tx *bbolt.Tx) []BankerInfo {
	b := tx.Bucket(BBankerInfo)
	if b == nil {
		return nil
	}
	var out []BankerInfo
	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if len(k) != 32 {
			continue
		}
		bi, ok := unpackBankerInfo(v)
		if !ok {
			continue
		}
		copy(bi.Identity[:], k)
		out = append(out, bi)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Identity[:], out[j].Identity[:]) < 0 })
	return out
}

// ListBankerInfo returns the whole projection, sorted by identity (read API / diffing).
func ListBankerInfo(db *bbolt.DB) ([]BankerInfo, error) {
	var out []BankerInfo
	err := db.View(func(tx *bbolt.Tx) error {
		out = listBankerInfoInTx(tx)
		return nil
	})
	return out, err
}

// ValidatorDescriptor is one entry of the Fund-derived validator set: a banker identity holding
// active Banker membership AND a valid-key consensus descriptor.
type ValidatorDescriptor struct {
	Identity     [32]byte
	ConsensusKey [33]byte // compressed P-256 validator id
	Endpoint     string
}

// BankerValidatorSet derives the Fund validator set (spec-18 §3.7): every identity that IsBanker
// (>= 1 active Banker-tagged stake >= the 50k floor) AND has a BBankerInfo descriptor with a VALID
// 33-byte compressed P-256 consensus key, sorted by identity. Pure over its inputs (the finalized
// stake rows + the descriptor projection) → identical on every validator that built the same
// finalized snapshot. In P4.1 this is exposed read-only (the env list still drives live consensus);
// P4.3 switches the live set source to it at the latching list→Fund flip.
func (ec Economics) BankerValidatorSet(rows []StakeRow, infos []BankerInfo) []ValidatorDescriptor {
	var out []ValidatorDescriptor
	for _, bi := range infos {
		if !ec.IsBanker(rows, bi.Identity) || !crypto.ValidCompressedP256(bi.ConsensusKey) {
			continue
		}
		var vd ValidatorDescriptor
		vd.Identity = bi.Identity
		copy(vd.ConsensusKey[:], bi.ConsensusKey)
		vd.Endpoint = bi.Endpoint
		out = append(out, vd)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Identity[:], out[j].Identity[:]) < 0 })
	return out
}

// ValidatorKeySet collapses a Fund-derived validator set to its DISTINCT consensus keys — the
// consensus layer is keyed by the 33-byte compressed P-256 key (one-banker-one-vote, flat), so two
// banker identities advertising the same key fold to one vote, exactly as the env list would. Used
// by the P4.3 flip both to build the live key set and to test the activation predicate.
func ValidatorKeySet(descs []ValidatorDescriptor) map[[33]byte]struct{} {
	out := make(map[[33]byte]struct{}, len(descs))
	for _, vd := range descs {
		out[vd.ConsensusKey] = struct{}{}
	}
	return out
}

// FundSetMatchesManifest reports whether the Fund-derived Banker set's consensus keys EXACTLY equal
// the manifest validator list's keys (working notes §3.9, user decision Q2 → exact match): same
// distinct keys, no extras, none missing. This is the deterministic, latching list→Fund activation
// predicate — a pure function of the finalized Banker state + the static manifest, so every node
// computes the same answer. Because the match requires the full key set, at the flip the Fund set is
// byte-identical to the list → zero validator-set discontinuity. An extra banker staked during
// bootstrap makes the Fund set a superset and (correctly, per the exact-match decision) holds the
// flip until the sets coincide.
func FundSetMatchesManifest(descs []ValidatorDescriptor, manifest map[[33]byte]struct{}) bool {
	keys := ValidatorKeySet(descs)
	if len(keys) != len(manifest) {
		return false
	}
	for k := range keys {
		if _, ok := manifest[k]; !ok {
			return false
		}
	}
	return true
}
