package core

// Runtime invariant layer (forquinn phase 4, BUILD-PLAN §2.9 / revised D7): six checks over ONE
// bbolt read View + the background audit that runs them off the epoch loop's critical path and
// HALTS the node on a violation.
//
// Layering (D7):
//   - Layer 1 — the per-tx §2.7 supply-cap/overflow VALIDITY RULE lives in verify_apply.go
//     (validate + apply). Inline, primary defense; not here.
//   - Layer 2 — these checks recompute the global invariants at the per-epoch commit barrier
//     (auditLoop, kicked after each commit) and as the post-resync gate (resync.go). A read
//     View gives them an MVCC-consistent snapshot, so they never race the commit and only ever
//     see fully-committed epochs (commitEpoch is one atomic Update, P7.6).
//   - Layer 3 — the halt: only when CAUGHT-UP-AND-LIVE (auditOnce's gate — a lagging/resyncing
//     node's discrepancy is lag, owned by the resync probe), or IMMEDIATELY when a rebuild that
//     passed the verifying walk still audits broken (runResync's gate — walk-passed heads are
//     network-agreed, so every peer would rebuild the identical broken balances; no retry).
//
// The checks NEVER panic (all parsing fails closed into errors) and a violation NEVER routes
// through the P7.6 recover()→resync path: haltInvariant freezes the node with the evidence
// intact — triggerResync becomes a refusing no-op, SubmitTx rejects, the loop idles, and reads
// + /health keep serving (engine.go hooks).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"time"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// ErrInvariantViolation is the sentinel every invariant-check failure wraps
// (errors.Is-matchable); the concrete error is an *InvariantViolationError.
var ErrInvariantViolation = errors.New("invariant violation")

// InvariantViolationError carries a COARSE category (safe to surface on the ungated /health,
// matching the PanicStats no-detail precedent) plus the full detail, which belongs in the
// node's CRITICAL logs only.
type InvariantViolationError struct {
	Category string // e.g. "supply-total" — the /health invariant_reason value
	Detail   string
}

func (e *InvariantViolationError) Error() string {
	return "invariant violation [" + e.Category + "]: " + e.Detail
}
func (e *InvariantViolationError) Unwrap() error { return ErrInvariantViolation }

func violation(category, format string, args ...any) error {
	return &InvariantViolationError{Category: category, Detail: fmt.Sprintf(format, args...)}
}

// addChecked accumulates sum+v, failing closed on uint64 wrap (a wrapped accumulator would
// let two corruptions cancel out — the overflow itself is proof of impossible amounts).
func addChecked(sum, v uint64, category, what string) (uint64, error) {
	if v > math.MaxUint64-sum {
		return 0, violation(category, "uint64 overflow accumulating %s (sum=%d + %d)", what, sum, v)
	}
	return sum + v, nil
}

// syntheticSeedHead returns the boot-seeded synthetic anchor head for an account under the
// given domain tag ("ANOS_GENESIS_HEAD_V1:" / "ANOS_FUND_HEAD_V1:", ensureGenesisOnBoot).
// These anchors are the ONLY heads with no backing tx bytes in BTxs.
func syntheticSeedHead(domain string, acct [32]byte) [32]byte {
	return sha256.Sum256(append([]byte(domain), acct[:]...))
}

// latestFrontierEpochInTx returns the max epoch present in BEpochFrontiers (the tx-scoped
// LatestFinalizedEpoch — keys are epoch(8 BE)||account, so the last key carries it).
func latestFrontierEpochInTx(tx *bbolt.Tx) uint64 {
	b := tx.Bucket(BEpochFrontiers)
	if b == nil {
		return 0
	}
	if k, _ := b.Cursor().Last(); len(k) >= 8 {
		return binary.BigEndian.Uint64(k[:8])
	}
	return 0
}

// --- The six §2.9 checks. Each is pure over the read tx (plus explicit params); a nil return
// --- means the invariant holds. All failures wrap ErrInvariantViolation.

// invSupplyTotal: Σ account balances + Σ UNCLAIMED receivable amounts == GenesisSupply.
// Receivables hold in-flight value between SEND and RECEIVE, so they MUST be counted or every
// in-flight transfer false-alarms; claimed rows stay in the DB forever (pruning would change
// consensus replay semantics) and are skipped. genesisSupply 0 == unset (direct-engine test
// configs): skip, mirroring the §2.7 cap's defensive precedent — buildSnapshot/main always set it.
func invSupplyTotal(tx *bbolt.Tx, genesisSupply uint64) error {
	const cat = "supply-total"
	if genesisSupply == 0 {
		return nil
	}
	acc := tx.Bucket(BAccounts)
	if acc == nil {
		return violation(cat, "accounts bucket missing")
	}
	var total uint64
	var err error
	c := acc.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if len(k) != 32 {
			return violation(cat, "malformed account key (len %d)", len(k))
		}
		r, ok := unpackAccountRecord(v)
		if !ok {
			return violation(cat, "unparseable account record %x…", k[:4])
		}
		if total, err = addChecked(total, r.Balance, cat, "account balances"); err != nil {
			return err
		}
	}
	rb := tx.Bucket(BRecv)
	if rb == nil {
		return violation(cat, "receivables bucket missing")
	}
	rc := rb.Cursor()
	for k, v := rc.First(); k != nil; k, v = rc.Next() {
		var rec pb.Receivable
		if perr := proto.Unmarshal(v, &rec); perr != nil {
			return violation(cat, "unparseable receivable %x…: %v", k[:min(4, len(k))], perr)
		}
		if rec.Claimed {
			continue
		}
		if total, err = addChecked(total, rec.Amount, cat, "unclaimed receivables"); err != nil {
			return err
		}
	}
	if total != genesisSupply {
		return violation(cat, "Σ balances + unclaimed receivables = %d, want genesis supply %d (delta %+d)",
			total, genesisSupply, int64(total-genesisSupply))
	}
	return nil
}

// invFundSolvency: Fund balance ≥ Σ ACTIVE stake amounts — the pool must always be able to
// return every outstanding stake (returned/kicked/reverted/recovered rows are inert).
func invFundSolvency(tx *bbolt.Tx, fundAcct [32]byte) error {
	const cat = "fund-solvency"
	fund, ok := getAccountRecord(tx, fundAcct)
	if !ok {
		return violation(cat, "fund account %x… missing", fundAcct[:4])
	}
	if fund.Class != pb.AccountClass_ACCOUNT_CLASS_FUND {
		return violation(cat, "fund account %x… has class %v, want FUND", fundAcct[:4], fund.Class)
	}
	var staked uint64
	var err error
	for _, row := range listStakesInTx(tx) {
		if row.Status != StakeStatusActive {
			continue
		}
		if staked, err = addChecked(staked, row.Amount, cat, "active stakes"); err != nil {
			return err
		}
	}
	if fund.Balance < staked {
		return violation(cat, "fund balance %d < Σ active stakes %d (short %d)", fund.Balance, staked, staked-fund.Balance)
	}
	return nil
}

// invReceivableSanity: every receivable row parses and is well-formed — id matches its key,
// From/To are 32-byte ids, an unclaimed amount cannot exceed the supply, and a claimed row
// must name the claiming tx (the single Claimed flag + apply's already-claimed reject make a
// double-claim unrepresentable; a claimed row WITHOUT its ClaimedByTx is the corruption shape).
func invReceivableSanity(tx *bbolt.Tx, genesisSupply uint64) error {
	const cat = "receivable-sanity"
	rb := tx.Bucket(BRecv)
	if rb == nil {
		return violation(cat, "receivables bucket missing")
	}
	c := rb.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if len(k) != 32 {
			return violation(cat, "malformed receivable key (len %d)", len(k))
		}
		var rec pb.Receivable
		if perr := proto.Unmarshal(v, &rec); perr != nil {
			return violation(cat, "unparseable receivable %x…: %v", k[:4], perr)
		}
		if rec.Id == nil || !bytes.Equal(rec.Id.V, k) {
			return violation(cat, "receivable %x… id field does not match its key", k[:4])
		}
		if rec.From == nil || len(rec.From.V) != 32 || rec.To == nil || len(rec.To.V) != 32 {
			return violation(cat, "receivable %x… has malformed from/to", k[:4])
		}
		if !rec.Claimed && genesisSupply != 0 && rec.Amount > genesisSupply {
			return violation(cat, "unclaimed receivable %x… amount %d exceeds genesis supply %d", k[:4], rec.Amount, genesisSupply)
		}
		if rec.Claimed && (rec.ClaimedByTx == nil || len(rec.ClaimedByTx.V) != 32) {
			return violation(cat, "claimed receivable %x… has no claiming txid", k[:4])
		}
	}
	return nil
}

// invContinuityFull: every stored head's tx bytes exist, hash back to the head, and agree with
// the record (account + seq). The boot-seeded genesis/Fund synthetic anchors are the only heads
// with no backing tx (ensureGenesisOnBoot) — exempt iff the head equals the account's OWN
// synthetic anchor, so a random corrupt head can never claim the exemption.
func invContinuityFull(tx *bbolt.Tx) error {
	const cat = "chain-continuity"
	acc := tx.Bucket(BAccounts)
	if acc == nil {
		return violation(cat, "accounts bucket missing")
	}
	txs := tx.Bucket(BTxs)
	if txs == nil {
		return violation(cat, "txs bucket missing")
	}
	c := acc.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if len(k) != 32 {
			return violation(cat, "malformed account key (len %d)", len(k))
		}
		var acct [32]byte
		copy(acct[:], k)
		r, ok := unpackAccountRecord(v)
		if !ok {
			return violation(cat, "unparseable account record %x…", acct[:4])
		}
		if r.Head == ([32]byte{}) {
			return violation(cat, "account %x… has a zero head", acct[:4])
		}
		if r.Head == syntheticSeedHead("ANOS_GENESIS_HEAD_V1:", acct) ||
			r.Head == syntheticSeedHead("ANOS_FUND_HEAD_V1:", acct) {
			continue // boot-seeded anchor: no backing tx by design
		}
		raw := txs.Get(r.Head[:])
		if raw == nil {
			return violation(cat, "account %x… head %x… has no stored tx bytes", acct[:4], r.Head[:4])
		}
		ptx, perr := ParseTx(raw)
		if perr != nil {
			return violation(cat, "account %x… head tx unparseable: %v", acct[:4], perr)
		}
		cid, terr := crypto.TxID(ptx)
		if terr != nil {
			return violation(cat, "account %x… head tx has no computable txid: %v", acct[:4], terr)
		}
		if cid != r.Head {
			return violation(cat, "account %x… head bytes hash to %x…, want %x…", acct[:4], cid[:4], r.Head[:4])
		}
		if ptx.Account == nil || !bytesEq32(ptx.Account.V, acct) {
			return violation(cat, "account %x… head tx belongs to a different account", acct[:4])
		}
		if ptx.Seq != r.Seq {
			return violation(cat, "account %x… record seq %d != head tx seq %d", acct[:4], r.Seq, ptx.Seq)
		}
	}
	return nil
}

// invValidatorSet (post-flip): the validator set the engine CACHED for the next epoch must
// equal the set re-derived from the committed Fund tables — the finalizing set may never drift
// from what the stake state says. The cached set for epoch E+1 is derived from end-of-E state
// BY DESIGN, so the comparison is only meaningful when the cache is exactly one epoch ahead of
// the View's committed tip (both then derive from the SAME state); any other alignment — a
// legitimate mid-derivation race, a just-cleared resync cache, a set-changing epoch still
// washing through — SKIPS rather than false-halts, and real drift persists into the next
// aligned round. Pre-flip the set is the static manifest list (nothing derived to compare).
func (e *Engine) invValidatorSet(tx *bbolt.Tx) error {
	const cat = "validator-set"
	flip := getFlipEpoch(tx)
	latest := latestFrontierEpochInTx(tx)
	if flip == 0 || latest+1 <= flip {
		return nil // the set for epoch latest+1 is the manifest list
	}
	e.mu.Lock()
	cachedEpoch := e.latestEpochCached
	cached := make(map[[33]byte]struct{}, len(e.latestEpochSet))
	for id := range e.latestEpochSet {
		cached[id] = struct{}{}
	}
	e.mu.Unlock()
	if cachedEpoch != latest+1 {
		return nil // cache not derived from THIS committed state — not comparable this round
	}
	descs := e.cfg.Econ.BankerValidatorSet(listStakesInTx(tx), listBankerInfoInTx(tx))
	derived := make(map[[33]byte]struct{}, len(descs))
	for _, vd := range descs {
		// Mirror validatorSetForEpoch's parse filter so the comparison is key-for-key.
		if _, perr := crypto.ParseCompressedP256(vd.ConsensusKey); perr == nil {
			derived[vd.ConsensusKey] = struct{}{}
		}
	}
	if len(derived) != len(cached) {
		return violation(cat, "epoch %d cached set has %d keys, fund-derived set has %d", cachedEpoch, len(cached), len(derived))
	}
	for id := range derived {
		if _, ok := cached[id]; !ok {
			return violation(cat, "epoch %d cached set missing fund-derived validator %x…", cachedEpoch, id[:4])
		}
	}
	return nil
}

// invStoredRootSelfCheck: the frontier root recomputed from the stored epoch-frontier rows must
// equal a root this node already agreed on — i.e. one carried by a stored (signature-verified at
// intake / walk-persisted) finalization for that epoch. Peer-root agreement at the same height
// is already enforced LIVE by finalizationQuorum; this catches post-commit local corruption of
// the rows behind a root we committed. epoch 0 == nothing committed: trivially clean.
func invStoredRootSelfCheck(tx *bbolt.Tx, epoch uint64) error {
	const cat = "stored-root"
	if epoch == 0 {
		return nil
	}
	fb := tx.Bucket(BEpochFrontiers)
	if fb == nil {
		return violation(cat, "epoch frontiers bucket missing")
	}
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint64(prefix, epoch)
	if k, _ := fb.Cursor().Seek(prefix); !bytes.HasPrefix(k, prefix) {
		return violation(cat, "no stored frontiers for committed epoch %d", epoch)
	}
	root, rerr := computeFrontiersRootInTx(tx, epoch)
	if rerr != nil {
		return violation(cat, "recompute frontier root for epoch %d: %v", epoch, rerr)
	}
	finB := tx.Bucket(BFinalizations)
	if finB == nil {
		return violation(cat, "finalizations bucket missing")
	}
	seen := 0
	c := finB.Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		var fin pb.EpochFinalization
		if perr := proto.Unmarshal(v, &fin); perr != nil {
			continue // one corrupt row can't mask the check; agreement needs a parseable match
		}
		if fin.Epoch != epoch || fin.FrontiersRoot == nil || len(fin.FrontiersRoot.V) != 32 {
			continue
		}
		seen++
		if bytes.Equal(fin.FrontiersRoot.V, root[:]) {
			return nil // the recomputed root is one we agreed on
		}
	}
	return violation(cat, "epoch %d recomputed frontier root %x… matches none of %d stored finalizations", epoch, root[:4], seen)
}

// runFullAudit runs all six checks in ONE read View (an MVCC-consistent snapshot of committed
// state) and stamps last_full_audit_epoch on a clean pass. A non-nil return always wraps
// ErrInvariantViolation. `epoch` scopes the stored-root check (the caller's committed tip:
// LatestFinalizedEpoch for the live cadence/boot audits, targetEp for the post-resync gate).
func (e *Engine) runFullAudit(epoch uint64) error {
	err := e.cfg.DB.View(func(tx *bbolt.Tx) error {
		if verr := invSupplyTotal(tx, e.cfg.GenesisSupply); verr != nil {
			return verr
		}
		if verr := invFundSolvency(tx, e.cfg.FundAccount); verr != nil {
			return verr
		}
		if verr := invReceivableSanity(tx, e.cfg.GenesisSupply); verr != nil {
			return verr
		}
		if verr := invContinuityFull(tx); verr != nil {
			return verr
		}
		if verr := e.invValidatorSet(tx); verr != nil {
			return verr
		}
		return invStoredRootSelfCheck(tx, epoch)
	})
	if err == nil {
		e.mu.Lock()
		if epoch > e.lastFullAuditEpoch {
			e.lastFullAuditEpoch = epoch
		}
		e.mu.Unlock()
	}
	return err
}

// --- Halt state + the background audit goroutine ---

// haltInvariant freezes the node on `err` (first violation wins — a later one must never
// overwrite the original evidence). Effects are enforced at the hooks: the loop idles
// (loopOnce), triggerResync refuses (forensic state is never wiped), SubmitTx rejects,
// commitEpoch refuses; reads + /health keep serving. Deliberately NOT a panic — the P7.6
// recover()→resync path must never see an invariant violation.
func (e *Engine) haltInvariant(err error, epoch uint64) {
	category := "invariant"
	var ive *InvariantViolationError
	if errors.As(err, &ive) {
		category = ive.Category
	}
	e.mu.Lock()
	if e.invariantHalted {
		e.mu.Unlock()
		return
	}
	e.invariantHalted = true
	e.invariantReason = category
	e.invariantEpoch = epoch
	e.mu.Unlock()
	log.Printf("CRITICAL: INVARIANT VIOLATION at epoch %d — HALTING finalization. State preserved for forensics; resync refused; submits rejected; reads + /health keep serving. %v", epoch, err)
}

// InvariantStats surfaces the halt state for /health and the gating hooks. reason is the
// coarse category only (the ungated-/health rule, like PanicStats); detail is in the logs.
func (e *Engine) InvariantStats() (halted bool, reason string, epoch uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.invariantHalted, e.invariantReason, e.invariantEpoch
}

// LastFullAuditEpoch surfaces the newest epoch that passed a clean full audit (/health).
func (e *Engine) LastFullAuditEpoch() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastFullAuditEpoch
}

// kickAudit pokes the audit goroutine after a successful commit (non-blocking: the channel
// holds one pending kick; a running audit re-reads the latest epoch anyway, so collapsed
// kicks lose nothing). Never on the loop's critical path — the audit runs on its own goroutine
// against its own MVCC View.
func (e *Engine) kickAudit() {
	select {
	case e.auditKick <- struct{}{}:
	default:
	}
}

// auditCaughtUpMarginEpochs is the "live" margin for the halt gate: at the commit barrier the
// wall clock is normally 1 epoch past the committed tip (an epoch commits just after its
// boundary), 2 across a skip/hiccup. Beyond it the node is LAGGING and skips the audit — its
// lag belongs to the behind-probe/resync, and the post-resync gate re-audits the rebuild.
const auditCaughtUpMarginEpochs = 2

// auditLoop is the background watchdog goroutine (Engine.Start): one audit at boot (a fresh DB
// trivially passes; a restarting node re-checks its committed state before participating), then
// one per kickAudit poke, throttled by FullAuditEveryEpochs.
func (e *Engine) auditLoop(ctx context.Context) {
	e.auditOnce(true)
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.auditKick:
			e.auditOnce(false)
		}
	}
}

// auditOnce runs one gated audit round. The caught-up-and-live gate (D7 layer 3) decides
// whether a violation may HALT: !ResyncActive() AND the committed tip within
// auditCaughtUpMarginEpochs of the wall-clock epoch — otherwise the round is skipped
// entirely (a lagging node's discrepancy is lag, not corruption). boot skips the cadence
// throttle so a restart always re-checks.
func (e *Engine) auditOnce(boot bool) {
	defer e.recoverBGPanic("invariant-audit")

	e.mu.Lock()
	halted := e.invariantHalted
	lastAudited := e.lastFullAuditEpoch
	e.mu.Unlock()
	if halted {
		return
	}
	epoch := e.LatestFinalizedEpoch()
	if !boot && epoch < lastAudited+e.cfg.FullAuditEveryEpochs {
		return // within the ANOS_FULL_AUDIT_EVERY_EPOCHS cadence window
	}
	if e.ResyncActive() {
		return
	}
	if now := e.epochNow(); now > epoch+auditCaughtUpMarginEpochs {
		if boot {
			log.Printf("[audit] boot audit skipped: committed tip %d is behind wall-clock epoch %d (lag is the resync probe's job; the first caught-up commit re-audits)", epoch, now)
		}
		return
	}
	if err := e.runFullAudit(epoch); err != nil {
		// Gate re-check: if a resync started mid-audit, the state we audited is already being
		// rebuilt — the post-resync gate re-audits the rebuild and owns the halt decision.
		if e.ResyncActive() {
			log.Printf("CRITICAL: invariant audit failed but a resync started mid-audit — deferring to the post-resync gate: %v", err)
			return
		}
		e.haltInvariant(err, epoch)
		return
	}
	if boot {
		log.Printf("[audit] boot full audit clean at epoch %d", epoch)
	}
}

// haltRelogEvery paces the halted loop's reminder log (loopOnce).
const haltRelogEvery = time.Minute
