package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// ResyncState is stored on Engine and guarded by e.mu.
// Keep it tiny: just enough to pause epochs, run a single resync, and return to normal.
type ResyncState struct {
	Mode          ResyncMode
	MismatchEpoch uint64
	WantAccepted  [32]byte
	WantRoot      [32]byte
	LastErr       string
	LastPeer      string
	LastTargetEp  uint64
}

type ResyncMode uint8

const (
	ResyncIdle ResyncMode = iota
	ResyncPending
	ResyncRunning
)

func (rs ResyncState) IsActive() bool {
	return rs.Mode != ResyncIdle
}

// triggerResync moves the engine into resync mode.
// It is intentionally idempotent (first mismatch wins).
func (e *Engine) triggerResync(mismatchEpoch uint64, wantAccepted [32]byte, wantRoot [32]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.resync.Mode != ResyncIdle {
		return
	}
	e.resync.Mode = ResyncPending
	e.resync.MismatchEpoch = mismatchEpoch
	e.resync.WantAccepted = wantAccepted
	e.resync.WantRoot = wantRoot
	e.resync.LastErr = ""
}

// runResync performs the P4.3b rigorous VERIFYING resync (the testnet gate, working notes §3.9).
//
// Unlike the P4.3a interim resync (which trusted the peer's tip and re-latched the flip from the
// rebuilt tip), this:
//  1. picks the highest-tip reachable peer (NO env-list quorum anchor — see pickResyncTarget),
//  2. downloads every account chain into a txid-indexed map (no apply yet),
//  3. runs an EPOCH-ORDERED VERIFYING WALK from the manifest-list trust anchor forward
//     (verifyingWalk): it re-derives each epoch's validator set + the list→Fund flip from the
//     verified state, verifies every set-change epoch + the tip against the PRIOR already-trusted
//     set, and checks the full frontier root once at the tip.
//
// The integrity anchor therefore flows from local config (the manifest list) through verified
// set-changes to the post-flip Fund-derived set — closing the proof-of-stake weak-subjectivity gap
// (a malicious peer cannot forge a post-flip set: it would have to get attacker keys past a quorum
// check against an already-trusted set) and handling a post-flip set DIVERGENCE (a kick/join after
// the flip) the P4.3a interim could not. Returns nil on success (engine returns to normal operation).
func (e *Engine) runResync(ctx context.Context) error {
	e.mu.Lock()
	mode := e.resync.Mode
	mismatchEpoch := e.resync.MismatchEpoch
	e.resync.Mode = ResyncRunning
	e.mu.Unlock()

	if mode == ResyncIdle {
		return nil
	}

	start := time.Now()

	peer, targetEp, err := e.pickResyncTarget(ctx, mismatchEpoch)
	if err != nil {
		e.setResyncError(err)
		e.elog(mismatchEpoch, "RESYNC failed (pick target): %v", err)
		return err
	}

	e.elog(mismatchEpoch, "RESYNC starting (verifying walk): peer=%s targetEpoch=%d", peer, targetEp)

	frontiers, err := e.fetchAllFrontiers(ctx, peer, targetEp)
	if err != nil {
		e.setResyncError(err)
		e.elog(targetEp, "RESYNC failed (frontiers): %v", err)
		return err
	}

	// Wipe local state, restore the genesis anchors, and download every account chain into a
	// txid-indexed map. No apply happens here — the verifying walk applies in epoch order below.
	txByID, err := e.wipeAndDownloadChains(ctx, peer, targetEp, frontiers)
	if err != nil {
		e.setResyncError(err)
		e.elog(targetEp, "RESYNC failed (download): %v", err)
		return err
	}

	// The epoch-ordered verifying walk: re-derives the validator-set history (and the flip) from the
	// manifest anchor, verifying each set-change + the tip, and checks the tip frontier root. The
	// per-epoch finalizations are fetched from the peer; the walk persists them as it goes.
	getFins := func(ep uint64) ([]*pb.EpochFinalization, error) { return e.httpSyncFinalization(ctx, peer, ep) }
	if err := e.verifyingWalk(ctx, targetEp, txByID, getFins); err != nil {
		e.setResyncError(err)
		e.elog(targetEp, "RESYNC failed (verifying walk): %v", err)
		return err
	}

	// Clear volatile in-memory pools (we've rebuilt canonical, verified state).
	e.mu.Lock()
	e.txPool = make(map[[32]byte][]byte)
	e.txSeenEpoch = make(map[[32]byte]uint64)
	e.conflictPool = make(map[[32]byte][][32]byte)
	e.approved = make(map[[32]byte][32]byte)
	e.gossipPending = make(map[[32]byte]struct{})
	e.peerLists = make(map[uint64]map[[33]byte]*CandidateList)
	e.peerFinals = make(map[uint64]map[[33]byte]*pb.EpochFinalization)
	// Drop cached per-epoch validator sets computed under the pre-resync flip state; the loop
	// re-derives + re-caches each epoch's set from the rebuilt finalized state before any quorum read.
	e.epochSets = make(map[uint64]map[[33]byte]*ecdsa.PublicKey)

	e.resync = ResyncState{
		Mode:         ResyncIdle,
		LastErr:      "",
		LastPeer:     peer,
		LastTargetEp: targetEp,
	}
	e.resyncNextAttempt = time.Time{}
	e.resyncFailCount = 0
	e.mu.Unlock()

	e.elog(targetEp, "RESYNC complete (verified): peer=%s flip_epoch=%d (elapsed=%s)",
		peer, e.FlipEpoch(), time.Since(start).Truncate(time.Millisecond))
	return nil
}

func (e *Engine) setResyncError(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.resync.LastErr = err.Error()
	// Keep Mode=Pending so loop will retry next tick/epoch.
	e.resync.Mode = ResyncPending

	// Exponential-ish backoff capped.
	e.resyncFailCount++
	delay := time.Duration(1<<minInt(e.resyncFailCount, 5)) * time.Second // 2s..32s
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	e.resyncNextAttempt = time.Now().Add(delay)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// pickResyncTarget chooses the resync peer + target epoch: the peer reporting the highest
// /sync/latest.
//
// Unlike the P4.3a interim it does NOT compute a finalization quorum against the static env list
// here. Post-flip the real validators are the Fund-derived set, not the env list, so an env-list
// quorum at the tip would be the WRONG anchor — it would reject an honest post-flip tip and could
// not detect a forged one. The trust anchor now flows through the epoch-ordered verifyingWalk, which
// re-derives every epoch's set from the manifest anchor forward and verifies each set-change + the
// tip against the prior already-trusted set. A peer that lies about its tip is rejected there (its
// finalizations won't verify against the derived set / the tip frontier root won't match), so simply
// picking the highest tip is safe.
func (e *Engine) pickResyncTarget(ctx context.Context, mismatchEpoch uint64) (peer string, targetEp uint64, err error) {
	bestEp := uint64(0)
	bestPeer := ""
	for _, p := range e.cfg.Peers {
		p = strings.TrimRight(p, "/")
		ep, e2 := e.httpSyncLatest(ctx, p)
		if e2 != nil {
			continue
		}
		if ep > bestEp {
			bestEp = ep
			bestPeer = p
		}
	}
	if bestPeer == "" {
		return "", 0, errors.New("resync: no reachable peers")
	}
	_ = mismatchEpoch // the mismatch only TRIGGERS resync; we re-anchor to the peer's verified tip.
	return bestPeer, bestEp, nil
}

// fetchAllFrontiers pulls /sync/frontiers pages until complete.
func (e *Engine) fetchAllFrontiers(ctx context.Context, peer string, epoch uint64) (map[[32]byte][32]byte, error) {
	peer = strings.TrimRight(peer, "/")
	out := make(map[[32]byte][32]byte)
	var cursor [32]byte
	for {
		resp, err := e.httpSyncFrontiers(ctx, peer, epoch, cursor, 1000)
		if err != nil {
			return nil, err
		}
		for _, ent := range resp.Entries {
			if ent == nil || ent.Account == nil || len(ent.Account.V) != 32 || ent.Head == nil || len(ent.Head.V) != 32 {
				continue
			}
			var acct [32]byte
			copy(acct[:], ent.Account.V)
			var head [32]byte
			copy(head[:], ent.Head.V)
			out[acct] = head
		}
		if resp.NextCursor == nil || len(resp.NextCursor.V) != 32 {
			break
		}
		var next [32]byte
		copy(next[:], resp.NextCursor.V)
		// Progress guard: the cursor is an account id and pages walk it strictly ascending, so a
		// non-advancing (or backward) cursor means the peer is misbehaving — stop rather than loop.
		if bytes.Compare(next[:], cursor[:]) <= 0 {
			break
		}
		cursor = next
	}
	return out, nil
}

// wipeAndDownloadChains clears all local state, restores the genesis anchors, and downloads every
// account chain referenced by the peer's tip frontiers into a txid-indexed map. It does NOT apply
// anything — the verifying walk applies the downloaded txs in epoch order. Every accepted txid in
// history is, by construction, a block in some account's chain reachable from the tip frontier (a
// conflict loser is never in any chain), so the returned map contains the bytes for every txid the
// walk needs to replay.
func (e *Engine) wipeAndDownloadChains(ctx context.Context, peer string, targetEp uint64, frontiers map[[32]byte][32]byte) (map[[32]byte][]byte, error) {
	peer = strings.TrimRight(peer, "/")

	// 1) Clear all derived + chain state — rebuilt from the verifying walk below.
	if err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}

		accBkt := tx.Bucket(BAccounts)
		if err := accBkt.ForEach(func(k, _ []byte) error { return accBkt.Delete(k) }); err != nil {
			return err
		}

		for _, b := range [][]byte{BEpochFrontiers, BFinalizations, BRecv, BTxs, BFundStakes, BGuardianActive, BBankerInfo, BFlipState} {
			if err := tx.DeleteBucket(b); err != nil && err != bbolt.ErrBucketNotFound {
				return err
			}
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("resync: wipe: %w", err)
	}

	// 2) Restore genesis anchors (the genesis account + the Fund synthetic head).
	if err := e.ensureGenesisOnBoot(); err != nil {
		return nil, fmt.Errorf("resync: ensure genesis: %w", err)
	}

	// 3) Download each chain and index every block by txid.
	fundGenesisHead := sha256.Sum256(append([]byte("ANOS_FUND_HEAD_V1:"), e.cfg.FundAccount[:]...))
	txByID := make(map[[32]byte][]byte)

	// Deterministic order for reproducible logs.
	accts := make([][32]byte, 0, len(frontiers))
	for acct := range frontiers {
		accts = append(accts, acct)
	}
	sort.Slice(accts, func(i, j int) bool { return bytes.Compare(accts[i][:], accts[j][:]) < 0 })

	for _, acct := range accts {
		head := frontiers[acct]
		if head == ([32]byte{}) {
			continue
		}
		// The Fund's synthetic seed head is not a real tx in BTxs; its balance is rebuilt purely by
		// replaying every SENDER's chain (each fee / to==Fund credit is a side-effect of the sender's
		// ApplyTx). Once the Fund first SENDs, its head is a real tx and this guard stops firing.
		if acct == e.cfg.FundAccount && head == fundGenesisHead {
			continue
		}

		// Boundary ("have"): the current account head after wipe+genesis (zero except the
		// genesis/Fund synthetic anchors).
		haveBoundary := [32]byte{}
		if err := e.cfg.DB.View(func(tx *bbolt.Tx) error {
			h, _, _, _ := getAccount(tx, acct)
			haveBoundary = h
			return nil
		}); err != nil {
			return nil, err
		}

		txsBack, reached, err := e.httpSyncChain(ctx, peer, acct, head, haveBoundary, 200000)
		if err != nil {
			return nil, err
		}
		if !reached {
			return nil, fmt.Errorf("resync: chain for acct %x... did not reach boundary have=%x (increase MaxBlocks)", acct[:4], haveBoundary[:4])
		}

		for _, raw := range txsBack {
			ptx, perr := ParseTx(raw)
			if perr != nil {
				return nil, fmt.Errorf("resync: parse downloaded tx: %w", perr)
			}
			id, terr := crypto.TxID(ptx)
			if terr != nil {
				return nil, fmt.Errorf("resync: txid downloaded tx: %w", terr)
			}
			txByID[id] = raw
		}
	}

	return txByID, nil
}

// verifyingWalk is the P4.3b epoch-ordered trust walk (working notes §3.9). For each finalized epoch
// from the trust anchor to the target tip it:
//   - derives the validator set DURING that epoch from the walk's verified end-of-(epoch−1) state
//     (manifest list pre-flip, Fund-derived post-flip),
//   - fetches + persists the epoch's finalizations,
//   - applies that epoch's accepted-txid set (advancing the verified state),
//   - re-derives the list→Fund flip one-way (no peer-trusted latch),
//   - VERIFIES a finalization quorum against the prior already-trusted set at every set-CHANGE epoch
//     (any epoch that touched the Fund — the only thing that can move the Banker set) AND at the tip,
//   - checks the full frontier root ONCE at the tip against the tip quorum's signed root.
//
// Granularity (user decision, working notes §3.9(a)): non-set-change epochs are NOT quorum-verified —
// their accepted-txid set is taken from the peer-reported PLURALITY (hash-bound) and trusted under
// honest-majority, with the tip frontier-root check as the full-state backstop. So the added signature
// verification cost is proportional to the number of set changes, not the number of epochs.
func (e *Engine) verifyingWalk(ctx context.Context, targetEp uint64, txByID map[[32]byte][]byte, getFins func(epoch uint64) ([]*pb.EpochFinalization, error)) error {
	pct := e.cfg.FinalizationQuorumPercent

	// Trust anchor (working notes §3.9(b)): the walk starts from a PARAMETERIZABLE anchor so a future
	// P7 cold-sync checkpoint can begin from a recent pinned set instead of genesis (config, not a
	// re-architecture). P4.3b wires only the genesis default — anchorEpoch 0 (start applying at epoch
	// 1), with the manifest list as the anchor set (validatorSetForEpoch returns it while pre-flip).
	const anchorEpoch = uint64(0)

	for ep := anchorEpoch + 1; ep <= targetEp; ep++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// The validator set DURING epoch `ep` — derived from the walk's verified end-of-(ep−1) state.
		// This is the set whose quorum signed epoch `ep`'s finalization.
		vset, _ := e.validatorSetForEpoch(ep)

		fins, err := getFins(ep)
		if err != nil {
			return fmt.Errorf("fetch finalization epoch %d: %w", ep, err)
		}
		if len(fins) > 0 {
			// Persist so THIS node can later serve the verifying walk to others.
			if perr := e.persistFinalizations(ep, fins); perr != nil {
				return fmt.Errorf("persist finalization epoch %d: %w", ep, perr)
			}
		}
		if len(fins) == 0 {
			if ep == targetEp {
				return fmt.Errorf("peer has no finalization at target epoch %d", ep)
			}
			continue // skipped / never-committed epoch: no state change
		}

		// Plurality selection (distinct signers, hash-bound, NOT sig-verified): chooses what to apply
		// at a non-verified epoch and decides Fund-relevance (→ whether to verify a quorum here). Any
		// manipulation is caught either by the quorum check at a Fund/tip epoch or by the tip root.
		pl, plOK := epochQuorumSelect(vset, ep, fins, pct, false)

		// Skip an epoch that did NOT commit. A committed epoch carries a quorum (≥ need) of agreeing
		// finalizations; a no-quorum / presence-skipped epoch persists only BELOW-quorum finalizations
		// (a node self-stores its finalization BEFORE the quorum check, engine.go), which the peer
		// still serves over /sync/finalization. The plurality distinct-signer count is an UPPER bound
		// on the verified quorum count (verify=false also counts non-members), so pl.count < need
		// PROVES the epoch never reached a real quorum → treat it as uncommitted (no state change),
		// exactly as the live network did, instead of replaying its proposed-but-never-committed txs
		// (which would double-apply at their real commit epoch and abort an HONEST resync). The tip is
		// always verified below: it must be committed (/sync/latest reports the committed tip).
		if (!plOK || pl.count < pl.need) && ep != targetEp {
			continue
		}

		fundRel := !plOK || e.anyFundRelevant(pl.txids, txByID) // !plOK ⇒ verify (can't rule out)
		verifyPoint := fundRel || ep == targetEp

		var applyIDs [][32]byte
		var tipRoot [32]byte
		if verifyPoint {
			q, qOK := epochQuorumSelect(vset, ep, fins, pct, true)
			if !qOK || q.count < q.need {
				return fmt.Errorf("epoch %d quorum not reached against the verified validator set (%d/%d) — peer's set/tip is unverifiable", ep, q.count, q.need)
			}
			applyIDs = q.txids
			tipRoot = q.root
		} else {
			applyIDs = pl.txids
		}

		if err := e.applyEpochTxids(applyIDs, txByID); err != nil {
			return fmt.Errorf("apply epoch %d: %w", ep, err)
		}

		// Re-derive the list→Fund flip from the VERIFIED applied state (one-way latch), gated on the
		// Fund-relevance of what we ACTUALLY APPLIED (applyIDs). At a verify point applyIDs is the
		// sig-verified quorum set, so a peer CANNOT steer this by stuffing fake plurality finalizations
		// (which could otherwise suppress the latch on a flip-epoch tip — the flip is not in the
		// heads-only frontier root, so the tip-root check would not catch it). At a non-verify epoch
		// applyIDs == the plurality and is non-Fund by construction, so this never latches there.
		// Equivalent to the live loop, which calls maybeLatchFlip after every commit.
		if e.anyFundRelevant(applyIDs, txByID) {
			e.maybeLatchFlip(ep)
		}

		// Full-state backstop: recompute the frontier root ONCE, at the tip, and require it equals the
		// tip quorum's signed root (verified against the tip's validator set above).
		if ep == targetEp {
			if err := SaveEpochFrontiers(e.cfg.DB, targetEp); err != nil {
				return fmt.Errorf("SaveEpochFrontiers: %w", err)
			}
			root, err := ComputeFrontiersRoot(e.cfg.DB, targetEp)
			if err != nil {
				return fmt.Errorf("ComputeFrontiersRoot: %w", err)
			}
			if root != tipRoot {
				return fmt.Errorf("tip frontier root mismatch at epoch %d: have=%x want=%x", targetEp, root[:8], tipRoot[:8])
			}
		}
	}
	return nil
}

// epochSelection is one (accepted_txids_hash, frontiers_root) group's result.
type epochSelection struct {
	accepted [32]byte
	root     [32]byte
	txids    [][32]byte // the group's accepted-txid list (sorted; verified to hash to `accepted`)
	count    int        // distinct signers in the group (verified members only when verify=true)
	need     int        // quorum threshold for vset (ceil(len(vset)*pct/100), min 1)
}

// epochQuorumSelect groups an epoch's finalizations by their (accepted_txids_hash, frontiers_root)
// pair and returns the LARGEST group (by DISTINCT signer count) plus that group's accepted-txid list
// (verified to hash to accepted_txids_hash).
//
// When verify is true, a signer counts only if it is a MEMBER of vset AND its signature verifies over
// FinalizationDigestP256 — so `count` is the verified quorum and the caller requires `count >= need`.
// When verify is false it counts distinct signers regardless of membership/sig — a peer-trusted
// PLURALITY used only to choose what to apply at a non-verified epoch (backstopped by the tip root).
// Returns ok=false if no group carries a hash-consistent accepted-txid list.
func epochQuorumSelect(vset map[[33]byte]*ecdsa.PublicKey, epoch uint64, fins []*pb.EpochFinalization, pct int, verify bool) (epochSelection, bool) {
	type gkey struct{ a, r [32]byte }
	signers := make(map[gkey]map[[33]byte]struct{})
	listFor := make(map[gkey][][32]byte)

	for _, fin := range fins {
		if fin == nil || fin.Epoch != epoch || fin.Signer == nil || len(fin.Signer.V) != 33 ||
			fin.AcceptedTxidsHash == nil || len(fin.AcceptedTxidsHash.V) != 32 ||
			fin.FrontiersRoot == nil || len(fin.FrontiersRoot.V) != 32 || fin.Sig == nil {
			continue
		}
		var signer [33]byte
		copy(signer[:], fin.Signer.V)
		var a, r [32]byte
		copy(a[:], fin.AcceptedTxidsHash.V)
		copy(r[:], fin.FrontiersRoot.V)

		if verify {
			pub := vset[signer]
			if pub == nil {
				continue
			}
			digest := crypto.FinalizationDigestP256(epoch, a, r)
			if !crypto.VerifyFinalizationSigP256(pub, digest, fin.Sig.V) {
				continue
			}
		}

		k := gkey{a: a, r: r}
		if signers[k] == nil {
			signers[k] = make(map[[33]byte]struct{})
		}
		signers[k][signer] = struct{}{}

		// Capture a hash-consistent accepted-txid list for the group once. The signature is over the
		// accepted_txids_hash, so binding the list to that hash is what ties the applied txs to what
		// the signers actually attested.
		if _, have := listFor[k]; !have {
			ids := make([][32]byte, 0, len(fin.AcceptedTxids))
			ok := true
			for _, raw := range fin.AcceptedTxids {
				if len(raw) != 32 {
					ok = false
					break
				}
				var id [32]byte
				copy(id[:], raw)
				ids = append(ids, id)
			}
			if ok {
				sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
				if crypto.CandidatesListHash(ids) == a {
					listFor[k] = ids
				}
			}
		}
	}

	need := (len(vset)*pct + 99) / 100
	if need < 1 {
		need = 1
	}

	best := gkey{}
	bestN := -1
	for k, s := range signers {
		if _, ok := listFor[k]; !ok {
			continue // no hash-consistent accepted-txid list → unusable group
		}
		n := len(s)
		if n > bestN || (n == bestN && groupLess(k.a, k.r, best.a, best.r)) {
			bestN = n
			best = k
		}
	}
	if bestN < 0 {
		return epochSelection{need: need}, false
	}
	return epochSelection{accepted: best.a, root: best.r, txids: listFor[best], count: bestN, need: need}, true
}

// groupLess gives a deterministic tie-break between equal-count groups (accepted, then root).
func groupLess(a1, r1, a2, r2 [32]byte) bool {
	if c := bytes.Compare(a1[:], a2[:]); c != 0 {
		return c < 0
	}
	return bytes.Compare(r1[:], r2[:]) < 0
}

// anyFundRelevant reports whether any of the epoch's accepted txs touches the Fund — a to==Fund SEND
// (stake / banker descriptor / rotation, which can change Banker membership or the descriptor) or a
// SEND from the Fund (return/kick, which changes a stake's status / membership). These are the ONLY
// txs that can move the Fund-derived validator set or the list→Fund match predicate, so such an epoch
// is treated as a (potential) set-change epoch and quorum-verified. A txid missing from txByID (or
// unparseable) returns true — we cannot rule out a Fund tx, so we verify (the safe over-approximation).
func (e *Engine) anyFundRelevant(ids [][32]byte, txByID map[[32]byte][]byte) bool {
	fund := e.cfg.FundAccount
	for _, id := range ids {
		raw := txByID[id]
		if raw == nil {
			return true
		}
		ptx, err := ParseTx(raw)
		if err != nil {
			return true
		}
		if ptx.Type != pb.TxType_TX_TYPE_SEND {
			continue
		}
		if ptx.Account != nil && bytesEq32(ptx.Account.V, fund) {
			return true // Fund's own SEND (return/kick)
		}
		if sb := ptx.GetSend(); sb != nil && sb.To != nil && bytesEq32(sb.To.V, fund) {
			return true // SEND to the Fund (stake / descriptor / rotation)
		}
	}
	return false
}

// applyEpochTxids applies one epoch's accepted txids in a single transaction. Within an epoch the
// winners are at most one per account and have no intra-epoch dependencies (the snapshot rule means a
// RECEIVE only claims a receivable minted in an EARLIER epoch), so order does not affect the result;
// we sort for reproducibility. Every accepted tx of a finalized epoch applied cleanly when it was
// committed live, so any ApplyTx failure here is a real inconsistency and aborts the resync (no
// deferred-retry is needed — epoch order already satisfies all cross-epoch dependencies, unlike the
// old whole-chain replay).
func (e *Engine) applyEpochTxids(ids [][32]byte, txByID map[[32]byte][]byte) error {
	if len(ids) == 0 {
		return nil
	}
	sorted := append([][32]byte(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i][:], sorted[j][:]) < 0 })

	return e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		view := &bboltTxView{tx: tx}
		for _, id := range sorted {
			raw := txByID[id]
			if raw == nil {
				return fmt.Errorf("missing tx bytes for accepted txid %x", id[:8])
			}
			ptx, err := ParseTx(raw)
			if err != nil {
				return fmt.Errorf("parse accepted tx %x: %w", id[:8], err)
			}
			cid, err := crypto.TxID(ptx)
			if err != nil {
				return fmt.Errorf("txid accepted tx %x: %w", id[:8], err)
			}
			if cid != id {
				return fmt.Errorf("accepted txid does not match its bytes: want %x have %x", id[:8], cid[:8])
			}
			if aerr := ApplyTx(view, raw, ptx, id, e.cfg.FundAccount); aerr != nil {
				return fmt.Errorf("apply accepted tx %x: %w", id[:8], aerr)
			}
		}
		return nil
	})
}

func (e *Engine) persistFinalizations(epoch uint64, fins []*pb.EpochFinalization) error {
	return e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		for _, fin := range fins {
			if fin == nil || fin.Signer == nil || len(fin.Signer.V) != 33 {
				continue
			}
			var signerID [33]byte
			copy(signerID[:], fin.Signer.V)
			raw, err := proto.Marshal(fin)
			if err != nil {
				continue
			}
			if err := PutFinalization(tx, epoch, signerID, raw); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---- HTTP helpers (protobuf over protodelim) ----

func (e *Engine) httpSyncLatest(ctx context.Context, peer string) (uint64, error) {
	peer = strings.TrimRight(peer, "/")
	req, _ := http.NewRequestWithContext(ctx, "GET", peer+"/sync/latest", nil)
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("sync/latest %s: %s body=%q", peer, resp.Status, string(b))
	}
	var out pb.SyncLatestResponse
	if err := protodelim.UnmarshalFrom(bufio.NewReader(resp.Body), &out); err != nil {
		return 0, err
	}
	return out.LatestEpoch, nil
}

func (e *Engine) httpSyncFinalization(ctx context.Context, peer string, epoch uint64) ([]*pb.EpochFinalization, error) {
	peer = strings.TrimRight(peer, "/")
	url := fmt.Sprintf("%s/sync/finalization?epoch=%d", peer, epoch)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sync/finalization %s: %s body=%q", peer, resp.Status, string(b))
	}
	var out pb.SyncFinalizationResponse
	if err := protodelim.UnmarshalFrom(bufio.NewReader(resp.Body), &out); err != nil {
		return nil, err
	}
	return out.Finalizations, nil
}

func (e *Engine) httpSyncFrontiers(ctx context.Context, peer string, epoch uint64, cursor [32]byte, limit int) (*pb.SyncFrontiersResponse, error) {
	peer = strings.TrimRight(peer, "/")
	url := fmt.Sprintf("%s/sync/frontiers?epoch=%d&limit=%d", peer, epoch, limit)
	if cursor != ([32]byte{}) {
		url += "&cursor=" + hex.EncodeToString(cursor[:])
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sync/frontiers %s: %s body=%q", peer, resp.Status, string(b))
	}
	var out pb.SyncFrontiersResponse
	if err := protodelim.UnmarshalFrom(bufio.NewReader(resp.Body), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (e *Engine) httpSyncChain(ctx context.Context, peer string, acct [32]byte, targetHead [32]byte, have [32]byte, max int) ([][]byte, bool, error) {
	peer = strings.TrimRight(peer, "/")
	reqMsg := &pb.SyncChainRequest{
		Account:    &pb.AccountId{V: acct[:]},
		TargetHead: &pb.Hash32{V: targetHead[:]},
		MaxBlocks:  uint32(max),
	}
	if have != ([32]byte{}) {
		reqMsg.Have = &pb.Hash32{V: have[:]}
	}
	var buf bytes.Buffer
	_, _ = protodelim.MarshalTo(&buf, reqMsg)

	req, _ := http.NewRequestWithContext(ctx, "POST", peer+"/sync/chain", &buf)
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("sync/chain %s: %s body=%q", peer, resp.Status, string(b))
	}
	var out pb.SyncChainResponse
	if err := protodelim.UnmarshalFrom(bufio.NewReader(resp.Body), &out); err != nil {
		return nil, false, err
	}

	// Convert pb.Tx -> canonical bytes so we store/execute a single wire format everywhere.
	ret := make([][]byte, 0, len(out.Tx))
	for _, tx := range out.Tx {
		if tx == nil {
			continue
		}
		raw, err := CanonicalTxBytes(tx)
		if err != nil {
			return nil, false, err
		}
		ret = append(ret, raw)
	}
	return ret, out.ReachedHave, nil
}
