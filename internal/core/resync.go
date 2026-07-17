package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
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

	// A failure past this point is attributed to the picked peer (unless WE are shutting down):
	// blacklist it so the next attempt re-anchors elsewhere instead of re-picking the same
	// highest-tip peer forever (P7.4 — a lying/broken peer could strand a wiped node).
	failPeer := func(stage string, err error) {
		if ctx.Err() == nil {
			e.blacklistResyncPeer(peer, stage+": "+err.Error())
		}
	}

	frontiers, err := e.fetchAllFrontiers(ctx, peer, targetEp)
	if err != nil {
		failPeer("frontiers", err)
		e.setResyncError(err)
		e.elog(targetEp, "RESYNC failed (frontiers): %v", err)
		return err
	}

	// Wipe local state, restore the genesis anchors, and download every account chain into a
	// txid-indexed map. No apply happens here — the verifying walk applies in epoch order below.
	txByID, err := e.wipeAndDownloadChains(ctx, peer, targetEp, frontiers)
	if err != nil {
		failPeer("download", err)
		e.setResyncError(err)
		e.elog(targetEp, "RESYNC failed (download): %v", err)
		return err
	}

	// The epoch-ordered verifying walk: re-derives the validator-set history (and the flip) from the
	// manifest anchor, verifying each set-change + the tip, and checks the tip frontier root. The
	// per-epoch finalizations come from the ranged-prefetching finFetcher (per-epoch fallback for an
	// old peer); the walk persists them in batches as it goes.
	if err := e.verifyingWalk(ctx, targetEp, txByID, newFinFetcher(e, ctx, peer, targetEp).get); err != nil {
		failPeer("verifying walk", err)
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
	// The latest-cached fallback (P7.4 flip-aware gossip gate) is dropped with them for the same
	// reason — until the loop re-caches, PeerMemberForEpoch falls back to the manifest set.
	e.epochSets = make(map[uint64]map[[33]byte]*ecdsa.PublicKey)
	e.latestEpochSet = nil
	e.latestEpochCached = 0

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

// pickResyncTarget chooses the resync peer + target epoch: the highest-tip reachable, non-
// blacklisted ROSTER peer (resync/bootstrap deliberately stays anchored to the static manifest
// roster — a wiped node has no Fund state to derive peers from; locked P7.4 decision).
//
// Unlike the P4.3a interim it does NOT compute a finalization quorum against the static env list
// here. Post-flip the real validators are the Fund-derived set, not the env list, so an env-list
// quorum at the tip would be the WRONG anchor — it would reject an honest post-flip tip and could
// not detect a forged one. The trust anchor now flows through the epoch-ordered verifyingWalk, which
// re-derives every epoch's set from the manifest anchor forward and verifies each set-change + the
// tip against the prior already-trusted set. A peer that lies about its tip is rejected there (its
// finalizations won't verify against the derived set / the tip frontier root won't match), so simply
// picking the highest tip is safe for STATE — but pre-P7.4 the SAME lying peer was re-picked forever
// (highest tip wins every retry), stranding a wiped node, and a bogus tip like 10^12 would drive the
// walk to loop toward 10^12. Three liveness layers fix that WITHOUT a hard clock dependence that
// could itself strand a clock-skewed node:
//   - wall-clock cap (SOFT): epochs are anchored to GenesisUnixMs+EpochDuration, so a committed tip
//     beyond the current wall-clock epoch (+ intake skew) is implausible. We PREFER a peer whose tip
//     is within the cap; a lone liar is simply not preferred (an honest within-cap peer wins). We do
//     NOT blacklist on the cap — if EVERY reachable peer is above it, that means OUR clock is slow,
//     not that the whole roster is lying, so we fall back to the highest tip but CLAMP the target to
//     the cap (bounding the walk against a genuine liar while still making progress). This is the fix
//     for the clock-skew self-strand: a slow clock stays ~cap epochs behind and keeps following,
//     never locking out (the walk has no clock dependence).
//   - blacklist: a peer whose resync ATTEMPT failed (runResync failPeer) is skipped for a window, so
//     the next attempt re-anchors to a different peer;
//   - never-strand: if every candidate was skipped by the blacklist, it is cleared and the scan
//     repeats once — the roster is the ONLY recovery path, so we rotate rather than lock out.
func (e *Engine) pickResyncTarget(ctx context.Context, mismatchEpoch uint64) (peer string, targetEp uint64, err error) {
	_ = mismatchEpoch // the mismatch only TRIGGERS resync; we re-anchor to the peer's verified tip.
	for pass := 0; pass < 2; pass++ {
		capEp := e.epochNow() + maxIntakeEpochAhead
		bestInCap, peerInCap := uint64(0), "" // highest tip within the plausibility cap (preferred)
		bestAny, peerAny := uint64(0), ""     // highest tip overall (fallback when OUR clock is slow)
		skippedBlacklisted := false
		for _, p := range e.cfg.Peers {
			p = strings.TrimRight(p, "/")
			if e.resyncPeerBlacklisted(p) {
				skippedBlacklisted = true
				continue
			}
			ep, e2 := e.httpSyncLatest(ctx, p)
			if e2 != nil {
				continue
			}
			if ep > bestAny {
				bestAny, peerAny = ep, p
			}
			if ep <= capEp && ep > bestInCap {
				bestInCap, peerInCap = ep, p
			}
		}
		switch {
		case peerInCap != "":
			// Normal case: an honest peer within the plausibility cap. A lone liar (tip > cap) is
			// ignored here, costing no resync attempt.
			return peerInCap, bestInCap, nil
		case peerAny != "":
			// Every reachable peer is above the cap ⇒ almost certainly our clock is slow, not the
			// whole roster lying. Use the highest tip but CLAMP the target to the cap so a genuine
			// liar cannot drive an unbounded walk; the target stays a real committed epoch (< the
			// honest tip when the clock is slow) so the walk still makes progress.
			target := bestAny
			if target > capEp {
				target = capEp
			}
			log.Printf("[resync] all peers report a tip above the wall-clock cap %d (local clock likely slow); using %s, target clamped to %d", capEp, peerAny, target)
			return peerAny, target, nil
		}
		if !skippedBlacklisted {
			break
		}
		e.mu.Lock()
		e.resyncBlacklist = make(map[string]time.Time)
		e.mu.Unlock()
		log.Printf("[resync] all candidate peers were blacklisted — clearing the blacklist and rescanning (never-strand)")
	}
	return "", 0, errors.New("resync: no reachable peers")
}

// resyncPeerBlacklisted reports (and lazily expires) a peer's resync blacklist entry.
func (e *Engine) resyncPeerBlacklisted(peer string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	until, ok := e.resyncBlacklist[peer]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(e.resyncBlacklist, peer)
		return false
	}
	return true
}

// blacklistResyncPeer skips a peer for resync target selection for resyncBlacklistWindow. Called
// on a failed attempt attributable to the picked peer (never on our own ctx cancellation) and on a
// provable tip lie. Liveness-only: worst case an honest peer is skipped for one window while the
// roster rotation finds another.
func (e *Engine) blacklistResyncPeer(peer, why string) {
	if peer == "" {
		return
	}
	e.mu.Lock()
	e.resyncBlacklist[peer] = time.Now().Add(resyncBlacklistWindow)
	e.mu.Unlock()
	log.Printf("[resync] blacklisting peer %s for %s: %s", peer, resyncBlacklistWindow, why)
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

	// Persist fetched finalizations in BATCHES (P7.4): one fsynced DB transaction per epoch was the
	// second hidden linear-in-chain-age resync cost (alongside the per-epoch fetch RTT).
	batch := finPersistBatch{e: e}

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
			if perr := batch.add(ep, fins); perr != nil {
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

		if err := e.applyEpochTxids(ep, applyIDs, txByID); err != nil {
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
	if err := batch.flush(); err != nil {
		return fmt.Errorf("persist finalizations: %w", err)
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
//
// epoch is the finalization epoch these txids were accepted at (the walk's ep) — threaded into
// ApplyTx so replay stamps the SAME LastGuardedSendEpoch the live commit did (committed data, byte-
// deterministic; plan D3).
func (e *Engine) applyEpochTxids(epoch uint64, ids [][32]byte, txByID map[[32]byte][]byte) error {
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
			if aerr := ApplyTx(view, raw, ptx, id, e.cfg.FundAccount, e.cfg.Econ, epoch); aerr != nil {
				return fmt.Errorf("apply accepted tx %x: %w", id[:8], aerr)
			}
		}
		return nil
	})
}

// finPersistBatch accumulates the walk's fetched finalizations and writes them in a few large DB
// transactions instead of one fsynced transaction per epoch (P7.4). A mid-walk failure loses only
// the unflushed tail — irrelevant, since a failed resync restarts from scratch anyway.
type finPersistBatch struct {
	e     *Engine
	items []finBatchItem
	nFins int
}

type finBatchItem struct {
	epoch uint64
	fins  []*pb.EpochFinalization
}

const (
	finPersistFlushEpochs = 512  // flush after this many buffered epochs...
	finPersistFlushFins   = 8192 // ...or this many buffered finalizations, whichever first
)

func (b *finPersistBatch) add(epoch uint64, fins []*pb.EpochFinalization) error {
	b.items = append(b.items, finBatchItem{epoch: epoch, fins: fins})
	b.nFins += len(fins)
	if len(b.items) >= finPersistFlushEpochs || b.nFins >= finPersistFlushFins {
		return b.flush()
	}
	return nil
}

func (b *finPersistBatch) flush() error {
	if len(b.items) == 0 {
		return nil
	}
	err := b.e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		for _, it := range b.items {
			for _, fin := range it.fins {
				if fin == nil || fin.Signer == nil || len(fin.Signer.V) != 33 {
					continue
				}
				var signerID [33]byte
				copy(signerID[:], fin.Signer.V)
				raw, merr := proto.Marshal(fin)
				if merr != nil {
					continue
				}
				if err := PutFinalization(tx, it.epoch, signerID, raw); err != nil {
					return err
				}
			}
		}
		return nil
	})
	b.items = nil
	b.nFins = 0
	return err
}

// ---- HTTP helpers (protobuf over protodelim, via the dedicated resync client) ----
//
// P7.4: resync has its OWN http.Client (EngineConfig.ResyncHTTPClient, NO global timeout) with a
// per-request deadline, 429/503 Retry-After pacing, and byte-capped whole-body reads. The shared 2s
// gossip client (cfg.HTTPClient) is untouched — 2s is right for tiny consensus messages and was the
// P7-kickoff Correction #1 bug when reused for bulk /sync downloads. The pacing is the P7.3
// carry-forward (a): /sync is metered for unknown sources, so a fresh (not-yet-member) node's
// bootstrap burst must slow down on 429 instead of livelocking (the old client aborted on ANY
// non-2xx → wipe → retry → same 429 forever).

const (
	// resyncMetaTimeout bounds one small resync request (latest / frontiers page / finalization
	// range). resyncChainTimeout bounds one /sync/chain PAGE — pages are byte-capped server-side
	// (P7.4), so a fixed generous per-page deadline is sound where a whole-chain deadline was not.
	resyncMetaTimeout  = 10 * time.Second
	resyncChainTimeout = 60 * time.Second

	// resyncMaxAttempts caps 429/503 retries per request; resyncRetryAfterMax caps how long a
	// peer's Retry-After can make us wait per attempt.
	resyncMaxAttempts   = 5
	resyncRetryAfterMax = 10 * time.Second

	// resyncMaxRespBytes caps any single resync response body read into memory. It deliberately
	// EXCEEDS protodelim's 4 MiB default (a 25-signer mass-send epoch's finalization set can pass
	// 4 MiB — a latent large-epoch resync breaker); responses are peer-supplied but everything
	// decoded from them is verified by the walk before it can affect state.
	resyncMaxRespBytes = 64 << 20

	// resyncBlacklistWindow is how long a peer that failed a resync attempt (or provably lied
	// about its tip) is skipped by pickResyncTarget. LOCAL liveness knob.
	resyncBlacklistWindow = 5 * time.Minute

	// finRangeSpan is how many epochs one ranged /sync/finalization request asks for; the server
	// may cover fewer (its byte budget) and says how far it got via X-Anos-Fin-Through.
	finRangeSpan = 4096
)

// resyncResp is one fully-read resync response: the body is consumed within the request deadline
// (so the deadline covers the whole transfer) and validated/parsed from memory afterwards.
type resyncResp struct {
	status int
	header http.Header
	body   []byte
}

// resyncDo issues one logical resync request, retrying on 429/503 with Retry-After pacing. build
// must return a FRESH request each attempt (POST bodies are consumed on send); resyncDo stamps the
// X-Anos-* identity headers. Any other status is returned to the caller undisturbed.
func (e *Engine) resyncDo(ctx context.Context, timeout time.Duration, build func(ctx context.Context) (*http.Request, error)) (*resyncResp, error) {
	for attempt := 1; ; attempt++ {
		rr, retryAfter, err := e.resyncDoOnce(ctx, timeout, build)
		if err != nil {
			return nil, err
		}
		if (rr.status != http.StatusTooManyRequests && rr.status != http.StatusServiceUnavailable) ||
			attempt >= resyncMaxAttempts {
			return rr, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryAfter):
		}
	}
}

func (e *Engine) resyncDoOnce(ctx context.Context, timeout time.Duration, build func(ctx context.Context) (*http.Request, error)) (*resyncResp, time.Duration, error) {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := build(rctx)
	if err != nil {
		return nil, 0, err
	}
	e.setAnosHeaders(req)
	resp, err := e.cfg.ResyncHTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, resyncMaxRespBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > resyncMaxRespBytes {
		return nil, 0, fmt.Errorf("resync: response exceeds %d bytes", resyncMaxRespBytes)
	}
	return &resyncResp{status: resp.StatusCode, header: resp.Header, body: body}, parseRetryAfter(resp.Header.Get("Retry-After")), nil
}

// parseRetryAfter reads a Retry-After seconds value (our own limiter sends "1"); default 1s,
// capped so a hostile peer cannot park the client.
func parseRetryAfter(v string) time.Duration {
	d := time.Second
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s > 0 {
		d = time.Duration(s) * time.Second
	}
	if d > resyncRetryAfterMax {
		d = resyncRetryAfterMax
	}
	return d
}

// resyncCheck applies the shared response validation: 2xx + the bidirectional network-id header
// (a wrong-network peer must be rejected BEFORE we decode its bytes, P7.2).
func (e *Engine) resyncCheck(rr *resyncResp, what, peer string) error {
	if rr.status < 200 || rr.status >= 300 {
		b := rr.body
		if len(b) > 200 {
			b = b[:200]
		}
		return fmt.Errorf("%s %s: status %d body=%q", what, peer, rr.status, string(b))
	}
	if err := e.checkAnosResponseHeader(rr.header); err != nil {
		return fmt.Errorf("%s %s: %w", what, peer, err)
	}
	return nil
}

// unmarshalDelim decodes one delimited message from a fully-read body, with the resync-side size
// cap (protodelim's default 4 MiB would reject the large responses resyncMaxRespBytes admits).
func unmarshalDelim(body []byte, m proto.Message) error {
	return protodelim.UnmarshalOptions{MaxSize: resyncMaxRespBytes}.UnmarshalFrom(bytes.NewReader(body), m)
}

func (e *Engine) httpSyncLatest(ctx context.Context, peer string) (uint64, error) {
	peer = strings.TrimRight(peer, "/")
	rr, err := e.resyncDo(ctx, resyncMetaTimeout, func(c context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(c, "GET", peer+"/sync/latest", nil)
	})
	if err != nil {
		return 0, err
	}
	if err := e.resyncCheck(rr, "sync/latest", peer); err != nil {
		return 0, err
	}
	var out pb.SyncLatestResponse
	if err := unmarshalDelim(rr.body, &out); err != nil {
		return 0, err
	}
	return out.LatestEpoch, nil
}

func (e *Engine) httpSyncFinalization(ctx context.Context, peer string, epoch uint64) ([]*pb.EpochFinalization, error) {
	peer = strings.TrimRight(peer, "/")
	url := fmt.Sprintf("%s/sync/finalization?epoch=%d", peer, epoch)
	rr, err := e.resyncDo(ctx, resyncMetaTimeout, func(c context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(c, "GET", url, nil)
	})
	if err != nil {
		return nil, err
	}
	if err := e.resyncCheck(rr, "sync/finalization", peer); err != nil {
		return nil, err
	}
	var out pb.SyncFinalizationResponse
	if err := unmarshalDelim(rr.body, &out); err != nil {
		return nil, err
	}
	return out.Finalizations, nil
}

// errRangedUnsupported marks a peer that predates the P7.4 ranged /sync/finalization form (its
// handler 400s on a missing ?epoch=, or it doesn't stamp X-Anos-Fin-Through). The caller falls
// back to the historical per-epoch fetch — mixed-version interop, no flag day.
var errRangedUnsupported = errors.New("resync: peer does not support ranged /sync/finalization")

// httpSyncFinalizationRange fetches finalizations for epochs [from..to] in ONE request. The server
// returns whole epochs up to its byte budget and stamps the last covered epoch in
// X-Anos-Fin-Through; each finalization self-describes its epoch (proto-clean, no new message).
// Returns the finalizations grouped by epoch plus `through` (>= from on success).
func (e *Engine) httpSyncFinalizationRange(ctx context.Context, peer string, from, to uint64) (map[uint64][]*pb.EpochFinalization, uint64, error) {
	peer = strings.TrimRight(peer, "/")
	url := fmt.Sprintf("%s/sync/finalization?from=%d&to=%d", peer, from, to)
	rr, err := e.resyncDo(ctx, resyncMetaTimeout, func(c context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(c, "GET", url, nil)
	})
	if err != nil {
		return nil, 0, err
	}
	if rr.status == http.StatusBadRequest || rr.status == http.StatusNotFound {
		return nil, 0, errRangedUnsupported
	}
	if err := e.resyncCheck(rr, "sync/finalization(range)", peer); err != nil {
		return nil, 0, err
	}
	through, perr := strconv.ParseUint(strings.TrimSpace(rr.header.Get(HeaderFinThrough)), 10, 64)
	if perr != nil || through < from || through > to {
		// Missing/nonsense coverage marker: treat as an old/odd peer, not a fatal error.
		return nil, 0, errRangedUnsupported
	}
	var out pb.SyncFinalizationResponse
	if err := unmarshalDelim(rr.body, &out); err != nil {
		return nil, 0, err
	}
	byEp := make(map[uint64][]*pb.EpochFinalization)
	for _, f := range out.Finalizations {
		if f == nil || f.Epoch < from || f.Epoch > through {
			continue // out-of-range entries are ignored (defensive; the walk verifies content anyway)
		}
		byEp[f.Epoch] = append(byEp[f.Epoch], f)
	}
	return byEp, through, nil
}

// finFetcher feeds verifyingWalk's ascending per-epoch finalization reads, prefetching RANGED
// pages when the peer supports them and transparently falling back to the per-epoch fetch when it
// doesn't. Consumed entries are deleted, bounding memory to ~one server page. This removes the
// 1-RTT-per-epoch cost that made resync duration scale linearly with chain AGE (~17k epochs/day
// at 5s epochs) — the P7.4 replacement for the once-mooted batch endpoint, with no proto change.
type finFetcher struct {
	e        *Engine
	ctx      context.Context
	peer     string
	targetEp uint64
	ranged   bool
	cache    map[uint64][]*pb.EpochFinalization
	through  uint64 // highest epoch covered by fetched ranges (0 = nothing fetched yet)
}

func newFinFetcher(e *Engine, ctx context.Context, peer string, targetEp uint64) *finFetcher {
	return &finFetcher{e: e, ctx: ctx, peer: peer, targetEp: targetEp, ranged: true,
		cache: make(map[uint64][]*pb.EpochFinalization)}
}

func (f *finFetcher) get(ep uint64) ([]*pb.EpochFinalization, error) {
	for f.ranged && f.through < ep {
		from := f.through + 1
		if from < ep {
			from = ep // the walk consumes ascending; anything below ep was already served
		}
		to := from + finRangeSpan - 1
		if to > f.targetEp {
			to = f.targetEp
		}
		byEp, through, err := f.e.httpSyncFinalizationRange(f.ctx, f.peer, from, to)
		if errors.Is(err, errRangedUnsupported) {
			f.ranged = false
			break
		}
		if err != nil {
			return nil, err
		}
		for k, v := range byEp {
			f.cache[k] = v
		}
		f.through = through // >= from (validated) → guaranteed progress, no spin
	}
	if f.ranged {
		fins := f.cache[ep]
		delete(f.cache, ep)
		return fins, nil
	}
	return f.e.httpSyncFinalization(f.ctx, f.peer, ep)
}

func (e *Engine) httpSyncFrontiers(ctx context.Context, peer string, epoch uint64, cursor [32]byte, limit int) (*pb.SyncFrontiersResponse, error) {
	peer = strings.TrimRight(peer, "/")
	url := fmt.Sprintf("%s/sync/frontiers?epoch=%d&limit=%d", peer, epoch, limit)
	if cursor != ([32]byte{}) {
		url += "&cursor=" + hex.EncodeToString(cursor[:])
	}
	rr, err := e.resyncDo(ctx, resyncMetaTimeout, func(c context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(c, "GET", url, nil)
	})
	if err != nil {
		return nil, err
	}
	if err := e.resyncCheck(rr, "sync/frontiers", peer); err != nil {
		return nil, err
	}
	var out pb.SyncFrontiersResponse
	if err := unmarshalDelim(rr.body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// httpSyncChain downloads an account chain from targetHead back to `have`, PAGING through the
// server's byte-budgeted responses (P7.4): a page that stops early (reachedHave=false, non-empty)
// is continued from the last returned tx's prev, using only the existing request fields. maxTotal
// bounds the total blocks across pages (the pre-P7.4 MaxBlocks semantics). This is what lets a
// long chain download survive both the old whole-body deadline and protodelim's 4 MiB read cap.
func (e *Engine) httpSyncChain(ctx context.Context, peer string, acct [32]byte, targetHead [32]byte, have [32]byte, maxTotal int) ([][]byte, bool, error) {
	peer = strings.TrimRight(peer, "/")
	var all [][]byte
	cur := targetHead
	for {
		remain := maxTotal - len(all)
		if remain <= 0 {
			return all, false, nil // total-block cap without reaching the boundary (caller errors)
		}
		txs, reached, err := e.httpSyncChainPage(ctx, peer, acct, cur, have, remain)
		if err != nil {
			return nil, false, err
		}
		all = append(all, txs...)
		if reached {
			return all, true, nil
		}
		if len(txs) == 0 {
			return all, false, nil // no progress and no boundary — stop (caller errors)
		}
		// Continue from the tail tx's prev. Progress guard: a zero prev (chain base without the
		// boundary) or a non-advancing prev means the peer cannot take us further — stop rather
		// than loop.
		last, perr := ParseTx(txs[len(txs)-1])
		if perr != nil {
			return nil, false, fmt.Errorf("resync: parse page tail: %w", perr)
		}
		if last.Prev == nil || len(last.Prev.V) != 32 {
			return all, false, nil
		}
		var prev [32]byte
		copy(prev[:], last.Prev.V)
		if prev == ([32]byte{}) || prev == cur {
			return all, false, nil
		}
		cur = prev
	}
}

// httpSyncChainPage is one /sync/chain request (the pre-P7.4 whole call, now with a per-page
// deadline and a fresh POST body per 429 retry).
func (e *Engine) httpSyncChainPage(ctx context.Context, peer string, acct [32]byte, targetHead [32]byte, have [32]byte, max int) ([][]byte, bool, error) {
	rr, err := e.resyncDo(ctx, resyncChainTimeout, func(c context.Context) (*http.Request, error) {
		reqMsg := &pb.SyncChainRequest{
			Account:    &pb.AccountId{V: acct[:]},
			TargetHead: &pb.Hash32{V: targetHead[:]},
			MaxBlocks:  uint32(max),
		}
		if have != ([32]byte{}) {
			reqMsg.Have = &pb.Hash32{V: have[:]}
		}
		var buf bytes.Buffer
		if _, err := protodelim.MarshalTo(&buf, reqMsg); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(c, "POST", peer+"/sync/chain", &buf)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		return req, nil
	})
	if err != nil {
		return nil, false, err
	}
	if err := e.resyncCheck(rr, "sync/chain", peer); err != nil {
		return nil, false, err
	}
	var out pb.SyncChainResponse
	if err := unmarshalDelim(rr.body, &out); err != nil {
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
