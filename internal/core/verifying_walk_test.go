package core

// P4.3b rigorous verifying resync (build-plan §P4.3, working notes §3.9). The TESTNET GATE.
//
// These tests pin the SECURITY-critical, deterministic core of the epoch-ordered verifying walk:
//   - epochQuorumSelect: the per-epoch finalization quorum — counts only DISTINCT, in-set, validly
//     signed signers (verify=true); rejects forged/non-member/bad-sig/duplicate signers; binds the
//     accepted-txid list to its signed hash; picks the largest group; and the peer-trusted plurality
//     mode (verify=false) used to select what to apply at non-verified epochs.
//   - verifyingWalk: the loop drives epoch-by-epoch, verifies the TIP quorum against the derived set,
//     checks the tip frontier root once, rejects a forged / below-quorum / wrong-root / missing tip,
//     and does NOT spuriously flip when there is no Fund activity.
//
// The full set-history INTEGRATION (a real flip + a post-flip set DIVERGENCE + a wipe→verifying-resync
// that converges + agrees, plus a peer that lies about the post-flip set being rejected) is exercised
// end-to-end by the live 3-validator harness (real chains over HTTP), which these units complement.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sort"
	"testing"

	"go.etcd.io/bbolt"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// --- test validator (consensus P-256 keypair) ---

type tValidator struct {
	priv *ecdsa.PrivateKey
	id   [33]byte
	pub  *ecdsa.PublicKey
}

func newTValidator(t *testing.T) *tValidator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	return &tValidator{priv: priv, id: crypto.CompressP256PublicKey(&priv.PublicKey), pub: &priv.PublicKey}
}

func vsetOf(vs ...*tValidator) map[[33]byte]*ecdsa.PublicKey {
	m := make(map[[33]byte]*ecdsa.PublicKey, len(vs))
	for _, v := range vs {
		m[v.id] = v.pub
	}
	return m
}

func acceptedHashOf(txids [][32]byte) [32]byte {
	sorted := append([][32]byte(nil), txids...)
	sort.Slice(sorted, func(i, j int) bool {
		for b := 0; b < 32; b++ {
			if sorted[i][b] != sorted[j][b] {
				return sorted[i][b] < sorted[j][b]
			}
		}
		return false
	})
	return crypto.CandidatesListHash(sorted)
}

// signFin builds a finalization for `epoch` over (accepted, root) signed by v, carrying txids.
func (v *tValidator) signFin(t *testing.T, epoch uint64, accepted, root [32]byte, txids [][32]byte) *pb.EpochFinalization {
	t.Helper()
	digest := crypto.FinalizationDigestP256(epoch, accepted, root)
	sig, err := crypto.SignDigestP256DER(v.priv, digest, rand.Reader)
	if err != nil {
		t.Fatalf("sign fin: %v", err)
	}
	fin := &pb.EpochFinalization{
		Epoch:             epoch,
		AcceptedTxidsHash: &pb.Hash32{V: append([]byte(nil), accepted[:]...)},
		FrontiersRoot:     &pb.Hash32{V: append([]byte(nil), root[:]...)},
		Signer:            &pb.Pub32{V: append([]byte(nil), v.id[:]...)},
		Sig:               &pb.SigDER{V: sig},
	}
	for _, id := range txids {
		fin.AcceptedTxids = append(fin.AcceptedTxids, append([]byte(nil), id[:]...))
	}
	return fin
}

// ---- epochQuorumSelect (the security core) ----

func TestEpochQuorumSelectVerifiedQuorum(t *testing.T) {
	v1, v2, v3 := newTValidator(t), newTValidator(t), newTValidator(t)
	vset := vsetOf(v1, v2, v3)
	txids := [][32]byte{{0x01}, {0x02}}
	acc, root := acceptedHashOf(txids), [32]byte{0xaa}
	fins := []*pb.EpochFinalization{
		v1.signFin(t, 7, acc, root, txids),
		v2.signFin(t, 7, acc, root, txids),
		v3.signFin(t, 7, acc, root, txids),
	}
	sel, ok := epochQuorumSelect(vset, 7, fins, 60, true)
	if !ok {
		t.Fatal("expected a usable quorum group")
	}
	if sel.count != 3 || sel.need != 2 {
		t.Fatalf("count/need = %d/%d, want 3/2", sel.count, sel.need)
	}
	if sel.accepted != acc || sel.root != root {
		t.Fatal("accepted/root mismatch")
	}
	if len(sel.txids) != 2 {
		t.Fatalf("txids len = %d, want 2", len(sel.txids))
	}
}

func TestEpochQuorumSelectForgedAndNonMemberDropped(t *testing.T) {
	v1, v2, v3 := newTValidator(t), newTValidator(t), newTValidator(t)
	outsider := newTValidator(t) // not in the set
	vset := vsetOf(v1, v2, v3)
	txids := [][32]byte{{0x09}}
	acc, root := acceptedHashOf(txids), [32]byte{0xbb}

	// A non-member's valid signature must NOT count.
	fins := []*pb.EpochFinalization{
		v1.signFin(t, 3, acc, root, txids),
		outsider.signFin(t, 3, acc, root, txids),
	}
	sel, ok := epochQuorumSelect(vset, 3, fins, 60, true)
	if !ok || sel.count != 1 {
		t.Fatalf("non-member counted: count=%d ok=%v (want 1)", sel.count, ok)
	}

	// A member with a corrupted signature must NOT count.
	bad := v2.signFin(t, 3, acc, root, txids)
	bad.Sig.V[len(bad.Sig.V)-1] ^= 0xff
	fins = []*pb.EpochFinalization{v1.signFin(t, 3, acc, root, txids), bad}
	sel, _ = epochQuorumSelect(vset, 3, fins, 60, true)
	if sel.count != 1 {
		t.Fatalf("bad-sig counted: count=%d (want 1)", sel.count)
	}
}

func TestEpochQuorumSelectDuplicateSignerCountedOnce(t *testing.T) {
	v1, v2 := newTValidator(t), newTValidator(t)
	vset := vsetOf(v1, v2)
	txids := [][32]byte{{0x11}}
	acc, root := acceptedHashOf(txids), [32]byte{0xcc}
	fins := []*pb.EpochFinalization{
		v1.signFin(t, 5, acc, root, txids),
		v1.signFin(t, 5, acc, root, txids), // same signer twice
	}
	sel, _ := epochQuorumSelect(vset, 5, fins, 60, true)
	if sel.count != 1 {
		t.Fatalf("duplicate signer counted twice: count=%d (want 1)", sel.count)
	}
}

func TestEpochQuorumSelectHashBindingRequired(t *testing.T) {
	v1, v2 := newTValidator(t), newTValidator(t)
	vset := vsetOf(v1, v2)
	realTxids := [][32]byte{{0x21}, {0x22}}
	acc := acceptedHashOf(realTxids)
	root := [32]byte{0xdd}
	// Both sign `acc` but advertise a LIST that does NOT hash to `acc` → group unusable.
	wrongList := [][32]byte{{0x99}}
	fins := []*pb.EpochFinalization{
		v1.signFin(t, 9, acc, root, wrongList),
		v2.signFin(t, 9, acc, root, wrongList),
	}
	if _, ok := epochQuorumSelect(vset, 9, fins, 60, true); ok {
		t.Fatal("group with hash-inconsistent accepted-txid list must be unusable")
	}
}

func TestEpochQuorumSelectLargestGroupWins(t *testing.T) {
	v1, v2, v3 := newTValidator(t), newTValidator(t), newTValidator(t)
	vset := vsetOf(v1, v2, v3)
	tA := [][32]byte{{0x01}}
	tB := [][32]byte{{0x02}}
	accA, accB := acceptedHashOf(tA), acceptedHashOf(tB)
	root := [32]byte{0xee}
	fins := []*pb.EpochFinalization{
		v1.signFin(t, 2, accA, root, tA),
		v2.signFin(t, 2, accA, root, tA),
		v3.signFin(t, 2, accB, root, tB), // minority group
	}
	sel, ok := epochQuorumSelect(vset, 2, fins, 60, true)
	if !ok || sel.accepted != accA || sel.count != 2 {
		t.Fatalf("largest group not chosen: ok=%v accepted==A:%v count=%d", ok, sel.accepted == accA, sel.count)
	}
}

func TestEpochQuorumSelectPluralityCountsNonMembers(t *testing.T) {
	v1 := newTValidator(t)
	out1, out2 := newTValidator(t), newTValidator(t)
	vset := vsetOf(v1) // only v1 is a member
	txids := [][32]byte{{0x31}}
	acc, root := acceptedHashOf(txids), [32]byte{0x12}
	fins := []*pb.EpochFinalization{
		out1.signFin(t, 4, acc, root, txids),
		out2.signFin(t, 4, acc, root, txids),
	}
	// verify=true: zero members → unusable / count 0.
	if sel, ok := epochQuorumSelect(vset, 4, fins, 60, true); ok && sel.count != 0 {
		t.Fatalf("verified count should be 0, got %d", sel.count)
	}
	// verify=false (plurality): counts all distinct signers regardless of membership.
	sel, ok := epochQuorumSelect(vset, 4, fins, 60, false)
	if !ok || sel.count != 2 {
		t.Fatalf("plurality count=%d ok=%v (want 2)", sel.count, ok)
	}
}

func TestEpochQuorumSelectEmptyEpoch(t *testing.T) {
	v1, v2 := newTValidator(t), newTValidator(t)
	vset := vsetOf(v1, v2)
	acc := acceptedHashOf(nil) // hash of the empty list
	root := [32]byte{0x34}
	fins := []*pb.EpochFinalization{
		v1.signFin(t, 8, acc, root, nil),
		v2.signFin(t, 8, acc, root, nil),
	}
	sel, ok := epochQuorumSelect(vset, 8, fins, 60, true)
	if !ok || sel.count != 2 || len(sel.txids) != 0 {
		t.Fatalf("empty epoch: ok=%v count=%d txids=%d (want ok,2,0)", ok, sel.count, len(sel.txids))
	}
}

// ---- verifyingWalk integration (engine-backed, no real account txs) ----

func newWalkTestEngine(t *testing.T, vs []*tValidator) *Engine {
	t.Helper()
	dir := t.TempDir()
	db, err := bbolt.Open(dir+"/walk.db", 0o600, nil)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	set := make(map[[33]byte]*ecdsa.PublicKey, len(vs))
	for _, v := range vs {
		set[v.id] = v.pub
	}
	var genesis, fund [32]byte
	genesis[0], fund[0] = 0xAA, 0xFD
	e, err := NewEngine(EngineConfig{
		DB:                db,
		Signer:            NewLocalP256Signer(vs[0].priv), // a manifest member, satisfies NewEngine
		ValidatorSet:      set,
		GenesisUnixMs:     1,
		GenesisAccount:    genesis,
		GenesisSupply:     1_000_000_000,
		GenesisAuthPubKey: make([]byte, crypto.HybridPubKeySize), // never spent in these tests
		FundAccount:       fund,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// genesisRoot computes the frontier root over the freshly-seeded {genesis, fund} accounts — what the
// walk must reproduce at the tip when no account txs are applied.
func genesisRoot(t *testing.T, e *Engine) [32]byte {
	t.Helper()
	if err := SaveEpochFrontiers(e.cfg.DB, 0); err != nil {
		t.Fatalf("SaveEpochFrontiers: %v", err)
	}
	r, err := ComputeFrontiersRoot(e.cfg.DB, 0)
	if err != nil {
		t.Fatalf("ComputeFrontiersRoot: %v", err)
	}
	return r
}

// finsMap builds a getFins closure that signs every epoch 1..targetEp with `signers` over the empty
// winner set at `root`. epochOverride lets a test replace specific epochs' finalizations.
func emptyEpochFins(t *testing.T, signers []*tValidator, targetEp uint64, root [32]byte, override map[uint64][]*pb.EpochFinalization) func(uint64) ([]*pb.EpochFinalization, error) {
	t.Helper()
	acc := acceptedHashOf(nil)
	return func(ep uint64) ([]*pb.EpochFinalization, error) {
		if override != nil {
			if f, ok := override[ep]; ok {
				return f, nil
			}
		}
		var out []*pb.EpochFinalization
		for _, s := range signers {
			out = append(out, s.signFin(t, ep, acc, root, nil))
		}
		return out, nil
	}
}

func TestVerifyingWalkEmptyEpochsConverge(t *testing.T) {
	v1, v2, v3 := newTValidator(t), newTValidator(t), newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v1, v2, v3})
	root := genesisRoot(t, e)

	getFins := emptyEpochFins(t, []*tValidator{v1, v2, v3}, 5, root, nil)
	if err := e.verifyingWalk(context.Background(), 5, map[[32]byte][]byte{}, getFins); err != nil {
		t.Fatalf("walk should converge on honest empty epochs: %v", err)
	}
	// No Fund activity → the flip must NOT latch.
	if fe := e.FlipEpoch(); fe != 0 {
		t.Fatalf("flip latched spuriously without Fund activity: %d", fe)
	}
	// The tip finalizations must have been persisted (so this node can serve them onward).
	if got, err := GetFinalizations(e.cfg.DB, 5); err != nil || len(got) != 3 {
		t.Fatalf("tip finalizations not persisted: n=%d err=%v", len(got), err)
	}
}

func TestVerifyingWalkSkippedMiddleEpoch(t *testing.T) {
	v1, v2, v3 := newTValidator(t), newTValidator(t), newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v1, v2, v3})
	root := genesisRoot(t, e)
	// Epoch 3 was skipped (presence <60%): no finalizations. The walk must treat it as a no-op.
	override := map[uint64][]*pb.EpochFinalization{3: {}}
	getFins := emptyEpochFins(t, []*tValidator{v1, v2, v3}, 5, root, override)
	if err := e.verifyingWalk(context.Background(), 5, map[[32]byte][]byte{}, getFins); err != nil {
		t.Fatalf("walk should tolerate a skipped middle epoch: %v", err)
	}
}

func TestVerifyingWalkSkipsUncommittedEpoch(t *testing.T) {
	// A no-quorum / presence-skipped epoch persists only BELOW-quorum finalizations (a node
	// self-stores its finalization before the quorum check), which the peer still serves. The walk
	// must treat such an epoch as UNCOMMITTED (skip it) rather than replay its proposed-but-never-
	// committed txs — which here reference a txid that was never downloaded, so the OLD behaviour
	// (process any epoch with finalizations) would abort an HONEST resync.
	v1, v2, v3 := newTValidator(t), newTValidator(t), newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v1, v2, v3})
	root := genesisRoot(t, e)

	// Epoch 3: ONE signer (below need=ceil(3*0.6)=2), proposing a txid NOT in txByID. Below quorum →
	// the epoch never committed → must be skipped, not applied.
	phantom := [32]byte{0x77, 0x88}
	phantomList := [][32]byte{phantom}
	accP := acceptedHashOf(phantomList)
	uncommitted := []*pb.EpochFinalization{v1.signFin(t, 3, accP, [32]byte{0x55}, phantomList)}

	getFins := emptyEpochFins(t, []*tValidator{v1, v2, v3}, 5, root, map[uint64][]*pb.EpochFinalization{3: uncommitted})
	if err := e.verifyingWalk(context.Background(), 5, map[[32]byte][]byte{}, getFins); err != nil {
		t.Fatalf("walk must skip a below-quorum (uncommitted) epoch, not abort: %v", err)
	}
}

func TestVerifyingWalkForgedTipRejected(t *testing.T) {
	v1, v2, v3 := newTValidator(t), newTValidator(t), newTValidator(t)
	att1, att2, att3 := newTValidator(t), newTValidator(t), newTValidator(t) // attacker keys, not in the set
	e := newWalkTestEngine(t, []*tValidator{v1, v2, v3})
	root := genesisRoot(t, e)
	// The tip (epoch 5) is signed ONLY by attacker keys outside the manifest set.
	acc := acceptedHashOf(nil)
	forged := []*pb.EpochFinalization{
		att1.signFin(t, 5, acc, root, nil),
		att2.signFin(t, 5, acc, root, nil),
		att3.signFin(t, 5, acc, root, nil),
	}
	getFins := emptyEpochFins(t, []*tValidator{v1, v2, v3}, 5, root, map[uint64][]*pb.EpochFinalization{5: forged})
	if err := e.verifyingWalk(context.Background(), 5, map[[32]byte][]byte{}, getFins); err == nil {
		t.Fatal("walk MUST reject a tip signed only by non-member (forged) validators")
	}
}

func TestVerifyingWalkBelowQuorumTipRejected(t *testing.T) {
	v1, v2, v3 := newTValidator(t), newTValidator(t), newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v1, v2, v3})
	root := genesisRoot(t, e)
	acc := acceptedHashOf(nil)
	// Only 1 of 3 signs the tip (need = ceil(3*0.6) = 2).
	under := []*pb.EpochFinalization{v1.signFin(t, 5, acc, root, nil)}
	getFins := emptyEpochFins(t, []*tValidator{v1, v2, v3}, 5, root, map[uint64][]*pb.EpochFinalization{5: under})
	if err := e.verifyingWalk(context.Background(), 5, map[[32]byte][]byte{}, getFins); err == nil {
		t.Fatal("walk MUST reject a tip below the finalization quorum")
	}
}

func TestVerifyingWalkTipRootMismatchRejected(t *testing.T) {
	v1, v2, v3 := newTValidator(t), newTValidator(t), newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v1, v2, v3})
	// The signers sign a WRONG root; the walk computes the real genesis root and must reject.
	wrong := [32]byte{0xde, 0xad}
	getFins := emptyEpochFins(t, []*tValidator{v1, v2, v3}, 4, wrong, nil)
	if err := e.verifyingWalk(context.Background(), 4, map[[32]byte][]byte{}, getFins); err == nil {
		t.Fatal("walk MUST reject when the tip quorum's signed root != the recomputed frontier root")
	}
}

func TestVerifyingWalkMissingTipFinalizationRejected(t *testing.T) {
	v1, v2, v3 := newTValidator(t), newTValidator(t), newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v1, v2, v3})
	root := genesisRoot(t, e)
	// No finalization at the tip (epoch 5).
	getFins := emptyEpochFins(t, []*tValidator{v1, v2, v3}, 5, root, map[uint64][]*pb.EpochFinalization{5: {}})
	if err := e.verifyingWalk(context.Background(), 5, map[[32]byte][]byte{}, getFins); err == nil {
		t.Fatal("walk MUST reject when the peer has no finalization at the target tip")
	}
}
