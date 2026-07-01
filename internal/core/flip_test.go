package core

// P4.3 list→Fund activation latch + exact-match predicate (build-plan §P4.3, working notes §3.9).
//
// These tests pin the deterministic, pure pieces of the flip: the one-way BFlipState latch (never
// un-set or moved once recorded, so a later kick can't revert a node to list mode) and the
// FundSetMatchesManifest exact-match predicate (the Fund-derived Banker key set must EQUAL the
// manifest list's keys — no extras, none missing). The live per-epoch source switch + cross-node
// determinism are covered by the live harness.

import (
	"testing"

	"go.etcd.io/bbolt"
)

func readFlipEpoch(t *testing.T, db *bbolt.DB) uint64 {
	t.Helper()
	var got uint64
	if err := db.View(func(tx *bbolt.Tx) error { got = getFlipEpoch(tx); return nil }); err != nil {
		t.Fatalf("read flip epoch: %v", err)
	}
	return got
}

func TestSetFlipEpochOneWay(t *testing.T) {
	db := newFundTestDB(t)
	if got := readFlipEpoch(t, db); got != 0 {
		t.Fatalf("unset flip epoch should be 0, got %d", got)
	}
	// Latch at 50.
	mustUpdate(t, db, func(tx *bbolt.Tx) error { return setFlipEpoch(tx, 50) })
	if got := readFlipEpoch(t, db); got != 50 {
		t.Fatalf("want 50 after latch, got %d", got)
	}
	// One-way: neither a later nor an earlier write may change it.
	mustUpdate(t, db, func(tx *bbolt.Tx) error { return setFlipEpoch(tx, 999) })
	mustUpdate(t, db, func(tx *bbolt.Tx) error { return setFlipEpoch(tx, 10) })
	if got := readFlipEpoch(t, db); got != 50 {
		t.Errorf("flip epoch changed after latch (must be one-way): got %d, want 50", got)
	}
}

// descsFor builds validator descriptors carrying the given consensus keys (distinct identities).
func descsFor(keys ...[]byte) []ValidatorDescriptor {
	out := make([]ValidatorDescriptor, 0, len(keys))
	for i, k := range keys {
		var vd ValidatorDescriptor
		vd.Identity[0] = byte(i + 1)
		copy(vd.ConsensusKey[:], k)
		out = append(out, vd)
	}
	return out
}

func manifestOf(keys ...[]byte) map[[33]byte]struct{} {
	m := make(map[[33]byte]struct{}, len(keys))
	for _, k := range keys {
		var id [33]byte
		copy(id[:], k)
		m[id] = struct{}{}
	}
	return m
}

func TestFundSetMatchesManifest(t *testing.T) {
	k1, k2, k3 := validConsensusKey(t), validConsensusKey(t), validConsensusKey(t)
	man := manifestOf(k1, k2, k3)

	if !FundSetMatchesManifest(descsFor(k1, k2, k3), man) {
		t.Error("exact match (same 3 keys) should be true")
	}
	if FundSetMatchesManifest(descsFor(k1, k2), man) {
		t.Error("subset (missing a key) should be false")
	}
	if FundSetMatchesManifest(descsFor(k1, k2, k3, validConsensusKey(t)), man) {
		t.Error("superset (extra key) should be false")
	}
	if FundSetMatchesManifest(descsFor(k1, k2, validConsensusKey(t)), man) {
		t.Error("same size but a different key should be false")
	}
	// Order-independent (keys compared as a set).
	if !FundSetMatchesManifest(descsFor(k3, k1, k2), man) {
		t.Error("key order must not matter")
	}
	// Empty manifest matches only an empty set.
	if !FundSetMatchesManifest(nil, manifestOf()) {
		t.Error("empty vs empty should match")
	}
	if FundSetMatchesManifest(descsFor(k1), manifestOf()) {
		t.Error("non-empty set vs empty manifest should be false")
	}
}

func TestValidatorKeySetDedup(t *testing.T) {
	k1, k2 := validConsensusKey(t), validConsensusKey(t)
	// Two distinct identities advertising the SAME consensus key fold to one key (flat
	// one-banker-one-vote, keyed by consensus key like the env list).
	ks := ValidatorKeySet(descsFor(k1, k1, k2))
	if len(ks) != 2 {
		t.Fatalf("want 2 distinct keys after dedup, got %d", len(ks))
	}
	// And such a set exactly matches a 2-key manifest of those keys.
	if !FundSetMatchesManifest(descsFor(k1, k1, k2), manifestOf(k1, k2)) {
		t.Error("duplicate-key descriptors should still exactly match the 2-key manifest")
	}
}
