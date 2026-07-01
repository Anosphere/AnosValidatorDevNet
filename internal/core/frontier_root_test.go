package core

// Frontier-root agreement guards (P3.1). Deleting the legacy attestor chain removed the
// synthetic AttestorChainID frontier entry from SaveEpochFrontiers AND
// ComputeDryRunFrontiersRoot. These two functions (the post-apply snapshot writer and the
// pre-apply predictor a validator broadcasts in its EpochFinalization) MUST agree on the
// frontier root, or validators fork at finalization. ComputeFrontiersRoot reads whatever
// SaveEpochFrontiers wrote, so all three are exercised here. These tests pin the invariant
// so a future edit that desynchronizes them (e.g. reintroducing a synthetic entry in only
// one path) fails loudly. Shares the fund_credit_test.go harness
// (newFundTestDB/seedFundRecord/seedSpending/applySendThrough/txidFor/testFund).

import "testing"

// The dry-run root a validator broadcasts must byte-equal the post-apply snapshot root.
func TestDryRunFrontierRootMatchesAppliedRoot(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)

	var a, aHead, b, bHead [32]byte
	a[0], aHead[0], b[0], bHead[0] = 0x0a, 0xaa, 0x0b, 0xbb
	const amt = uint64(2_000_000)
	fee := ExpectedFee(amt)
	seedSpending(t, db, a, aHead, amt+fee, 1)
	seedSpending(t, db, b, bHead, amt+fee, 1)

	// applySendThrough derives the new head as txidFor(from, seq); predict the winners.
	winners := map[[32]byte][32]byte{
		a: txidFor(a, 2),
		b: txidFor(b, 2),
	}

	// Predictor: the root each validator computes BEFORE applying and signs into its finalization.
	dryRoot, err := ComputeDryRunFrontiersRoot(db, winners)
	if err != nil {
		t.Fatalf("dry-run root: %v", err)
	}

	// Apply the same winners for real (each is a to==Fund send → head advances, Fund head unchanged),
	// then snapshot + compute the post-state root.
	applySendThrough(t, db, a, aHead, 2, testFund, amt, fee, testFund)
	applySendThrough(t, db, b, bHead, 2, testFund, amt, fee, testFund)

	const epoch = uint64(1)
	if err := SaveEpochFrontiers(db, epoch); err != nil {
		t.Fatalf("save frontiers: %v", err)
	}
	root, err := ComputeFrontiersRoot(db, epoch)
	if err != nil {
		t.Fatalf("compute root: %v", err)
	}
	if root != dryRoot {
		t.Fatalf("frontier root mismatch: dry-run %x != applied %x\n"+
			"the dry-run predictor and the post-apply snapshot MUST agree or finalization forks", dryRoot, root)
	}
}

// The frontier set must be EXACTLY the BAccounts head set — no synthetic entry. The legacy
// attestor chain injected one under AttestorChainID; P3.1 removed it, and nothing else may
// leak a non-account entry into the consensus root.
func TestFrontiersContainExactlyAccountHeads(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)

	var a, aHead [32]byte
	a[0], aHead[0] = 0x0a, 0xaa
	const amt = uint64(2_000_000)
	fee := ExpectedFee(amt)
	seedSpending(t, db, a, aHead, amt+fee, 1)
	applySendThrough(t, db, a, aHead, 2, testFund, amt, fee, testFund)

	const epoch = uint64(7)
	if err := SaveEpochFrontiers(db, epoch); err != nil {
		t.Fatalf("save frontiers: %v", err)
	}

	accts := map[[32]byte][32]byte{}
	heads, err := ListAllAccountHeads(db)
	if err != nil {
		t.Fatalf("list heads: %v", err)
	}
	for _, h := range heads {
		accts[h.Account] = h.Head
	}
	// Sanity: the only records are the Fund + account a.
	if len(accts) != 2 {
		t.Fatalf("expected exactly 2 account records (Fund + a), got %d", len(accts))
	}

	entries, _, err := IterEpochFrontiers(db, epoch, [32]byte{}, 10000)
	if err != nil {
		t.Fatalf("iter frontiers: %v", err)
	}
	if len(entries) != len(accts) {
		t.Fatalf("frontier entry count %d != BAccounts count %d (a synthetic/extra entry leaked into the root)",
			len(entries), len(accts))
	}
	for _, e := range entries {
		h, ok := accts[e.AccountID]
		if !ok {
			t.Fatalf("frontier carries account %x not present in BAccounts (synthetic entry?)", e.AccountID[:4])
		}
		if h != e.HeadHash {
			t.Fatalf("frontier head for %x = %x, BAccounts head = %x", e.AccountID[:4], e.HeadHash[:4], h[:4])
		}
	}
}
