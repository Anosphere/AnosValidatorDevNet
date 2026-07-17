package core

// forquinn phase 4 invariant layer (§2.9, revised D7): per-check corruption detection over
// hand-built DBs, the caught-up-and-live halt gate, the halt's effects (finalization frozen,
// resync refused, submits rejected, reads still serving), and the clean-pass bar on
// engine-shaped state. The post-resync gate has its own end-to-end file
// (resync_audit_gate_test.go); the §2.7 overflow rule has overflow_supply_test.go.

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// newAuditEngine mirrors newWalkTestEngine but lets the test pin the genesis wall-clock (the
// caught-up gate compares EpochNow against the committed tip), the audit cadence, and — for
// the resync-gate tests — a peer roster.
func newAuditEngine(t *testing.T, vs []*tValidator, genesisMs int64, cadence uint64, peers []string) *Engine {
	t.Helper()
	db, err := bbolt.Open(t.TempDir()+"/audit.db", 0o600, nil)
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
		DB:                        db,
		Signer:                    NewLocalP256Signer(vs[0].priv),
		ValidatorSet:              set,
		Peers:                     peers,
		GenesisUnixMs:             genesisMs,
		GenesisAccount:            genesis,
		GenesisSupply:             1_000_000_000,
		GenesisAuthPubKey:         make([]byte, crypto.HybridPubKeySize),
		FundAccount:               fund,
		QuorumPercent:             80,
		FinalizationQuorumPercent: 60,
		MaxCandidateScanPerSlot:   64,
		FullAuditEveryEpochs:      cadence,
		Econ:                      testEcon,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// caughtUpGenesisMs anchors genesis so EpochNow() lands at wall-clock epoch `nowEpoch`
// (mid-window, so the value is stable for the test's lifetime).
func caughtUpGenesisMs(nowEpoch uint64) int64 {
	epochMs := int64(5000) // the NewEngine default EpochDuration
	return time.Now().UnixMilli() - int64(nowEpoch-1)*epochMs - epochMs/2
}

// commitFrontiersWithFin snapshots the current account heads as epoch `ep`'s frontiers and
// stores one finalization carrying the matching root — the minimal "this node committed ep
// and agreed on its root" shape the stored-root check audits.
func commitFrontiersWithFin(t *testing.T, e *Engine, v *tValidator, ep uint64) [32]byte {
	t.Helper()
	if err := SaveEpochFrontiers(e.cfg.DB, ep); err != nil {
		t.Fatalf("SaveEpochFrontiers(%d): %v", ep, err)
	}
	root, err := ComputeFrontiersRoot(e.cfg.DB, ep)
	if err != nil {
		t.Fatalf("ComputeFrontiersRoot(%d): %v", ep, err)
	}
	fin := v.signFin(t, ep, acceptedHashOf(nil), root, nil)
	raw, merr := proto.Marshal(fin)
	if merr != nil {
		t.Fatalf("marshal fin: %v", merr)
	}
	if err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		return PutFinalization(tx, ep, v.id, raw)
	}); err != nil {
		t.Fatalf("PutFinalization: %v", err)
	}
	return root
}

// corruptGenesisBalance bumps the genesis account balance by delta — supply-total corruption
// that leaves every head untouched (so only the supply check should fire).
func corruptGenesisBalance(t *testing.T, e *Engine, delta uint64) {
	t.Helper()
	if err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		rec, ok := getAccountRecord(tx, e.cfg.GenesisAccount)
		if !ok {
			t.Fatal("genesis record missing")
		}
		rec.Balance += delta
		return putAccountRecord(tx, e.cfg.GenesisAccount, rec)
	}); err != nil {
		t.Fatalf("corrupt genesis: %v", err)
	}
}

func viewCheck(t *testing.T, db *bbolt.DB, fn func(tx *bbolt.Tx) error) error {
	t.Helper()
	var out error
	if err := db.View(func(tx *bbolt.Tx) error {
		out = fn(tx)
		return nil
	}); err != nil {
		t.Fatalf("view: %v", err)
	}
	return out
}

func wantViolation(t *testing.T, err error, category, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: passed, want a %q violation", what, category)
	}
	if !errors.Is(err, ErrInvariantViolation) {
		t.Fatalf("%s: error %v does not wrap ErrInvariantViolation", what, err)
	}
	var ive *InvariantViolationError
	if !errors.As(err, &ive) {
		t.Fatalf("%s: error %v is not an InvariantViolationError", what, err)
	}
	if ive.Category != category {
		t.Fatalf("%s: category %q, want %q (err=%v)", what, ive.Category, category, err)
	}
}

// --- invSupplyTotal ---

func TestInvSupplyTotalConservesThroughRealApply(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)
	var acct, head [32]byte
	acct[0], head[0] = 0xA1, 0x51
	const supply = uint64(10_000_000)
	seedSpending(t, db, acct, head, supply, 3)

	if err := viewCheck(t, db, func(tx *bbolt.Tx) error { return invSupplyTotal(tx, supply) }); err != nil {
		t.Fatalf("seeded state: %v", err)
	}

	// A real SEND through ApplyTx: sender debited amt+fee, fee credited to the Fund, amt held
	// in-flight as an UNCLAIMED receivable — the total must not move.
	var to [32]byte
	to[0] = 0xB1
	const amt = uint64(70_000)
	fee := testEcon.RequiredFee(amt)
	sendID := applySendThrough(t, db, acct, head, 4, to, amt, fee, testFund)
	if err := viewCheck(t, db, func(tx *bbolt.Tx) error { return invSupplyTotal(tx, supply) }); err != nil {
		t.Fatalf("after send (in-flight receivable must count): %v", err)
	}

	// Mark the receivable claimed WITHOUT crediting the recipient: value vanishes → violation.
	rid := crypto.ReceivableIDFromTxID(sendID)
	if err := db.Update(func(tx *bbolt.Tx) error {
		raw, err := getReceivableRaw(tx, rid)
		if err != nil {
			return err
		}
		var rec pb.Receivable
		if err := proto.Unmarshal(raw, &rec); err != nil {
			return err
		}
		rec.Claimed = true
		rec.ClaimedByTx = &pb.Hash32{V: make([]byte, 32)}
		nraw, _ := proto.Marshal(&rec)
		return putReceivableRaw(tx, rid, nraw)
	}); err != nil {
		t.Fatalf("mark claimed: %v", err)
	}
	wantViolation(t, viewCheck(t, db, func(tx *bbolt.Tx) error { return invSupplyTotal(tx, supply) }),
		"supply-total", "claimed-but-never-credited receivable")

	// Credit the recipient (the RECEIVE's balance effect): conserved again — and proves
	// CLAIMED rows are excluded from the sum.
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, to, AccountRecord{Head: [32]byte{0xB2}, Balance: amt, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING})
	}); err != nil {
		t.Fatalf("credit recipient: %v", err)
	}
	if err := viewCheck(t, db, func(tx *bbolt.Tx) error { return invSupplyTotal(tx, supply) }); err != nil {
		t.Fatalf("after claim credit: %v", err)
	}

	// Inflate any balance by one unit → violation.
	if err := db.Update(func(tx *bbolt.Tx) error {
		rec, _ := getAccountRecord(tx, to)
		rec.Balance++
		return putAccountRecord(tx, to, rec)
	}); err != nil {
		t.Fatalf("inflate: %v", err)
	}
	wantViolation(t, viewCheck(t, db, func(tx *bbolt.Tx) error { return invSupplyTotal(tx, supply) }),
		"supply-total", "inflated balance")
}

// --- invFundSolvency ---

func TestInvFundSolvency(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund) // balance 0
	var staker, dep [32]byte
	staker[0], dep[0] = 0xC1, 0xD1

	// An ACTIVE stake the pool cannot cover → violation.
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putStakeRecord(tx, dep, StakeRecord{StakerID: staker, Amount: 500, TimeDelay: pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR, Status: StakeStatusActive, StakedFor: "attestor"})
	}); err != nil {
		t.Fatalf("seed stake: %v", err)
	}
	wantViolation(t, viewCheck(t, db, func(tx *bbolt.Tx) error { return invFundSolvency(tx, testFund) }),
		"fund-solvency", "active stake exceeding fund balance")

	// Fund the pool to exactly the stake → solvent.
	if err := db.Update(func(tx *bbolt.Tx) error {
		rec, _ := getAccountRecord(tx, testFund)
		rec.Balance = 500
		return putAccountRecord(tx, testFund, rec)
	}); err != nil {
		t.Fatalf("fund pool: %v", err)
	}
	if err := viewCheck(t, db, func(tx *bbolt.Tx) error { return invFundSolvency(tx, testFund) }); err != nil {
		t.Fatalf("exactly-covered stake: %v", err)
	}

	// A RETURNED row is inert: drain the pool, flip the row → still solvent.
	if err := db.Update(func(tx *bbolt.Tx) error {
		rec, _ := getAccountRecord(tx, testFund)
		rec.Balance = 0
		if err := putAccountRecord(tx, testFund, rec); err != nil {
			return err
		}
		return putStakeRecord(tx, dep, StakeRecord{StakerID: staker, Amount: 500, TimeDelay: pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR, Status: StakeStatusReturned, StakedFor: "attestor"})
	}); err != nil {
		t.Fatalf("return stake: %v", err)
	}
	if err := viewCheck(t, db, func(tx *bbolt.Tx) error { return invFundSolvency(tx, testFund) }); err != nil {
		t.Fatalf("returned row must be inert: %v", err)
	}
}

// --- invReceivableSanity ---

func TestInvReceivableSanity(t *testing.T) {
	db := newFundTestDB(t)
	const supply = uint64(1_000_000)
	put := func(rid [32]byte, rec *pb.Receivable) {
		t.Helper()
		raw, _ := proto.Marshal(rec)
		if err := db.Update(func(tx *bbolt.Tx) error { return putReceivableRaw(tx, rid, raw) }); err != nil {
			t.Fatalf("put receivable: %v", err)
		}
	}
	del := func(rid [32]byte) {
		t.Helper()
		if err := db.Update(func(tx *bbolt.Tx) error { return tx.Bucket(BRecv).Delete(rid[:]) }); err != nil {
			t.Fatalf("del receivable: %v", err)
		}
	}
	check := func() error {
		return viewCheck(t, db, func(tx *bbolt.Tx) error { return invReceivableSanity(tx, supply) })
	}
	var rid, from, to [32]byte
	rid[0], from[0], to[0] = 0xE1, 0xE2, 0xE3
	good := func() *pb.Receivable {
		return &pb.Receivable{
			Id:     &pb.Hash32{V: rid[:]},
			From:   &pb.AccountId{V: from[:]},
			To:     &pb.AccountId{V: to[:]},
			Amount: 1000,
		}
	}

	put(rid, good())
	if err := check(); err != nil {
		t.Fatalf("well-formed unclaimed row: %v", err)
	}

	r := good()
	r.Id = &pb.Hash32{V: make([]byte, 32)} // id != key
	put(rid, r)
	wantViolation(t, check(), "receivable-sanity", "id/key mismatch")

	r = good()
	r.From = &pb.AccountId{V: []byte{1, 2, 3}}
	put(rid, r)
	wantViolation(t, check(), "receivable-sanity", "malformed from")

	r = good()
	r.Amount = supply + 1
	put(rid, r)
	wantViolation(t, check(), "receivable-sanity", "unclaimed amount above supply")

	r = good()
	r.Claimed = true // no ClaimedByTx
	put(rid, r)
	wantViolation(t, check(), "receivable-sanity", "claimed without claiming txid")

	r = good()
	r.Claimed = true
	r.ClaimedByTx = &pb.Hash32{V: make([]byte, 32)}
	r.Amount = supply + 1 // a CLAIMED amount is history, not in-flight value — no cap
	put(rid, r)
	if err := check(); err != nil {
		t.Fatalf("claimed row with claiming txid: %v", err)
	}
	del(rid)
}

// --- invContinuityFull ---

// applyRealSend builds an (unsigned — ApplyTx never verifies sigs) SEND whose txid is the REAL
// crypto.TxID over its bytes, applies it, and returns (txid, tx). Continuity recomputes the
// txid from the stored bytes, so fake txidFor ids would false-positive here.
func applyRealSend(t *testing.T, e *Engine, from, prev [32]byte, seq uint64, to [32]byte, amt, fee uint64, class pb.AccountClass) ([32]byte, *pb.Tx) {
	t.Helper()
	ptx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: from[:]},
		Prev:    &pb.Hash32{V: prev[:]},
		Seq:     seq,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: to[:]},
			Amount:       amt,
			Fee:          fee,
			AccountClass: class,
		}},
	}
	id, err := crypto.TxID(ptx)
	if err != nil {
		t.Fatalf("txid: %v", err)
	}
	raw, _ := proto.Marshal(ptx)
	if err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: tx}, raw, ptx, id, e.cfg.FundAccount, e.cfg.Econ, 1)
	}); err != nil {
		t.Fatalf("apply real send: %v", err)
	}
	return id, ptx
}

func TestInvContinuityFull(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})
	db := e.cfg.DB
	check := func() error {
		return viewCheck(t, db, func(tx *bbolt.Tx) error { return invContinuityFull(tx) })
	}

	// Fresh engine: only the genesis + Fund synthetic anchors — exempt by their own-account
	// anchor equality.
	if err := check(); err != nil {
		t.Fatalf("fresh engine: %v", err)
	}

	// A real send advances genesis to a real head with stored, hash-matching bytes.
	var to [32]byte
	to[0] = 0xB9
	genesisSynthetic := syntheticSeedHead("ANOS_GENESIS_HEAD_V1:", e.cfg.GenesisAccount)
	const amt = uint64(5_000)
	id, _ := applyRealSend(t, e, e.cfg.GenesisAccount, genesisSynthetic, 2, to, amt, testEcon.RequiredFee(amt), pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	if err := check(); err != nil {
		t.Fatalf("after real send: %v", err)
	}

	// Record seq drifts from the head tx's seq → violation.
	if err := db.Update(func(tx *bbolt.Tx) error {
		rec, _ := getAccountRecord(tx, e.cfg.GenesisAccount)
		rec.Seq = 9
		return putAccountRecord(tx, e.cfg.GenesisAccount, rec)
	}); err != nil {
		t.Fatalf("drift seq: %v", err)
	}
	wantViolation(t, check(), "chain-continuity", "record/head seq drift")
	if err := db.Update(func(tx *bbolt.Tx) error {
		rec, _ := getAccountRecord(tx, e.cfg.GenesisAccount)
		rec.Seq = 2
		return putAccountRecord(tx, e.cfg.GenesisAccount, rec)
	}); err != nil {
		t.Fatalf("restore seq: %v", err)
	}

	// The head's backing bytes vanish → violation.
	if err := db.Update(func(tx *bbolt.Tx) error { return tx.Bucket(BTxs).Delete(id[:]) }); err != nil {
		t.Fatalf("delete head bytes: %v", err)
	}
	wantViolation(t, check(), "chain-continuity", "missing head bytes")

	// A head that is neither a stored tx nor the account's OWN synthetic anchor (another
	// account's anchor preimage must not be exempt) → violation.
	if err := db.Update(func(tx *bbolt.Tx) error {
		rec, _ := getAccountRecord(tx, e.cfg.GenesisAccount)
		rec.Head = syntheticSeedHead("ANOS_GENESIS_HEAD_V1:", to) // someone else's anchor
		return putAccountRecord(tx, e.cfg.GenesisAccount, rec)
	}); err != nil {
		t.Fatalf("foreign anchor: %v", err)
	}
	wantViolation(t, check(), "chain-continuity", "foreign synthetic anchor")
}

// --- invStoredRootSelfCheck ---

func TestInvStoredRootSelfCheck(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})
	db := e.cfg.DB
	check := func(ep uint64) error {
		return viewCheck(t, db, func(tx *bbolt.Tx) error { return invStoredRootSelfCheck(tx, ep) })
	}

	if err := check(0); err != nil {
		t.Fatalf("epoch 0 (nothing committed) must be clean: %v", err)
	}

	// Committed frontiers but NO stored finalization → the agreed root is underivable → violation.
	if err := SaveEpochFrontiers(db, 6); err != nil {
		t.Fatalf("SaveEpochFrontiers: %v", err)
	}
	wantViolation(t, check(6), "stored-root", "no stored finalizations")

	// A stored finalization carrying a DIFFERENT root only → violation.
	badFin := v.signFin(t, 6, acceptedHashOf(nil), [32]byte{0xBB}, nil)
	rawBad, _ := proto.Marshal(badFin)
	other := newTValidator(t)
	if err := db.Update(func(tx *bbolt.Tx) error { return PutFinalization(tx, 6, other.id, rawBad) }); err != nil {
		t.Fatalf("put bad fin: %v", err)
	}
	wantViolation(t, check(6), "stored-root", "no matching stored root")

	// Add the MATCHING finalization → clean (the bad one from the mismatch path may coexist).
	_ = commitFrontiersWithFin(t, e, v, 6)
	if err := check(6); err != nil {
		t.Fatalf("matching fin stored: %v", err)
	}

	// Post-commit corruption of a frontier row → recomputed root matches nothing → violation.
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(BEpochFrontiers).Put(epochFrontierKey(6, e.cfg.GenesisAccount), make([]byte, 32))
	}); err != nil {
		t.Fatalf("corrupt frontier row: %v", err)
	}
	wantViolation(t, check(6), "stored-root", "corrupted frontier row")
}

// --- invValidatorSet ---

func TestInvValidatorSet(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})
	db := e.cfg.DB
	check := func() error {
		return viewCheck(t, db, func(tx *bbolt.Tx) error { return e.invValidatorSet(tx) })
	}

	// Pre-flip: nothing derived to compare.
	if err := check(); err != nil {
		t.Fatalf("pre-flip: %v", err)
	}

	// Post-flip with the cache one epoch ahead of the committed tip, but EMPTY fund tables →
	// the cached set cannot be justified by the stake state → violation.
	if err := db.Update(func(tx *bbolt.Tx) error { return setFlipEpoch(tx, 1) }); err != nil {
		t.Fatalf("set flip: %v", err)
	}
	if err := SaveEpochFrontiers(db, 3); err != nil {
		t.Fatalf("frontiers: %v", err)
	}
	e.mu.Lock()
	e.latestEpochCached = 4
	e.latestEpochSet = map[[33]byte]*ecdsa.PublicKey{v.id: v.pub}
	e.mu.Unlock()
	wantViolation(t, check(), "validator-set", "cached set with empty fund tables")

	// Cache NOT aligned to tip+1 → skip (legitimate derivation skew, never a false halt).
	e.mu.Lock()
	e.latestEpochCached = 3
	e.mu.Unlock()
	if err := check(); err != nil {
		t.Fatalf("unaligned cache must skip: %v", err)
	}
	e.mu.Lock()
	e.latestEpochCached = 4
	e.mu.Unlock()

	// Tables deriving EXACTLY the cached set → clean.
	var staker, dep [32]byte
	staker[0], dep[0] = 0xC7, 0xD7
	if err := db.Update(func(tx *bbolt.Tx) error {
		if err := putStakeRecord(tx, dep, StakeRecord{
			StakerID:  staker,
			Amount:    testEcon.BankerStakeFloorAnos * UnitsPerAnos,
			TimeDelay: pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR,
			Status:    StakeStatusActive,
			StakedFor: StakedForBanker,
		}); err != nil {
			return err
		}
		return putBankerInfo(tx, staker, v.id[:], "127.0.0.1:9999", 2)
	}); err != nil {
		t.Fatalf("seed banker: %v", err)
	}
	if err := check(); err != nil {
		t.Fatalf("matching derived set: %v", err)
	}
}

// --- The halt: caught-up gate, effects, cadence ---

func TestAuditHaltsCaughtUpNodeAndFreezesEverything(t *testing.T) {
	v := newTValidator(t)
	e := newAuditEngine(t, []*tValidator{v}, caughtUpGenesisMs(4), 1, nil)
	commitFrontiersWithFin(t, e, v, 3) // committed tip 3, wall clock in epoch 4 → caught up

	if err := e.runFullAudit(3); err != nil {
		t.Fatalf("pre-corruption audit must be clean: %v", err)
	}
	if got := e.LastFullAuditEpoch(); got != 3 {
		t.Fatalf("last_full_audit_epoch = %d, want 3", got)
	}

	// The clean pass stamped last_full_audit_epoch=3, so a re-kick at the SAME epoch dedups
	// (by-design cadence behavior). Corrupt, then commit the next epoch — the realistic shape:
	// the corruption is caught at the next commit barrier's kick.
	corruptGenesisBalance(t, e, 1)
	commitFrontiersWithFin(t, e, v, 4)
	e.auditOnce(false)

	halted, reason, hEpoch := e.InvariantStats()
	if !halted || reason != "supply-total" || hEpoch != 4 {
		t.Fatalf("after audit: halted=%v reason=%q epoch=%d (want true, supply-total, 4)", halted, reason, hEpoch)
	}

	// Frozen: submits rejected...
	if err := e.SubmitTx([]byte{1}); err == nil || !strings.Contains(err.Error(), "halted") {
		t.Fatalf("SubmitTx while halted: %v (want halted reject)", err)
	}
	// ...resync refused (forensic state preserved)...
	e.triggerResync(4, [32]byte{}, [32]byte{})
	if e.ResyncActive() {
		t.Fatalf("triggerResync must be a no-op while halted")
	}
	// ...commits refused...
	if _, _, err := e.commitEpoch(4, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "halted") {
		t.Fatalf("commitEpoch while halted: %v (want halted reject)", err)
	}
	// ...reads keep serving...
	rec, err := e.AccountState(e.cfg.GenesisAccount)
	if err != nil || rec.Balance == 0 {
		t.Fatalf("reads must keep serving while halted: rec=%+v err=%v", rec, err)
	}
	// ...and the loop idles without touching state (one halted iteration returns promptly).
	if stop := e.loopOnce(context.Background(), 5000, 1); stop {
		t.Fatalf("halted loop iteration must not stop the loop")
	}

	// First violation wins: a second halt attempt must not overwrite the evidence.
	e.haltInvariant(violation("fund-solvency", "late"), 9)
	if _, reason2, ep2 := e.InvariantStats(); reason2 != "supply-total" || ep2 != 4 {
		t.Fatalf("second halt overwrote the first: %q/%d", reason2, ep2)
	}

	// kickAudit never blocks, even unconsumed.
	e.kickAudit()
	e.kickAudit()
}

func TestAuditSkipsLaggingNode(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v}) // GenesisUnixMs=1 → wall clock far ahead of any tip
	commitFrontiersWithFin(t, e, v, 3)
	corruptGenesisBalance(t, e, 1)

	e.auditOnce(false)
	if halted, _, _ := e.InvariantStats(); halted {
		t.Fatalf("a lagging node must SKIP the audit (its lag belongs to the resync probe), not halt")
	}
	// The boot flavor skips the same way.
	e.auditOnce(true)
	if halted, _, _ := e.InvariantStats(); halted {
		t.Fatalf("a lagging boot audit must not halt")
	}
}

func TestAuditSkipsWhileResyncing(t *testing.T) {
	v := newTValidator(t)
	e := newAuditEngine(t, []*tValidator{v}, caughtUpGenesisMs(4), 1, nil)
	commitFrontiersWithFin(t, e, v, 3)
	corruptGenesisBalance(t, e, 1)

	e.mu.Lock()
	e.resync.Mode = ResyncPending
	e.mu.Unlock()
	e.auditOnce(false)
	if halted, _, _ := e.InvariantStats(); halted {
		t.Fatalf("a resyncing node must not halt (the post-resync gate owns that decision)")
	}
}

func TestAuditCadenceThrottle(t *testing.T) {
	v := newTValidator(t)
	e := newAuditEngine(t, []*tValidator{v}, caughtUpGenesisMs(5), 5, nil) // cadence 5, wall clock epoch 5
	commitFrontiersWithFin(t, e, v, 3)
	if err := e.runFullAudit(3); err != nil { // lastFullAuditEpoch = 3
		t.Fatalf("baseline audit: %v", err)
	}

	corruptGenesisBalance(t, e, 1)
	commitFrontiersWithFin(t, e, v, 4)
	e.auditOnce(false) // epoch 4 < 3+5 → inside the cadence window → skip
	if halted, _, _ := e.InvariantStats(); halted {
		t.Fatalf("cadence window must skip the audit")
	}

	commitFrontiersWithFin(t, e, v, 8) // epoch 8 == 3+5 → due (wall clock 5 ≤ 8+margin → still "live")
	e.auditOnce(false)
	if halted, reason, _ := e.InvariantStats(); !halted || reason != "supply-total" {
		t.Fatalf("cadence-due audit must run and halt: halted=%v reason=%q", halted, reason)
	}
}

func TestFullAuditCleanOnCommittedEngineState(t *testing.T) {
	// The zero-false-positive bar in unit form: an engine-shaped DB — genesis distribution
	// send applied with a REAL txid, frontiers + matching stored finalization — audits clean
	// end to end (all six checks), and the boot-flavor auditOnce leaves the node running.
	v := newTValidator(t)
	e := newAuditEngine(t, []*tValidator{v}, caughtUpGenesisMs(2), 1, nil)
	var to [32]byte
	to[0] = 0xB5
	genesisSynthetic := syntheticSeedHead("ANOS_GENESIS_HEAD_V1:", e.cfg.GenesisAccount)
	const amt = uint64(250_000)
	applyRealSend(t, e, e.cfg.GenesisAccount, genesisSynthetic, 2, to, amt, testEcon.RequiredFee(amt), pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	commitFrontiersWithFin(t, e, v, 1)

	e.auditOnce(true)
	if halted, reason, _ := e.InvariantStats(); halted {
		t.Fatalf("clean committed state must not halt (false positive!): %q", reason)
	}
	if got := e.LastFullAuditEpoch(); got != 1 {
		t.Fatalf("clean boot audit must stamp last_full_audit_epoch: got %d, want 1", got)
	}
}
