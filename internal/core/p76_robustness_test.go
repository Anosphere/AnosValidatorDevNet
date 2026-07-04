package core

// P7.6 input-robustness units: the epoch-loop recover guard (guardIteration + noteLoopPanic +
// the repeated-panic poison purge), the background-sender guard (recoverBGPanic), and the atomic
// epoch commit (commitEpoch: winner apply + frontier snapshot + flip latch in ONE bbolt Update,
// any failed winner rolling the whole epoch back). The fuzz targets in fuzz_test.go exercise the
// parse surface these guards backstop; these tests pin the guards themselves.

import (
	"strings"
	"sync"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	pb "anos/internal/proto"
)

// --- guardIteration: the exact production recover wrapper around one loop iteration ---

func TestGuardIterationRecoversPanic(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t)})

	stop, panicked := e.guardIteration(func() bool { panic("poison tx crossed the loop") })
	if stop || !panicked {
		t.Fatalf("panicking iteration: stop=%v panicked=%v (want false,true — the loop must continue)", stop, panicked)
	}
	total, last := e.PanicStats()
	if total != 1 {
		t.Fatalf("stats after one panic: total=%d (want 1)", total)
	}
	if !strings.Contains(last, "poison tx crossed the loop") {
		t.Fatalf("lastPanic %q should carry the panic value", last)
	}
}

// A recovered loop panic must drive a resync (loop()'s panicked branch) — the fix for the
// skip-a-commit-then-diverge finding. The loop triggers it via triggerResync after a panicked
// guardIteration; here we exercise that exact sequence and assert the engine enters resync mode.
func TestRecoveredLoopPanicTriggersResync(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t)})
	if e.ResyncActive() {
		t.Fatalf("fresh engine should not be resyncing")
	}
	_, panicked := e.guardIteration(func() bool { panic("nil deref during winner selection") })
	if !panicked {
		t.Fatalf("guardIteration must report the panic")
	}
	// This is what loop() does on panicked=true.
	e.triggerResync(e.EpochNow(), [32]byte{}, [32]byte{})
	if !e.ResyncActive() {
		t.Fatalf("a recovered loop panic must trigger a resync (never continue on a possibly-skipped-commit base)")
	}
}

func TestGuardIterationPassesThroughClean(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t)})

	stop, panicked := e.guardIteration(func() bool { return true })
	if !stop || panicked {
		t.Fatalf("clean stop iteration: stop=%v panicked=%v (want true,false)", stop, panicked)
	}
	stop, panicked = e.guardIteration(func() bool { return false })
	if stop || panicked {
		t.Fatalf("clean continue iteration: stop=%v panicked=%v (want false,false)", stop, panicked)
	}
	if total, _ := e.PanicStats(); total != 0 {
		t.Fatalf("clean iterations must not count panics, got total=%d", total)
	}
}

// --- noteLoopPanic: bookkeeping only (count + last message); recovery is loop()'s job ---

func TestNoteLoopPanicIsBookkeepingOnly(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t)})

	// A pooled tx must NOT be touched by noteLoopPanic — the resync loop() triggers clears the
	// pools; noteLoopPanic itself is pure bookkeeping (no pool surgery, no e.mu-reentrancy risk).
	var id [32]byte
	id[0] = 0xEE
	e.mu.Lock()
	if e.txPool == nil {
		e.txPool = make(map[[32]byte][]byte)
	}
	e.txPool[id] = []byte{1, 2, 3}
	e.mu.Unlock()

	e.noteLoopPanic("boom")
	e.noteLoopPanic("boom again")

	e.mu.Lock()
	poolLen := len(e.txPool)
	e.mu.Unlock()
	if poolLen != 1 {
		t.Fatalf("noteLoopPanic must not purge pools (resync does); pool=%d", poolLen)
	}
	if total, last := e.PanicStats(); total != 2 || !strings.Contains(last, "boom again") {
		t.Fatalf("stats: total=%d last=%q (want 2, last message recorded)", total, last)
	}
}

// --- recoverBGPanic: a background sender goroutine panic is contained + counted ---

func TestRecoverBGPanicContainsGoroutinePanic(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t)})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer e.recoverBGPanic("test-sender")
		panic("broadcast invariant break")
	}()
	wg.Wait() // reaching here at all proves the panic did not kill the process

	total, last := e.PanicStats()
	if total != 1 {
		t.Fatalf("background panic must be counted, total=%d", total)
	}
	if !strings.Contains(last, "test-sender") {
		t.Fatalf("lastPanic %q should name the goroutine", last)
	}
	if e.ResyncActive() {
		t.Fatalf("a background-sender panic must NOT trigger a resync (only a loop panic can skip a commit)")
	}
}

// --- commitEpoch: apply + frontiers + flip are ONE transaction; any failure rolls back ALL ---

// commitFixture seeds a SPENDING account on the engine's DB and returns a valid appliable SEND
// from it (ApplyTx takes the txid as an argument and does not verify signatures — that is
// validate's job — so a seeded head/seq-consistent SEND applies; same technique as
// fund_credit_test.go).
// commitFixtureBal comfortably covers amount + the manifest MinFee clamp.
const commitFixtureBal = uint64(1_000_000)

type commitFixture struct {
	e       *Engine
	acct    [32]byte
	head    [32]byte
	goodID  [32]byte
	goodRaw []byte
	goodTx  *pb.Tx
	winners map[[32]byte][32]byte
	txBytes map[[32]byte][]byte
	parsed  map[[32]byte]*pb.Tx
}

func newCommitFixture(t *testing.T) *commitFixture {
	t.Helper()
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t)})

	var acct, head, to [32]byte
	acct[0], head[0], to[0] = 0xA1, 0x51, 0xB2
	seedSpending(t, e.cfg.DB, acct, head, commitFixtureBal, 3)

	goodTx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: acct[:]},
		Prev:    &pb.Hash32{V: head[:]},
		Seq:     4,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: to[:]},
			Amount:       100,
			Fee:          testEcon.RequiredFee(100), // ApplyTx enforces the exact manifest fee
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
		}},
	}
	goodRaw, err := proto.Marshal(goodTx)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	goodID := txidFor(acct, 4)

	f := &commitFixture{
		e: e, acct: acct, head: head, goodID: goodID, goodRaw: goodRaw, goodTx: goodTx,
		winners: map[[32]byte][32]byte{acct: goodID},
		txBytes: map[[32]byte][]byte{goodID: goodRaw},
		parsed:  map[[32]byte]*pb.Tx{goodID: goodTx},
	}
	return f
}

// addBadWinner adds a parse-clean SEND from a NONEXISTENT account (ApplyTx rejects it) — the
// "quorum accepted it but it cannot apply" shape that must abort the whole epoch.
func (f *commitFixture) addBadWinner(t *testing.T) [32]byte {
	t.Helper()
	var ghost, ghostHead, to [32]byte
	ghost[0], ghostHead[0], to[0] = 0xDE, 0xAD, 0xB2
	badTx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: ghost[:]},
		Prev:    &pb.Hash32{V: ghostHead[:]},
		Seq:     9,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To: &pb.AccountId{V: to[:]}, Amount: 1, AccountClass: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
		}},
	}
	badRaw, err := proto.Marshal(badTx)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	badID := txidFor(ghost, 9)
	f.winners[ghost] = badID
	f.txBytes[badID] = badRaw
	f.parsed[badID] = badTx
	return badID
}

func TestCommitEpochHappyPathIsAtomicallyComplete(t *testing.T) {
	f := newCommitFixture(t)
	const epoch = 6

	applied, failed, err := f.e.commitEpoch(epoch, f.winners, f.txBytes, f.parsed)
	if err != nil || len(failed) != 0 {
		t.Fatalf("commitEpoch: err=%v failed=%v (want clean)", err, failed)
	}
	if _, ok := applied[f.goodID]; !ok || len(applied) != 1 {
		t.Fatalf("applied=%d, want exactly the good winner", len(applied))
	}

	// The apply persisted...
	rec := readAccountRecord(t, f.e, f.acct)
	wantBal := commitFixtureBal - 100 - testEcon.RequiredFee(100)
	if rec.Seq != 4 || rec.Balance != wantBal {
		t.Fatalf("post-commit account: seq=%d bal=%d (want 4,%d)", rec.Seq, rec.Balance, wantBal)
	}
	// ...and the SAME transaction wrote the epoch frontiers (genesis + fund + our account).
	entries, _, err := IterEpochFrontiers(f.e.cfg.DB, epoch, [32]byte{}, 100)
	if err != nil {
		t.Fatalf("IterEpochFrontiers: %v", err)
	}
	if len(entries) < 3 {
		t.Fatalf("epoch %d frontiers: %d entries (want >=3: genesis, fund, account) — snapshot must land with the apply", epoch, len(entries))
	}
}

func TestCommitEpochRollsBackEverythingOnAnyFailedWinner(t *testing.T) {
	f := newCommitFixture(t)
	badID := f.addBadWinner(t)
	const epoch = 7

	applied, failed, err := f.e.commitEpoch(epoch, f.winners, f.txBytes, f.parsed)
	if err != nil {
		t.Fatalf("failed winners are reported via the map, not err (pre-P7.6 caller contract): %v", err)
	}
	if _, ok := failed[badID]; !ok {
		t.Fatalf("bad winner missing from failed map")
	}
	if len(applied) != 0 {
		t.Fatalf("applied=%d after an aborted epoch — rolled-back txs must not be reported applied", len(applied))
	}

	// The GOOD winner must have rolled back with the epoch: account untouched...
	rec := readAccountRecord(t, f.e, f.acct)
	if rec.Seq != 3 || rec.Balance != commitFixtureBal || rec.Head != f.head {
		t.Fatalf("account after rollback: seq=%d bal=%d (want the seeded 3,%d — partial state persisted!)", rec.Seq, rec.Balance, commitFixtureBal)
	}
	// ...and no frontier snapshot exists for the epoch.
	entries, _, err := IterEpochFrontiers(f.e.cfg.DB, epoch, [32]byte{}, 100)
	if err == nil && len(entries) != 0 {
		t.Fatalf("epoch %d has %d frontier entries after an aborted commit (want none)", epoch, len(entries))
	}
}

func readAccountRecord(t *testing.T, e *Engine, acct [32]byte) AccountRecord {
	t.Helper()
	var rec AccountRecord
	if err := e.cfg.DB.View(func(tx *bbolt.Tx) error {
		r, ok := getAccountRecord(tx, acct)
		if !ok {
			t.Fatal("account record missing")
		}
		rec = r
		return nil
	}); err != nil {
		t.Fatalf("read account: %v", err)
	}
	return rec
}
