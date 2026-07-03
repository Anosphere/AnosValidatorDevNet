package core

import (
	"testing"
	"time"

	pb "anos/internal/proto"
)

// mkConflictTx builds a minimal tx whose (account, prev, seq) yields a valid conflict key.
func mkConflictTx(acctB, prevB byte, seq uint64) *pb.Tx {
	acct := make([]byte, 32)
	acct[0] = acctB
	prev := make([]byte, 32)
	prev[0] = prevB
	return &pb.Tx{Account: &pb.AccountId{V: acct}, Prev: &pb.Hash32{V: prev}, Seq: seq}
}

// TestAdmissionGlobalCap: the global mempool cap rejects an unsolicited tx once txPool is full and
// admits one below the cap. (P7.3)
func TestAdmissionGlobalCap(t *testing.T) {
	e := &Engine{
		cfg:          EngineConfig{MaxMempoolTxs: 2, MaxCandidateScanPerSlot: 64},
		txPool:       map[[32]byte][]byte{{1}: {}, {2}: {}}, // at cap
		conflictPool: map[[32]byte][][32]byte{},
	}
	tx := mkConflictTx(0xAA, 0xBB, 1)
	if reason := e.admissionRejectLocked(tx, [32]byte{9}); reason == "" {
		t.Fatalf("expected rejection at len(txPool)==MaxMempoolTxs")
	}
	e.cfg.MaxMempoolTxs = 3 // now room
	if reason := e.admissionRejectLocked(tx, [32]byte{9}); reason != "" {
		t.Fatalf("expected admit under the cap, got %q", reason)
	}
}

// TestAdmissionSlotCap: the per-conflict-slot cap (== MaxCandidateScanPerSlot) rejects an unsolicited
// tx once the slot is full (FIFO, so incumbents survive) — this is what closes the P7.1 >64-junk
// burial residual: a slot can never hold more candidates than buildCandidateList scans. (P7.3)
func TestAdmissionSlotCap(t *testing.T) {
	tx := mkConflictTx(0xAA, 0xBB, 1)
	key, ok := conflictKeyHash(tx)
	if !ok {
		t.Fatal("conflictKeyHash returned !ok for a well-formed tx")
	}
	slot := make([][32]byte, 3)
	for i := range slot {
		slot[i] = [32]byte{byte(i + 1)}
	}
	e := &Engine{
		cfg:          EngineConfig{MaxMempoolTxs: 1_000_000, MaxCandidateScanPerSlot: 3},
		txPool:       map[[32]byte][]byte{},
		conflictPool: map[[32]byte][][32]byte{key: slot}, // slot at cap (3)
	}
	if reason := e.admissionRejectLocked(tx, [32]byte{9}); reason == "" {
		t.Fatalf("expected slot-cap rejection at len(slot)==MaxCandidateScanPerSlot")
	}
	e.cfg.MaxCandidateScanPerSlot = 4 // now room in the slot
	if reason := e.admissionRejectLocked(tx, [32]byte{9}); reason != "" {
		t.Fatalf("expected admit with slot room, got %q", reason)
	}
}

// TestAdmissionNoConflictKeyOnlyGlobal: a tx with no valid conflict key is governed by the global cap
// only (no per-slot bound applies).
func TestAdmissionNoConflictKeyOnlyGlobal(t *testing.T) {
	e := &Engine{
		cfg:          EngineConfig{MaxMempoolTxs: 10, MaxCandidateScanPerSlot: 1},
		txPool:       map[[32]byte][]byte{},
		conflictPool: map[[32]byte][][32]byte{},
	}
	badKey := &pb.Tx{Seq: 1} // no Account/Prev → conflictKeyHash !ok
	if reason := e.admissionRejectLocked(badKey, [32]byte{9}); reason != "" {
		t.Fatalf("no-conflict-key tx under global cap should admit, got %q", reason)
	}
}

// TestEpochWithinIntakeWindow pins the live-message intake bounds (P7.3): a candidate list /
// finalization is buffered only for epochs within [now-lag, now+ahead].
func TestEpochWithinIntakeWindow(t *testing.T) {
	const epochMs = int64(3_600_000) // 1h epochs so epochNow is stable across the test
	e := &Engine{cfg: EngineConfig{
		GenesisUnixMs: time.Now().UnixMilli() - 1000*epochMs,
		EpochDuration: time.Duration(epochMs) * time.Millisecond,
	}}
	now := e.epochNow()
	inWindow := []uint64{now, now - maxIntakeEpochLag, now + maxIntakeEpochAhead}
	for _, ep := range inWindow {
		if !e.epochWithinIntakeWindow(ep) {
			t.Errorf("epoch %d (now=%d) should be IN the window", ep, now)
		}
	}
	outWindow := []uint64{now - maxIntakeEpochLag - 1, now + maxIntakeEpochAhead + 1}
	for _, ep := range outWindow {
		if e.epochWithinIntakeWindow(ep) {
			t.Errorf("epoch %d (now=%d) should be OUT of the window", ep, now)
		}
	}
}
