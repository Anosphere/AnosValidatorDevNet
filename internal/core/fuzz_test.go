package core

// P7.6 native fuzz targets over the untrusted-input decode/validate/apply chain. The threat these
// pin: /submit is public and gossip crosses nodes, and the bytes those paths accept are later
// consumed by the UNSHIELDED epoch-loop goroutine (net/http's per-request recover protects only
// the handlers), so any panic reachable from wire bytes was a process kill pre-P7.6 — the recover
// guards now contain it, and these targets hunt for it so it gets FIXED, not just contained.
//
// Assertions are "no panic / no runaway allocation" plus, where cheap, real invariants
// (canonicalization fixed-point, txid stability). Seeds are REAL transactions built with the
// simkit builders the sims use, so the mutation corpus starts from every wire flavor.
//
// Run: ~/sdk/go/bin/go test ./internal/core/ -fuzz FuzzParseTxCanonical -fuzztime 60s   (etc.)

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

// newFuzzEngine mirrors newWalkTestEngine but accepts testing.TB so fuzz targets can build one
// shared engine at setup time (per fuzz worker process).
func newFuzzEngine(tb testing.TB) *Engine {
	tb.Helper()
	db, err := bbolt.Open(tb.TempDir()+"/fuzz.db", 0o600, nil)
	if err != nil {
		tb.Fatalf("open db: %v", err)
	}
	tb.Cleanup(func() { _ = db.Close() })

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("gen key: %v", err)
	}
	signer := NewLocalP256Signer(priv)
	set := map[[33]byte]*ecdsa.PublicKey{signer.PublicKeyCompressed(): &priv.PublicKey}

	var genesis, fund [32]byte
	genesis[0], fund[0] = 0xAA, 0xFD
	e, err := NewEngine(EngineConfig{
		DB:                        db,
		Signer:                    signer,
		ValidatorSet:              set,
		GenesisUnixMs:             1,
		GenesisAccount:            genesis,
		GenesisSupply:             1_000_000_000,
		GenesisAuthPubKey:         make([]byte, crypto.HybridPubKeySize),
		FundAccount:               fund,
		QuorumPercent:             80,
		FinalizationQuorumPercent: 60,
		MaxCandidateScanPerSlot:   64,
		Econ:                      testEcon,
	})
	if err != nil {
		tb.Fatalf("NewEngine: %v", err)
	}
	return e
}

// fuzzSeedAccounts returns the deterministic simkit accounts the seed corpus and the validate
// snapshot share (same keys → sig-verifying seeds reach the deepest validate branches).
func fuzzSeedAccounts() (sender, receiver *simkit.Account) {
	sender = simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x51}, [32]byte{0x52})
	receiver = simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x61}, [32]byte{0x62})
	return sender, receiver
}

// The forquinn guarded/U2 fuzz fixture constants: the chain-spawning SEND's seq (the derived
// chain id folds it), the chain's balance (releases are exact-match full-balance drains), and
// the unlock epoch (== the snapshot epoch, so release seeds are inside the allowed window).
const (
	fuzzChainFromSeq = uint64(5)
	fuzzChainBalance = uint64(10_000)
	fuzzChainUnlock  = uint64(10)
)

// fuzzGuardedFix carries the deterministic forquinn-surface accounts shared by the seed corpus,
// the validate snapshot, and the apply DB: a GUARDED account mid-opening (U2 registration + PoP),
// a live GUARDED account with a registered U2, its attestor-flagged TRANSFER chain (copied U1+U2,
// the D2 derived copy), and two staked attestors for the path-(b) quorum (M=2).
type fuzzGuardedFix struct {
	guardedOpen *simkit.Account // does not exist yet; opens via ridG
	guardedLive *simkit.Account // existing GUARDED account, U2 registered (the chain's key source)
	chain       *simkit.Account // guardedLive's TRANSFER chain, release_requires_attestor set
	att1, att2  *simkit.Account // staked Fund Attestors (quorum M=2)
	ridG        [32]byte        // pending receivable feeding guardedOpen's opening RECEIVE
	chainHead   [32]byte
	dest        [32]byte // the chain's pinned release destination
}

func fuzzGuardedFixture() *fuzzGuardedFix {
	f := &fuzzGuardedFix{
		guardedOpen: simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_GUARDED, [32]byte{0x53}, [32]byte{0x54}).AttachU2([32]byte{0x55}),
		guardedLive: simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_GUARDED, [32]byte{0x57}, [32]byte{0x58}).AttachU2([32]byte{0x59}),
		att1:        simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x63}, [32]byte{0x64}),
		att2:        simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x65}, [32]byte{0x66}),
	}
	f.chain = simkit.DerivedTransferAccount(f.guardedLive, fuzzChainFromSeq)
	f.ridG[0], f.chainHead[0], f.dest[0] = 0x43, 0x81, 0x91
	return f
}

// fuzzSnapshotFor builds the static validate snapshot embedding the seed accounts: the sender
// exists (head/seq/balance/keys), the receiver does not yet exist but has a pending receivable
// (so a signed opening RECEIVE seed validates end to end). The forquinn surface (phase 6): a
// live GUARDED account with a registered U2, its attestor-flagged TRANSFER chain carrying both
// copied keys (so the path-(a)/path-(b) release seeds verify end to end), two staked attestors
// satisfying the M=2 quorum, a pending GUARDED-routed receivable for the U2-registration opening
// seed, and the supply/rate-limit scalars every post-cutover snapshot carries.
func fuzzSnapshotFor(sender, receiver *simkit.Account, rid [32]byte, senderHead [32]byte, senderSeq uint64) *Snapshot {
	var fund [32]byte
	fund[0] = 0xFD
	fix := fuzzGuardedFixture()
	var guardedHead [32]byte
	guardedHead[0] = 0x75
	return &Snapshot{
		Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			sender.ID: {
				Head:             senderHead,
				Balance:          1_000_000_000,
				Seq:              senderSeq,
				Class:            pb.AccountClass_ACCOUNT_CLASS_SPENDING,
				AuthPubKey:       sender.AuthPubKeyBytes(),
				BreakglassCommit: sender.Commit,
			},
			fix.guardedLive.ID: {
				Head:                 guardedHead,
				Balance:              500_000,
				Seq:                  fuzzChainFromSeq,
				Class:                pb.AccountClass_ACCOUNT_CLASS_GUARDED,
				AuthPubKey:           fix.guardedLive.AuthPubKeyBytes(),
				BreakglassCommit:     fix.guardedLive.Commit,
				U2PubKey:             fix.guardedLive.U2PubKeyBytes(),
				LastGuardedSendEpoch: 2, // epoch 10 - 2 = 8 >= interval 6 → next hop-1 allowed
			},
			fix.chain.ID: {
				Head:           fix.chainHead,
				Balance:        fuzzChainBalance,
				Seq:            1,
				Class:          pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
				TransferSource: fix.guardedLive.ID,
				TransferDest:   fix.dest,
				TransferUnlock: fuzzChainUnlock,
				TransferFlags:  transferFlagReleaseRequiresAttestor,
				AuthPubKey:     fix.guardedLive.AuthPubKeyBytes(),
				U2PubKey:       fix.guardedLive.U2PubKeyBytes(),
			},
			fix.att1.ID: {Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: fix.att1.AuthPubKeyBytes()},
			fix.att2.ID: {Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: fix.att2.AuthPubKeyBytes()},
		},
		Receivables: map[[32]byte]ReceivableSnap{
			rid: {
				From:              sender.ID,
				To:                receiver.ID,
				Amount:            10_000,
				RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
				FromSeq:           senderSeq,
			},
			fix.ridG: {
				From:              sender.ID,
				To:                fix.guardedOpen.ID,
				Amount:            20_000,
				RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_GUARDED,
				FromSeq:           senderSeq,
			},
		},
		FundStakeRows: []StakeRow{
			{DepositTxid: [32]byte{0x01, 0xaa}, StakeRecord: StakeRecord{
				StakerID: fix.att1.ID, Amount: anosUnits(5_000), TimeDelay: oneMonth,
				Status: StakeStatusActive, StakedFor: StakedForAttestor,
			}},
			{DepositTxid: [32]byte{0x02, 0xaa}, StakeRecord: StakeRecord{
				StakerID: fix.att2.ID, Amount: anosUnits(5_000), TimeDelay: oneMonth,
				Status: StakeStatusActive, StakedFor: StakedForAttestor,
			}},
		},
		Epoch:                        10,
		DelayEpochs:                  6,
		FundAccount:                  fund,
		GuardianActiveWeight:         0,
		StakeLock1moEpochs:           4,
		StakeLock1yrEpochs:           48,
		GuardedDelayEpochs:           8,
		VaultDelayEpochs:             16,
		AttestorQuorumM:              2, // the deployed floor (D11); 0 fail-closes, 1 is sub-floor
		GenesisSupply:                1_000_000_000,
		GuardedSendMinIntervalEpochs: 6,
	}
}

// fuzzSeedTxs builds one canonical wire tx of each flavor the sims actually produce. A seed
// failing to build is fatal (the corpus is part of the target's contract).
func fuzzSeedTxs(tb testing.TB) [][]byte {
	tb.Helper()
	sender, receiver := fuzzSeedAccounts()
	var senderHead, rid, fund [32]byte
	senderHead[0], rid[0], fund[0] = 0x71, 0x42, 0xFD
	const senderSeq = uint64(3)

	var seeds [][]byte
	add := func(tx *pb.Tx, sign *simkit.Account) {
		tb.Helper()
		if sign != nil {
			if err := sign.Sign(tx); err != nil {
				tb.Fatalf("sign seed: %v", err)
			}
		}
		raw, err := CanonicalTxBytes(tx)
		if err != nil {
			tb.Fatalf("canonical seed: %v", err)
		}
		seeds = append(seeds, raw)
	}

	// Signed SPENDING send (exact manifest fee) — the everyday /submit shape.
	add(simkit.BuildSend(sender, senderHead, senderSeq+1, receiver.ID, 10_000, testEcon.RequiredFee(10_000)), sender)
	// Signed opening RECEIVE (registers pubkey + breakglass commitment).
	add(simkit.BuildOpeningReceive(receiver, rid, nil, 0), receiver)
	// Signed non-opening RECEIVE.
	add(simkit.BuildReceive(receiver, senderHead, 2, rid), receiver)
	// Signed banker-floor stake send to the Fund (stake metadata branch).
	add(simkit.BuildStakeSend(sender, senderHead, senderSeq+1, fund, 50_000, testEcon.RequiredFee(50_000), "banker", pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR, nil), sender)
	// Keyless Fund SEND shape (guardian multisig envelope; unsigned — shape seed).
	add(simkit.BuildFundSend(fund, senderHead, 2, receiver.ID, 77, 9), nil)
	// §2.7 regression seed: the uint64-wrap mint shape — amt=2^64-1 with its exact (wrapped)
	// manifest fee, signed. Validate/apply must REJECT it (overflow_supply_test.go pins the
	// rejection); the fuzz targets pin that it and its mutations never panic the chain.
	add(simkit.BuildSend(sender, senderHead, senderSeq+1, receiver.ID, math.MaxUint64, testEcon.RequiredFee(math.MaxUint64)), sender)

	// forquinn seeds (phase 6): every new wire shape the cutover introduces, built against the
	// same fixture fuzzSnapshotFor embeds so each validates end to end before mutation.
	fix := fuzzGuardedFixture()
	// GUARDED opening RECEIVE registering U2 (pubkey + proof-of-possession, D12).
	gtx, err := simkit.BuildGuardedOpeningReceive(fix.guardedOpen, fix.ridG)
	if err != nil {
		tb.Fatalf("build guarded opening seed: %v", err)
	}
	add(gtx, fix.guardedOpen)
	// Path (a) release: U1 in Tx.sig + U2 in Tx.sig2 (D5 fixed roles), no attestors, no case fields.
	pa := simkit.BuildSend(fix.chain, fix.chainHead, 2, fix.dest, fuzzChainBalance, 0)
	if err := simkit.SignPathARelease(pa, fix.chain); err != nil {
		tb.Fatalf("sign path-(a) seed: %v", err)
	}
	add(pa, nil)
	// Path (b) release: one user sig + M=2 attestor multisig + the 32-byte case commitment
	// (case_nonce + attestation_hash folded into every signature's preimage).
	pbRel := simkit.BuildSend(fix.chain, fix.chainHead, 2, fix.dest, fuzzChainBalance, 0)
	if err := simkit.SignAttestorRelease(pbRel, fix.chain, []*simkit.Account{fix.att1, fix.att2}, [32]byte{0xCA}, [32]byte{0xA7}); err != nil {
		tb.Fatalf("sign path-(b) seed: %v", err)
	}
	add(pbRel, nil)
	return seeds
}

// TestForquinnFuzzSeedsValidate pins the corpus DEPTH of the phase-6 forquinn seeds: each of
// the three new wire shapes must validate CLEANLY against the shared fuzz snapshot (not merely
// not-panic), so their mutations start from inside the deepest U2/PoP/release branches. A
// fixture drift that silently turned them into early rejects would gut the fuzz coverage
// without failing any target — this test is the tripwire.
func TestForquinnFuzzSeedsValidate(t *testing.T) {
	sender, receiver := fuzzSeedAccounts()
	var senderHead, rid [32]byte
	senderHead[0], rid[0] = 0x71, 0x42
	snap := fuzzSnapshotFor(sender, receiver, rid, senderHead, 3)
	fix := fuzzGuardedFixture()

	gtx, err := simkit.BuildGuardedOpeningReceive(fix.guardedOpen, fix.ridG)
	if err != nil {
		t.Fatalf("build guarded opening: %v", err)
	}
	if err := fix.guardedOpen.Sign(gtx); err != nil {
		t.Fatalf("sign guarded opening: %v", err)
	}
	if _, err := ValidateTxAgainstSnapshot(gtx, snap); err != nil {
		t.Errorf("guarded U2 opening seed does not validate: %v", err)
	}

	pa := simkit.BuildSend(fix.chain, fix.chainHead, 2, fix.dest, fuzzChainBalance, 0)
	if err := simkit.SignPathARelease(pa, fix.chain); err != nil {
		t.Fatalf("sign path (a): %v", err)
	}
	if _, err := ValidateTxAgainstSnapshot(pa, snap); err != nil {
		t.Errorf("path-(a) release seed does not validate: %v", err)
	}

	pbRel := simkit.BuildSend(fix.chain, fix.chainHead, 2, fix.dest, fuzzChainBalance, 0)
	if err := simkit.SignAttestorRelease(pbRel, fix.chain, []*simkit.Account{fix.att1, fix.att2}, [32]byte{0xCA}, [32]byte{0xA7}); err != nil {
		t.Fatalf("sign path (b): %v", err)
	}
	if _, err := ValidateTxAgainstSnapshot(pbRel, snap); err != nil {
		t.Errorf("path-(b) release seed does not validate: %v", err)
	}
}

// --- ParseTx / CanonicalTxBytes: parse-canonicalize fixed point + txid stability ---

func FuzzParseTxCanonical(f *testing.F) {
	for _, s := range fuzzSeedTxs(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		tx, err := ParseTx(data)
		if err != nil {
			return
		}
		canon, err := CanonicalTxBytes(tx)
		if err != nil {
			return
		}
		tx2, err := ParseTx(canon)
		if err != nil {
			t.Fatalf("canonical bytes must re-parse: %v", err)
		}
		canon2, err := CanonicalTxBytes(tx2)
		if err != nil || !bytes.Equal(canon, canon2) {
			t.Fatalf("canonicalization must be a fixed point (err=%v)", err)
		}
		id1, err1 := crypto.TxID(tx)
		id2, err2 := crypto.TxID(tx2)
		if (err1 == nil) != (err2 == nil) || (err1 == nil && id1 != id2) {
			t.Fatalf("TxID must be stable across a canonical round-trip")
		}
		// The signing preimage folds every field length-framed — walk it for panics too.
		_, _ = crypto.SignBytesACTE(tx)
		_, _, _ = crypto.MsgHash(tx)
	})
}

// --- ValidateTxAgainstSnapshot: full validate over a static rich snapshot ---

func FuzzValidateTx(f *testing.F) {
	for _, s := range fuzzSeedTxs(f) {
		f.Add(s)
	}
	sender, receiver := fuzzSeedAccounts()
	var senderHead, rid [32]byte
	senderHead[0], rid[0] = 0x71, 0x42
	snap := fuzzSnapshotFor(sender, receiver, rid, senderHead, 3)

	f.Fuzz(func(t *testing.T, data []byte) {
		tx, err := ParseTx(data)
		if err != nil {
			return
		}
		_, _ = ValidateTxAgainstSnapshot(tx, snap) // assertion: no panic
	})
}

// --- ApplyTx: the resync contract — quorum-accepted bytes apply WITHOUT local re-validation,
// so ApplyTx must fail gracefully (never panic) on anything that parses. Always rolled back, so
// every exec sees the same seeded state. The DB is seeded with the SAME sender account + pending
// receivable the validate snapshot uses, so a mutated SEND/RECEIVE whose account/prev/seq match
// passes the early prev/seq guards and reaches the ApplyTx TYPE-SWITCH + class-specific apply
// logic — without this seeding every input dies at ErrBadPrev against the bare genesis DB and the
// whole apply surface goes unfuzzed. ---

func FuzzApplyTx(f *testing.F) {
	for _, s := range fuzzSeedTxs(f) {
		f.Add(s)
	}
	e := newFuzzEngine(f)
	sender, receiver := fuzzSeedAccounts()
	var senderHead, rid [32]byte
	senderHead[0], rid[0] = 0x71, 0x42
	// Seed the sender (SPENDING, at senderHead/seq 3) and a pending receivable to receiver, so the
	// apply branches are reachable. Done once at target setup.
	if err := e.cfg.DB.Update(func(btx *bbolt.Tx) error {
		if err := ensureBuckets(btx); err != nil {
			return err
		}
		if err := putAccountRecord(btx, sender.ID, AccountRecord{
			Head: senderHead, Balance: 1_000_000_000, Seq: 3,
			Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: sender.AuthPubKeyBytes(),
			BreakglassCommit: sender.Commit,
		}); err != nil {
			return err
		}
		recRaw, err := proto.Marshal(&pb.Receivable{
			Id:                &pb.Hash32{V: rid[:]},
			From:              &pb.AccountId{V: sender.ID[:]},
			To:                &pb.AccountId{V: receiver.ID[:]},
			Amount:            10_000,
			RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
			FromSeq:           3,
		})
		if err != nil {
			return err
		}
		if err := putReceivableRaw(btx, rid, recRaw); err != nil {
			return err
		}
		// forquinn surface (phase 6): a live GUARDED account with U2, its attestor-flagged
		// TRANSFER chain (both copied keys), and a GUARDED-routed pending receivable — so the
		// guarded-opening seed reaches apply's U2/PoP re-verification and the release seeds
		// reach the release apply logic (resync replays apply WITHOUT validate).
		fix := fuzzGuardedFixture()
		var guardedHead [32]byte
		guardedHead[0] = 0x75
		if err := putAccountRecord(btx, fix.guardedLive.ID, AccountRecord{
			Head: guardedHead, Balance: 500_000, Seq: fuzzChainFromSeq,
			Class: pb.AccountClass_ACCOUNT_CLASS_GUARDED, AuthPubKey: fix.guardedLive.AuthPubKeyBytes(),
			BreakglassCommit: fix.guardedLive.Commit, U2PubKey: fix.guardedLive.U2PubKeyBytes(),
		}); err != nil {
			return err
		}
		if err := putAccountRecord(btx, fix.chain.ID, AccountRecord{
			Head: fix.chainHead, Balance: fuzzChainBalance, Seq: 1,
			Class:          pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			TransferSource: fix.guardedLive.ID, TransferDest: fix.dest,
			TransferUnlock: fuzzChainUnlock, TransferFlags: transferFlagReleaseRequiresAttestor,
			AuthPubKey: fix.guardedLive.AuthPubKeyBytes(), U2PubKey: fix.guardedLive.U2PubKeyBytes(),
		}); err != nil {
			return err
		}
		recRawG, err := proto.Marshal(&pb.Receivable{
			Id:                &pb.Hash32{V: fix.ridG[:]},
			From:              &pb.AccountId{V: sender.ID[:]},
			To:                &pb.AccountId{V: fix.guardedOpen.ID[:]},
			Amount:            20_000,
			RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_GUARDED,
			FromSeq:           3,
		})
		if err != nil {
			return err
		}
		return putReceivableRaw(btx, fix.ridG, recRawG)
	}); err != nil {
		f.Fatalf("seed apply DB: %v", err)
	}

	rollback := func() error { return context.Canceled } // any non-nil error rolls the Update back

	f.Fuzz(func(t *testing.T, data []byte) {
		tx, err := ParseTx(data)
		if err != nil {
			return
		}
		txid, err := crypto.TxID(tx)
		if err != nil {
			txid = [32]byte{}
		}
		_ = e.cfg.DB.Update(func(btx *bbolt.Tx) error {
			if err := ensureBuckets(btx); err != nil {
				return err
			}
			_ = ApplyTx(&bboltTxView{tx: btx}, data, tx, txid, e.cfg.FundAccount, e.cfg.Econ, 0)
			return rollback() // never persist — every exec sees the same seeded state
		})
	})
}

// --- SubmitTx / ReceiveGossipedTx: the exact public front door (/submit, /peer/tx/push) ---

func FuzzSubmitIntake(f *testing.F) {
	for _, s := range fuzzSeedTxs(f) {
		f.Add(s)
	}
	e := newFuzzEngine(f)
	var execs int

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = e.SubmitTx(data)
		_ = e.ReceiveGossipedTx(data)
		if execs++; execs%2048 == 0 {
			// Drain the pools so a long fuzz run measures parsing, not mempool pressure.
			e.mu.Lock()
			e.txPool = make(map[[32]byte][]byte)
			e.txSeenEpoch = make(map[[32]byte]uint64)
			e.conflictPool = make(map[[32]byte][][32]byte)
			e.approved = make(map[[32]byte][32]byte)
			e.gossipPending = make(map[[32]byte]struct{})
			e.gossipMask = make(map[[32]byte]uint64)
			e.mu.Unlock()
		}
	})
}

// --- Peer intake messages: the handler decode→convert→engine sequence for candidates,
// finalizations, and the gossip inv/want/push protos (mirrors cmd/validator's handlers at the
// same byte boundary; the handler-local guards above the calls are length checks the conversion
// here reproduces). ---

func FuzzPeerIntake(f *testing.F) {
	// Seeds: a well-formed candidate list + finalization + inv/want/push, protodelim-framed like
	// the wire.
	seedMsg := func(m proto.Message) []byte {
		var buf bytes.Buffer
		_, _ = protodelim.MarshalTo(&buf, m)
		return buf.Bytes()
	}
	var id32 [32]byte
	id32[0] = 0x3C
	var id33 [33]byte
	id33[0] = 0x02
	f.Add(seedMsg(&pb.CandidateListV2{Epoch: 4, Proposer: &pb.Pub32{V: id33[:]}, ListHash: &pb.Hash32{V: id32[:]}, Sig: &pb.SigDER{V: make([]byte, 70)}, Txid: []*pb.Hash32{{V: id32[:]}}}))
	f.Add(seedMsg(&pb.EpochFinalization{Epoch: 4, AcceptedTxidsHash: &pb.Hash32{V: id32[:]}, FrontiersRoot: &pb.Hash32{V: id32[:]}, Signer: &pb.Pub32{V: id33[:]}, Sig: &pb.SigDER{V: make([]byte, 70)}, AcceptedTxids: [][]byte{id32[:]}}))
	f.Add(seedMsg(&pb.TxInv{Epoch: 4, From: &pb.Pub32{V: id33[:]}, Txid: []*pb.Hash32{{V: id32[:]}}}))
	f.Add(seedMsg(&pb.TxWant{Txid: []*pb.Hash32{{V: id32[:]}}}))
	f.Add(seedMsg(&pb.TxPush{Epoch: 4, From: &pb.Pub32{V: id33[:]}, Tx: []*pb.Tx{{Account: &pb.AccountId{V: id32[:]}, Prev: &pb.Hash32{V: make([]byte, 32)}, Seq: 1}}}))

	e := newFuzzEngine(f)
	unmarshal := protodelim.UnmarshalOptions{MaxSize: 8 << 20} // hoisted: a composite literal can't start an `if` init clause

	f.Fuzz(func(t *testing.T, data []byte) {
		// Candidate list (mirrors /peer/candidates).
		var cl pb.CandidateListV2
		if err := unmarshal.UnmarshalFrom(newFuzzByteReader(data), &cl); err == nil {
			if cl.Proposer != nil && len(cl.Proposer.V) == 33 && cl.ListHash != nil && len(cl.ListHash.V) == 32 && cl.Sig != nil && len(cl.Sig.V) >= 64 && len(cl.Sig.V) <= 80 {
				var vid [33]byte
				copy(vid[:], cl.Proposer.V)
				var lh [32]byte
				copy(lh[:], cl.ListHash.V)
				txids := make([][32]byte, 0, len(cl.Txid))
				for _, h := range cl.Txid {
					if h == nil || len(h.V) != 32 {
						continue
					}
					var id [32]byte
					copy(id[:], h.V)
					txids = append(txids, id)
				}
				_ = e.ReceiveCandidateList("fuzz", &CandidateList{Epoch: cl.Epoch, ValidatorID: vid, ListHash: lh, SigDER: append([]byte(nil), cl.Sig.V...), TxIDs: txids})
			}
		}
		// Finalization (mirrors /peer/finalization).
		var fin pb.EpochFinalization
		if err := unmarshal.UnmarshalFrom(newFuzzByteReader(data), &fin); err == nil {
			if fin.Signer != nil && len(fin.Signer.V) == 33 && fin.AcceptedTxidsHash != nil && len(fin.AcceptedTxidsHash.V) == 32 && fin.FrontiersRoot != nil && len(fin.FrontiersRoot.V) == 32 && fin.Sig != nil && len(fin.Sig.V) >= 64 && len(fin.Sig.V) <= 80 {
				_ = e.ReceiveFinalization(&fin)
			}
		}
		// Gossip protos: decode is the surface (the handlers' own guards are inline above their
		// engine calls); TxPush raw bodies additionally flow through ReceiveGossipedTx (already
		// fuzzed directly), so just decode here.
		var inv pb.TxInv
		_ = unmarshal.UnmarshalFrom(newFuzzByteReader(data), &inv)
		var want pb.TxWant
		_ = unmarshal.UnmarshalFrom(newFuzzByteReader(data), &want)
		var push pb.TxPush
		if err := unmarshal.UnmarshalFrom(newFuzzByteReader(data), &push); err == nil {
			for _, tx := range push.Tx {
				if tx == nil {
					continue
				}
				raw, cerr := CanonicalTxBytes(tx) // exact /peer/tx/push handler path
				if cerr != nil {
					continue
				}
				_ = e.ReceiveGossipedTx(raw)
			}
		}
	})
}

// newFuzzByteReader wraps data in the buffered reader shape protodelim wants.
func newFuzzByteReader(data []byte) *bytes.Reader { return bytes.NewReader(data) }

// --- Resync response decoders: hostile peer bytes through the REAL client path
// (resyncDo → body cap → protodelim → per-entry guards), served by a live httptest server whose
// body — and the X-Anos-Fin-Through header — are the fuzz payload. ---

func FuzzResyncResponses(f *testing.F) {
	seedMsg := func(m proto.Message) []byte {
		var buf bytes.Buffer
		_, _ = protodelim.MarshalTo(&buf, m)
		return buf.Bytes()
	}
	var id32 [32]byte
	id32[0] = 0x3C
	var id33 [33]byte
	id33[0] = 0x02
	f.Add(seedMsg(&pb.SyncLatestResponse{LatestEpoch: 7}))
	f.Add(seedMsg(&pb.SyncFinalizationResponse{Finalizations: []*pb.EpochFinalization{{Epoch: 2, AcceptedTxidsHash: &pb.Hash32{V: id32[:]}, FrontiersRoot: &pb.Hash32{V: id32[:]}, Signer: &pb.Pub32{V: id33[:]}, Sig: &pb.SigDER{V: make([]byte, 70)}}}}))
	f.Add(seedMsg(&pb.SyncFrontiersResponse{Epoch: 2, Entries: []*pb.FrontierEntry{{Account: &pb.AccountId{V: id32[:]}, Head: &pb.Hash32{V: id32[:]}}}}))
	f.Add(seedMsg(&pb.SyncChainResponse{ReachedHave: true, Tx: []*pb.Tx{{Account: &pb.AccountId{V: id32[:]}, Prev: &pb.Hash32{V: make([]byte, 32)}, Seq: 1}}}))

	e := newFuzzEngine(f)
	var payload atomic.Value // []byte
	payload.Store([]byte{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := payload.Load().([]byte)
		if len(body) > 0 {
			// The ranged-fin client parses this header with strconv.ParseUint(base 10), so a
			// peer-controlled value must be a base-10 number to actually exercise the accept
			// branch. Derive one from the payload so the fuzzer varies it (and still occasionally
			// emit non-numeric junk to cover the parse-failure path via the raw byte 0 case).
			var thru uint64
			for _, b := range body[:min(8, len(body))] {
				thru = thru<<8 | uint64(b)
			}
			w.Header().Set("X-Anos-Fin-Through", strconv.FormatUint(thru, 10))
		}
		_, _ = w.Write(body)
	}))
	f.Cleanup(srv.Close)

	f.Fuzz(func(t *testing.T, data []byte) {
		payload.Store(append([]byte(nil), data...))
		ctx := context.Background()
		_, _ = e.httpSyncLatest(ctx, srv.URL)
		_, _ = e.httpSyncFinalization(ctx, srv.URL, 3)
		_, _, _ = e.httpSyncFinalizationRange(ctx, srv.URL, 1, 8)
		_, _ = e.httpSyncFrontiers(ctx, srv.URL, 3, [32]byte{}, 100)
		_, _, _ = e.httpSyncChain(ctx, srv.URL, [32]byte{1}, [32]byte{2}, [32]byte{}, 300)
	})
}

// --- DB record decoders (defense-in-depth: today only self-written bytes reach them, but they
// are pure functions and a refactor must never make them panic on junk) ---

func FuzzRecordDecoders(f *testing.F) {
	var h [32]byte
	h[0] = 0x11
	f.Add(packAccountRecord(AccountRecord{Head: h, Balance: 5, Seq: 2, Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING}))
	f.Add(packStakeRecord(StakeRecord{StakerID: h, Amount: 50_000, TimeDelay: pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR, StakedFor: "banker"}))
	f.Add(packBankerInfo(make([]byte, 33), "10.0.0.1:9090", 7))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = unpackAccountRecord(data)
		_, _, _, _, _ = unpackAccount(data)
		_, _ = unpackStakeRecord(data)
		_, _ = unpackBankerInfo(data)
	})
}
