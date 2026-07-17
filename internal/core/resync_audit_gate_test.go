package core

// forquinn phase 4, the post-resync invariant gate (§2.9 / D7 layer 3), end to end: a full
// runResync against a fake peer serving a WALK-PASSING history. The audit-FAILING variant is a
// history every node would agree on — a quorum-signed Guardian "grant" Fund SEND that legally
// drains the pool below the Σ-active-stakes floor — so the verifying walk passes (heads match
// the signed tip root; supply is conserved) while fund-solvency is broken. Per D7 the rebuild
// is deterministic (any peer reproduces it), so the gate must HALT immediately, with no retry
// scheduled and the rebuilt state preserved for forensics. The clean variant (no grant) must
// pass the gate, return to Idle, and stamp last_full_audit_epoch — proving the gate runs (and
// arms) on every successful resync.

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

const (
	gateStakeAmt = uint64(10_000) // sub-floor is fine: solvency counts EVERY active row
	gateTargetEp = uint64(2)
)

type gateFixture struct {
	stakeTx *pb.Tx
	stakeID [32]byte
	grantTx *pb.Tx // nil in the clean variant
	grantID [32]byte
	// fins[ep] are the quorum finalizations the fake peer serves (signed by the one-member set).
	fins     map[uint64][]*pb.EpochFinalization
	frontier map[[32]byte][32]byte // tip frontiers served for epoch 2
}

// buildGateHistory replays the served history on a throwaway builder engine (identical
// genesis/fund/supply constants to the resyncer) to compute the real txids and the real
// per-epoch frontier roots the finalizations must sign.
func buildGateHistory(t *testing.T, v *tValidator, withGrant bool) *gateFixture {
	t.Helper()
	b := newWalkTestEngine(t, []*tValidator{v})
	genesis, fund := b.cfg.GenesisAccount, b.cfg.FundAccount
	genesisSyn := syntheticSeedHead("ANOS_GENESIS_HEAD_V1:", genesis)
	fundSyn := syntheticSeedHead("ANOS_FUND_HEAD_V1:", fund)

	apply := func(ptx *pb.Tx, epoch uint64) [32]byte {
		t.Helper()
		id, err := crypto.TxID(ptx)
		if err != nil {
			t.Fatalf("txid: %v", err)
		}
		raw, _ := proto.Marshal(ptx)
		if aerr := b.cfg.DB.Update(func(tx *bbolt.Tx) error {
			return ApplyTx(&bboltTxView{tx: tx}, raw, ptx, id, fund, testEcon, epoch)
		}); aerr != nil {
			t.Fatalf("builder apply: %v", aerr)
		}
		return id
	}
	rootAt := func(ep uint64) [32]byte {
		t.Helper()
		if err := SaveEpochFrontiers(b.cfg.DB, ep); err != nil {
			t.Fatalf("SaveEpochFrontiers: %v", err)
		}
		r, err := ComputeFrontiersRoot(b.cfg.DB, ep)
		if err != nil {
			t.Fatalf("ComputeFrontiersRoot: %v", err)
		}
		return r
	}

	// Epoch 1: genesis stakes to the Fund (an ordinary attestor-tagged deposit). The Fund pool
	// now holds stake+fee; the stake row is ACTIVE for gateStakeAmt.
	stakeFee := testEcon.RequiredFee(gateStakeAmt)
	stakeTx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: genesis[:]},
		Prev:    &pb.Hash32{V: genesisSyn[:]},
		Seq:     2,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: fund[:]},
			Amount:       gateStakeAmt,
			Fee:          stakeFee,
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
			StakedFor:    StakedForAttestor,
			TimeDelay:    pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_MONTH,
		}},
	}
	stakeID := apply(stakeTx, 1)
	root1 := rootAt(1)

	// Epoch 2 (audit-failing variant): a Guardian grant pays the whole stake amount out of the
	// pool, leaving balance == fee < Σ active stakes. Apply trusts the (notionally
	// quorum-authorized) winner — the walk replays it cleanly and supply stays conserved (the
	// grant becomes an unclaimed receivable), so ONLY fund-solvency breaks.
	fx := &gateFixture{stakeTx: stakeTx, stakeID: stakeID, fins: map[uint64][]*pb.EpochFinalization{}}
	if withGrant {
		var dest [32]byte
		dest[0] = 0xB0
		fx.grantTx = &pb.Tx{
			Type:    pb.TxType_TX_TYPE_SEND,
			Account: &pb.AccountId{V: fund[:]},
			Prev:    &pb.Hash32{V: fundSyn[:]},
			Seq:     2,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To:           &pb.AccountId{V: dest[:]},
				Amount:       gateStakeAmt,
				Fee:          0,
				AccountClass: pb.AccountClass_ACCOUNT_CLASS_FUND,
			}},
		}
		fx.grantID = apply(fx.grantTx, 2)
	}
	root2 := rootAt(2)

	fx.fins[1] = []*pb.EpochFinalization{v.signFin(t, 1, acceptedHashOf([][32]byte{stakeID}), root1, [][32]byte{stakeID})}
	if withGrant {
		fx.fins[2] = []*pb.EpochFinalization{v.signFin(t, 2, acceptedHashOf([][32]byte{fx.grantID}), root2, [][32]byte{fx.grantID})}
	} else {
		fx.fins[2] = []*pb.EpochFinalization{v.signFin(t, 2, acceptedHashOf(nil), root2, nil)}
	}

	fundHead := fundSyn
	if withGrant {
		fundHead = fx.grantID
	}
	fx.frontier = map[[32]byte][32]byte{genesis: stakeID, fund: fundHead}
	return fx
}

// serveGatePeer is the fake resync peer: /sync/latest, ranged /sync/finalization,
// /sync/frontiers, /sync/chain — just enough protocol for a full runResync.
func serveGatePeer(t *testing.T, fx *gateFixture) *httptest.Server {
	t.Helper()
	txs := map[[32]byte]*pb.Tx{fx.stakeID: fx.stakeTx}
	if fx.grantTx != nil {
		txs[fx.grantID] = fx.grantTx
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sync/latest":
			_, _ = protodelim.MarshalTo(w, &pb.SyncLatestResponse{LatestEpoch: gateTargetEp})
		case "/sync/finalization":
			q := r.URL.Query()
			if q.Get("from") == "" {
				http.Error(w, "test peer serves the ranged form only", 500)
				return
			}
			from, _ := strconv.ParseUint(q.Get("from"), 10, 64)
			to, _ := strconv.ParseUint(q.Get("to"), 10, 64)
			through := to
			if through > gateTargetEp {
				through = gateTargetEp
			}
			resp := &pb.SyncFinalizationResponse{}
			for ep := from; ep <= through; ep++ {
				resp.Finalizations = append(resp.Finalizations, fx.fins[ep]...)
			}
			w.Header().Set(HeaderFinThrough, strconv.FormatUint(through, 10))
			_, _ = protodelim.MarshalTo(w, resp)
		case "/sync/frontiers":
			resp := &pb.SyncFrontiersResponse{Epoch: gateTargetEp}
			for acct, head := range fx.frontier {
				resp.Entries = append(resp.Entries, &pb.FrontierEntry{
					Account: &pb.AccountId{V: append([]byte(nil), acct[:]...)},
					Head:    &pb.Hash32{V: append([]byte(nil), head[:]...)},
				})
			}
			_, _ = protodelim.MarshalTo(w, resp)
		case "/sync/chain":
			var req pb.SyncChainRequest
			if err := protodelim.UnmarshalFrom(bufio.NewReader(r.Body), &req); err != nil {
				http.Error(w, "bad proto", 400)
				return
			}
			var target [32]byte
			copy(target[:], req.GetTargetHead().GetV())
			tx, ok := txs[target]
			if !ok {
				http.Error(w, "unknown head", 404)
				return
			}
			// Every served chain is one block deep, rooted on a synthetic anchor.
			_, _ = protodelim.MarshalTo(w, &pb.SyncChainResponse{Tx: []*pb.Tx{tx}, ReachedHave: true})
		default:
			http.Error(w, "unexpected path "+r.URL.Path, 500)
		}
	}))
}

func TestPostResyncGateHaltsOnWalkPassingAuditFailingRebuild(t *testing.T) {
	v := newTValidator(t)
	fx := buildGateHistory(t, v, true)
	srv := serveGatePeer(t, fx)
	defer srv.Close()
	e := newAuditEngine(t, []*tValidator{v}, 1, 1, []string{srv.URL})

	e.triggerResync(gateTargetEp, [32]byte{}, [32]byte{})
	err := e.runResync(context.Background())
	if err == nil || !errors.Is(err, ErrInvariantViolation) {
		t.Fatalf("runResync over an insolvent (but walk-passing) history: err=%v, want an invariant violation", err)
	}

	halted, reason, hEpoch := e.InvariantStats()
	if !halted || reason != "fund-solvency" || hEpoch != gateTargetEp {
		t.Fatalf("gate halt: halted=%v reason=%q epoch=%d (want true, fund-solvency, %d)", halted, reason, hEpoch, gateTargetEp)
	}

	// NO retry: the gate is terminal (a walk-passing rebuild is deterministic — every peer
	// reproduces the identical broken balances). Idle mode, no backoff schedule, no fail count.
	e.mu.Lock()
	mode, lastErr := e.resync.Mode, e.resync.LastErr
	nextAt, fails := e.resyncNextAttempt, e.resyncFailCount
	e.mu.Unlock()
	if mode != ResyncIdle || !nextAt.IsZero() || fails != 0 {
		t.Fatalf("gate must not schedule a retry: mode=%v nextAttempt=%v fails=%d", mode, nextAt, fails)
	}
	if !strings.Contains(lastErr, "invariant") {
		t.Fatalf("resync LastErr should record the halt, got %q", lastErr)
	}

	// The halt seals the node: no new resync, no submits — but the rebuilt forensic state serves.
	e.triggerResync(gateTargetEp+1, [32]byte{}, [32]byte{})
	if e.ResyncActive() {
		t.Fatalf("triggerResync must be refused after the gate halt")
	}
	if serr := e.SubmitTx([]byte{1}); serr == nil || !strings.Contains(serr.Error(), "halted") {
		t.Fatalf("SubmitTx after gate halt: %v", serr)
	}
	fundRec, rerr := e.AccountState(e.cfg.FundAccount)
	if rerr != nil || fundRec.Balance != testEcon.RequiredFee(gateStakeAmt) {
		t.Fatalf("rebuilt forensic state must be preserved + readable: fund balance=%d err=%v (want the insolvent %d)",
			fundRec.Balance, rerr, testEcon.RequiredFee(gateStakeAmt))
	}
}

func TestPostResyncGatePassesCleanRebuildAndArms(t *testing.T) {
	v := newTValidator(t)
	fx := buildGateHistory(t, v, false)
	srv := serveGatePeer(t, fx)
	defer srv.Close()
	e := newAuditEngine(t, []*tValidator{v}, 1, 1, []string{srv.URL})

	e.triggerResync(gateTargetEp, [32]byte{}, [32]byte{})
	if err := e.runResync(context.Background()); err != nil {
		t.Fatalf("clean resync must succeed: %v", err)
	}
	if halted, reason, _ := e.InvariantStats(); halted {
		t.Fatalf("clean rebuild must not halt (false positive at the gate!): %q", reason)
	}
	if e.ResyncActive() {
		t.Fatalf("resync must return to Idle after a clean gate pass")
	}
	if got := e.LastFullAuditEpoch(); got != gateTargetEp {
		t.Fatalf("the gate must stamp last_full_audit_epoch on pass: got %d, want %d", got, gateTargetEp)
	}
	if got := e.LatestFinalizedEpoch(); got != gateTargetEp {
		t.Fatalf("rebuilt tip = %d, want %d", got, gateTargetEp)
	}
	genRec, err := e.AccountState(e.cfg.GenesisAccount)
	if err != nil {
		t.Fatalf("read genesis: %v", err)
	}
	wantGen := uint64(1_000_000_000) - gateStakeAmt - testEcon.RequiredFee(gateStakeAmt)
	if genRec.Balance != wantGen {
		t.Fatalf("rebuilt genesis balance=%d, want %d", genRec.Balance, wantGen)
	}
}
