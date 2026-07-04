package core

// P7.4 units: the paced/paging resync client, target blacklist + lying-tip cap, the Fund-native
// dial list, the flip-aware /peer/tx/* membership resolver, and the gossip false-ACK fix. The
// end-to-end behaviours (a real non-roster validator joining post-flip, resync across a set
// divergence) are exercised by the live ≥4-validator harness; these pin the deterministic pieces.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/encoding/protodelim"

	pb "anos/internal/proto"
)

// --- resync client: 429 pacing ---

func TestResyncDo429ThenSuccess(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		_, _ = protodelim.MarshalTo(w, &pb.SyncLatestResponse{LatestEpoch: 7})
	}))
	defer srv.Close()

	got, err := e.httpSyncLatest(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("httpSyncLatest should retry through a 429: %v", err)
	}
	if got != 7 {
		t.Fatalf("latest = %d, want 7", got)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("expected exactly 2 requests (429 then 200), got %d", n)
	}
}

func TestResyncDoGivesUpAfterMaxAttempts(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	if _, err := e.httpSyncLatest(context.Background(), srv.URL); err == nil {
		t.Fatalf("a permanently-429ing peer must eventually surface an error")
	}
	if n := atomic.LoadInt32(&calls); n != resyncMaxAttempts {
		t.Fatalf("expected %d attempts, got %d", resyncMaxAttempts, n)
	}
}

// --- resync client: /sync/chain paging ---

// fakeChain builds an n-block synthetic chain (head-first order, ids[0] = head) whose blocks parse
// via ParseTx and link via Prev. ids are synthetic keys (the client never recomputes txids — the
// verifying walk does that later).
func fakeChain(t *testing.T, n int) (ids [][32]byte, raws map[[32]byte][]byte, order [][32]byte) {
	t.Helper()
	raws = make(map[[32]byte][]byte, n)
	var acct [32]byte
	acct[0] = 0xAC
	prev := [32]byte{} // base block's prev is zero
	for i := 1; i <= n; i++ {
		var id [32]byte
		id[0], id[1] = 0x1D, byte(i)
		tx := &pb.Tx{
			Account: &pb.AccountId{V: acct[:]},
			Prev:    &pb.Hash32{V: append([]byte(nil), prev[:]...)},
			Seq:     uint64(i),
			Type:    pb.TxType_TX_TYPE_SEND,
		}
		raw, err := CanonicalTxBytes(tx)
		if err != nil {
			t.Fatalf("canonical: %v", err)
		}
		raws[id] = raw
		order = append(order, id)
		prev = id
	}
	// head-first ids
	for i := len(order) - 1; i >= 0; i-- {
		ids = append(ids, order[i])
	}
	return ids, raws, order
}

// chainServer serves /sync/chain over the fake chain with a per-page block cap, mimicking the
// byte-budgeted server (a page that stops early returns reachedHave=false).
func chainServer(t *testing.T, raws map[[32]byte][]byte, perPage int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req pb.SyncChainRequest
		if err := protodelim.UnmarshalFrom(bufio.NewReader(r.Body), &req); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		var cur [32]byte
		copy(cur[:], req.TargetHead.V)
		resp := &pb.SyncChainResponse{}
		for i := 0; i < perPage; i++ {
			raw, ok := raws[cur]
			if !ok {
				break
			}
			tx, _ := ParseTx(raw)
			resp.Tx = append(resp.Tx, tx)
			var prev [32]byte
			copy(prev[:], tx.Prev.V)
			if prev == ([32]byte{}) {
				resp.ReachedHave = true // base reached with have==zero
				break
			}
			cur = prev
		}
		_, _ = protodelim.MarshalTo(w, resp)
	}))
}

func TestHttpSyncChainPagesToCompletion(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})

	ids, raws, _ := fakeChain(t, 5)
	srv := chainServer(t, raws, 2) // 2 blocks per page → 3 pages
	defer srv.Close()

	var acct, have [32]byte
	txs, reached, err := e.httpSyncChain(context.Background(), srv.URL, acct, ids[0], have, 100)
	if err != nil {
		t.Fatalf("paged chain download failed: %v", err)
	}
	if !reached {
		t.Fatalf("paged download should reach the chain base")
	}
	if len(txs) != 5 {
		t.Fatalf("stitched %d blocks, want 5", len(txs))
	}
}

func TestHttpSyncChainRespectsTotalCap(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})

	ids, raws, _ := fakeChain(t, 5)
	srv := chainServer(t, raws, 2)
	defer srv.Close()

	var acct, have [32]byte
	txs, reached, err := e.httpSyncChain(context.Background(), srv.URL, acct, ids[0], have, 3)
	if err != nil {
		t.Fatalf("capped download errored: %v", err)
	}
	if reached {
		t.Fatalf("total cap smaller than the chain must not report reached")
	}
	if len(txs) > 4 { // one page may complete past the cap check, but paging must stop
		t.Fatalf("total cap ignored: got %d blocks", len(txs))
	}
}

// --- SyncChain server-side byte budget ---

func TestSyncChainByteBudgetPages(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})

	_, raws, order := fakeChain(t, 5)
	if err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		for id, raw := range raws {
			if err := putTxRaw(tx, id, raw); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed chain: %v", err)
	}

	head := order[len(order)-1] // newest block id
	var acct, have [32]byte
	oneBlock := len(raws[head])

	// Budget of one block → the page stops after the first tx, not reached.
	page1, reached := e.SyncChain(acct, head, have, 100, oneBlock)
	if reached {
		t.Fatalf("byte-budgeted page must not claim the boundary")
	}
	if len(page1) != 1 {
		t.Fatalf("budget=1 block returned %d txs, want 1", len(page1))
	}

	// Unbudgeted → the whole chain, reached (zero-prev base with have==zero).
	full, reached := e.SyncChain(acct, head, have, 100, 0)
	if !reached || len(full) != 5 {
		t.Fatalf("unbudgeted walk: reached=%v n=%d, want true,5", reached, len(full))
	}

	// Boundary verdict must not be lost when the budget lands on the boundary block.
	lastPage, reached := e.SyncChain(acct, order[0], have, 100, 1) // base block only
	if !reached || len(lastPage) != 1 {
		t.Fatalf("base page: reached=%v n=%d, want true,1", reached, len(lastPage))
	}
}

// --- pickResyncTarget: lying-tip cap + blacklist + never-strand ---

func latestServer(ep uint64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = protodelim.MarshalTo(w, &pb.SyncLatestResponse{LatestEpoch: ep})
	}))
}

// A lone liar (tip beyond the wall-clock cap) must be IGNORED in favor of an honest within-cap peer
// — NOT blacklisted (blacklisting on the cap is what stranded a clock-skewed node; that regression
// is asserted absent by TestPickResyncTargetClockSkewDoesNotStrand below).
func TestPickResyncTargetPrefersHonestOverLiar(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})

	capEp := e.epochNow() + maxIntakeEpochAhead
	liar := latestServer(capEp + 100) // provably impossible committed tip
	defer liar.Close()
	honest := latestServer(3)
	defer honest.Close()

	e.cfg.Peers = []string{liar.URL, honest.URL}

	peer, ep, err := e.pickResyncTarget(context.Background(), 0)
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	if peer != honest.URL || ep != 3 {
		t.Fatalf("picked %s@%d, want the honest peer @3 (liar ignored, not preferred)", peer, ep)
	}
}

// The clock-skew self-strand regression (found in review): when EVERY reachable peer reports a tip
// above the wall-clock cap — which means OUR clock is slow, not that the whole roster is lying — the
// picker must still return a peer (highest tip, target clamped to the cap) rather than blacklist
// them all and return "no reachable peers" forever.
func TestPickResyncTargetClockSkewDoesNotStrand(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})

	capEp := e.epochNow() + maxIntakeEpochAhead
	ahead := latestServer(capEp + 1000) // an honest peer whose real tip is above our slow-clock cap
	defer ahead.Close()
	e.cfg.Peers = []string{ahead.URL}

	peer, ep, err := e.pickResyncTarget(context.Background(), 0)
	if err != nil {
		t.Fatalf("a slow local clock must NOT strand resync: %v", err)
	}
	if peer != ahead.URL {
		t.Fatalf("picked %q, want the only peer", peer)
	}
	if ep > capEp {
		t.Fatalf("target %d must be clamped to the wall-clock cap %d (bounds the walk vs a real liar)", ep, capEp)
	}
	if e.resyncPeerBlacklisted(ahead.URL) {
		t.Fatalf("an above-cap peer must NOT be blacklisted (that is the strand bug)")
	}
}

func TestPickResyncTargetNeverStrands(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})

	honest := latestServer(4)
	defer honest.Close()
	e.cfg.Peers = []string{honest.URL}

	// Blacklist the ONLY peer — the picker must clear the blacklist rather than strand.
	e.blacklistResyncPeer(honest.URL, "test")
	peer, ep, err := e.pickResyncTarget(context.Background(), 0)
	if err != nil {
		t.Fatalf("never-strand pick failed: %v", err)
	}
	if peer != honest.URL || ep != 4 {
		t.Fatalf("picked %s@%d, want the (unblacklisted) honest peer @4", peer, ep)
	}
}

// probeBehind must NOT trigger a destructive wipe-resync on an implausible (above wall-clock cap)
// tip — the lying-tip livelock/griefing lever found in review — but MUST trigger on an honest
// within-cap tip that is genuinely ahead.
func TestProbeBehindIgnoresLyingTip(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})
	capEp := e.epochNow() + maxIntakeEpochAhead

	liar := latestServer(capEp + 1_000_000) // absurd tip, beyond the wall-clock cap
	defer liar.Close()
	e.cfg.Peers = []string{liar.URL}
	e.probeBehind(context.Background(), 1)
	if e.resync.IsActive() {
		t.Fatalf("a tip above the wall-clock cap must NOT trigger a destructive resync")
	}

	// An honest peer within the cap, genuinely ahead of our local tip (0), must trigger.
	honest := latestServer(capEp - 1) // within cap, >> local tip 0 + maxIntakeEpochLag
	defer honest.Close()
	e.cfg.Peers = []string{honest.URL}
	e.probeBehind(context.Background(), 1)
	if !e.resync.IsActive() {
		t.Fatalf("an honest within-cap tip far ahead of local must trigger resync")
	}
}

// --- ranged finalization fetcher ---

func TestFinFetcherRangedPrefetch(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})

	var rangeCalls, epochCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("from") != "" {
			atomic.AddInt32(&rangeCalls, 1)
			from, _ := strconv.ParseUint(q.Get("from"), 10, 64)
			to, _ := strconv.ParseUint(q.Get("to"), 10, 64)
			// Cover at most 2 epochs per page (a tiny byte budget), stamp the coverage header.
			through := from + 1
			if through > to {
				through = to
			}
			resp := &pb.SyncFinalizationResponse{}
			for ep := from; ep <= through; ep++ {
				resp.Finalizations = append(resp.Finalizations,
					v.signFin(t, ep, [32]byte{1}, [32]byte{2}, nil))
			}
			w.Header().Set(HeaderFinThrough, strconv.FormatUint(through, 10))
			_, _ = protodelim.MarshalTo(w, resp)
			return
		}
		atomic.AddInt32(&epochCalls, 1)
		http.Error(w, "unexpected per-epoch call", 500)
	}))
	defer srv.Close()

	ff := newFinFetcher(e, context.Background(), srv.URL, 5)
	for ep := uint64(1); ep <= 5; ep++ {
		fins, err := ff.get(ep)
		if err != nil {
			t.Fatalf("get(%d): %v", ep, err)
		}
		if len(fins) != 1 || fins[0].Epoch != ep {
			t.Fatalf("get(%d): wrong fins %v", ep, fins)
		}
	}
	if n := atomic.LoadInt32(&rangeCalls); n != 3 { // epochs [1,2] [3,4] [5]
		t.Fatalf("range calls = %d, want 3", n)
	}
	if n := atomic.LoadInt32(&epochCalls); n != 0 {
		t.Fatalf("per-epoch fallback fired %d times against a ranged server", n)
	}
}

func TestFinFetcherFallsBackPerEpoch(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})

	var epochCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("epoch") == "" {
			// A pre-P7.4 server: the ranged form doesn't exist.
			http.Error(w, "need ?epoch=<u64>", 400)
			return
		}
		atomic.AddInt32(&epochCalls, 1)
		ep, _ := strconv.ParseUint(q.Get("epoch"), 10, 64)
		resp := &pb.SyncFinalizationResponse{
			Finalizations: []*pb.EpochFinalization{v.signFin(t, ep, [32]byte{1}, [32]byte{2}, nil)},
		}
		_, _ = protodelim.MarshalTo(w, resp)
	}))
	defer srv.Close()

	ff := newFinFetcher(e, context.Background(), srv.URL, 3)
	for ep := uint64(1); ep <= 3; ep++ {
		fins, err := ff.get(ep)
		if err != nil {
			t.Fatalf("get(%d): %v", ep, err)
		}
		if len(fins) != 1 || fins[0].Epoch != ep {
			t.Fatalf("get(%d): wrong fins", ep)
		}
	}
	if n := atomic.LoadInt32(&epochCalls); n != 3 {
		t.Fatalf("per-epoch calls = %d, want 3 (fallback per epoch)", n)
	}
}

// --- Fund-native dial list ---

func TestDialURLFromEndpoint(t *testing.T) {
	cases := []struct{ in, want string }{
		{"127.0.0.1:9093", "http://127.0.0.1:9093"}, // bare host:port (the Fund convention)
		{"http://10.0.0.1:9090", "http://10.0.0.1:9090"},
		{"https://10.0.0.1:9090/", "https://10.0.0.1:9090"},
		{"[2001:db8::1]:9090", "http://[2001:db8::1]:9090"},
		{"garbage", ""}, // no port → never dialed blind
		{"", ""},
		{"ftp://x:1", ""}, // non-http scheme
	}
	for _, c := range cases {
		if got := dialURLFromEndpoint(c.in); got != c.want {
			t.Errorf("dialURLFromEndpoint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildDialList(t *testing.T) {
	self := [33]byte{9}
	other1, other2, other3 := [33]byte{1}, [33]byte{2}, [33]byte{3}
	roster := []string{"http://127.0.0.1:9090", "http://127.0.0.1:9091/"}
	descs := []ValidatorDescriptor{
		{Identity: [32]byte{1}, ConsensusKey: other1, Endpoint: "127.0.0.1:9090"}, // dup of roster[0]
		{Identity: [32]byte{2}, ConsensusKey: self, Endpoint: "127.0.0.1:9099"},   // self → excluded
		{Identity: [32]byte{3}, ConsensusKey: other2, Endpoint: "127.0.0.1:9093"}, // the joiner
		{Identity: [32]byte{4}, ConsensusKey: other3, Endpoint: "junk"},           // skipped
	}
	got := buildDialList(roster, descs, self)
	want := []string{"http://127.0.0.1:9090", "http://127.0.0.1:9091", "http://127.0.0.1:9093"}
	if len(got) != len(want) {
		t.Fatalf("dial list %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dial list %v, want %v", got, want)
		}
	}
}

func TestRefreshPeerViewsClearsMaskOnChange(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})
	e.cfg.Peers = []string{"http://127.0.0.1:9090"}

	var id [32]byte
	id[0] = 7
	e.mu.Lock()
	e.gossipMask = map[[32]byte]uint64{id: 3}
	e.mu.Unlock()

	e.refreshPeerViews(1) // dialPeers nil → [roster] = a change → mask cleared
	e.mu.Lock()
	n := len(e.gossipMask)
	dial := append([]string(nil), e.dialPeers...)
	e.mu.Unlock()
	if n != 0 {
		t.Fatalf("gossipMask must be cleared when the dial list changes (still %d entries)", n)
	}
	if len(dial) != 1 || dial[0] != "http://127.0.0.1:9090" {
		t.Fatalf("dial list = %v", dial)
	}

	// Unchanged list → mask preserved.
	e.mu.Lock()
	e.gossipMask = map[[32]byte]uint64{id: 3}
	e.mu.Unlock()
	e.refreshPeerViews(2)
	e.mu.Lock()
	n = len(e.gossipMask)
	e.mu.Unlock()
	if n != 1 {
		t.Fatalf("gossipMask must be preserved when the dial list is unchanged")
	}
}

func TestDialHealthCooldown(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})
	u := "http://10.255.255.1:9"

	e.recordDialResult(u, false)
	e.recordDialResult(u, false)
	if !e.dialAllowed(u) {
		t.Fatalf("below the threshold the peer must still be dialable")
	}
	e.recordDialResult(u, false) // threshold reached → cooldown armed
	if e.dialAllowed(u) {
		t.Fatalf("after %d consecutive failures the peer must cool down", dialFailThreshold)
	}
	e.recordDialResult(u, true) // success clears
	if !e.dialAllowed(u) {
		t.Fatalf("a success must clear the cooldown")
	}
}

// --- flip-aware PeerMemberForEpoch (the two P7.3 residuals) ---

func TestPeerMemberForEpochFlipAware(t *testing.T) {
	founder, joiner := newTValidator(t), newTValidator(t)
	e := &Engine{
		cfg:       EngineConfig{ValidatorSet: map[[33]byte]*ecdsa.PublicKey{founder.id: founder.pub}},
		epochSets: map[uint64]map[[33]byte]*ecdsa.PublicKey{},
	}

	// Nothing cached yet (fresh boot / mid-resync): manifest fallback.
	if !e.PeerMemberForEpoch(5, founder.id) {
		t.Fatalf("fresh boot: manifest founder must pass")
	}
	if e.PeerMemberForEpoch(5, joiner.id) {
		t.Fatalf("fresh boot: an unknown key must not pass")
	}

	// The loop caches epoch 10 = post-flip Fund set {joiner} (founder kicked).
	e.setEpochValidatorSet(10, map[[33]byte]*ecdsa.PublicKey{joiner.id: joiner.pub})

	// Cached epoch: authoritative — no manifest fallback behind it.
	if !e.PeerMemberForEpoch(10, joiner.id) {
		t.Fatalf("cached epoch: the joined banker must pass")
	}
	if e.PeerMemberForEpoch(10, founder.id) {
		t.Fatalf("cached epoch: the kicked founder must be refused (residual 7)")
	}

	// UNCACHED epoch 11 (the pre-cache window gossip is stamped with): latest cached set, not the
	// manifest — the joiner passes (residual 6) and the kicked founder stays out (residual 7).
	if !e.PeerMemberForEpoch(11, joiner.id) {
		t.Fatalf("uncached epoch: the joined banker must pass via the latest cached set")
	}
	if e.PeerMemberForEpoch(11, founder.id) {
		t.Fatalf("uncached epoch: the kicked founder must not fall back to the manifest")
	}
}

// --- gossip false-ACK fix ---

func TestGossipNonOKInvIsNotAnAck(t *testing.T) {
	v := newTValidator(t)
	e := newWalkTestEngine(t, []*tValidator{v})

	var id [32]byte
	id[0] = 0x77
	seed := func() {
		e.mu.Lock()
		e.gossipPending = map[[32]byte]struct{}{id: {}}
		e.gossipMask = map[[32]byte]uint64{id: 0}
		e.mu.Unlock()
	}

	reject := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unknown validator", 400) // the membership gate's refusal
	}))
	defer reject.Close()
	accept := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = protodelim.MarshalTo(w, &pb.TxWant{}) // 2xx, wants nothing → a REAL full ack
	}))
	defer accept.Close()

	seed()
	e.gossipToPeer(context.Background(), 0, reject.URL, [][32]byte{id}, 1)
	e.mu.Lock()
	_, stillPending := e.gossipPending[id]
	e.mu.Unlock()
	if !stillPending {
		t.Fatalf("a rejected inv must NOT ack (pre-P7.4 false-ACK bug): tx dropped for the peer")
	}

	seed()
	e.gossipToPeer(context.Background(), 0, accept.URL, [][32]byte{id}, 1)
	e.mu.Lock()
	_, stillPending = e.gossipPending[id]
	e.mu.Unlock()
	if stillPending {
		t.Fatalf("a 2xx wants-nothing inv should ack and (at majority) drop the pending entry")
	}
}
