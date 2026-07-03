package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newProbe returns a terminal handler and a pointer that records whether it was reached.
func newProbe() (http.Handler, *bool) {
	called := new(bool)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	}), called
}

func TestIPRateLimiterBurstThenDeny(t *testing.T) {
	l := newIPRateLimiter(1, 3) // 1 token/s, burst 3
	ip := "203.0.113.7"
	for i := 0; i < 3; i++ {
		if !l.allow(ip) {
			t.Fatalf("call %d should be allowed within the burst", i)
		}
	}
	if l.allow(ip) {
		t.Fatalf("call past the burst should be denied")
	}
	// Simulate ~2s elapsed → ~2 tokens refilled.
	l.mu.Lock()
	l.buckets[ip].last = time.Now().Add(-2 * time.Second)
	l.mu.Unlock()
	if !l.allow(ip) || !l.allow(ip) {
		t.Fatalf("after ~2s refill, 2 calls should be allowed")
	}
	if l.allow(ip) {
		t.Fatalf("after consuming the refill, the next call should be denied")
	}
}

func TestIPRateLimiterEvictsStale(t *testing.T) {
	l := newIPRateLimiter(1, 1)
	l.maxIPs = 2
	l.allow("a")
	l.allow("b")
	// Age out "a".
	l.mu.Lock()
	l.buckets["a"].last = time.Now().Add(-2 * l.idle)
	l.mu.Unlock()
	l.allow("c") // must evict stale "a" to make room, stay within maxIPs
	l.mu.Lock()
	_, aExists := l.buckets["a"]
	_, cExists := l.buckets["c"]
	n := len(l.buckets)
	l.mu.Unlock()
	if aExists {
		t.Errorf("stale bucket 'a' should have been evicted")
	}
	if !cExists {
		t.Errorf("'c' should have been admitted after eviction")
	}
	if n > l.maxIPs {
		t.Errorf("bucket map exceeded maxIPs: %d > %d", n, l.maxIPs)
	}
}

func TestDebugLoopbackGate(t *testing.T) {
	next, called := newProbe()
	h := debugLoopbackGate(next)

	do := func(path, remote string) *httptest.ResponseRecorder {
		*called = false
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	if rec := do("/debug/fund/stakes", "127.0.0.1:5555"); !*called || rec.Code != http.StatusOK {
		t.Errorf("loopback /debug must pass: called=%v code=%d", *called, rec.Code)
	}
	if rec := do("/debug/fund/stakes", "203.0.113.9:5555"); *called || rec.Code != http.StatusForbidden {
		t.Errorf("remote /debug must be 403: called=%v code=%d", *called, rec.Code)
	}
	if rec := do("/submit", "203.0.113.9:5555"); !*called || rec.Code != http.StatusOK {
		t.Errorf("remote non-/debug must pass the debug gate: called=%v code=%d", *called, rec.Code)
	}
}

func TestPeerIPFirewall(t *testing.T) {
	allowed := map[string]bool{"10.0.0.1:1": true}
	pred := func(addr string) bool { return allowed[addr] }
	next, called := newProbe()
	h := peerIPFirewall(next, pred)

	do := func(method, path, remote string) *httptest.ResponseRecorder {
		*called = false
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	if rec := do("POST", "/peer/candidates", "10.0.0.1:1"); !*called || rec.Code != http.StatusOK {
		t.Errorf("allowed source must reach /peer: called=%v code=%d", *called, rec.Code)
	}
	if rec := do("POST", "/peer/candidates", "9.9.9.9:1"); *called || rec.Code != http.StatusForbidden {
		t.Errorf("disallowed source must be 403 on /peer: called=%v code=%d", *called, rec.Code)
	}
	if rec := do("GET", "/peer/id", "9.9.9.9:1"); !*called || rec.Code != http.StatusOK {
		t.Errorf("/peer/id probe must be exempt from the firewall: called=%v code=%d", *called, rec.Code)
	}
	if rec := do("GET", "/sync/latest", "9.9.9.9:1"); !*called || rec.Code != http.StatusOK {
		t.Errorf("/sync/* must NOT be firewalled here (fresh nodes sync first): called=%v code=%d", *called, rec.Code)
	}
}

func TestRateLimitGate(t *testing.T) {
	sub := newIPRateLimiter(1, 2)
	syn := newIPRateLimiter(1, 2)
	next, called := newProbe()
	// syncExempt models engine.PeerSourceAllowed: known peers (and loopback) skip /sync metering.
	exempt := map[string]bool{"10.9.9.9:1": true}
	syncExempt := func(remoteAddr string) bool { return exempt[remoteAddr] }
	h := rateLimitGate(next, sub, syn, syncExempt)

	do := func(method, path, remote string) *httptest.ResponseRecorder {
		*called = false
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	// Loopback is exempt: many /submit all pass.
	for i := 0; i < 5; i++ {
		if rec := do("POST", "/submit", "127.0.0.1:1"); !*called || rec.Code != http.StatusOK {
			t.Fatalf("loopback /submit #%d must pass: code=%d", i, rec.Code)
		}
	}
	// Non-loopback /submit: burst 2, then 429.
	ip := "198.51.100.3:1"
	for i := 0; i < 2; i++ {
		if rec := do("POST", "/submit", ip); !*called || rec.Code != http.StatusOK {
			t.Fatalf("/submit #%d should pass within burst: code=%d", i, rec.Code)
		}
	}
	if rec := do("POST", "/submit", ip); *called || rec.Code != http.StatusTooManyRequests {
		t.Errorf("/submit past burst must be 429: called=%v code=%d", *called, rec.Code)
	}
	// A non-metered public path from the same throttled IP still passes.
	if rec := do("POST", "/account", ip); !*called || rec.Code != http.StatusOK {
		t.Errorf("/account must not be rate limited: called=%v code=%d", *called, rec.Code)
	}

	// /sync/* from an UNKNOWN source is metered (burst 2, then 429).
	sip := "198.51.100.9:1"
	for i := 0; i < 2; i++ {
		if rec := do("GET", "/sync/finalization", sip); !*called || rec.Code != http.StatusOK {
			t.Fatalf("/sync from unknown #%d should pass within burst: code=%d", i, rec.Code)
		}
	}
	if rec := do("GET", "/sync/finalization", sip); *called || rec.Code != http.StatusTooManyRequests {
		t.Errorf("/sync from unknown past burst must be 429: called=%v code=%d", *called, rec.Code)
	}
	// /sync/* from a KNOWN peer is UNMETERED — a resyncing member must never be throttled (its client
	// aborts on the first 429). Hammer well past the burst.
	for i := 0; i < 10; i++ {
		if rec := do("GET", "/sync/chain", "10.9.9.9:1"); !*called || rec.Code != http.StatusOK {
			t.Fatalf("/sync from known peer #%d must pass unmetered: code=%d", i, rec.Code)
		}
	}
	// /sync/* from loopback is likewise unmetered.
	for i := 0; i < 10; i++ {
		if rec := do("GET", "/sync/latest", "127.0.0.1:2"); !*called || rec.Code != http.StatusOK {
			t.Fatalf("loopback /sync #%d must pass unmetered: code=%d", i, rec.Code)
		}
	}
}
