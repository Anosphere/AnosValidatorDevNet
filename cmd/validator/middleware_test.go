package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"anos/internal/core"
)

const testNetID = "20bd2ec07a6eb9a6ca9314934f3b252767bce683150e4f3ec081f91578951ff2"

func TestGatedPath(t *testing.T) {
	gated := []string{"/peer/candidates", "/peer/finalization", "/peer/tx/inv", "/peer/tx/push", "/peer/tx/get", "/sync/latest", "/sync/chain"}
	ungated := []string{"/peer/id", "/submit", "/account", "/receivables", "/debug/accounts/heads", "/debug/consensus/flip", "/"}
	for _, p := range gated {
		if !gatedPath(p) {
			t.Errorf("gatedPath(%q) = false, want true", p)
		}
	}
	for _, p := range ungated {
		if gatedPath(p) {
			t.Errorf("gatedPath(%q) = true, want false", p)
		}
	}
}

func TestAnosNetworkMiddleware(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	h := anosNetworkMiddleware(next, testNetID, 1)

	do := func(path string, setHeaders bool, netID string, ver string) *httptest.ResponseRecorder {
		nextCalled = false
		req := httptest.NewRequest("POST", path, nil)
		if setHeaders {
			req.Header.Set(core.HeaderNetworkID, netID)
			req.Header.Set(core.HeaderProtocolVersion, ver)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// A gated path with correct headers passes and the response is stamped with our identity.
	rec := do("/peer/candidates", true, testNetID, "1")
	if !nextCalled || rec.Code != http.StatusOK {
		t.Errorf("gated + correct headers: nextCalled=%v code=%d", nextCalled, rec.Code)
	}
	if rec.Header().Get(core.HeaderNetworkID) != testNetID || rec.Header().Get(core.HeaderProtocolVersion) != "1" {
		t.Errorf("response missing our identity headers: %v", rec.Header())
	}

	// A gated path with a wrong network id is rejected (421) and never reaches the handler.
	rec = do("/peer/tx/push", true, "deadbeef", "1")
	if nextCalled || rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("gated + wrong id: nextCalled=%v code=%d (want 421, no next)", nextCalled, rec.Code)
	}

	// A gated path with NO headers is rejected (misconfig guard, fail-closed).
	rec = do("/sync/latest", false, "", "")
	if nextCalled || rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("gated + missing headers: nextCalled=%v code=%d (want 421, no next)", nextCalled, rec.Code)
	}

	// The /peer/id liveness probe is EXEMPT — a plain curl with no headers passes.
	rec = do("/peer/id", false, "", "")
	if !nextCalled || rec.Code != http.StatusOK {
		t.Errorf("/peer/id must pass without headers: nextCalled=%v code=%d", nextCalled, rec.Code)
	}

	// Public /submit and /debug pass through without headers.
	for _, p := range []string{"/submit", "/debug/accounts/heads"} {
		rec = do(p, false, "", "")
		if !nextCalled || rec.Code != http.StatusOK {
			t.Errorf("%s must pass without headers: nextCalled=%v code=%d", p, nextCalled, rec.Code)
		}
	}
}
