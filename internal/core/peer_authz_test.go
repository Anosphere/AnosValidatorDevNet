package core

import (
	"crypto/ecdsa"
	"testing"
)

// TestPeerSourceAllowed pins the /peer/* IP front door (P7.3): loopback always, roster + dynamic Fund
// endpoints allowed, everything else fail-closed.
func TestPeerSourceAllowed(t *testing.T) {
	e := &Engine{
		rosterIPs:  map[string]struct{}{"203.0.113.1": {}},
		dynPeerIPs: map[string]struct{}{"198.51.100.2": {}},
	}
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9090", true}, // loopback
		{"[::1]:9090", true},     // ipv6 loopback
		{"203.0.113.1:5", true},  // manifest roster (pre-flip / fallback)
		{"198.51.100.2:5", true}, // dynamic Fund banker endpoint (post-flip)
		{"8.8.8.8:5", false},     // not in any set
		{"203.0.113.9:5", false}, // near a roster IP but distinct
		{"", false},              // empty
		{"garbage", false},       // unparseable, not in any set
	}
	for _, c := range cases {
		if got := e.PeerSourceAllowed(c.addr); got != c.want {
			t.Errorf("PeerSourceAllowed(%q) = %v, want %v", c.addr, got, c.want)
		}
	}

	// IPv6 canonicalization: a source in non-canonical form must match the canonical stored IP.
	e6 := &Engine{
		rosterIPs:  map[string]struct{}{"2001:db8::1": {}},
		dynPeerIPs: map[string]struct{}{},
	}
	if !e6.PeerSourceAllowed("[2001:db8:0:0::1]:5") {
		t.Errorf("non-canonical IPv6 source should match the canonical stored roster IP")
	}
	if e6.PeerSourceAllowed("[2001:db8::2]:5") {
		t.Errorf("a different IPv6 source must not match")
	}
}

// TestPeerMemberForEpoch pins that membership resolves via the per-epoch set, falling back to the
// manifest list when no epoch set is cached (the same lenient resolution the candidate/finalization
// handlers use).
func TestPeerMemberForEpoch(t *testing.T) {
	var id1, id2 [33]byte
	id1[0], id2[0] = 1, 2
	e := &Engine{
		cfg:       EngineConfig{ValidatorSet: map[[33]byte]*ecdsa.PublicKey{id1: {}}},
		epochSets: map[uint64]map[[33]byte]*ecdsa.PublicKey{},
	}
	if !e.PeerMemberForEpoch(5, id1) {
		t.Errorf("id1 is in the manifest set — should be a member via fallback")
	}
	if e.PeerMemberForEpoch(5, id2) {
		t.Errorf("id2 is in no set — should not be a member")
	}
}

// TestHostHelpers covers URL/remote-addr host extraction + the roster IP set builder (dedup by IP).
// The scheme-less cases are the load-bearing ones: Fund banker endpoints are registered as bare
// "host:port", which a plain url.Parse().Hostname() would silently drop (leaving the dynamic allowlist
// empty). hostFromURL must extract the host from BOTH forms.
func TestHostHelpers(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://35.234.70.37:30303", "35.234.70.37"}, // manifest roster form (with scheme)
		{"http://127.0.0.1:9090", "127.0.0.1"},
		{"10.0.0.1:9090", "10.0.0.1"},                 // Fund banker-endpoint form (scheme-less host:port)
		{"35.234.70.37:30303", "35.234.70.37"},        // _gentestnet -endpoints form
		{"[2001:db8::1]:30303", "2001:db8::1"},        // scheme-less IPv6
		{"http://[2001:db8::1]:30303", "2001:db8::1"}, // URL IPv6
		{"", ""},
	}
	for _, c := range cases {
		if h := hostFromURL(c.in); h != c.want {
			t.Errorf("hostFromURL(%q) = %q, want %q", c.in, h, c.want)
		}
	}
	if h := hostFromRemoteAddr("10.0.0.5:1234"); h != "10.0.0.5" {
		t.Errorf("hostFromRemoteAddr(ip:port) = %q", h)
	}
	if h := hostFromRemoteAddr("[::1]:2"); h != "::1" {
		t.Errorf("hostFromRemoteAddr(ipv6) = %q", h)
	}
	if h := hostFromRemoteAddr("bare"); h != "bare" {
		t.Errorf("hostFromRemoteAddr(bare) = %q", h)
	}
	// canonicalHost round-trips IP literals (non-canonical IPv6 -> canonical) and passes hostnames through.
	if c := canonicalHost("2001:db8:0:0::1"); c != "2001:db8::1" {
		t.Errorf("canonicalHost(non-canonical ipv6) = %q, want 2001:db8::1", c)
	}
	if c := canonicalHost("10.0.0.1"); c != "10.0.0.1" {
		t.Errorf("canonicalHost(ipv4) = %q", c)
	}
	// ipSetFromURLs now populates from BOTH scheme-less and URL endpoints (dedup by canonical IP).
	set := ipSetFromURLs([]string{"10.0.0.1:9090", "http://10.0.0.1:9091", "5.6.7.8:9"})
	for _, want := range []string{"10.0.0.1", "5.6.7.8"} {
		if _, ok := set[want]; !ok {
			t.Errorf("ipSetFromURLs missing %s (set=%v)", want, set)
		}
	}
	if len(set) != 2 {
		t.Errorf("ipSetFromURLs should dedup by IP: got %d, want 2", len(set))
	}
}
