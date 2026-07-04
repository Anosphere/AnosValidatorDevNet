package core

import (
	"net"
	"net/url"
	"strings"
)

// P7.3 peer authorization: the /peer/* front door and the per-epoch membership resolution the
// consensus wire uses. This is DoS/spam defense-in-depth and connectivity-follows-the-Fund gating,
// NOT the consensus boundary — every candidate/finalization/tx is signature-verified regardless of
// which peer delivered it (finalizationQuorum, ReceiveCandidateList, the epoch-close dry-run), so
// making authorization flip-aware is liveness-only and cannot fork. Worst case a stale/blocked dial
// fails and is skipped.
//
// Two orthogonal mechanisms compose:
//   - IP allowlist (PeerSourceAllowed): a coarse source-IP front door on /peer/*, keyed off the same
//     per-epoch set consensus uses (static manifest roster pre-flip / Fund banker endpoints post-flip,
//     roster kept as a permanent fallback). Loopback is always allowed (operator + self).
//   - Membership (PeerMemberForEpoch): the finer per-epoch validator-set check the handlers apply to
//     /peer/*, resolved via the same pubForEpoch the candidate/finalization handlers already use, so a
//     newly-admitted banker is accepted and a kicked one refused (the pre-P7.3 liveness smell where
//     inv/push used the STATIC env set and tx/get had no check).

// PeerSourceAllowed reports whether an inbound /peer/* connection from remoteAddr (an "ip:port" as in
// http.Request.RemoteAddr, or a bare host) is permitted: loopback, a manifest-roster IP, or a
// current Fund banker-endpoint IP (refreshed each epoch). Fail-closed: an unparseable or unknown
// source is refused. /sync/* deliberately does NOT use this (a fresh node must sync before it appears
// in any set) — it is rate-limited instead.
func (e *Engine) PeerSourceAllowed(remoteAddr string) bool {
	host := hostFromRemoteAddr(remoteAddr)
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	host = canonicalHost(host) // canonicalize so IPv6 forms match the stored set
	e.mu.Lock()
	_, roster := e.rosterIPs[host]
	_, dyn := e.dynPeerIPs[host]
	e.mu.Unlock()
	return roster || dyn
}

// PeerMemberForEpoch reports whether a peer consensus id is a member of the validator set for epoch
// (manifest list pre-flip, Fund-derived post-flip) — the /peer/tx/* DoS-gate membership check.
//
// P7.4 (flip-aware resolver, closing the two P7.3 residuals): the fallback for an epoch the loop
// has NOT cached yet is the LATEST cached epoch set — which follows the Fund post-flip — rather
// than the static manifest. Gossip is stamped with the sender's wall-clock epoch, which runs ahead
// of the receiver's loop by its epoch-close processing tail (~1.6s), so the "uncached epoch" window
// recurs every epoch; with the manifest fallback a post-flip newly-joined banker was rejected for
// that whole window (and re-rejected every epoch), while a kicked FOUNDER kept passing. Against the
// latest cached set, a joined banker is accepted from its second member-epoch on and a kicked one
// refused once the next epoch caches. The static manifest remains only the nothing-cached-yet
// fallback (fresh boot / mid-resync). Unlike pubForEpoch (which the sig-verifying candidate/
// finalization intakes keep, unchanged), a CACHED set answers authoritatively — no manifest
// fallback behind it — because this is a membership question, not a key-resolution one.
// DoS-gate-only and liveness-only either way: the epoch-close union re-validates every tx and the
// quorum re-checks membership, so a wrong verdict here can delay a tx, never fork.
func (e *Engine) PeerMemberForEpoch(epoch uint64, id [33]byte) bool {
	e.mu.Lock()
	set := e.epochSets[epoch]
	if set == nil {
		set = e.latestEpochSet
	}
	e.mu.Unlock()
	if set != nil {
		_, ok := set[id]
		return ok
	}
	return e.cfg.ValidatorSet[id] != nil
}

// The dynamic (Fund-derived) source-IP allowlist is refreshed once per epoch by refreshPeerViews
// (peer_dial.go, P7.4) — one BankerValidatorSet read now feeds BOTH the inbound allowlist and the
// outbound dial list, so the two connectivity views can never disagree about the set. Pre-flip the
// Fund set may be empty or a founders' superset; either way it only ADDS IPs alongside the
// permanent roster fallback, never removes one, so gating can never strand a rostered node.

// ipSetFromURLs collapses a list of endpoints (the manifest roster / cfg.Peers / Fund banker
// endpoints) to the set of their canonical host IPs — the set of source addresses those peers connect
// to us from. Used to seed the static roster allowlist and (via refreshDynPeerIPs) the dynamic one.
func ipSetFromURLs(urls []string) map[string]struct{} {
	out := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		if h := hostFromURL(u); h != "" {
			out[canonicalHost(h)] = struct{}{}
		}
	}
	return out
}

// hostFromURL extracts the host (IP or hostname, no port) from an endpoint that may be EITHER a full
// base URL ("http://35.234.70.37:30303", the manifest roster form) OR a bare "host:port" / "[ipv6]:port"
// (the Fund banker-endpoint form registered by the sims / _gentestnet -endpoints). Returns "" only if
// no host can be extracted. NOTE: url.Parse on a scheme-less "10.0.0.1:9090" fails ("first path segment
// in URL cannot contain colon") and on "host:9090" mis-parses the host as a scheme — so a plain
// url.Parse().Hostname() silently drops every banker endpoint. The SplitHostPort / bare-host fallbacks
// below are what make the dynamic Fund-endpoint allowlist actually populate.
func hostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil {
		if h := u.Hostname(); h != "" {
			return h
		}
	}
	// Scheme-less endpoint: try "host:port" / "[ipv6]:port".
	if h, _, err := net.SplitHostPort(raw); err == nil && h != "" {
		return h
	}
	// Bare host with no port.
	return raw
}

// canonicalHost normalizes a host so equal addresses compare equal: an IP literal is round-tripped
// through net.IP (canonical form, so e.g. "2001:db8:0:0::1" == "2001:db8::1"); a non-IP host (a
// hostname — outside the raw-IP convention, but tolerated) is returned unchanged.
func canonicalHost(h string) string {
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return h
}

// hostFromRemoteAddr extracts the host from an "ip:port" (http.Request.RemoteAddr) or a bare host.
func hostFromRemoteAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	// No port present — treat the whole thing as the host.
	return addr
}
