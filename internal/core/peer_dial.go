package core

import (
	"net"
	"net/url"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

// P7.4 Fund-native DIALING: the outbound half of connectivity-follows-the-Fund (P7.3 shipped the
// inbound gating half). Once per epoch the loop rebuilds the DIAL LIST — the peers every
// broadcast / gossip / fetch loop talks to — as the manifest roster ∪ the CURRENT finalized Fund
// banker endpoints (self excluded by consensus key). BankerValidatorSet computes vd.Endpoint from
// each banker's deposit descriptor (P4.1/P4.2 put it there precisely for this) and, pre-P7.4,
// validatorSetForEpoch dropped it — nothing ever dialed a Fund-registered address, so a post-flip
// newly-joined banker was counted by consensus but never spoken to.
//
// Invariants:
//   - The manifest roster is a PERMANENT union member — a node can never strand itself, and a net
//     whose Fund descriptors carry stale/garbage endpoints still coheres over the roster.
//   - Resync/bootstrap deliberately does NOT use this list (roster-only): a wiped node has no Fund
//     state to derive peers from — the chicken-and-egg the P7.4 scoping locked.
//   - LIVENESS-ONLY: every candidate/finalization/tx is signature-verified regardless of which
//     peer delivered it, so a wrong/stale dial list cannot fork; a dead dial fails, is skipped,
//     and cools down (dialHealth below).

const (
	// dialFailThreshold consecutive transport failures put a dial URL on a dialCooldown pause.
	// Stale Fund endpoints are EXPECTED (rotations leave dead IPs; the harness flip sim registers
	// unroutable ones), and the gossip flush blocks on its slowest dial each 200ms tick — without
	// a cooldown one dead peer turns every tick into a 2s stall. LOCAL liveness knobs.
	dialFailThreshold = 3
	dialCooldown      = 30 * time.Second

	// maxGossipPushBytes caps one /peer/tx/push body so it always clears the receiver's 4 MiB
	// protodelim read cap (300 hybrid-signed txs can approach it). Overflow stays pending for the
	// next tick.
	maxGossipPushBytes = 3 << 19 // 1.5 MiB
)

type dialHealthEntry struct {
	fails   int
	retryAt time.Time
}

// buildDialList composes the per-epoch dial list: roster first (in roster order), then Fund banker
// endpoints (BankerValidatorSet is identity-sorted → deterministic), self excluded by consensus
// key, deduped by canonical host:port so a founder whose Fund descriptor repeats its roster URL
// (in either form) is dialed once. Pure — unit-tested directly.
func buildDialList(roster []string, descs []ValidatorDescriptor, self [33]byte) []string {
	out := make([]string, 0, len(roster)+len(descs))
	seen := make(map[string]struct{}, len(roster)+len(descs))
	add := func(u string) {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if u == "" {
			return
		}
		k := canonicalDialKey(u)
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		out = append(out, u)
	}
	for _, r := range roster {
		add(r)
	}
	for _, vd := range descs {
		if vd.ConsensusKey == self {
			continue
		}
		if u := dialURLFromEndpoint(vd.Endpoint); u != "" {
			add(u)
		}
	}
	return out
}

// dialURLFromEndpoint turns a Fund banker endpoint into a dialable base URL: the bare "host:port"
// / "[v6]:port" registration convention becomes "http://host:port"; a full http(s) URL passes
// through host-normalized. Anything else (port-less, unparseable) returns "" — skipped, never
// dialed blind. Mirrors hostFromURL's tolerance (peer_authz.go) on the inbound side.
func dialURLFromEndpoint(ep string) string {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return ""
	}
	if strings.Contains(ep, "://") {
		u, err := url.Parse(ep)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return ""
		}
		return u.Scheme + "://" + u.Host
	}
	if h, p, err := net.SplitHostPort(ep); err == nil && h != "" && p != "" {
		return "http://" + net.JoinHostPort(canonicalHost(h), p)
	}
	return ""
}

// canonicalDialKey collapses equivalent dial URLs ("http://127.0.0.1:9090" vs a Fund-registered
// "127.0.0.1:9090") to one "host:port" dedupe key (IP literals canonicalized, IPv6-safe).
func canonicalDialKey(u string) string {
	raw := u
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	raw = strings.TrimRight(raw, "/")
	if h, p, err := net.SplitHostPort(raw); err == nil && h != "" {
		return net.JoinHostPort(canonicalHost(h), p)
	}
	return raw
}

// refreshPeerViews recomputes BOTH per-epoch connectivity views from the finalized Fund banker
// state — the inbound /peer/* source-IP allowlist (P7.3, dynPeerIPs) and the outbound dial list
// (P7.4) — from ONE DB read, once per epoch from the loop, so the two views can never disagree
// about the set. If the dial list CHANGED, gossipMask (whose bits are indexes into the list) is
// cleared and dialHealth entries for departed URLs pruned; worst case one redundant re-inv per
// pending tx (a peer that already holds it answers "want nothing" → instant re-ack).
// gossipPending is kept. Liveness-only (never a fork).
func (e *Engine) refreshPeerViews(epoch uint64) {
	var descs []ValidatorDescriptor
	_ = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		descs = e.cfg.Econ.BankerValidatorSet(listStakesInTx(tx), listBankerInfoInTx(tx))
		return nil
	})
	ips := make(map[string]struct{}, len(descs))
	for _, vd := range descs {
		if h := hostFromURL(vd.Endpoint); h != "" {
			ips[canonicalHost(h)] = struct{}{}
		}
	}
	dial := buildDialList(e.cfg.Peers, descs, e.cfg.Signer.PublicKeyCompressed())

	e.mu.Lock()
	e.dynPeerIPs = ips
	changed := !equalStrings(e.dialPeers, dial)
	if changed {
		e.dialPeers = dial
		e.gossipMask = make(map[[32]byte]uint64)
		inList := make(map[string]struct{}, len(dial))
		for _, u := range dial {
			inList[strings.TrimRight(u, "/")] = struct{}{}
		}
		for u := range e.dialHealth {
			if _, ok := inList[u]; !ok {
				delete(e.dialHealth, u)
			}
		}
	}
	e.mu.Unlock()
	if changed {
		e.elog(epoch, "dial set refreshed: %d peers (roster ∪ fund endpoints)", len(dial))
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// currentDialPeers snapshots the dial list. Before the first refresh (and in direct-engine tests
// that never run the loop) it falls back to the static cfg.Peers — pre-P7.4 behaviour exactly.
func (e *Engine) currentDialPeers() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.dialPeers) > 0 {
		return append([]string(nil), e.dialPeers...)
	}
	return append([]string(nil), e.cfg.Peers...)
}

// dialAllowed reports whether a dial URL is currently worth trying: after dialFailThreshold
// consecutive transport failures it is paused until retryAt (then probed again — one attempt
// re-arms or clears the cooldown). Only gossip/broadcast/fetch dialing consults this; resync has
// its own blacklist and inbound intake is never affected.
func (e *Engine) dialAllowed(u string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.dialHealth[u]
	if h == nil || h.fails < dialFailThreshold {
		return true
	}
	return time.Now().After(h.retryAt)
}

// recordDialResult feeds dialAllowed: success clears the entry; a transport failure increments it
// and (re-)arms the cooldown at the threshold.
func (e *Engine) recordDialResult(u string, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dialHealth == nil {
		e.dialHealth = make(map[string]*dialHealthEntry)
	}
	if ok {
		delete(e.dialHealth, u)
		return
	}
	h := e.dialHealth[u]
	if h == nil {
		h = &dialHealthEntry{}
		e.dialHealth[u] = h
	}
	h.fails++
	if h.fails >= dialFailThreshold {
		h.retryAt = time.Now().Add(dialCooldown)
	}
}
