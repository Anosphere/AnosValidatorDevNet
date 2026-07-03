package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// P7.3 endpoint hardening: the transport-layer edge middlewares + a hand-rolled per-IP rate limiter
// (no external deps — golang.org/x/time is not vendored). These are DoS/spam defenses layered OUTSIDE
// the P7.2 network-id middleware and the consensus signature checks; they are defense-in-depth, never
// the consensus boundary (a forged candidate/finalization is rejected by finalizationQuorum regardless
// of which IP delivered it).

// ---- http.Server hardening (Slowloris / oversized-request defenses) ----
const (
	// readHeaderTimeout is THE Slowloris cut: the longest a client may take to trickle request headers.
	readHeaderTimeout = 10 * time.Second
	// readTimeout bounds the whole request read (headers + body). Peer + public request bodies are small.
	readTimeout = 20 * time.Second
	// writeTimeout bounds a response. Generous enough to stream a testnet-scale /sync/chain; large-chain
	// WAN resync deadlines are a P7.4 concern (splitting the resync CLIENT timeout).
	writeTimeout = 60 * time.Second
	// idleTimeout bounds a kept-alive idle connection.
	idleTimeout = 120 * time.Second
	// maxHeaderBytes caps request header size (the net/http default is 1 MiB; pinned explicitly).
	maxHeaderBytes = 1 << 20

	// maxPublicBodyBytes caps the body of the io.ReadAll public endpoints (/submit, /account,
	// /receivables). One SubmitTxRequest is a single tx — a few KB even with a hybrid pubkey + multisig.
	maxPublicBodyBytes = 1 << 20 // 1 MiB

	// maxFrontiersLimit / maxSyncChainBlocks ceiling the caller-controlled pagination on /sync/*. The
	// resync client asks for 1000 frontiers/page and 200000 chain blocks, so these never truncate a
	// legitimate resync; they only bound an absurd request. (True long-chain pagination is P7.4.)
	maxFrontiersLimit  = 10_000
	maxSyncChainBlocks = 200_000
)

// ---- per-IP token-bucket rate limiter ----
const (
	submitRatePerSec  = 25.0 // sustained /submit accepts per source IP
	submitBurst       = 100.0
	syncRatePerSec    = 20.0 // sustained /sync/* requests per source IP
	syncBurst         = 40.0
	rateLimiterMaxIPs = 8192 // bound the tracking map (memory); stale entries evicted first
	rateLimiterIdle   = 10 * time.Minute
)

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// ipRateLimiter is a simple per-source-IP token bucket. Concurrency-safe. Memory-bounded: at most
// maxIPs buckets, stale ones (idle) evicted before a new IP is admitted, and a fresh-flooded map fails
// OPEN (the limiter is defense-in-depth, not a hard gate).
type ipRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64 // tokens per second
	burst   float64 // bucket capacity
	maxIPs  int
	idle    time.Duration
}

func newIPRateLimiter(ratePerSec, burst float64) *ipRateLimiter {
	return &ipRateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    ratePerSec,
		burst:   burst,
		maxIPs:  rateLimiterMaxIPs,
		idle:    rateLimiterIdle,
	}
}

// allow reports whether a request from ip may proceed, consuming one token if so.
func (l *ipRateLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[ip]
	if b == nil {
		if len(l.buckets) >= l.maxIPs {
			l.evictStaleLocked(now)
		}
		if len(l.buckets) >= l.maxIPs {
			return true // map full of fresh entries (wide source-IP flood): fail open, stay bounded
		}
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictStaleLocked drops buckets untouched for longer than idle. Caller holds l.mu.
func (l *ipRateLimiter) evictStaleLocked(now time.Time) {
	for ip, b := range l.buckets {
		if now.Sub(b.last) > l.idle {
			delete(l.buckets, ip)
		}
	}
}

// ---- source-IP helpers ----

// clientIP extracts the source host from r.RemoteAddr ("ip:port" or a bare host).
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

// isLoopback reports whether host is a loopback IP (operator + self + the local test harness).
func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ---- edge middlewares (composed in main around the mux) ----

// debugLoopbackGate restricts every /debug/* route to loopback callers. Those routes dump full account
// / stake / Fund state, so on an open testnet they must never answer a remote client; operators reach
// them via SSH on the box or an SSH tunnel. The local harness + every /debug-touching sim hit them over
// 127.0.0.1, so this does not affect the green gate.
func debugLoopbackGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/debug/") && !isLoopback(clientIP(r)) {
			http.Error(w, "forbidden: /debug is loopback-only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// peerIPFirewall fail-closes every /peer/* route (except the /peer/id liveness probe) to source IPs the
// sourceAllowed predicate accepts — engine.PeerSourceAllowed, i.e. the per-epoch peer set (manifest
// roster pre-flip / Fund banker endpoints post-flip; loopback always allowed). Coarse DoS/spam
// defense-in-depth. /sync/* is deliberately NOT firewalled here (a fresh node must sync before it
// appears in any set) — it is rate-limited instead. Taking a predicate (not the engine) keeps the
// middleware unit-testable with a stub.
func peerIPFirewall(next http.Handler, sourceAllowed func(remoteAddr string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/peer/") && r.URL.Path != "/peer/id" {
			if !sourceAllowed(r.RemoteAddr) {
				// No per-request log here: /peer/* is unmetered, so an unauthenticated remote could
				// otherwise turn each refusal into a log/disk-fill line (the vector P7.3-G removes
				// elsewhere). The 403 is the signal; aggregate refusal metrics are a later item.
				http.Error(w, "forbidden: source not in the peer set", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitGate meters /submit and /sync/* per source IP. Loopback is always exempt (the local harness
// + sims). /submit is public but must not be a free lever to fill the bounded mempool. /sync/* is the
// bootstrap/resync read path and needs special care: the resync client is a SEQUENTIAL burst reader
// that aborts on the FIRST non-2xx (resync.go), so metering a legitimate member's resync would livelock
// it (429 -> abort -> re-wipe -> retry -> same 429). We therefore exempt KNOWN peers (roster / Fund
// bankers, via syncExempt == engine.PeerSourceAllowed) from /sync metering and meter only UNKNOWN
// sources, preserving the bulk-read amplification defense against attackers. A fresh node bootstrapping
// a long chain still needs the P7.4 paced / 429-aware resync client — that is a P7.4 dependency, not
// something this gate can satisfy. Everything else passes untouched.
func rateLimitGate(next http.Handler, submitLim, syncLim *ipRateLimiter, syncExempt func(remoteAddr string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip := clientIP(r); !isLoopback(ip) {
			var lim *ipRateLimiter
			switch {
			case r.URL.Path == "/submit":
				lim = submitLim
			case strings.HasPrefix(r.URL.Path, "/sync/"):
				if !syncExempt(r.RemoteAddr) {
					lim = syncLim
				}
			}
			if lim != nil && !lim.allow(ip) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
