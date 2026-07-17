package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/bits"
	"net/http"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

type EngineConfig struct {
	DB           *bbolt.DB
	Signer       ValidatorSigner
	ValidatorSet map[[33]byte]*ecdsa.PublicKey // validator_id -> pubkey (membership)

	Peers         []string
	EpochDuration time.Duration
	// GenesisUnixMs anchors epoch numbering to wall-clock time:
	// epoch = floor((nowMs - genesisMs) / epochMs) + 1
	GenesisUnixMs             int64
	QuorumPercent             int // used only for conflict resolution
	FinalizationQuorumPercent int // quorum for EpochFinalization agreement (default 60)
	HTTPClient                *http.Client
	// ResyncHTTPClient is the DEDICATED bulk-sync client (P7.4): NO global timeout — every resync
	// request carries its own per-request deadline (resync.go) so a large /sync/chain page can
	// finish where the shared 2s gossip client could not. Defaulted by NewEngine; injectable for
	// tests. LOCAL liveness knob, never consensus-relevant.
	ResyncHTTPClient *http.Client
	CandidatesSkew   time.Duration
	FinalizationSkew time.Duration

	FundAccount    [32]byte
	GenesisAccount [32]byte
	GenesisSupply  uint64

	// GenesisAuthPubKey is the canonical 2625-byte hybrid auth pubkey of the genesis
	// account (keys-spec §5.2). Because genesis is seeded directly and has no
	// key-registering opening block, its pubkey is manifest-pinned (GENESIS_AUTH_PUBKEY_HEX)
	// and seeded into the genesis account's AUTH_PUBKEY TLV at boot so its distribution
	// SENDs verify as hybrid (spec-18 §8). The genesis id stays the GENESIS_HEX
	// constant and is exempt from id-derivation enforcement (keys-spec §6.5).
	GenesisAuthPubKey []byte

	// TimelockedDelayEpochs is the minimum timelock (in epochs) applied when funds move out
	// of a TIMELOCKED account through a transfer chain. CONSENSUS-CRITICAL: must be identical
	// on all validators (set via TIMELOCKED_DELAY_EPOCHS, exactly like EPOCH_MS/GENESIS_UNIX_MS).
	TimelockedDelayEpochs uint64

	// GuardianActiveWindowEpochs is the trailing window (in epochs) within which a Guardian
	// counts toward the ACTIVE set — the denominator M for the weighted Fund-SEND quorum
	// (spec-19 §6.2; ~5–6 weeks in production). CONSENSUS-CRITICAL: must be identical on all
	// validators (set via GUARDIAN_ACTIVE_WINDOW_EPOCHS). Read by buildSnapshot when computing
	// GuardianActiveWeight; local test configs set a small value for testability.
	GuardianActiveWindowEpochs uint64

	// StakeLock1moEpochs / StakeLock1yrEpochs are the lock delays (in epochs) for the two stake
	// tiers (P2.3b, working notes §3.6). A Guardian-returned stake opens a TRANSFER chain whose
	// unlock is at least creation_epoch + the staked tier's lock, so the staker cannot drain the
	// returned funds before the lock elapses. CONSENSUS-CRITICAL (set via STAKE_LOCK_1MO_EPOCHS /
	// STAKE_LOCK_1YR_EPOCHS); local test configs set small values.
	StakeLock1moEpochs uint64
	StakeLock1yrEpochs uint64

	// GuardedDelayEpochs / VaultDelayEpochs are the per-class transfer delays for GUARDED / VAULT
	// sources (P3.2, spec-18 §6). A transfer funded by a GUARDED/VAULT account locks at least this
	// long (VAULT > GUARDED > TIMELOCKED by configuration). CONSENSUS-CRITICAL: identical on every
	// validator (set via GUARDED_DELAY_EPOCHS / VAULT_DELAY_EPOCHS); local test configs set small
	// values. P7's network manifest must content-address them.
	GuardedDelayEpochs uint64
	VaultDelayEpochs   uint64

	// AttestorQuorumM is the flat M-of-N Fund Attestor quorum threshold (P3.2, spec-19 §6.1): an
	// attestor-gated TRANSFER release-to-dest needs at least this many DISTINCT verifying Fund
	// Attestor signatures (a count, NOT a weight). CONSENSUS-CRITICAL manifest constant (set via
	// ATTESTOR_QUORUM_M); must be >= 1. P7's network manifest must content-address it.
	AttestorQuorumM uint64

	// EscrowAttestationDelayEpochs is the minimum gap (in epochs) between an escrow's creation and
	// its attestation_trigger_epoch (P3.3, spec-18 §5.6.3): the 1-of-2 → Fund attestation trigger
	// (attested escrows only) cannot fire before creation_epoch + this. CONSENSUS-CRITICAL: identical
	// on every validator (set via ESCROW_ATTESTATION_DELAY_EPOCHS); local test configs set a small
	// value. P7's network manifest must content-address it.
	EscrowAttestationDelayEpochs uint64

	// BreakglassExtraEpochs is the +1-week fraud-challenge window added to a breakglass move's
	// transfer-chain unlock floor (P5.1, spec-18 §6, spec-19 §6.4), on top of the source class's
	// normal transfer delay. During this window the real owner can cancel via return-to-source.
	// CONSENSUS-CRITICAL: identical on every validator (set via BREAKGLASS_EXTRA_EPOCHS); local test
	// configs set a small value. P7's network manifest must content-address it.
	BreakglassExtraEpochs uint64

	// GuardedSendMinIntervalEpochs is the guarded/vault outbound rate limit (forquinn confirm-item
	// 2: one new guarded send per 24h, epoch-denominated — 86_400_000/epoch_ms in a mainnet
	// manifest; devnet 12). A SEND from a GUARDED/VAULT account is rejected while
	// epoch - LastGuardedSendEpoch is below it. CONSENSUS-CRITICAL once wired (phase 2 adds the
	// manifest timing field + env bridge; until then it is 0 == no limit).
	GuardedSendMinIntervalEpochs uint64

	// Econ carries the manifest-pinned monetary + role scalars (fee schedule, role floors, Guardian
	// divisor/threshold, fund-send epoch slack). buildSnapshot copies it into every Snapshot, and the
	// engine-side validator-set / Guardian derivations invoke it as e.cfg.Econ.X. CONSENSUS-CRITICAL:
	// identical on every validator (network_id pins it); NewEngine fails closed if it is unset — P7.2
	// removed the code-side const defaults.
	Econ Economics

	// MaxCandidateScanPerSlot bounds how many txids buildCandidateList validates per conflict slot
	// (P7.1). Manifest-pinned so candidate proposal is deterministic network-wide under a flood;
	// NewEngine fails closed if 0. P7.3 ALSO uses it as the per-conflict-slot mempool admission cap
	// (FIFO reject-when-full), so a slot can never accumulate more txids than buildCandidateList
	// scans — closing the P7.1 ">64-junk buries the real opening" residual.
	MaxCandidateScanPerSlot uint64

	// MaxMempoolTxs bounds the unsolicited transaction pool (reject-when-full). A LOCAL operational
	// knob (memory bound), NOT consensus-critical and deliberately NOT manifest-pinned: divergent
	// caps cannot fork — solicited consensus fetches (fetchMissingTxs) bypass it, and a tx dropped by
	// one full pool is still held/proposed by other nodes and fetched on demand by any node that needs
	// it for the union. 0 => NewEngine substitutes defaultMaxMempoolTxs. (P7.3)
	MaxMempoolTxs int

	// NetworkID / ProtocolVersion are this node's network identity (config.Manifest.NetworkID = the
	// content hash + SupportedProtocolVersion). The engine stamps them as X-Anos-* headers on every
	// outbound /peer/* + /sync/* request and verifies them on resync RESPONSES; the cmd/validator
	// mux middleware verifies them on inbound requests. A misconfiguration guard (spoofable-is-fine),
	// NOT a security boundary — consensus is sig-authed regardless. Empty NetworkID disables the
	// check (used only by tests that build an engine directly).
	NetworkID       string
	ProtocolVersion int

	// SelfIdentity is this node's Banker account-id (the durable 32-byte PQ identity that staked
	// Banker), set via VALIDATOR_IDENTITY_HEX (P4.3, working notes §3.7). Until the list→Fund flip
	// the validator set is keyed by the P-256 consensus key (the env list); after the flip the set
	// is keyed by identity, so a node needs to know its OWN identity to recognise its slot / a kick.
	// In P4.3a it backs the read API + a boot self-check; it does not yet gate participation (a
	// node validates as long as its consensus key is in the active set). Zero == unset.
	SelfIdentity [32]byte
}

type Engine struct {
	cfg EngineConfig

	mu sync.Mutex
	// epoch -> validator_id -> candidate list
	peerLists     map[uint64]map[[33]byte]*CandidateList
	txPool        map[[32]byte][]byte     // txid -> raw tx bytes (submitted/gossiped/fetched)
	txSeenEpoch   map[[32]byte]uint64     // txid -> epoch when first seen
	conflictPool  map[[32]byte][][32]byte // keyHash -> txids (all conflict candidates we’ve seen)
	approved      map[[32]byte][32]byte   // keyHash -> txid we “approve” this epoch
	gossipPending map[[32]byte]struct{}   // txids to announce on next gossip tick
	gossipMask    map[[32]byte]uint64     // txid -> bitmask of peers that have it via push/want(ack)

	peerFinals map[uint64]map[[33]byte]*pb.EpochFinalization // epoch -> signer -> fin

	// --- P4.3 list→Fund validator-set source switch ---
	// manifestKeys is the static manifest validator list's consensus-key set (derived once from
	// cfg.ValidatorSet), the anchor the list→Fund activation predicate matches against.
	manifestKeys map[[33]byte]struct{}
	// epochSets caches the deterministic validator set used for each epoch (manifest list while
	// flipEpoch==0 or epoch<=flipEpoch, else the Fund-derived set off the finalized end-of-(E−1)
	// snapshot). The epoch loop populates it when it builds the epoch's snapshot; the message
	// handlers + quorum read it so membership / the denominator are deterministic. Pruned to a
	// trailing window and cleared on resync. Guarded by e.mu.
	epochSets map[uint64]map[[33]byte]*ecdsa.PublicKey

	// --- resync state (minimal state machine) ---
	resync            ResyncState
	resyncNextAttempt time.Time
	resyncFailCount   int
	// resyncBlacklist skips a roster peer for target selection after a failed attempt / a provable
	// tip lie (P7.4) — the pre-P7.4 picker re-chose the same highest-tip peer forever, so one
	// lying peer could strand a wiped node. Guarded by e.mu; cleared wholesale when it would
	// otherwise exclude every peer (never-strand).
	resyncBlacklist map[string]time.Time

	// --- P7.4 latest-cached validator set (flip-aware gossip gating) ---
	// latestEpochSet mirrors the most recent epochSets[E] entry. PeerMemberForEpoch falls back to
	// it (NOT the static manifest) for epochs the loop has not cached yet — the window in which a
	// post-flip newly-joined banker's gossip was rejected and a kicked founder's accepted (the two
	// P7.3 residuals). Written only by setEpochValidatorSet (the loop) + cleared on resync; e.mu.
	latestEpochSet    map[[33]byte]*ecdsa.PublicKey
	latestEpochCached uint64

	// --- P7.3 peer-source IP allowlist (the /peer/* front door) ---
	// rosterIPs is the static set of source IPs the manifest roster reaches us from (derived once
	// from cfg.Peers at NewEngine). It is the pre-flip set AND a permanent fallback so a node can
	// never strand itself. dynPeerIPs is refreshed each epoch by the loop from the finalized Fund
	// banker endpoints (post-flip), so connectivity gating follows the Fund (Q3/Q4). Both are read by
	// PeerSourceAllowed; dynPeerIPs is guarded by e.mu. Loopback is always allowed (operator/self).
	rosterIPs  map[string]struct{}
	dynPeerIPs map[string]struct{}

	// --- P7.4 Fund-native dialing (the outbound half of connectivity-follows-the-Fund) ---
	// dialPeers is the per-epoch DIAL LIST every broadcast/gossip/fetch loop iterates: the manifest
	// roster ∪ the finalized Fund banker endpoints (self excluded by consensus key), rebuilt once
	// per epoch by refreshPeerViews and frozen in between (gossipMask bits are index-keyed against
	// it; the mask is cleared when the list changes). Empty ⇒ currentDialPeers falls back to
	// cfg.Peers (direct-engine tests / pre-first-refresh). dialHealth cools down repeatedly
	// unreachable dial URLs (stale Fund endpoints) so the 200ms gossip tick doesn't stall 2s per
	// dead peer. Both guarded by e.mu. Resync deliberately does NOT use this (roster-only).
	dialPeers  []string
	dialHealth map[string]*dialHealthEntry

	// --- P7.6 input-robustness: background-goroutine panic containment ---
	// net/http recovers a panic in a REQUEST handler (one request dies, the node lives), but the
	// epoch loop and the gossip/broadcast goroutines had no recover — a panic there killed the
	// whole process, silently stopping finalization while /health kept answering 200. The loop now
	// runs each iteration under guardIteration (a recovered LOOP panic triggers a resync — see loop)
	// and every background sender under recoverBGPanic; panicTotal/lastPanic make a recovering node
	// OBSERVABLE via /health (PanicStats). Guarded by e.mu.
	panicTotal uint64
	lastPanic  string

	// presenceSkips counts consecutive presence-gate skips for the P7.4 behind-probe pacing.
	// Cross-iteration loop state (was a loop local before the P7.6 loopOnce extraction); touched
	// only by the loop goroutine.
	presenceSkips int

	startOnce sync.Once
}

type CandidateList struct {
	Epoch       uint64
	ValidatorID [33]byte
	ListHash    [32]byte
	SigDER      []byte
	TxIDs       [][32]byte // txids only (votes)
}

// For consistent logging
func (e *Engine) elog(epoch uint64, format string, args ...any) {
	prefix := append([]any{epoch}, args...)
	log.Printf("[epoch=%d] "+format, prefix...)
}

func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.DB == nil {
		return nil, errors.New("missing db")
	}
	if cfg.Signer == nil {
		return nil, errors.New("missing signer")
	}
	if len(cfg.ValidatorSet) == 0 {
		return nil, errors.New("missing validator set")
	}
	selfID := cfg.Signer.PublicKeyCompressed()
	if _, ok := cfg.ValidatorSet[selfID]; !ok {
		// P7.4: a NON-FOUNDER node (key not in the manifest roster) may boot — that is the open-net
		// join path: resync from the roster, follow the chain, then stake Banker; it becomes a
		// voting member the epoch the Fund-derived set includes its key (post-flip). Pre-flip it can
		// only observe. Loud, because for a FOUNDER this same condition means a mis-pointed key file
		// (the manifest loader + network-id handshake are the misconfig tripwires now).
		log.Printf("[boot] WARNING: this node's consensus key %x… is NOT in the manifest validator set — "+
			"booting as a NON-FOUNDER (observer until the post-flip Fund banker set includes this key); "+
			"if this node is a roster founder, VALIDATOR_KEY_PATH points at the wrong key", selfID[:6])
	}
	if cfg.EpochDuration <= 0 {
		cfg.EpochDuration = 5 * time.Second
	}
	if cfg.GenesisUnixMs == 0 {
		return nil, errors.New("missing genesis time: set GENESIS_UNIX_MS (milliseconds since unix epoch)")
	}

	// P7.2: the consensus-critical scalars are manifest-pinned (network_id covers them) and have NO
	// code-side default — a validator that cannot supply them fails closed rather than silently
	// running a value different from what its network_id hashed. The liveness-only skews below keep
	// their defaults.
	if cfg.QuorumPercent == 0 || cfg.FinalizationQuorumPercent == 0 {
		return nil, errors.New("missing consensus quorum percents (set from the manifest consensus block)")
	}
	if cfg.Econ.unset() {
		return nil, errors.New("missing economics (fees/floors/divisor/threshold): set from the manifest economics block")
	}
	if cfg.MaxCandidateScanPerSlot == 0 {
		return nil, errors.New("missing consensus.max_candidate_scan_per_slot (set from the manifest)")
	}
	// MaxMempoolTxs is a LOCAL liveness bound (not manifest-pinned); substitute the default when unset
	// so tests / direct engine construction get a sane cap without having to specify one.
	if cfg.MaxMempoolTxs == 0 {
		cfg.MaxMempoolTxs = defaultMaxMempoolTxs
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 2 * time.Second}
	}
	if cfg.ResyncHTTPClient == nil {
		// No global timeout — resync.go applies a per-request deadline (a whole-client timeout is
		// exactly the pre-P7.4 bug: it covered an entire bulk body read).
		cfg.ResyncHTTPClient = &http.Client{}
	}
	if cfg.CandidatesSkew == 0 {
		cfg.CandidatesSkew = 300 * time.Millisecond
	}
	if cfg.FinalizationSkew == 0 {
		cfg.FinalizationSkew = 500 * time.Millisecond
	}
	manifestKeys := make(map[[33]byte]struct{}, len(cfg.ValidatorSet))
	for id := range cfg.ValidatorSet {
		manifestKeys[id] = struct{}{}
	}
	e := &Engine{
		cfg:             cfg,
		peerLists:       make(map[uint64]map[[33]byte]*CandidateList),
		manifestKeys:    manifestKeys,
		epochSets:       make(map[uint64]map[[33]byte]*ecdsa.PublicKey),
		rosterIPs:       ipSetFromURLs(cfg.Peers),
		dynPeerIPs:      make(map[string]struct{}),
		resyncBlacklist: make(map[string]time.Time),
		dialHealth:      make(map[string]*dialHealthEntry),
	}

	if err := cfg.DB.Update(func(tx *bbolt.Tx) error { return ensureBuckets(tx) }); err != nil {
		return nil, err
	}
	if err := e.ensureGenesisOnBoot(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) Start(ctx context.Context) {
	e.startOnce.Do(func() {
		go e.loop(ctx)
		go e.gossipLoop(ctx)
	})
}

// SubmitTx enqueues raw tx bytes for this epoch; it only checks signature and basic parse.
// resolveAuthPubKeyDB resolves the CANDIDATE auth pubkeys a tx's hybrid signature may verify
// against at gossip/submit time, where no epoch snapshot is available. An account-opening
// RECEIVE (the account is not yet persisted) carries its own pubkey on the tx; every other
// account tx verifies against the pubkey cached on the persisted account record — PLUS, when
// the record registered a second user key (forquinn D4), U2: a single user signature is U1 OR
// U2 everywhere one is accepted, so the gate must try both or a legit U2-signed tx would be
// dropped at submit. Returns (candidates, true) when resolvable (the caller accepts if ANY
// candidate verifies — verifyTxSigAnyKey). Returns (nil, false) when the account is referenced
// but not yet persisted (e.g. an out-of-order SEND whose opening RECEIVE has not finalized):
// the caller then accepts the tx and lets the authoritative hybrid verify run at epoch close
// (ValidateTxAgainstSnapshot), which no winner can skip.
func (e *Engine) resolveAuthPubKeyDB(tx *pb.Tx) ([][]byte, bool) {
	if tx.Account == nil || len(tx.Account.V) != 32 {
		return nil, false
	}
	var acct [32]byte
	copy(acct[:], tx.Account.V)
	// A Fund SEND (account == Fund id) is keyless — it carries no single auth pubkey, only the
	// weighted-Guardian HybridMultiSig, which needs the finalized snapshot (signer pubkeys +
	// weights + active denominator) to verify. Nothing to check at submit/gossip: DEFER (accept
	// into the pool); the authoritative quorum verify runs at epoch close (verifyFundSendQuorum)
	// and no winner can skip it.
	if tx.Type == pb.TxType_TX_TYPE_SEND && e.cfg.FundAccount != ([32]byte{}) && acct == e.cfg.FundAccount {
		return nil, false
	}
	// A breakglass move (P5.1) is authorized by the REVEALED breakglass key, not the cached auth key:
	// resolve it so the submit-time signature check verifies against the right key (the commitment
	// match is deferred to the authoritative epoch-close verify — best-effort at the gate). Without
	// this a legit breakglass tx (hop-1 source SEND / opening RECEIVE / hop-2 release) would be checked
	// against the account's cached auth key and dropped at submit. The Fund SEND is handled above; an
	// escrow outflow is keyless (no Tx.sig) so a stray reveal on it simply fails the sig check here.
	// GATED to SEND/RECEIVE: a reveal is only ever valid on those two types, and resolving it for a
	// non-SEND/RECEIVE tx (UNSPECIFIED / reserved) would verify against the ATTACKER's own key — letting
	// attacker-keyed junk pass the sig check and occupy a victim chain's conflict slot (which ignores
	// tx.Type). For those types we fall through to the cached-auth-key check, which the junk fails.
	if tx.Type == pb.TxType_TX_TYPE_SEND || tx.Type == pb.TxType_TX_TYPE_RECEIVE {
		if bg := tx.GetRevealedBreakglassPubkey().GetV(); len(bg) == crypto.HybridPubKeySize {
			return [][]byte{bg}, true
		}
	}
	var rec AccountRecord
	found := false
	_ = e.cfg.DB.View(func(dbtx *bbolt.Tx) error {
		rec, found = getAccountRecord(dbtx, acct)
		return nil
	})
	if !found {
		// Only an account-OPENING RECEIVE carries its own pubkey on the tx. A
		// non-opening RECEIVE (or a SEND) on an account we haven't synced yet has no
		// resolvable pubkey here — DEFER it (accept into the pool) rather than reject,
		// exactly like the SEND case. Gating on the pubkey's PRESENCE (not merely
		// tx.Type) is what stops a legit lagging-node 2nd-RECEIVE from being dropped
		// and needlessly triggering a resync; the authoritative verify at epoch close
		// keys "opening" off snapshot presence and cannot be skipped by any winner.
		// (An opening is always U1-signed — a U2, if any, registers via its PoP.)
		if tx.Type == pb.TxType_TX_TYPE_RECEIVE {
			if ap := tx.GetReceive().GetAuthPubkey().GetV(); len(ap) > 0 {
				return [][]byte{ap}, true // opening block: pubkey carried on the tx
			}
		}
		return nil, false // SEND, or non-opening RECEIVE on an unsynced account: defer
	}
	// A keyless escrow outflow (a SEND extending an EXISTING escrow) carries no Tx.sig — it is
	// authorized solely by the 2-of-2 / 1-of-2 HybridMultiSig, verified at epoch close. DEFER it at
	// the gate (like a Fund SEND); the submit-time floor is bestEffortReleaseCheck's escrow branch.
	if tx.Type == pb.TxType_TX_TYPE_SEND && rec.Class == pb.AccountClass_ACCOUNT_CLASS_ESCROW {
		return nil, false
	}
	keys := [][]byte{rec.AuthPubKey}
	if len(rec.U2PubKey) == crypto.HybridPubKeySize {
		keys = append(keys, rec.U2PubKey) // registered U2 (guarded/vault or a derived-copy chain)
	}
	return keys, true
}

// verifyTxSigAnyKey verifies a tx's single hybrid signature against each candidate key in order
// (U1 first, then a registered U2 — forquinn D4), accepting on the first match. Mirrors the
// authoritative U1-or-U2 resolution in ValidateTxAgainstSnapshot so the submit/gossip gate never
// drops a tx the epoch-close verify would accept.
func verifyTxSigAnyKey(tx *pb.Tx, pubs [][]byte) error {
	var lastErr error
	for _, pub := range pubs {
		if err := crypto.VerifyTxSignature(tx, pub); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = crypto.ErrMissingField // no candidate keys resolved (defensive; callers pass >= 1)
	}
	return lastErr
}

// isFundSendTx reports whether tx is a SEND extending the Fund's own chain (the keyless,
// multisig-authorized Fund outflow).
func (e *Engine) isFundSendTx(tx *pb.Tx) bool {
	if tx.Type != pb.TxType_TX_TYPE_SEND || e.cfg.FundAccount == ([32]byte{}) ||
		tx.Account == nil || len(tx.Account.V) != 32 {
		return false
	}
	var acct [32]byte
	copy(acct[:], tx.Account.V)
	return acct == e.cfg.FundAccount
}

// bestEffortFundSendCheck rejects an obviously-unauthorized Fund SEND at submit/gossip so a
// ground-low-txid garbage multisig cannot occupy the Fund chain's next conflict slot and stall
// legit Fund SENDs. (A Fund SEND is keyless, so resolveAuthPubKeyDB defers it — without this an
// invalid multisig would sit in the pool as the lowest-txid "approved" candidate, be proposed
// every epoch, fail the epoch-close verify, and block the Fund chain at that seq = liveness DoS.)
//
// It is best-effort: the AUTHORITATIVE weighted quorum runs at epoch close against the finalized
// snapshot and no winner can skip it. It returns nil (accept/defer) UNLESS it can confidently
// judge the send unauthorized — only when not resyncing AND the local Fund head == tx.prev (so
// the node is at the exact Fund position this tx extends and its finalized state is the right
// basis). Even then it enforces ONLY the N>=1 floor (>=1 valid eligible-Guardian signature, via
// GuardianActiveWeight=0 → zero threshold), never the 70% threshold (which depends on the active
// denominator and could race), so a legitimately-signed Fund SEND is never rejected here.
func (e *Engine) bestEffortFundSendCheck(tx *pb.Tx) error {
	// A Fund SEND is keyless and must carry no Tx.sig (consensus-critical — see the validate
	// gate: it keeps crypto.TxID's multisig-binding discriminator sound). Reject it here too so a
	// Tx.sig-bearing variant (whose single-sig txid does NOT bind the multisig, and which could be
	// ground to a low txid) never even enters the pool to occupy the Fund's next conflict slot.
	if tx.Sig != nil {
		return errors.New("fund send must be keyless: no Tx.sig (authorized by the guardian multisig)")
	}
	e.mu.Lock()
	resyncing := e.resync.IsActive()
	e.mu.Unlock()
	if resyncing {
		return nil // catching up — don't judge
	}
	var prev [32]byte
	if tx.Prev != nil && len(tx.Prev.V) == 32 {
		copy(prev[:], tx.Prev.V)
	}
	snap := &Snapshot{
		Accounts:             map[[32]byte]AccountSnap{},
		FundAccount:          e.cfg.FundAccount,
		GuardianActiveWeight: 0,          // M=0 → threshold collapses to the N>=1 floor (submit-time leniency)
		Econ:                 e.cfg.Econ, // manifest economics: the quorum/weight math needs the real divisor/threshold
	}
	atPosition := false
	_ = e.cfg.DB.View(func(dbtx *bbolt.Tx) error {
		fr, ok := getAccountRecord(dbtx, e.cfg.FundAccount)
		if !ok || fr.Head != prev {
			return nil // not at this Fund position — leave atPosition false
		}
		atPosition = true
		snap.FundStakeRows = listStakesInTx(dbtx)
		if ms := tx.MultiSig; ms != nil {
			for _, en := range ms.Entries {
				if en == nil || en.SignerId == nil || len(en.SignerId.V) != 32 {
					continue
				}
				var id [32]byte
				copy(id[:], en.SignerId.V)
				if rec, ok := getAccountRecord(dbtx, id); ok {
					snap.Accounts[id] = AccountSnap{AuthPubKey: rec.AuthPubKey}
				}
			}
		}
		// P5.4: when this Fund SEND redirects a stake (recovery_beneficiary set), load the referenced
		// stake's CURRENT owner (auth key + breakglass commitment) so the owner_auth can be verified at
		// the gate. Loaded with the full fields (a multisig signer's snap above carries only AuthPubKey).
		if bg := tx.GetSend().GetRecoveryBeneficiary().GetV(); len(bg) == 32 {
			if rdt := tx.GetSend().GetReturnDepositTxid().GetV(); len(rdt) == 32 {
				var dtx [32]byte
				copy(dtx[:], rdt)
				if srec, ok := findStakeRow(snap.FundStakeRows, dtx); ok {
					if rec, ok := getAccountRecord(dbtx, srec.StakerID); ok {
						snap.Accounts[srec.StakerID] = AccountSnap{
							AuthPubKey:       rec.AuthPubKey,
							BreakglassCommit: rec.BreakglassCommit,
							Class:            rec.Class,
						}
					}
				}
			}
		}
		return nil
	})
	if !atPosition {
		return nil // can't confidently judge
	}
	if err := verifyFundSendQuorum(tx, snap); err != nil {
		return err
	}
	return e.bestEffortFundRecoveryReject(tx, snap)
}

// bestEffortFundRecoveryReject rejects a Fund SEND whose P5.4 stake-recovery fields make it
// never-finalizable, so a Guardian-signed-but-invalid variant (e.g. junk in the 4691-byte owner_auth,
// ground to a low txid) cannot occupy the Fund's conflict slot and stall it — the same liveness-DoS
// class bestEffortFundSendCheck closes for the quorum, now with a larger grind surface. It mirrors the
// validate-time recovery-field policy but FAILS OPEN on any lookup miss (stake row absent, owner not
// loaded): it rejects ONLY when it can positively judge the variant unfinalizable. Every field it reads
// is folded into m (Guardian-signed), so a passing quorum means the Guardians signed exactly these
// bytes and the check is deterministic. Called only after verifyFundSendQuorum passed + at-position.
func (e *Engine) bestEffortFundRecoveryReject(tx *pb.Tx, snap *Snapshot) error {
	s := tx.GetSend()
	if s == nil {
		return nil
	}
	var to [32]byte
	copy(to[:], s.GetTo().GetV())
	toFund := snap.FundAccount != ([32]byte{}) && to == snap.FundAccount
	rdt := s.GetReturnDepositTxid().GetV()
	hasBeneficiary := len(s.GetRecoveryBeneficiary().GetV()) > 0
	isReturn := len(rdt) == 32 && !toFund
	isReattribute := len(rdt) == 32 && toFund && hasBeneficiary // C1 (P5.4b)
	if !isReturn && !isReattribute {
		// No other sub-mode admits recovery fields (kick / plain payout carry none). Reject any present.
		if hasStakeRecoveryFields(s) {
			return errors.New("fund send: stake-recovery fields not valid for this send")
		}
		return nil
	}
	var dtx [32]byte
	copy(dtx[:], rdt)
	srec, ok := findStakeRow(snap.FundStakeRows, dtx)
	if !ok {
		return nil // can't judge the stake — defer to epoch-close validate
	}
	if isReattribute {
		// C1 re-attribution: verify the owner_auth (op = re-attribute) so a junk-owner_auth variant
		// can't grind the Fund slot. Fail open if the owner isn't loaded locally.
		bg := s.GetRecoveryBeneficiary().GetV()
		if len(bg) != 32 {
			return errors.New("fund send: recovery_beneficiary must be 32 bytes")
		}
		var b [32]byte
		copy(b[:], bg)
		ownerAS, ok := snap.Accounts[srec.StakerID]
		if !ok {
			return nil // owner not loaded — defer
		}
		return verifyStakeOwnerAuth(s.GetOwnerAuth(), crypto.StakeOwnerAuthOpReattribute, dtx, b, ownerAS)
	}
	keySrc := srec.StakerID
	redirect := false
	if bg := s.GetRecoveryBeneficiary().GetV(); len(bg) > 0 {
		if len(bg) != 32 {
			return errors.New("fund send: recovery_beneficiary must be 32 bytes")
		}
		copy(keySrc[:], bg)
		redirect = keySrc != srec.StakerID
	}
	if !redirect {
		if hasOwnerAuth(s) { // content-based, matching the fold (present-but-empty folds like nil)
			return errors.New("fund send: return to the staker must not carry owner_auth")
		}
		return nil
	}
	ownerAS, ok := snap.Accounts[srec.StakerID]
	if !ok {
		return nil // owner not loaded — defer
	}
	return verifyStakeOwnerAuth(s.GetOwnerAuth(), crypto.StakeOwnerAuthOpReturn, dtx, keySrc, ownerAS)
}

// bestEffortReleaseCheck is the attestor-gated-release (and escrow-outflow) analogue of
// bestEffortFundSendCheck. A SEND carrying a HybridMultiSig is legitimate ONLY as a keyless Fund
// SEND (handled elsewhere), an attestor-gated TRANSFER release-to-dest, or a keyless escrow
// outflow (the 2-of-2 / 1-of-2 trigger); crypto.TxID folds that multisig into the txid, so —
// unlike an ordinary single-sig send whose txid an attacker cannot grind — an attacker can attach
// length-valid junk entries (or extra entries onto a legit Tx.sig-signed release) to grind a lower
// txid that becomes the approved (lowest-txid) conflict candidate, is proposed every epoch, fails
// the epoch-close validate, and stalls that account's chain at that seq (liveness DoS). This
// rejects such a variant at the gate so it never enters the conflict pool.
//
// It is best-effort: the AUTHORITATIVE flat M-of-N attestor quorum runs at epoch close against the
// finalized snapshot and no winner can skip it. It judges ONLY when not resyncing AND the local
// chain head == tx.prev (the node is at the exact position this send extends, so its finalized
// record + class + flag are the right basis); otherwise it defers (returns nil), exactly like the
// Fund-send gate. When it can judge, a multisig is rejected unless the account is an attestor-gated
// release-to-dest, and even then only the N>=1 floor (>=1 verifying attestor signature) is enforced
// — never the full M (which could race attestor staking) — so a legitimately-signed release is
// never rejected here. Returns nil immediately for any SEND that carries no multisig and no sig2.
//
// forquinn item 1 adds sig2 — the path-(a) second user signature — which is txid-folded and
// third-party-attachable exactly like the multisig, so it gets the same gate: legitimate ONLY on
// an attestor-flagged TRANSFER release-to-dest, where the path-(a) shape is judged at-position
// (no multisig, no case fields, chain HAS a U2, Tx.sig verifies under the chain's U1 [D5 fixed
// roles] and sig2 under its U2 — all against the immutable chain record, so a legit path-(a)
// release is never rejected). A sig2 anywhere else can never finalize → rejected statelessly.
func (e *Engine) bestEffortReleaseCheck(tx *pb.Tx) error {
	sig2 := tx.GetSig2().GetV()
	hasSig2 := len(sig2) > 0
	if tx.Type != pb.TxType_TX_TYPE_SEND {
		if hasSig2 {
			// Pure function of the tx bytes: no RECEIVE (or unknown-typed tx) ever carries a
			// sig2 (validate rejects unconditionally), so a sig2-ground variant can never
			// finalize — keep it out of the conflict pool.
			return errors.New("sig2 is only valid on an attestor-flagged transfer release-to-dest")
		}
		return nil
	}
	ms := tx.MultiSig
	hasMS := ms != nil && len(ms.Entries) > 0
	if !hasMS && !hasSig2 {
		return nil // ordinary single-sig send, nothing to judge here
	}
	if e.isFundSendTx(tx) {
		if hasSig2 {
			return errors.New("fund send must not carry a second user signature (sig2)") // stateless (validate mirrors)
		}
		return nil // a Fund SEND's multisig is judged by bestEffortFundSendCheck
	}
	if tx.Account == nil || len(tx.Account.V) != 32 {
		return nil
	}
	e.mu.Lock()
	resyncing := e.resync.IsActive()
	e.mu.Unlock()
	if resyncing {
		return nil // catching up — don't judge
	}
	var acct, prev, to [32]byte
	copy(acct[:], tx.Account.V)
	if tx.Prev != nil && len(tx.Prev.V) == 32 {
		copy(prev[:], tx.Prev.V)
	}
	if sb := tx.GetSend(); sb != nil && sb.To != nil && len(sb.To.V) == 32 {
		copy(to[:], sb.To.V)
	}
	snap := &Snapshot{Accounts: map[[32]byte]AccountSnap{}, Econ: e.cfg.Econ}
	judged := false
	var jerr error
	_ = e.cfg.DB.View(func(dbtx *bbolt.Tx) error {
		rec, ok := getAccountRecord(dbtx, acct)
		if !ok || rec.Head != prev {
			return nil // not at this position — can't confidently judge → defer
		}
		judged = true
		// sig2 is legitimate ONLY on an attestor-flagged TRANSFER release-to-dest (the path-(a)
		// branch below). At the exact position, every other shape carrying one — an escrow
		// outflow, a plain account's send, a cancel, a non-gated release — can never finalize.
		if hasSig2 && (rec.Class != pb.AccountClass_ACCOUNT_CLASS_TRANSFER ||
			to != rec.TransferDest || rec.TransferFlags&transferFlagReleaseRequiresAttestor == 0) {
			jerr = errors.New("sig2 is only valid on an attestor-flagged transfer release-to-dest")
			return nil
		}
		// A keyless escrow outflow also carries a multisig (the 2-of-2 / 1-of-2). crypto.TxID folds
		// it (and any Tx.sig) into the txid, so it is equally txid-grindable — the gate must reject
		// every variant that can NEVER finalize, or a ground-low permanently-invalid variant occupies
		// the conflict slot and stalls the escrow chain (a single party can do this with its own sig).
		if rec.Class == pb.AccountClass_ACCOUNT_CLASS_ESCROW {
			// Keyless: a Tx.sig is never valid on an escrow outflow (validate rejects it, and its
			// single-sig txid would not even bind the multisig). Reject like the Fund-send gate.
			if tx.Sig != nil {
				jerr = errors.New("escrow outflow must be keyless: no Tx.sig (authorized by the party multisig)")
				return nil
			}
			m, _, merr := crypto.MsgHash(tx)
			if merr != nil {
				jerr = merr
				return nil
			}
			lo, hi := escrowSlotsSigned(ms, m, rec.EscrowPartyLoPub, rec.EscrowPartyLoBG, rec.EscrowPartyHiPub, rec.EscrowPartyHiBG)
			switch {
			case lo && hi:
				// 2-of-2 is valid to any destination — defer to the authoritative check.
			case lo != hi:
				// A single party slot is valid ONLY as the attested 1-of-2 -> Fund trigger (whose
				// epoch may advance by epoch close, so don't race it). A plain-escrow single-party
				// outflow, or one to a non-Fund destination, can NEVER finalize — reject it so a
				// grindable permanently-invalid variant cannot stall the conflict slot.
				attested := rec.EscrowFlags&escrowFlagAttested != 0
				toFund := e.cfg.FundAccount != ([32]byte{}) && to == e.cfg.FundAccount
				if !(attested && toFund) {
					jerr = errors.New("escrow 1-of-2 outflow is only valid as an attested 1-of-2 to the Fund")
				}
			default:
				jerr = errors.New("escrow outflow: no valid party signature")
			}
			return nil
		}
		// At the chain's exact position: a multisig is legitimate ONLY on an attestor-gated
		// TRANSFER release-to-dest. Reject it anywhere else. (A sig2 on these shapes was
		// already rejected above.)
		if rec.Class != pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			jerr = errors.New("send must not carry a multisig")
			return nil
		}
		if to != rec.TransferDest {
			jerr = errors.New("transfer return-to-source must not carry a multisig")
			return nil
		}
		if rec.TransferFlags&transferFlagReleaseRequiresAttestor == 0 {
			jerr = errors.New("transfer release is not attestor-gated: must not carry a multisig")
			return nil
		}
		if hasSig2 {
			// ---- path (a) (forquinn item 1): U1 + U2, attestor-free ----
			// Judged fully against the chain's IMMUTABLE record (keys copied at creation), so a
			// legit path-(a) release is never rejected; every reject below is a shape validate
			// will reject identically at epoch close.
			if hasMS {
				jerr = errors.New("path (a) release must not carry a multisig")
				return nil
			}
			if len(tx.GetSend().GetCaseNonce()) > 0 || len(tx.GetSend().GetAttestationHash()) > 0 {
				jerr = errors.New("path (a) release must not carry attestor case fields")
				return nil
			}
			if len(rec.U2PubKey) != crypto.HybridPubKeySize {
				jerr = errors.New("path (a) release: chain has no registered second user key (U2)")
				return nil
			}
			// D5 fixed roles: Tx.sig under the chain's copied U1, sig2 under its copied U2 —
			// both over the same digest m.
			if err := crypto.VerifyTxSignature(tx, rec.AuthPubKey); err != nil {
				jerr = errors.New("path (a) release: Tx.sig must verify under the chain's copied U1 auth key")
				return nil
			}
			m, _, merr := crypto.MsgHash(tx)
			if merr != nil {
				jerr = merr
				return nil
			}
			u2pub, perr := crypto.ParseHybridPubKey(rec.U2PubKey)
			if perr != nil {
				jerr = errors.New("path (a) release: stored U2 pubkey not parseable")
				return nil
			}
			s2, serr := crypto.ParseHybridSig(sig2)
			if serr != nil {
				jerr = errors.New("path (a) release: malformed sig2")
				return nil
			}
			if !crypto.HybridVerify(u2pub, m, s2) {
				jerr = errors.New("path (a) release: sig2 does not verify under the chain's U2")
			}
			return nil
		}
		// ---- path (b): one user sig + the attestor quorum ----
		// Legit attestor-gated release: enforce the N>=1 floor (reqM=1) to reject pure garbage
		// while never racing the authoritative flat M-of-N at epoch close. Resolve the listed
		// signers' cached pubkeys + the finalized stake rows for the verify.
		snap.FundStakeRows = listStakesInTx(dbtx)
		for _, en := range ms.Entries {
			if en == nil || en.SignerId == nil || len(en.SignerId.V) != 32 {
				continue
			}
			var id [32]byte
			copy(id[:], en.SignerId.V)
			if r, ok := getAccountRecord(dbtx, id); ok {
				snap.Accounts[id] = AccountSnap{AuthPubKey: r.AuthPubKey}
			}
		}
		jerr = verifyReleaseAttestorQuorum(tx, snap, 1)
		return nil
	})
	if judged {
		return jerr
	}
	return nil // deferred
}

// bestEffortBreakglassCheck is the single-sig analogue of bestEffortFundSendCheck / bestEffortRelease-
// Check for a BREAKGLASS tx (P5.1) — one carrying revealed_breakglass_pubkey. It closes a liveness
// DoS: resolveAuthPubKeyDB returns the tx's OWN revealed key, so VerifyTxSignature passes for a key the
// ATTACKER controls (no victim key needed). The reveal + Tx.sig are folded into the txid, so an
// attacker grinds an arbitrarily LOW txid onto a victim chain's next conflict slot (account||prev||seq),
// becomes the lowest-txid "approved" candidate proposed every epoch, fails the epoch-close commitment
// check (checkBreakglassReveal), and stalls the victim's chain at that seq. This gate rejects such a
// variant before it enters the pool, exactly like the multisig gates above.
//
// Best-effort: the AUTHORITATIVE commitment + context checks run at epoch close and no winner can skip
// them. It judges ONLY when not resyncing AND the node is at the relevant position (so its finalized
// record/class/commitment are the right basis), and rejects ONLY a variant that can NEVER finalize
// (wrong commitment, reveal on a non-breakglass-capable account/chain, non-breakglass receivable), so a
// legitimate breakglass move is never dropped. Returns nil for a tx with no reveal.
func (e *Engine) bestEffortBreakglassCheck(tx *pb.Tx) error {
	bg := tx.GetRevealedBreakglassPubkey().GetV()
	if len(bg) == 0 {
		return nil // not a breakglass tx
	}
	if len(bg) != crypto.HybridPubKeySize {
		return errors.New("breakglass: revealed pubkey must be 2625 bytes")
	}
	if tx.Account == nil || len(tx.Account.V) != 32 {
		return errors.New("breakglass: bad account")
	}
	e.mu.Lock()
	resyncing := e.resync.IsActive()
	e.mu.Unlock()
	if resyncing {
		return nil
	}
	var acct, prev [32]byte
	copy(acct[:], tx.Account.V)
	if tx.Prev != nil && len(tx.Prev.V) == 32 {
		copy(prev[:], tx.Prev.V)
	}
	var jerr error
	_ = e.cfg.DB.View(func(dbtx *bbolt.Tx) error {
		rec, ok := getAccountRecord(dbtx, acct)
		switch tx.Type {
		case pb.TxType_TX_TYPE_SEND:
			if !ok || rec.Head != prev {
				return nil // not at this position — defer
			}
			switch {
			case isBaseOwnerClass(rec.Class):
				// hop-1 drain: the revealed key must match the account's OWN stored commitment.
				if !crypto.VerifyBreakglassReveal(bg, rec.BreakglassCommit) {
					jerr = errors.New("breakglass drain: revealed key does not match the account commitment")
				}
			case rec.Class == pb.AccountClass_ACCOUNT_CLASS_TRANSFER:
				// hop-2 outbound: bind to the chain's own COPIED commitment (class-independent since P5.2 —
				// no source lookup, which also removes the "source not synced → defer" case). Then mirror
				// the validate policy (P5.3), rejecting ONLY variants that can NEVER finalize so a legit
				// move is never dropped: a revealed key may RETURN-to-source on any ordinary (keyed-source)
				// chain, but RELEASE-to-dest only on a breakglass-origin chain; a return on a Fund-sourced
				// chain (P5.5) or an outbound to neither stored endpoint can never finalize.
				if !crypto.VerifyBreakglassReveal(bg, rec.BreakglassCommit) {
					jerr = errors.New("breakglass transfer outbound: revealed key does not match the chain commitment")
					return nil
				}
				toV := tx.GetSend().GetTo().GetV()
				var to [32]byte
				if len(toV) == 32 {
					copy(to[:], toV)
				}
				switch {
				case to == rec.TransferSource:
					// P5.5: a bg return-to-source is now allowed even to the keyless Fund (a return-stake
					// chain), PROVIDED the chain carries the threaded return-deposit link (ApplyTx uses it to
					// mark the row Reverted). A Fund-sourced chain lacking it can never finalize (validate
					// rejects it), so reject here too; a keyed-source ordinary chain has no such requirement.
					if rec.TransferSource == e.cfg.FundAccount && rec.TransferReturnDepositTxid == ([32]byte{}) {
						jerr = errors.New("breakglass: Fund-sourced return chain missing its return-deposit link")
					}
				case to == rec.TransferDest:
					if rec.TransferFlags&transferFlagBreakglassOrigin == 0 {
						jerr = errors.New("breakglass: a revealed key may release-to-dest only on a breakglass-origin chain")
					}
				default:
					jerr = errors.New("breakglass transfer outbound must go to the stored source or destination")
				}
			default:
				// FUND / ESCROW / UNSPECIFIED: a single-sig reveal is never valid here.
				jerr = errors.New("breakglass: revealed key on a non-breakglass-capable account")
			}
		case pb.TxType_TX_TYPE_RECEIVE:
			if ok {
				// A reveal on a NON-opening RECEIVE is never valid (validate rejects it).
				jerr = errors.New("breakglass: revealed key only allowed on a breakglass TRANSFER-chain opening")
				return nil
			}
			// Opening RECEIVE (account absent): resolve the funding receivable → source → commitment.
			rid := tx.GetReceive().GetReceivableId().GetV()
			if len(rid) != 32 {
				return nil
			}
			var ridArr [32]byte
			copy(ridArr[:], rid)
			rr, rerr := getReceivableRaw(dbtx, ridArr)
			if rerr != nil {
				return nil // receivable not synced → defer
			}
			var rcv pb.Receivable
			if proto.Unmarshal(rr, &rcv) != nil {
				return nil
			}
			// Openable by a reveal iff the receivable is breakglass-flagged (P5.1) OR a return-stake mint
			// (P5.5, KeySourceId set). In both the reveal must match the commitment the chain COPIES — the
			// KEY SOURCE's: the funding source (rcv.From) for a bg mint, or the staker/beneficiary
			// (rcv.KeySourceId) for a return-stake chain (whose rcv.From is the KEYLESS Fund, which has no
			// commitment). Reject a reveal on any other opening (never-finalizable — validate rejects it).
			hasKeySrc := rcv.KeySourceId != nil && len(rcv.KeySourceId.V) == 32
			if !rcv.FromBreakglass && !hasKeySrc {
				jerr = errors.New("breakglass opening: receivable is neither breakglass-flagged nor a return-stake mint")
				return nil
			}
			var keySrc [32]byte
			if hasKeySrc {
				copy(keySrc[:], rcv.KeySourceId.V)
			} else {
				if rcv.From == nil || len(rcv.From.V) != 32 {
					return nil
				}
				copy(keySrc[:], rcv.From.V)
			}
			if srec, sok := getAccountRecord(dbtx, keySrc); sok {
				if !crypto.VerifyBreakglassReveal(bg, srec.BreakglassCommit) {
					jerr = errors.New("breakglass opening: revealed key does not match the key-source commitment")
				}
			} // key source not synced yet → defer
		default:
			// A reveal is valid ONLY on a SEND or an opening RECEIVE. On any other tx type (UNSPECIFIED
			// / a reserved type) it can never finalize (validate returns ErrWrongType), so reject it
			// UNCONDITIONALLY (no position gate) — otherwise an attacker-keyed reveal on an
			// unknown-typed tx (whose conflict key, account‖prev‖seq, ignores tx.Type) would occupy a
			// victim chain's next slot and stall it. resolveAuthPubKeyDB also no longer resolves the
			// reveal for these types, so this is defence-in-depth.
			jerr = errors.New("breakglass: revealed key only valid on a SEND or opening RECEIVE")
		}
		return nil
	})
	return jerr
}

// isZeroOpeningPrev reports whether prev is the canonical opening-slot predecessor: nil, empty, or
// an all-zero 32-byte hash. validate coerces nil/empty prev to zeros (ErrBadPrev otherwise), and an
// opening block carries a 32-zero prev; a non-zero-length-!=32 prev is malformed and never produces
// a conflict key (conflictKeyHash requires 32 bytes), so it is not the opening slot.
func isZeroOpeningPrev(prev *pb.Hash32) bool {
	if prev == nil || len(prev.V) == 0 {
		return true
	}
	if len(prev.V) != 32 {
		return false
	}
	for _, b := range prev.V {
		if b != 0 {
			return false
		}
	}
	return true
}

// judgeAbsentOpening decides whether a tx contesting the opening slot (prev=0, seq=1) of a
// GENUINELY-ABSENT account can never finalize. It is a pure function of the tx bytes (no state), so
// a lagging node and a fully-synced node reach the identical verdict — a reject here can never be a
// false-reject caused by local sync lag. It returns an error ONLY for a provably-never-finalizable
// shape; anything ambiguous (a well-formed opening of the holder's OWN derived id, or a
// TRANSFER/ESCROW opening whose id-derivation needs the unsynced funding receivable + key source)
// returns nil (defer) — the authoritative validate at epoch close makes the final call.
//
// The one legitimate "an account chain begins with a SEND" case is the Fund and the genesis
// distributor, both SEEDED at genesis (always present in the DB, first real block at seq>=2 with a
// non-zero prev), so they never reach this function — the caller's account-present + seq==1 guards
// exclude them twice over. For any genuinely-absent account, no SEND is a valid first block (its
// balance is 0, so the normal-send branch fails ErrInsufficientBal, and no other SEND branch admits
// an absent account), so a SEND — with or without a HybridMultiSig — at the opening slot is junk.
func judgeAbsentOpening(tx *pb.Tx, acct [32]byte) error {
	if tx.Type != pb.TxType_TX_TYPE_RECEIVE {
		// SEND / UNSPECIFIED / reserved type: the only finalizable first block is an opening
		// RECEIVE, so none of these can ever create the account. Reject so a txid-ground variant
		// (a bare junk SEND, or one carrying a junk multisig to grind the txid) cannot occupy the
		// opening conflict slot and stall the real opening.
		return errors.New("opening slot: only an opening RECEIVE can create an account")
	}
	rb := tx.GetReceive()
	class := rb.GetAccountClass()
	// sig2 (forquinn item 1) is a SEND-release-only field: no RECEIVE — an opening included —
	// can ever finalize with one (validate rejects it unconditionally), and it is txid-folded +
	// third-party-attachable, so a stateless reject here keeps a sig2-ground variant out of the
	// opening conflict slot. Pure function of the tx bytes.
	if len(tx.GetSig2().GetV()) > 0 {
		return errors.New("opening RECEIVE: sig2 is never valid on a RECEIVE")
	}
	switch class {
	case pb.AccountClass_ACCOUNT_CLASS_TRANSFER, pb.AccountClass_ACCOUNT_CLASS_ESCROW:
		// A TRANSFER chain gets U2 by DERIVED COPY at apply (forquinn D2) and an escrow is
		// keyless — neither opening may CARRY a U2 registration block, so that shape can never
		// finalize regardless of unsynced state: reject it statelessly.
		if hasU2Registration(rb) {
			return errors.New("opening RECEIVE: a TRANSFER/ESCROW opening never carries a u2 registration")
		}
		// The id derives from the funding receivable (rs.From / rs.FromSeq) and the key source's
		// stored keys, which may not be synced here → defer (ambiguous). This residual (a junk opening
		// relabelled TRANSFER/ESCROW still occupies the conflict slot) is closed downstream by the
		// validity-aware candidate proposal (buildCandidateList proposes the lowest VALID txid per
		// contested slot), NOT at this stateless front-door gate.
		return nil
	case pb.AccountClass_ACCOUNT_CLASS_FUND:
		// FUND is a reserved keyless singleton, seeded at genesis and never opened by a RECEIVE.
		return errors.New("opening RECEIVE: FUND is never opened by a RECEIVE")
	case pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED:
		// validate requires a concrete account_class on an opening.
		return errors.New("opening RECEIVE: account_class is required")
	default:
		// SPENDING/TIMELOCKED/GUARDED/VAULT and ANY unknown enum value (proto3 open enums preserve an
		// undefined number like 99). The authoritative validate derives a non-TRANSFER/non-ESCROW id as
		// BaseAccountID(AccountTypeByteForClass(class), auth_pubkey) — a PURE function of the carried key
		// (AccountTypeByteForClass returns 0 for an unknown class, exactly what validate uses). If the
		// carried key does not derive to acct, no signature/receivable/future state can make this an
		// opening of acct — the core forge (attacker self-signs a RECEIVE with its OWN key over the
		// VICTIM's id), incl. the one-byte-relabel-to-unknown-class variant. A key that DOES derive
		// means the tx opens the holder's own account (SHA-512 preimage resistance rules out hitting a
		// victim's id), so defer.
		ap := rb.GetAuthPubkey().GetV()
		if len(ap) != crypto.HybridPubKeySize {
			return errors.New("opening RECEIVE: auth_pubkey must be 2625 bytes")
		}
		if crypto.BaseAccountID(crypto.AccountTypeByteForClass(class), ap) != acct {
			return errors.New("opening RECEIVE: account-id does not derive from the carried auth_pubkey")
		}
		// U2 registration shape (forquinn item 1) — still a pure function of the tx bytes: a
		// GUARDED/VAULT opening REQUIRES a well-formed, PoP-verifying U2 block (the PoP binds
		// acct + the pubkey, both on the tx, so it is fully checkable statelessly), and every
		// other base/unknown class must not carry one. Either failure can never finalize
		// (validate enforces the identical rule), so rejecting keeps a malformed-U2 variant out
		// of the opening conflict slot.
		if classRequiresU2(class) {
			if _, err := verifyU2Registration(rb, acct, ap); err != nil {
				return err
			}
		} else if hasU2Registration(rb) {
			return errors.New("opening RECEIVE: u2 registration is only valid on a guarded/vault opening")
		}
		return nil
	}
}

// bestEffortOpeningCheck closes the opening-slot DoS (P7.1): a junk SEND/RECEIVE on a not-yet-created
// account grabs that account's opening conflict slot (sha256(account||prev||seq) with prev=0, seq=1)
// so the real opening can never be proposed. Two shapes enter the pool unguarded today: a SEND on a
// locally-absent account (resolveAuthPubKeyDB defers it with NO sig check), and a RECEIVE whose
// carried auth_pubkey the attacker self-signs (verified against the attacker's OWN key). Either can
// be txid-ground to the lowest txid, which alone becomes the approved candidate proposed every epoch;
// it fails the epoch-close validate, so that slot commits nothing while the higher-txid real opening
// is never even proposed = liveness DoS sustained by cheap re-injection each epoch.
//
// It mirrors the established bestEffort* gates: own locking (never called under e.mu), defer while
// resyncing, and reject ONLY a provably-never-finalizable shape at the exact position — everything
// ambiguous is deferred to the authoritative epoch-close validate, which no winner can skip. It fires
// its reject arm ONLY on a GENUINELY-ABSENT account at prev=0/seq=1, so it can never touch the Fund,
// the genesis account (both seeded → always present, first real block seq>=2), or any legit keyless
// / multisig SEND (all seq>=2 on an existing account) — those are excluded by the account-present and
// seq==1 guards before any judgement. ApplyTx is untouched → resync-safe.
func (e *Engine) bestEffortOpeningCheck(tx *pb.Tx) error {
	if tx.Account == nil || len(tx.Account.V) != 32 {
		return nil // no 32-byte account → conflictKeyHash produces no key → no DoS; defer
	}
	if tx.Seq != 1 || !isZeroOpeningPrev(tx.Prev) {
		return nil // only the true opening slot can contest a legitimate opening; anything else defers
	}
	// NOTE: a breakglass reveal is NOT blanket-deferred here. A reveal-carrying SEND at the opening
	// slot is still junk (no SEND is a valid first block) and judgeAbsentOpening must reject it — else
	// attaching a reveal is a one-field bypass of the SEND-reject arm. A legit breakglass/return-stake
	// opening is a TRANSFER-class RECEIVE, which judgeAbsentOpening defers; bestEffortBreakglassCheck
	// (which runs first) still owns the reveal-commitment verdict for those.
	var acct [32]byte
	copy(acct[:], tx.Account.V)
	e.mu.Lock()
	resyncing := e.resync.IsActive()
	e.mu.Unlock()
	if resyncing {
		return nil // catching up — don't judge
	}
	var jerr error
	_ = e.cfg.DB.View(func(dbtx *bbolt.Tx) error {
		if _, ok := getAccountRecord(dbtx, acct); ok {
			// Account already exists locally (this includes the always-seeded Fund + genesis). It is
			// NOT an opening: a seq=1/prev=0 tx here can never finalize (validate: prev!=head,
			// seq!=head+1) and is already sig-checked against the cached key upstream. Defer.
			return nil
		}
		jerr = judgeAbsentOpening(tx, acct)
		return nil
	})
	return jerr
}

// P7.3 mempool admission bounds. These are LOCAL liveness knobs (see EngineConfig.MaxMempoolTxs), NOT
// consensus-critical: a node that rejects a tx here does not fork — the tx is still held/proposed by
// other nodes, and any node that needs it for the epoch union fetches it via the SOLICITED path
// (fetchMissingTxs), which bypasses these bounds. Two caps compose:
//   - global: MaxMempoolTxs total unsolicited txs (a memory bound).
//   - per conflict slot: MaxCandidateScanPerSlot txids, FIFO reject-when-full, so a slot can never hold
//     more candidates than buildCandidateList scans — an already-admitted opening cannot be evicted by
//     later ground-lower junk. This closes the P7.1 ">64-junk buries the real opening" residual.
const defaultMaxMempoolTxs = 200_000

// admissionRejectLocked returns a non-empty reason to reject an UNSOLICITED tx (submit / gossip-push)
// under the mempool bounds, or "" to admit. The caller holds e.mu and has confirmed txid is not
// already pooled. It reads but does not mutate the pool.
func (e *Engine) admissionRejectLocked(tx *pb.Tx, txid [32]byte) string {
	if e.cfg.MaxMempoolTxs > 0 && len(e.txPool) >= e.cfg.MaxMempoolTxs {
		return "global mempool cap"
	}
	if key, ok := conflictKeyHash(tx); ok {
		if uint64(len(e.conflictPool[key])) >= e.cfg.MaxCandidateScanPerSlot {
			return "conflict-slot cap" // slot full; keep incumbents (FIFO) so junk can't evict a real block
		}
	}
	return ""
}

func (e *Engine) SubmitTx(raw []byte) error {
	tx, err := ParseTx(raw)
	if err != nil {
		return err
	}
	if pubs, ok := e.resolveAuthPubKeyDB(tx); ok {
		if err := verifyTxSigAnyKey(tx, pubs); err != nil {
			return err
		}
	} else if e.isFundSendTx(tx) {
		// Keyless Fund SEND: no single sig to verify, but reject obvious garbage at the gate.
		if err := e.bestEffortFundSendCheck(tx); err != nil {
			return err
		}
	} // else: cached pubkey not yet available; authoritative verify runs at epoch close
	// A single-sig BREAKGLASS tx is verified above against its OWN revealed key, so it needs a
	// best-effort commitment gate too (or an attacker-keyed reveal grinds a victim chain's conflict
	// slot). No-op for a non-breakglass tx.
	if err := e.bestEffortBreakglassCheck(tx); err != nil {
		return err
	}
	// A non-Fund SEND carrying a multisig is an attestor-gated release (or junk); judge it at the
	// gate so a txid-ground variant can't occupy the chain's conflict slot. No-op without a multisig.
	if err := e.bestEffortReleaseCheck(tx); err != nil {
		return err
	}
	// A junk SEND/RECEIVE contesting an absent account's opening slot (prev=0, seq=1) is rejected
	// here so it can't grind the opening conflict slot and stall the real opening (P7.1). No-op for
	// any tx that isn't at an opening slot on a locally-absent account.
	if err := e.bestEffortOpeningCheck(tx); err != nil {
		return err
	}
	txid, err := crypto.TxID(tx)
	if err != nil {
		return err
	}

	// If we already have this tx (either still in txPool OR persisted in DB),
	// don't re-enqueue it or re-announce it. This prevents repeated /tx/get cycles.
	if e.HasTx(txid) {
		acct4 := "--------"
		if tx.Account != nil && len(tx.Account.V) >= 4 {
			acct4 = fmt.Sprintf("%x", tx.Account.V[:4])
		}
		log.Printf("[tx] submit dup txid=%x acct=%s seq=%d type=%s", txid[:4], acct4, tx.Seq, tx.Type.String())
		return nil
	}

	seen := e.epochNow()

	dup := false

	e.mu.Lock()
	if e.txPool == nil {
		e.txPool = make(map[[32]byte][]byte)
	}
	if _, ok := e.txPool[txid]; ok {
		dup = true
	} else {
		// Bounded mempool admission (P7.3). A submitted tx is UNSOLICITED, so it is subject to the
		// global + per-conflict-slot caps; reject-when-full rather than evict.
		if reason := e.admissionRejectLocked(tx, txid); reason != "" {
			e.mu.Unlock()
			log.Printf("[tx] submit reject (%s) txid=%x", reason, txid[:4])
			return fmt.Errorf("mempool full: %s", reason)
		}
		e.txPool[txid] = append([]byte(nil), raw...)
	}

	if e.txSeenEpoch == nil {
		e.txSeenEpoch = make(map[[32]byte]uint64)
	}
	if _, exists := e.txSeenEpoch[txid]; !exists {
		e.txSeenEpoch[txid] = seen
	}

	if e.gossipPending == nil {
		e.gossipPending = make(map[[32]byte]struct{})
	}
	e.gossipPending[txid] = struct{}{}

	// temp log
	log.Printf("[tx] submit-pool txid=%x epoch=%d wallMs=%d", txid[:4], seen, time.Now().UnixMilli())

	if e.gossipMask == nil {
		e.gossipMask = make(map[[32]byte]uint64)
	}
	if _, ok := e.gossipMask[txid]; !ok {
		e.gossipMask[txid] = 0
	}

	if e.conflictPool == nil {
		e.conflictPool = make(map[[32]byte][][32]byte)
	}
	if e.approved == nil {
		e.approved = make(map[[32]byte][32]byte)
	}

	if key, ok := conflictKeyHash(tx); ok {
		e.conflictPool[key] = appendUnique32(e.conflictPool[key], txid)

		// Deterministic approval: lowest txid wins for this conflict key.
		if cur, exists := e.approved[key]; !exists {
			e.approved[key] = txid
		} else if bytes.Compare(txid[:], cur[:]) < 0 {
			e.approved[key] = txid
		}
	}
	e.mu.Unlock()

	acct4 := "--------"
	if tx.Account != nil && len(tx.Account.V) >= 4 {
		acct4 = fmt.Sprintf("%x", tx.Account.V[:4])
	}
	status := "ok"
	if dup {
		status = "dup"
	}
	log.Printf("[tx] submit %s txid=%x acct=%s seq=%d type=%s", status, txid[:4], acct4, tx.Seq, tx.Type.String())
	return nil
}

func (e *Engine) AccountState(acct [32]byte) (rec AccountRecord, err error) {
	err = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		rec, _ = getAccountRecord(tx, acct) // zero-value record for a missing account
		return nil
	})
	return
}

func (e *Engine) ListReceivables(toAcct [32]byte) ([]*pb.Receivable, error) {
	var out []*pb.Receivable
	err := e.cfg.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BRecv)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			_ = k
			var r pb.Receivable
			if err := proto.Unmarshal(v, &r); err != nil {
				return nil
			}
			if r.To != nil && r.To.V != nil && bytesEq32(r.To.V, toAcct) {
				out = append(out, &r)
			}
			return nil
		})
	})
	return out, err
}

// ReceiveCandidateList stores a peer candidate list for an epoch after verifying signature and list hash.
// P7.3 epoch-window intake bounds. A live candidate list / finalization for an epoch far from the
// current wall-clock epoch is rejected up front so a member cannot grow peerLists / peerFinals (both
// keyed by epoch and pruned only for the epoch that just closed) or the on-disk finalization store
// without bound. LOCAL liveness consts, not consensus: a message outside the window could never be
// counted for the current epoch anyway, and differing windows across nodes cannot fork (the message
// is simply re-sendable once its epoch is current). Generous vs any real clock skew / processing lag
// — epochNow is wall-clock, so even a GC-stalled node computes the current epoch.
const (
	maxIntakeEpochLag   = 8 // buffer messages up to this many epochs behind wall-clock now
	maxIntakeEpochAhead = 2 // ...and this many ahead (clock-skew tolerance)
)

// epochWithinIntakeWindow reports whether ep is close enough to the current wall-clock epoch to
// buffer a live candidate list / finalization for it (guards against uint underflow).
func (e *Engine) epochWithinIntakeWindow(ep uint64) bool {
	now := e.epochNow()
	return ep+maxIntakeEpochLag >= now && ep <= now+maxIntakeEpochAhead
}

func (e *Engine) ReceiveCandidateList(fromURL string, cl *CandidateList) error {
	_ = fromURL // identity is the pubkey, not URL

	// 0) reject a candidate list for an epoch far from now so a member can't grow peerLists unbounded.
	if !e.epochWithinIntakeWindow(cl.Epoch) {
		return errors.New("reject: epoch outside intake window")
	}

	// 1) membership check against the validator set for THIS epoch (manifest list pre-flip, the
	// Fund-derived set post-flip). The loop re-checks membership against the authoritative cached
	// set when counting, so this receive-time gate only needs to resolve a verifying pubkey.
	pub := e.pubForEpoch(cl.Epoch, cl.ValidatorID)
	if pub == nil {
		return errors.New("unknown validator")
	}

	// 2) canonicalize txids and recompute list hash
	txids := append([][32]byte(nil), cl.TxIDs...)
	sort.Slice(txids, func(i, j int) bool { return bytes.Compare(txids[i][:], txids[j][:]) < 0 })
	recomputed := crypto.CandidatesListHash(txids)
	if recomputed != cl.ListHash {
		return errors.New("reject: list_hash mismatch")
	}

	// 3) verify signature
	digest := crypto.CandidatesDigestP256(cl.Epoch, cl.ValidatorID, cl.ListHash)
	if !crypto.VerifyCandidatesSigP256(pub, digest, cl.SigDER) {
		return errors.New("reject: bad signature")
	}

	// 4) store by (epoch, validator_id)
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.peerLists == nil {
		e.peerLists = make(map[uint64]map[[33]byte]*CandidateList)
	}
	m := e.peerLists[cl.Epoch]
	if m == nil {
		m = make(map[[33]byte]*CandidateList)
		e.peerLists[cl.Epoch] = m
	}

	if prev := m[cl.ValidatorID]; prev != nil {
		// idempotent accept if identical
		if prev.ListHash == cl.ListHash && bytes.Equal(prev.SigDER, cl.SigDER) {
			return nil
		}
		return errors.New("reject: duplicate/conflicting list for validator+epoch")
	}

	m[cl.ValidatorID] = cl
	return nil
}

func (e *Engine) ValidatorPub(id [33]byte) *ecdsa.PublicKey {
	return e.cfg.ValidatorSet[id]
}

// --- P4.3 list→Fund validator-set source switch ---
//
// The validator set for an epoch is the MANIFEST list while flipEpoch==0 or epoch<=flipEpoch, and the
// FUND-DERIVED set (BankerValidatorSet over the finalized end-of-(E−1) Banker state) once epoch>flipEpoch.
// Pre-flip the Fund branch is never taken, so behaviour is byte-identical to the env-list code path; the
// flip only changes anything once the founders have staked their list keys and the predicate latches.

// FlipEpoch returns the latched list→Fund activation epoch (0 == still on the manifest list). Read API.
func (e *Engine) FlipEpoch() uint64 {
	var ep uint64
	_ = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		ep = getFlipEpoch(tx)
		return nil
	})
	return ep
}

// validatorSetForEpoch derives the deterministic validator set for `epoch` from the CURRENT finalized
// DB state — which, while the epoch loop is processing `epoch`, is exactly the end-of-(epoch−1) state
// the working-notes §3.7 determinism rule requires. Returns (set keyed by compressed P-256 key,
// isFund). The epoch loop caches the result per-epoch (setEpochValidatorSet) so later message handlers
// and the quorum read a frozen, consistent set even as the DB advances.
func (e *Engine) validatorSetForEpoch(epoch uint64) (map[[33]byte]*ecdsa.PublicKey, bool) {
	useFund := false
	set := e.cfg.ValidatorSet
	_ = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		flip := getFlipEpoch(tx)
		if flip == 0 || epoch <= flip {
			return nil // manifest list
		}
		descs := e.cfg.Econ.BankerValidatorSet(listStakesInTx(tx), listBankerInfoInTx(tx))
		m := make(map[[33]byte]*ecdsa.PublicKey, len(descs))
		for _, vd := range descs {
			pub, err := crypto.ParseCompressedP256(vd.ConsensusKey)
			if err != nil {
				continue // BankerValidatorSet already filtered invalid keys; belt-and-suspenders
			}
			m[vd.ConsensusKey] = pub
		}
		set = m
		useFund = true
		return nil
	})
	return set, useFund
}

// setEpochValidatorSet caches (and prunes) the validator set the epoch loop derived for `epoch`.
func (e *Engine) setEpochValidatorSet(epoch uint64, set map[[33]byte]*ecdsa.PublicKey) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.epochSets == nil {
		e.epochSets = make(map[uint64]map[[33]byte]*ecdsa.PublicKey)
	}
	e.epochSets[epoch] = set
	// P7.4: mirror the newest set for the flip-aware gossip-gate fallback (PeerMemberForEpoch).
	// The loop is the ONLY writer here — intake paths never populate epochSets/latestEpochSet, so
	// the quorum's frozen per-epoch set can never be seeded by a mid-epoch racy derivation.
	if epoch >= e.latestEpochCached {
		e.latestEpochCached = epoch
		e.latestEpochSet = set
	}
	// Prune epochs well behind the one just cached (keep a generous window for late messages).
	const keepWindow = 128
	if epoch > keepWindow {
		for ep := range e.epochSets {
			if ep+keepWindow < epoch {
				delete(e.epochSets, ep)
			}
		}
	}
}

// pubForEpoch resolves a signer's verifying pubkey for `epoch`: the cached per-epoch set first, then the
// manifest list as a fallback so a pre-flip / manifest validator is always verifiable even before the
// loop caches the epoch. The loop's quorum re-checks membership against the authoritative cached set, so
// this lenient receive-time resolution can never inflate a quorum (a non-member is dropped there).
func (e *Engine) pubForEpoch(epoch uint64, id [33]byte) *ecdsa.PublicKey {
	e.mu.Lock()
	set := e.epochSets[epoch]
	e.mu.Unlock()
	if set != nil {
		if pub := set[id]; pub != nil {
			return pub
		}
	}
	return e.cfg.ValidatorSet[id]
}

// maybeLatchFlip is called after an epoch commits. If the flip is not yet latched and the Fund-derived
// Banker set now EXACTLY matches the manifest list (FundSetMatchesManifest, the deterministic §3.9
// predicate over the just-finalized end-of-`epoch` state), it latches flipEpoch=`epoch` one-way. Pure
// over finalized state + the static manifest, so every node latches at the same epoch.
func (e *Engine) maybeLatchFlip(epoch uint64) {
	err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		return e.maybeLatchFlipInTx(tx, epoch)
	})
	if err != nil {
		e.elog(epoch, "maybeLatchFlip error: %v", err)
		return
	}
}

// maybeLatchFlipInTx is the transaction-scoped body of maybeLatchFlip, so the epoch commit can
// run it inside the SAME atomic bbolt Update as the winner apply + frontier snapshot (P7.6
// commitEpoch) — it sees the just-applied (uncommitted) state exactly as the post-commit variant
// saw the committed state.
func (e *Engine) maybeLatchFlipInTx(tx *bbolt.Tx, epoch uint64) error {
	if len(e.manifestKeys) == 0 {
		return nil // never latch to an empty set (would zero the quorum denominator); unreachable — the
		// manifest is guarded non-empty in NewEngine / ParseValidatorSetCSV — but fail safe.
	}
	if getFlipEpoch(tx) != 0 {
		return nil
	}
	descs := e.cfg.Econ.BankerValidatorSet(listStakesInTx(tx), listBankerInfoInTx(tx))
	if !FundSetMatchesManifest(descs, e.manifestKeys) {
		return nil
	}
	return setFlipEpoch(tx, epoch)
}

func (e *Engine) HasTx(txid [32]byte) bool {
	e.mu.Lock()
	_, ok := e.txPool[txid]
	e.mu.Unlock()
	if ok {
		return true
	}
	found := false
	_ = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		if tx.Bucket(BTxs) == nil {
			return nil
		}
		found = hasTx(tx, txid)
		return nil
	})
	return found
}

func (e *Engine) GetTxBytes(txid [32]byte) []byte {
	e.mu.Lock()
	if raw, ok := e.txPool[txid]; ok && len(raw) > 0 {
		out := append([]byte(nil), raw...)
		e.mu.Unlock()
		return out
	}
	e.mu.Unlock()

	var out []byte
	_ = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		raw, err := getTxRaw(tx, txid)
		if err != nil {
			return nil
		}
		out = raw
		return nil
	})
	return out
}

// LatestFinalizedEpoch returns the latest COMMITTED epoch — the max epoch present in BEpochFrontiers,
// which is written ONLY after an epoch's winners are applied (SaveEpochFrontiers on commit, both
// commit paths). It deliberately does NOT read BFinalizations: a node stores its OWN finalization for
// an epoch when it broadcasts it (ReceiveFinalization), BEFORE the quorum check, and even for epochs
// that never reach quorum / never commit — so the max BFinalizations epoch can run AHEAD of the last
// committed epoch (e.g. while the node lacks a finalization quorum). This feeds /sync/latest, which the
// P4.3b verifying resync uses to pick a target: the target MUST be a committed epoch (one with saved
// frontiers AND a stored quorum of finalizations), or the resync would fetch empty frontiers and fail.
func (e *Engine) LatestFinalizedEpoch() uint64 {
	var latest uint64
	_ = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BEpochFrontiers)
		if b == nil {
			return nil
		}
		// Keys are epochFrontierKey = epoch(8 BE) || account(32), so the LAST key carries the max epoch.
		if k, _ := b.Cursor().Last(); len(k) >= 8 {
			latest = binary.BigEndian.Uint64(k[:8])
		}
		return nil
	})
	return latest
}

// ReceiveGossipedTx admits an UNSOLICITED gossiped tx (the /peer/tx/push path): it is subject to the
// bounded-mempool admission caps (P7.3). Solicited consensus fetches use receiveGossipedTx(raw, true).
func (e *Engine) ReceiveGossipedTx(raw []byte) error { return e.receiveGossipedTx(raw, false) }

// receiveGossipedTx is the shared gossip-intake path. solicited=true (fetchMissingTxs pulling txs the
// epoch union NEEDS) BYPASSES the mempool admission caps so finalization can always complete; the caps
// gate only unsolicited push/submit intake, so a full pool can never starve a node of a tx it must
// validate — it fetches that tx on demand regardless.
func (e *Engine) receiveGossipedTx(raw []byte, solicited bool) error {
	tx, err := ParseTx(raw)
	if err != nil {
		return err
	}
	// Best-effort signature check now; the authoritative hybrid verify runs at epoch
	// close against the snapshot. We can verify immediately when the auth pubkey is
	// resolvable (opening RECEIVE carries it; existing accounts cache it); otherwise
	// we accept and defer (see resolveAuthPubKeyDB).
	if pubs, ok := e.resolveAuthPubKeyDB(tx); ok {
		if err := verifyTxSigAnyKey(tx, pubs); err != nil {
			return err
		}
	} else if e.isFundSendTx(tx) {
		// Keyless Fund SEND: reject obvious garbage at the gate (see bestEffortFundSendCheck).
		if err := e.bestEffortFundSendCheck(tx); err != nil {
			return err
		}
	}
	// Single-sig breakglass: best-effort commitment gate (see bestEffortBreakglassCheck). No-op for a
	// non-breakglass tx. Closes the same conflict-slot DoS on the gossip path as on submit.
	if err := e.bestEffortBreakglassCheck(tx); err != nil {
		return err
	}
	// Attestor-gated release (or a junk-multisig variant): judge at the gate (no-op without a multisig).
	if err := e.bestEffortReleaseCheck(tx); err != nil {
		return err
	}
	// Opening-slot DoS gate (P7.1): reject a junk SEND/RECEIVE grinding an absent account's opening
	// conflict slot on the gossip path too (junk propagates via /peer/tx/push + the inv/get fetch).
	if err := e.bestEffortOpeningCheck(tx); err != nil {
		return err
	}
	txid, err := crypto.TxID(tx)
	if err != nil {
		return err
	}

	// If we already have this tx persisted (likely already applied), ignore it.
	// This prevents re-adding completed txs to txPool/approved and triggering fetch loops.
	if e.HasTx(txid) {
		acct4 := "--------"
		if tx.Account != nil && len(tx.Account.V) >= 4 {
			acct4 = fmt.Sprintf("%x", tx.Account.V[:4])
		}
		log.Printf("[tx] gossip dup txid=%x acct=%s seq=%d type=%s", txid[:4], acct4, tx.Seq, tx.Type.String())
		return nil
	}

	seen := e.epochNow()

	e.mu.Lock()
	if e.txPool == nil {
		e.txPool = make(map[[32]byte][]byte)
	}
	_, gdup := e.txPool[txid]
	if !gdup && !solicited {
		// Bounded mempool admission (P7.3): unsolicited gossip is subject to the caps. Reject BEFORE
		// stamping txSeenEpoch so a rejected tx leaves no bookkeeping behind.
		if reason := e.admissionRejectLocked(tx, txid); reason != "" {
			e.mu.Unlock()
			log.Printf("[tx] gossip reject (%s) txid=%x", reason, txid[:4])
			return fmt.Errorf("mempool full: %s", reason)
		}
	}
	if e.txSeenEpoch == nil {
		e.txSeenEpoch = make(map[[32]byte]uint64)
	}
	if _, exists := e.txSeenEpoch[txid]; !exists {
		e.txSeenEpoch[txid] = seen
	}
	if !gdup {
		e.txPool[txid] = append([]byte(nil), raw...)
	}
	if e.gossipPending == nil {
		e.gossipPending = make(map[[32]byte]struct{})
	}
	e.gossipPending[txid] = struct{}{}
	if e.gossipMask == nil {
		e.gossipMask = make(map[[32]byte]uint64)
	}
	if _, ok := e.gossipMask[txid]; !ok {
		e.gossipMask[txid] = 0
	}
	if e.conflictPool == nil {
		e.conflictPool = make(map[[32]byte][][32]byte)
	}
	if e.approved == nil {
		e.approved = make(map[[32]byte][32]byte)
	}
	if key, ok := conflictKeyHash(tx); ok {
		e.conflictPool[key] = appendUnique32(e.conflictPool[key], txid)

		// Deterministic approval: lowest txid wins for this conflict key.
		if cur, exists := e.approved[key]; !exists {
			e.approved[key] = txid
		} else if bytes.Compare(txid[:], cur[:]) < 0 {
			e.approved[key] = txid
		}
	}
	e.mu.Unlock()

	acct4 := "--------"
	if tx.Account != nil && len(tx.Account.V) >= 4 {
		acct4 = fmt.Sprintf("%x", tx.Account.V[:4])
	}
	status := "ok"
	if gdup {
		status = "dup"
	}
	log.Printf("[tx] gossip %s txid=%x acct=%s seq=%d type=%s", status, txid[:4], acct4, tx.Seq, tx.Type.String())

	return nil
}

// ReceiveFinalization ingests a finalization received from a PEER (the /peer/finalization handler): it
// is subject to the epoch-intake window. The epoch loop stores its OWN finalization via
// storeSelfFinalization, which bypasses the window (self-produced authoritative data — the node's own
// quorum vote must never be dropped just because a slow loop iteration drifted past the window).
func (e *Engine) ReceiveFinalization(fin *pb.EpochFinalization) error {
	return e.receiveFinalization(fin, false)
}

// storeSelfFinalization records THIS node's own finalization (loop path), bypassing the intake window.
func (e *Engine) storeSelfFinalization(fin *pb.EpochFinalization) error {
	return e.receiveFinalization(fin, true)
}

func (e *Engine) receiveFinalization(fin *pb.EpochFinalization, selfStore bool) error {
	if fin == nil {
		return errors.New("nil finalization")
	}
	if fin.Signer == nil || len(fin.Signer.V) != 33 {
		return errors.New("bad signer")
	}
	if fin.AcceptedTxidsHash == nil || len(fin.AcceptedTxidsHash.V) != 32 {
		return errors.New("bad accepted_txids_hash")
	}
	if fin.FrontiersRoot == nil || len(fin.FrontiersRoot.V) != 32 {
		return errors.New("bad frontiers_root")
	}
	if fin.Sig == nil || len(fin.Sig.V) < 64 || len(fin.Sig.V) > 80 {
		return errors.New("bad sig")
	}

	// Reject a PEER finalization for an epoch far from now so a member can't grow peerFinals / the
	// on-disk finalization store unbounded (P7.3). The node's OWN finalization (selfStore) bypasses this
	// — finalizationQuorum counts votes only from peerFinals[epoch] with no separate self-count, so
	// dropping the self-store would silently discard the node's own vote. Resync persists past-epoch
	// finalizations via a different path (the walk's finPersistBatch), so this live-intake bound never
	// impedes catch-up.
	if !selfStore && !e.epochWithinIntakeWindow(fin.Epoch) {
		return errors.New("epoch outside intake window")
	}

	var signerID [33]byte
	copy(signerID[:], fin.Signer.V)

	// Resolve the verifying pubkey from the per-epoch set (manifest list pre-flip, Fund-derived
	// post-flip); the loop's finalizationQuorum re-checks membership + sig against the authoritative
	// cached set, so a lenient resolve here cannot inflate the quorum.
	pub := e.pubForEpoch(fin.Epoch, signerID)
	if pub == nil {
		return errors.New("unknown validator")
	}

	var accepted [32]byte
	copy(accepted[:], fin.AcceptedTxidsHash.V)
	var root [32]byte
	copy(root[:], fin.FrontiersRoot.V)

	digest := crypto.FinalizationDigestP256(fin.Epoch, accepted, root)
	if !crypto.VerifyFinalizationSigP256(pub, digest, fin.Sig.V) {
		return errors.New("bad signature")
	}

	// store raw proto in DB
	raw, err := proto.Marshal(fin)
	if err != nil {
		return err
	}
	if err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		return PutFinalization(tx, fin.Epoch, signerID, raw)
	}); err != nil {
		return err
	}

	// store in memory for quick quorum checks
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.peerFinals == nil {
		e.peerFinals = make(map[uint64]map[[33]byte]*pb.EpochFinalization)
	}
	m := e.peerFinals[fin.Epoch]
	if m == nil {
		m = make(map[[33]byte]*pb.EpochFinalization)
		e.peerFinals[fin.Epoch] = m
	}
	// idempotent accept if identical
	if prev := m[signerID]; prev != nil {
		// if same hashes and sig, ignore
		if bytes.Equal(prev.AcceptedTxidsHash.V, fin.AcceptedTxidsHash.V) &&
			bytes.Equal(prev.FrontiersRoot.V, fin.FrontiersRoot.V) &&
			bytes.Equal(prev.Sig.V, fin.Sig.V) {
			return nil
		}
		// conflicting finalization from same signer for same epoch is a protocol violation
		return errors.New("conflicting finalization for signer+epoch")
	}

	m[signerID] = fin
	return nil
}

// SyncChain returns raw tx bytes walking backwards from targetHead (inclusive).
// Stops if it reaches `have` (if non-zero) or hits max blocks or missing tx bytes.
// Returns (txsHeadBackwards, reachedHave).
//
// maxBytes > 0 additionally byte-budgets the PAGE (P7.4): the walk stops early (reachedHave=false)
// once the accumulated raw bytes reach it, always after at least one tx. The serving handler was
// otherwise building a whole-chain response in memory, and the resync CLIENT could not read a
// response past protodelim's 4 MiB cap anyway — the P7.4 paging client continues from the returned
// tail's prev, so an early stop is a page boundary, never data loss.
//
// accountID is used only for diagnostics / special synthetic-anchor handling;
// tx bytes themselves are always read from BTxs.
func (e *Engine) SyncChain(accountID [32]byte, targetHead [32]byte, have [32]byte, max int, maxBytes int) ([][]byte, bool) {
	if max <= 0 {
		max = 2000
	}

	var out [][]byte
	reachedHave := false
	totalBytes := 0

	if err := e.cfg.DB.View(func(tx *bbolt.Tx) error {
		if tx.Bucket(BTxs) == nil {
			return nil
		}

		cur := targetHead
		for i := 0; i < max; i++ {
			if have != ([32]byte{}) && cur == have {
				reachedHave = true
				break
			}

			raw, err := getTxRaw(tx, cur)
			if err != nil {
				// Missing current head bytes is only acceptable if this exact hash is the requested boundary.
				if have != ([32]byte{}) && cur == have {
					reachedHave = true
				}
				break
			}

			out = append(out, raw)
			totalBytes += len(raw)

			ptx, err := ParseTx(raw)
			if err != nil {
				log.Printf("SYNCCHAIN parse error acct=%x cur=%x: %v", accountID[:4], cur[:4], err)
				break
			}

			if ptx.Prev == nil || len(ptx.Prev.V) != 32 {
				log.Printf("SYNCCHAIN missing prev acct=%x cur=%x", accountID[:4], cur[:4])
				break
			}

			var prev [32]byte
			copy(prev[:], ptx.Prev.V)

			if have != ([32]byte{}) && prev == have {
				reachedHave = true
				break
			}

			if prev == ([32]byte{}) {
				if have == ([32]byte{}) {
					reachedHave = true
				}
				break
			}

			if have == ([32]byte{}) {
				// Normal account-chain heuristic: missing prev means synthetic base.
				if _, err := getTxRaw(tx, prev); err != nil {
					reachedHave = true
					break
				}
			}

			// P7.4 page budget — checked LAST so a boundary/base verdict above is never lost, and
			// only after ≥1 appended tx so a page always advances the client.
			if maxBytes > 0 && totalBytes >= maxBytes {
				break
			}

			cur = prev
		}
		return nil
	}); err != nil {
		log.Printf("SYNCCHAIN DB.View error: %v", err)
	}

	return out, reachedHave
}

// behindProbeEverySkips paces the P7.4 behind-probe: every Nth consecutive presence-skip the loop
// polls the roster peers' tips (see probeBehind). LOCAL liveness knob.
const behindProbeEverySkips = 8

// loop runs epochs. Each iteration executes under guardIteration (P7.6): a panic anywhere in an
// iteration — a poison pool tx crossing ParseTx/Validate/Apply, a fault inside the synchronous
// runResync/probeBehind calls, an invariant break — is logged loudly (with stack) and the loop
// CONTINUES instead of the goroutine dying while /health kept answering 200 (a silent finalization
// stop).
//
// A recovered panic before the epoch's commit means we may have SKIPPED an epoch that peers
// finalized, leaving our committed tip behind. Simply continuing would then build epoch N+1 on
// stale base and — via the MISMATCH-apply path — commit a frontier root no finalization describes
// (silent divergence). So a recovered loop panic TRIGGERS A RESYNC: the next iteration short-
// circuits into the verifying walk, which rebuilds canonical state from the manifest anchor and
// clears every volatile pool (incl. the poison mempool tx). This makes recover-and-continue behave
// exactly like the pre-P7.6 crash+restart+resync — minus the process death. The epoch commit is
// also one atomic bbolt Update (commitEpoch), so a mid-commit panic rolls the whole epoch back and
// never leaves applied-but-unsnapshotted state for the resync to trip over.
func (e *Engine) loop(ctx context.Context) {
	epochMs := e.cfg.EpochDuration.Milliseconds()
	if epochMs <= 0 {
		epochMs = 5000
	}

	genesisMs := e.cfg.GenesisUnixMs

	for {
		stop, panicked := e.guardIteration(func() bool { return e.loopOnce(ctx, epochMs, genesisMs) })
		if stop {
			return
		}
		if panicked {
			// Resync away any skipped-commit divergence (idempotent; a no-op if a resync is already
			// pending/active). Zero want-hashes: the verifying walk re-derives the target from peers.
			e.triggerResync(e.epochNow(), [32]byte{}, [32]byte{})
			// Pace the retry: a panic before the iteration's first sleep point would otherwise spin
			// the loop hot. One second keeps the node responsive without burning a core.
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

// guardIteration runs one loop iteration under the P7.6 recover guard. Extracted (rather than a
// defer inside loopOnce) so the exact production guard is directly unit-testable with a panicking
// fn. On a panic the iteration reports stop=false — the loop keeps going.
func (e *Engine) guardIteration(fn func() (stop bool)) (stop, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			stop, panicked = false, true
			e.noteLoopPanic(r)
		}
	}()
	return fn(), false
}

// loopOnce is ONE iteration of the epoch loop (the body of the pre-P7.6 for-loop, verbatim except
// `return` → `return true` and top-level `continue` → `return false`). Returns stop=true only on
// context cancellation.
func (e *Engine) loopOnce(ctx context.Context, epochMs, genesisMs int64) (stop bool) {
	{
		// If we're in resync mode, short-circuit normal epoch processing.
		// This prevents continuing to apply epochs while we know we're divergent.
		if e.resync.IsActive() {
			// Backoff gate: don't hammer resync in a tight loop on repeated failure.
			e.mu.Lock()
			next := e.resyncNextAttempt
			active := e.resync.IsActive()
			e.mu.Unlock()

			if active && !next.IsZero() && time.Now().Before(next) {
				// Sleep until next attempt (or context cancel).
				d := time.Until(next)
				if d > 250*time.Millisecond {
					d = 250 * time.Millisecond
				}
				select {
				case <-ctx.Done():
					return true
				case <-time.After(d):
				}
				return false
			}

			_ = e.runResync(ctx)

			// After resync attempt (success or failure), restart loop to re-evaluate wall-clock epoch.
			select {
			case <-ctx.Done():
				return true
			default:
			}
			return false
		}

		// If genesis is in the future, wait until it begins.
		nowMs := time.Now().UnixMilli()
		if nowMs < genesisMs {
			wait := time.Duration(genesisMs-nowMs) * time.Millisecond
			select {
			case <-ctx.Done():
				return true
			case <-time.After(wait):
			}
			return false
		}

		// Determine the current wall-clock epoch window.
		epoch := uint64((nowMs-genesisMs)/epochMs) + 1
		epochEndMs := genesisMs + int64(epoch)*epochMs
		log.Printf("[epoch=%d] phase:epoch-calc wallMs=%d epochEndMs=%d gapMs=%d", epoch, nowMs, epochEndMs, epochEndMs-nowMs)

		start := time.Now()
		e.elog(epoch, " ----- Starting New Epoch ----- ")

		// Snapshot at the *start* of the epoch window (best-effort).
		epochSnap, _ := e.buildSnapshot(epoch)

		// P4.3: derive + cache the deterministic validator set for this epoch off the finalized
		// end-of-(epoch−1) state (manifest list pre-flip, Fund-derived post-flip). Frozen here so
		// the message handlers + quorum below read one consistent set even as the DB advances.
		epochSet, epochSetIsFund := e.validatorSetForEpoch(epoch)
		e.setEpochValidatorSet(epoch, epochSet)
		if epochSetIsFund {
			log.Printf("[epoch=%d] phase:validator-set source=fund size=%d", epoch, len(epochSet))
		}
		// P7.3/P7.4: refresh BOTH connectivity views from the finalized Fund banker endpoints —
		// the inbound /peer/* source-IP allowlist AND the outbound dial list — so connectivity
		// (gating + dialing) follows the Fund post-flip (roster stays a permanent union member /
		// fallback). Once per epoch; liveness-only (never a fork).
		e.refreshPeerViews(epoch)

		// Sleep until the epoch boundary (end of this epoch).
		sleepMs := epochEndMs - nowMs
		if sleepMs > 0 {
			select {
			case <-ctx.Done():
				return true
			case <-time.After(time.Duration(sleepMs) * time.Millisecond):
			}
		} else {
			// We're already past the boundary (GC pause / scheduling / etc). Continue immediately.
			select {
			case <-ctx.Done():
				return true
			default:
			}
		}

		// Close: build our candidate list from txs received during this epoch window.
		log.Printf("[epoch=%d] phase:candidates-start wallMs=%d poolSize=%d approvedSize=%d", epoch, time.Now().UnixMilli(), len(e.txPool), len(e.approved))
		selfList, _ := e.buildCandidateList(epoch, epochSnap)
		log.Printf("[epoch=%d] phase:candidates-built txids=%d wallMs=%d", epoch, len(selfList.TxIDs), time.Now().UnixMilli())

		// Broadcast once at epoch close
		e.broadcastCandidates(epoch, selfList)
		log.Printf("[epoch=%d] phase:candidates-broadcast-done wallMs=%d", epoch, time.Now().UnixMilli())

		// Wait a small skew for peers to arrive
		select {
		case <-ctx.Done():
			return true
		case <-time.After(e.cfg.CandidatesSkew):
		}

		log.Printf("[epoch=%d] phase:skew-done wallMs=%d", epoch, time.Now().UnixMilli())
		peerLists := e.getPeerLists(epoch)
		// P4.3 determinism: only count candidate lists from members of THIS epoch's set. The
		// receive-time gate is lenient (manifest-list fallback), so post-flip a kicked validator's
		// list could still be stored; drop it here so conflict-resolution voting is over exactly the
		// epoch's authoritative validators. Pre-flip epochSet == the env list → nothing is dropped.
		for vid := range peerLists {
			if _, ok := epochSet[vid]; !ok {
				delete(peerLists, vid)
			}
		}
		for vid, cl := range peerLists {
			log.Printf("[epoch=%d] phase:peer-list-received from=%x txids=%d", epoch, vid[:4], len(cl.TxIDs))
		}
		if len(peerLists) == 0 {
			log.Printf("[epoch=%d] phase:peer-list-received NONE", epoch)
		}

		// --- Presence quorum gate (liveness) ---
		// P7.4: the denominator is THIS epoch's validator set — the manifest list pre-flip (where
		// it equals self + cfg.Peers, so the arithmetic is byte-identical to the old static form)
		// and the Fund-derived set post-flip (where the static form ignored joiners/kicks). A
		// non-member (a pre-join follower node) counts only the member lists it received; its own
		// presence doesn't count and its participation is observation. Purely a liveness heuristic
		// — the finalization quorum below is the authoritative gate either way.
		selfID := e.cfg.Signer.PublicKeyCompressed()
		_, selfIsMember := epochSet[selfID]
		expected := len(epochSet)
		present := len(peerLists) // member lists received (filtered above)
		if selfIsMember {
			present++
		}
		required := (expected*60 + 99) / 100 // ceil(expected * 0.60)
		if required < 1 {
			required = 1
		}

		if present < required {
			log.Printf("epoch %d skipped: presence %d/%d (<60%%); will retry next epoch", epoch, present, expected)

			// P7.4 behind-probe: a node NOBODY dials (a non-roster pre-join follower, booted fresh)
			// receives no lists and no finalizations, so it would presence-skip forever at genesis
			// state and never notice the chain is far ahead. While skipping, periodically ask the
			// ROSTER peers for their committed tip; if one is beyond our intake window, resync.
			// Members never linger here in steady state (peers dial them → presence passes), and a
			// genesis cold start is safe (everyone reports tip 0 → never triggers).
			e.presenceSkips++
			if e.presenceSkips%behindProbeEverySkips == 0 {
				e.probeBehind(ctx, epoch)
			}
			return false
		}
		e.presenceSkips = 0
		// --- end presence quorum gate ---

		// Model B: Merge union of all valid txs; vote only within conflicts.
		totalValidators := len(epochSet)                              // P4.3: this epoch's set (manifest list pre-flip, Fund-derived post-flip)
		threshold := (totalValidators*e.cfg.QuorumPercent + 99) / 100 // ceil
		if threshold < 1 {
			threshold = 1
		}

		// Union: txid support count (how many lists contained it)
		support := make(map[[32]byte]int)

		// Collect union txids (unique)
		unionSet := make(map[[32]byte]struct{})

		// self votes
		for _, id := range selfList.TxIDs {
			support[id]++
			unionSet[id] = struct{}{}
		}

		// peers votes
		for _, cl := range peerLists {
			for _, id := range cl.TxIDs {
				support[id]++
				unionSet[id] = struct{}{}
			}
		}

		// Resolve unionSet -> slice
		unionIDs := make([][32]byte, 0, len(unionSet))
		for id := range unionSet {
			unionIDs = append(unionIDs, id)
		}

		// Fill txBytesByID from local pool/DB; fetch missing from peers if needed
		txBytesByID := make(map[[32]byte][]byte, len(unionIDs))

		missing := make([][32]byte, 0)
		for _, id := range unionIDs {
			raw := e.GetTxBytes(id) // <- must check txPool then DB
			if len(raw) == 0 {
				missing = append(missing, id)
				continue
			}
			txBytesByID[id] = raw
		}

		log.Printf("[epoch=%d] phase:union-built unionSize=%d localHave=%d missing=%d", epoch, len(unionIDs), len(txBytesByID), len(missing))

		// If missing, fetch from peers via /peer/tx/get and try again
		if len(missing) > 0 {
			e.fetchMissingTxs(epoch, missing)
			for _, id := range missing {
				if _, ok := txBytesByID[id]; ok {
					continue
				}
				raw := e.GetTxBytes(id)
				if len(raw) > 0 {
					txBytesByID[id] = raw
				}
			}
		}

		// Validate all txs against snapshot (objective validity)
		validIDs := make([][32]byte, 0, len(txBytesByID))
		validParsed := make(map[[32]byte]*pb.Tx, len(txBytesByID))
		for id, raw := range txBytesByID {
			tx, err := ParseTx(raw)
			if err != nil {
				continue
			}
			// validate returns computed txid; require it matches map key
			cid, err := ValidateTxAgainstSnapshot(tx, epochSnap)
			if err != nil || cid != id {
				continue
			}
			validIDs = append(validIDs, id)
			validParsed[id] = tx
		}

		// Group by conflict key: (account, prev, seq). With snapshot rules, prev/seq are same per account.
		type ckey struct {
			acct [32]byte
			prev [32]byte
			seq  uint64
		}
		conf := make(map[ckey][][32]byte)
		for _, id := range validIDs {
			tx := validParsed[id]
			var acct [32]byte
			copy(acct[:], tx.Account.V)
			var prev [32]byte
			if tx.Prev != nil && len(tx.Prev.V) == 32 {
				copy(prev[:], tx.Prev.V)
			}
			k := ckey{acct: acct, prev: prev, seq: tx.Seq}
			conf[k] = append(conf[k], id)
		}

		// Decide winners
		winners := make(map[[32]byte][32]byte) // acct -> txid
		for k, ids := range conf {
			if len(ids) == 1 {
				winners[k.acct] = ids[0]
				continue
			}
			// conflict: vote only within this group
			// collect candidates reaching threshold
			type cand struct {
				id      [32]byte
				support int
			}
			cands := make([]cand, 0, len(ids))
			for _, id := range ids {
				cands = append(cands, cand{id: id, support: support[id]})
			}
			// Filter by threshold
			eligible := make([]cand, 0, len(cands))
			for _, c := range cands {
				if c.support >= threshold {
					eligible = append(eligible, c)
				}
			}
			if len(eligible) == 0 {
				// safety-first: accept none
				continue
			}
			// pick highest support, tie-break lowest txid
			sort.Slice(eligible, func(i, j int) bool {
				if eligible[i].support != eligible[j].support {
					return eligible[i].support > eligible[j].support
				}
				return bytes.Compare(eligible[i].id[:], eligible[j].id[:]) < 0
			})
			winners[k.acct] = eligible[0].id
		}

		// --- DRY-RUN: compute hashes WITHOUT writing to DB ---
		// Instead of applying winners immediately, we compute what the acceptedHash
		// and frontiersRoot would be, then broadcast finalization and wait for quorum
		// agreement before committing anything. This prevents the need for resync
		// when validators disagree.
		acceptedIDs := make([][32]byte, 0, len(winners))
		for _, txid := range winners {
			acceptedIDs = append(acceptedIDs, txid)
		}
		sort.Slice(acceptedIDs, func(i, j int) bool { return bytes.Compare(acceptedIDs[i][:], acceptedIDs[j][:]) < 0 })

		acceptedHash := crypto.CandidatesListHash(acceptedIDs)

		// Compute what the frontiers root would look like after applying winners,
		// without actually writing to DB.
		dryRunRoot, err := ComputeDryRunFrontiersRoot(e.cfg.DB, winners)
		if err != nil {
			e.elog(epoch, "dry-run frontiers root error: %v — retrying", err)
			return false
		}

		log.Printf("[epoch=%d] phase:dry-run-done winners=%d acceptedHash=%x frontiersRoot=%x wallMs=%d",
			epoch, len(winners), acceptedHash[:4], dryRunRoot[:4], time.Now().UnixMilli())

		// --- Finalization (checkpoint anchor) ---
		// Sign and broadcast our proposed finalization, including the full list of
		// accepted txids so that mismatched validators can apply the quorum's set
		// without needing a full resync.
		signerID := e.cfg.Signer.PublicKeyCompressed()
		digest := crypto.FinalizationDigestP256(epoch, acceptedHash, dryRunRoot)
		sigDER, sigErr := e.cfg.Signer.SignDigest(digest)
		if sigErr != nil {
			e.elog(epoch, "finalization: sign error: %v — retrying", sigErr)
			return false
		}

		// Build accepted txid bytes for the proto field
		acceptedTxidBytes := make([][]byte, len(acceptedIDs))
		for i, id := range acceptedIDs {
			cp := make([]byte, 32)
			copy(cp, id[:])
			acceptedTxidBytes[i] = cp
		}

		fin := &pb.EpochFinalization{
			Epoch:             epoch,
			AcceptedTxidsHash: &pb.Hash32{V: acceptedHash[:]},
			FrontiersRoot:     &pb.Hash32{V: dryRunRoot[:]},
			Signer:            &pb.Pub32{V: signerID[:]},
			Sig:               &pb.SigDER{V: sigDER}, // DER P-256 over the finalization digest
			AcceptedTxids:     acceptedTxidBytes,
		}

		// store our own finalization (and memory map); bypasses the intake window (self-vote must count)
		if err := e.storeSelfFinalization(fin); err != nil {
			e.elog(epoch, "finalization: store self error: %v", err)
		}

		// broadcast to peers
		log.Printf("[epoch=%d] phase:fin-broadcast-start wallMs=%d", epoch, time.Now().UnixMilli())
		e.broadcastFinalization(fin)
		log.Printf("[epoch=%d] phase:fin-broadcast-done wallMs=%d", epoch, time.Now().UnixMilli())

		// allow some skew to receive peers' finalizations (peers must finish apply first)
		select {
		case <-ctx.Done():
			return true
		case <-time.After(e.cfg.FinalizationSkew):
		}
		log.Printf("[epoch=%d] phase:fin-skew-done wallMs=%d", epoch, time.Now().UnixMilli())

		// --- Quorum check and commit decision ---
		// Three outcomes:
		// 1) Quorum agrees with us -> commit our winners to DB
		// 2) Quorum agrees on something different -> apply quorum's winner set instead
		// 3) No quorum reached -> discard everything, txs stay in pool for next epoch
		qAccepted, qRoot, qCount, qNeed, qTxids := e.finalizationQuorum(epoch)

		if qCount >= qNeed {
			if bytes.Equal(qAccepted[:], acceptedHash[:]) && bytes.Equal(qRoot[:], dryRunRoot[:]) {
				// MATCH: quorum agrees with us. Commit our winners to DB — apply + epoch-frontier
				// snapshot + flip latch in ONE atomic bbolt Update (P7.6 commitEpoch).
				log.Printf("[epoch=%d] phase:apply-start winners=%d validTxs=%d wallMs=%d", epoch, len(winners), len(validParsed), time.Now().UnixMilli())
				acceptedSet, failedApplied, aerr := e.commitEpoch(epoch, winners, txBytesByID, validParsed)
				log.Printf("[epoch=%d] phase:apply-done failed=%d wallMs=%d", epoch, len(failedApplied), time.Now().UnixMilli())
				if aerr != nil {
					e.elog(epoch, "apply error: %v — triggering resync", aerr)
					e.triggerResync(epoch, qAccepted, qRoot)
					return false
				}
				if len(failedApplied) > 0 {
					i := 0
					for id, ferr := range failedApplied {
						e.elog(epoch, "apply rejected tx %x...: %v", id[:4], ferr)
						i++
						if i >= 5 {
							break
						}
					}
					e.elog(epoch, "apply had %d failed txs (epoch rolled back) — triggering resync", len(failedApplied))
					e.triggerResync(epoch, qAccepted, qRoot)
					return false
				}

				// Cleanup: delete losers + delete accepted-but-failed-apply
				postSnap, _ := e.buildSnapshot(epoch)
				log.Printf("[epoch=%d] phase:cleanup-start txPool=%d wallMs=%d", epoch, len(e.txPool), time.Now().UnixMilli())
				e.cleanupAfterEpoch(epoch, acceptedSet, failedApplied, postSnap)
				log.Printf("[epoch=%d] phase:cleanup-done txPool=%d wallMs=%d", epoch, len(e.txPool), time.Now().UnixMilli())

				e.elog(epoch,
					"finalized. quorum=%d/%d: (elapsed=%s) : broadcasted to %d : lists received=%d : Applied (winner_accounts=%d, candidate_txs=%d)",
					qCount, qNeed, time.Since(start).Truncate(time.Millisecond), len(e.currentDialPeers()), len(peerLists), len(winners), len(validParsed))

			} else {
				// MISMATCH: quorum agreed on something different.
				// Instead of triggering a full resync, try to apply the quorum's winner
				// set directly. The quorum's finalization message includes the actual txid
				// list, so we can fetch any missing tx bytes and apply them.
				e.elog(epoch, "FINALIZATION MISMATCH quorum=%d/%d: have=(%x,%x) want=(%x,%x) — applying quorum set",
					qCount, qNeed, acceptedHash[:4], dryRunRoot[:4], qAccepted[:4], qRoot[:4])

				if len(qTxids) > 0 {
					// Build quorum winners from the txid list
					qWinners := make(map[[32]byte][32]byte)
					qTxBytesMap := make(map[[32]byte][]byte)
					qParsedMap := make(map[[32]byte]*pb.Tx)
					fetchFailed := false

					for _, txid := range qTxids {
						// Try to get tx bytes locally first (from our own pool/DB)
						raw := txBytesByID[txid]
						if len(raw) == 0 {
							raw = e.GetTxBytes(txid)
						}
						if len(raw) == 0 {
							// Fetch from peers
							e.fetchMissingTxs(epoch, [][32]byte{txid})
							raw = e.GetTxBytes(txid)
						}
						if len(raw) == 0 {
							e.elog(epoch, "MISMATCH: cannot find tx bytes for quorum txid %x — triggering resync", txid[:4])
							e.triggerResync(epoch, qAccepted, qRoot)
							fetchFailed = true
							break
						}
						tx, perr := ParseTx(raw)
						if perr != nil {
							e.elog(epoch, "MISMATCH: cannot parse quorum txid %x — triggering resync", txid[:4])
							e.triggerResync(epoch, qAccepted, qRoot)
							fetchFailed = true
							break
						}
						var acct [32]byte
						copy(acct[:], tx.Account.V)
						qWinners[acct] = txid
						qTxBytesMap[txid] = raw
						qParsedMap[txid] = tx
					}

					if !fetchFailed {
						// Apply the quorum's winners instead of our own — same atomic commitEpoch
						// (apply + frontiers + flip in one Update; any failure rolls it all back).
						log.Printf("[epoch=%d] phase:apply-quorum-start winners=%d wallMs=%d", epoch, len(qWinners), time.Now().UnixMilli())
						acceptedSet, failedApplied, aerr := e.commitEpoch(epoch, qWinners, qTxBytesMap, qParsedMap)
						log.Printf("[epoch=%d] phase:apply-quorum-done failed=%d wallMs=%d", epoch, len(failedApplied), time.Now().UnixMilli())
						if aerr != nil || len(failedApplied) > 0 {
							e.elog(epoch, "MISMATCH: apply quorum failed (err=%v, failed=%d; epoch rolled back) — triggering resync", aerr, len(failedApplied))
							e.triggerResync(epoch, qAccepted, qRoot)
						} else {
							// Cleanup: same as normal path
							postSnap, _ := e.buildSnapshot(epoch)
							log.Printf("[epoch=%d] phase:cleanup-start txPool=%d wallMs=%d", epoch, len(e.txPool), time.Now().UnixMilli())
							e.cleanupAfterEpoch(epoch, acceptedSet, failedApplied, postSnap)
							log.Printf("[epoch=%d] phase:cleanup-done txPool=%d wallMs=%d", epoch, len(e.txPool), time.Now().UnixMilli())

							e.elog(epoch, "applied quorum set: %d winners", len(qWinners))
						}
					}
				} else {
					// No txid list available from quorum — must fall back to resync
					e.elog(epoch, "MISMATCH: no quorum txid list available — triggering resync")
					e.triggerResync(epoch, qAccepted, qRoot)
				}
			}
		} else {
			// NO QUORUM: not enough validators responded.
			// Discard everything — no DB writes. Txs stay in pool for next epoch.
			e.elog(epoch, "finalization not reached: %d/%d", qCount, qNeed)
		}
		// --- end finalization ---
	}
	return false
}

// gossipLoop periodically advertises pending txids to peers (INV) and, when requested, delivers
// full transactions (PUSH). Gossip is considered "done" for a tx once it has been delivered to a
// majority of our configured peers (not counting self).
//
// This is intentionally memory-only. If a validator restarts or the pool is cleaned before peers
// fetch/push occurs, bytes may be lost; the majority threshold reduces the probability of that.
func (e *Engine) gossipLoop(ctx context.Context) {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// P7.6: one panicking flush must not kill the gossip loop for the life of the process.
			func() {
				defer e.recoverBGPanic("gossip-flush")
				e.flushGossipOnce(ctx)
			}()
		}
	}
}

func (e *Engine) flushGossipOnce(ctx context.Context) {
	// P7.4: gossip fans out over the per-epoch DIAL LIST (roster ∪ Fund banker endpoints), not the
	// static boot list. The list is frozen between refreshes and gossipMask bits index into it (the
	// mask is cleared whenever the list changes). Peers in a dial-health cooldown are skipped this
	// tick — the flush below BLOCKS on its slowest dial, so one dead Fund endpoint must not turn
	// every 200ms tick into a 2s stall.
	peers := e.currentDialPeers()
	if len(peers) == 0 {
		return
	}

	// Majority of dial peers (excluding self): floor(n/2)+1
	need := (len(peers) / 2) + 1
	if need < 1 {
		need = 1
	}

	type peerBatch struct {
		idx int
		url string
		ids [][32]byte
	}

	// Health-filter BEFORE taking e.mu (dialAllowed locks e.mu itself).
	type dialTarget struct {
		idx int
		url string
	}
	targets := make([]dialTarget, 0, len(peers))
	for i, peer := range peers {
		if i >= 63 {
			break // bitmask limitation (documented 63-peer gossip cap)
		}
		peer = strings.TrimRight(peer, "/")
		if !e.dialAllowed(peer) {
			continue
		}
		targets = append(targets, dialTarget{idx: i, url: peer})
	}
	if len(targets) == 0 {
		return
	}

	var batches []peerBatch

	e.mu.Lock()
	if len(e.gossipPending) == 0 {
		e.mu.Unlock()
		return
	}
	if e.gossipMask == nil {
		e.gossipMask = make(map[[32]byte]uint64)
	}

	// Bound per-tick so protobufs don’t explode.
	const maxTick = 300
	pending := make([][32]byte, 0, minInt(len(e.gossipPending), maxTick))
	for id := range e.gossipPending {
		pending = append(pending, id)
		if len(pending) >= maxTick {
			break
		}
	}

	// Pre-prune txids that already reached majority.
	for _, id := range pending {
		if bits.OnesCount64(e.gossipMask[id]) >= need {
			delete(e.gossipPending, id)
			delete(e.gossipMask, id)
		}
	}

	// Rebuild pending after prune.
	pending = pending[:0]
	for id := range e.gossipPending {
		pending = append(pending, id)
		if len(pending) >= maxTick {
			break
		}
	}

	if len(pending) == 0 {
		e.mu.Unlock()
		return
	}

	// Per-peer selection: only txids not yet acked by that peer.
	for _, t := range targets {
		bit := uint64(1) << uint(t.idx)

		ids := make([][32]byte, 0, len(pending))
		for _, id := range pending {
			if (e.gossipMask[id] & bit) == 0 {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			continue
		}
		batches = append(batches, peerBatch{idx: t.idx, url: t.url, ids: ids})
	}
	e.mu.Unlock()

	if len(batches) == 0 {
		return
	}

	totalIds := 0
	for _, b := range batches {
		totalIds += len(b.ids)
	}
	log.Printf("[gossip] flushing batches=%d totalIds=%d wallMs=%d", len(batches), totalIds, time.Now().UnixMilli())
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, b := range batches {
		b := b
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer e.recoverBGPanic("gossip-peer") // P7.6: runs before wg.Done (LIFO), so a panic can't leak past Wait
			sem <- struct{}{}
			defer func() { <-sem }()
			e.gossipToPeer(ctx, b.idx, b.url, b.ids, need)
		}()
	}
	wg.Wait()
}

func (e *Engine) gossipToPeer(ctx context.Context, peerIdx int, peerURL string, ids [][32]byte, need int) {
	if len(ids) == 0 || peerIdx < 0 || peerIdx >= 63 {
		return
	}
	// No per-tick "start" log here: a REACHABLE peer that persistently refuses our inv (a kicked
	// founder — still in the permanent roster dial set — or a network-id mismatch) is correctly
	// never acked (the P7.4 false-ACK fix), so we re-inv it every 200ms; a per-tick line would be a
	// slow disk-fill (the vector P7.3 removed elsewhere). The flush-level aggregate log remains.
	bit := uint64(1) << uint(peerIdx)

	epoch := e.epochNow()
	vid := e.cfg.Signer.PublicKeyCompressed()

	inv := &pb.TxInv{Epoch: epoch, From: &pb.Pub32{V: vid[:]}}
	for _, id := range ids {
		inv.Txid = append(inv.Txid, &pb.Hash32{V: id[:]})
	}

	var invBuf bytes.Buffer
	_, _ = protodelim.MarshalTo(&invBuf, inv)

	req, _ := http.NewRequestWithContext(ctx, "POST", peerURL+"/peer/tx/inv", &invBuf)
	req.Header.Set("Content-Type", "application/x-protobuf")
	e.setAnosHeaders(req)
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil || resp == nil {
		e.recordDialResult(peerURL, false) // transport failure feeds the dial-health cooldown
		return
	}
	e.recordDialResult(peerURL, true)

	var want pb.TxWant
	invOK := false
	func() {
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return
		}
		br := bufio.NewReader(resp.Body)
		if protodelim.UnmarshalFrom(br, &want) != nil {
			return
		}
		invOK = true
	}()
	if !invOK {
		// The peer refused or garbled the inv (membership gate, network-id mismatch, overload).
		// Do NOT ack (P7.4 false-ACK fix): the txids stay pending and retry next tick, bounded by
		// cleanupAfterEpoch draining gossip state every committed epoch. Pre-P7.4 a non-2xx here
		// fell through to "peer wants nothing" = a FULL ACK — the amplifier that turned a
		// transient membership rejection (e.g. a just-joined banker's pre-cache window) into a
		// permanently-undelivered tx for that peer.
		return
	}

	// If peer (2xx, well-formed) wants nothing, treat as ACK for everything we advertised.
	acked := make([][32]byte, 0, len(ids))
	if len(want.Txid) == 0 {
		acked = append(acked, ids...)
		e.recordGossipAck(bit, need, acked)
		return
	}

	// Build PUSH with only wanted txs, byte-capped so the body always clears the receiver's 4 MiB
	// protodelim read limit (overflow stays pending → next tick).
	push := &pb.TxPush{Epoch: epoch, From: &pb.Pub32{V: vid[:]}}
	pushBytes := 0
	for _, h := range want.Txid {
		if h == nil || len(h.V) != 32 {
			continue
		}
		var txid [32]byte
		copy(txid[:], h.V)

		raw := e.GetTxBytes(txid)
		if len(raw) == 0 {
			continue
		}
		if pushBytes > 0 && pushBytes+len(raw) > maxGossipPushBytes {
			break
		}
		tx, err := ParseTx(raw)
		if err != nil {
			continue
		}
		pushBytes += len(raw)
		push.Tx = append(push.Tx, tx)
		acked = append(acked, txid)
	}
	if len(push.Tx) == 0 {
		return
	}

	var pushBuf bytes.Buffer
	_, _ = protodelim.MarshalTo(&pushBuf, push)

	req2, _ := http.NewRequestWithContext(ctx, "POST", peerURL+"/peer/tx/push", &pushBuf)
	req2.Header.Set("Content-Type", "application/x-protobuf")
	e.setAnosHeaders(req2)
	resp2, err := e.cfg.HTTPClient.Do(req2)
	if err != nil || resp2 == nil {
		return
	}
	func() {
		defer resp2.Body.Close()
		if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
			acked = nil
		}
	}()
	if len(acked) == 0 {
		return
	}
	e.recordGossipAck(bit, need, acked)
}

func (e *Engine) recordGossipAck(bit uint64, need int, acked [][32]byte) {
	if len(acked) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.gossipMask == nil {
		e.gossipMask = make(map[[32]byte]uint64)
	}
	for _, id := range acked {
		e.gossipMask[id] |= bit
		if e.gossipPending != nil && bits.OnesCount64(e.gossipMask[id]) >= need {
			delete(e.gossipPending, id)
			delete(e.gossipMask, id)
		}
	}
}

func (e *Engine) buildSnapshot(epoch uint64) (*Snapshot, error) {
	snap := &Snapshot{
		Accounts:           make(map[[32]byte]AccountSnap),
		Receivables:        make(map[[32]byte]ReceivableSnap),
		Epoch:              epoch,
		DelayEpochs:        e.cfg.TimelockedDelayEpochs,
		FundAccount:        e.cfg.FundAccount,
		StakeLock1moEpochs: e.cfg.StakeLock1moEpochs,
		StakeLock1yrEpochs: e.cfg.StakeLock1yrEpochs,
		GuardedDelayEpochs: e.cfg.GuardedDelayEpochs,
		VaultDelayEpochs:   e.cfg.VaultDelayEpochs,
		AttestorQuorumM:    e.cfg.AttestorQuorumM,

		EscrowAttestationDelayEpochs: e.cfg.EscrowAttestationDelayEpochs,
		BreakglassExtraEpochs:        e.cfg.BreakglassExtraEpochs,
		Econ:                         e.cfg.Econ,
		GenesisSupply:                e.cfg.GenesisSupply,
		GuardedSendMinIntervalEpochs: e.cfg.GuardedSendMinIntervalEpochs,
	}
	err := e.cfg.DB.View(func(tx *bbolt.Tx) error {
		ab := tx.Bucket(BAccounts)
		if ab != nil {
			_ = ab.ForEach(func(k, v []byte) error {
				if len(k) == 32 {
					var acct [32]byte
					copy(acct[:], k)
					if r, ok := unpackAccountRecord(v); ok {
						snap.Accounts[acct] = AccountSnap{
							Head:                      r.Head,
							Balance:                   r.Balance,
							Seq:                       r.Seq,
							Class:                     r.Class,
							TransferSource:            r.TransferSource,
							TransferDest:              r.TransferDest,
							TransferUnlock:            r.TransferUnlock,
							TransferFlags:             r.TransferFlags,
							TransferReturnDepositTxid: r.TransferReturnDepositTxid,
							AuthPubKey:                r.AuthPubKey,
							BreakglassCommit:          r.BreakglassCommit,
							U2PubKey:                  r.U2PubKey,
							LastGuardedSendEpoch:      r.LastGuardedSendEpoch,
							EscrowPartyLoPub:          r.EscrowPartyLoPub,
							EscrowPartyLoBG:           r.EscrowPartyLoBG,
							EscrowPartyHiPub:          r.EscrowPartyHiPub,
							EscrowPartyHiBG:           r.EscrowPartyHiBG,
							EscrowTrigger:             r.EscrowTrigger,
							EscrowFlags:               r.EscrowFlags,
						}
					}
				}
				return nil
			})
		}
		rb := tx.Bucket(BRecv)
		if rb != nil {
			_ = rb.ForEach(func(k, v []byte) error {
				if len(k) == 32 {
					var rid [32]byte
					copy(rid[:], k)
					// only include unclaimed receivables in the snapshot
					var rec pb.Receivable
					if err := proto.Unmarshal(v, &rec); err == nil {
						if !rec.Claimed {
							var rs ReceivableSnap
							if rec.From != nil && len(rec.From.V) == 32 {
								copy(rs.From[:], rec.From.V)
							}
							if rec.To != nil && len(rec.To.V) == 32 {
								copy(rs.To[:], rec.To.V)
							}
							rs.Amount = rec.Amount
							rs.RequiredDestClass = rec.RequiredDestClass
							rs.FromSeq = rec.FromSeq
							if rec.KeySourceId != nil && len(rec.KeySourceId.V) == 32 {
								copy(rs.KeySourceID[:], rec.KeySourceId.V)
							}
							rs.ReturnTier = rec.ReturnTier
							rs.ReturnDelayEpochs = rec.ReturnDelayEpochs
							rs.FromBreakglass = rec.FromBreakglass
							snap.Receivables[rid] = rs
						}
					}
				}
				return nil
			})
		}

		// P2.3 Fund-SEND inputs (spec-19 §6.2): the finalized stake table (signer weights /
		// role membership) and the precomputed active-Guardian DENOMINATOR M for this epoch.
		// Both read the finalized DB state at epoch start, so every validator in the round
		// derives identical values — the determinism the quorum math depends on.
		snap.FundStakeRows = listStakesInTx(tx)
		active := listGuardianActiveInTx(tx)
		snap.GuardianActiveWeight = e.cfg.Econ.ActiveGuardianWeight(snap.FundStakeRows, active, epoch, e.cfg.GuardianActiveWindowEpochs)

		return nil
	})
	return snap, err
}

// buildCandidateListV2 builds a txid-only candidate list ("votes").
// It ignores raws and uses e.approved (one tx per conflict key).
// e.cfg.MaxCandidateScanPerSlot (manifest consensus.max_candidate_scan_per_slot) bounds how many
// txids buildCandidateList validates per conflict slot when searching for the lowest VALID candidate.
// It caps the CPU an attacker can force by flooding a slot with ground-low invalid txids; the
// residual (a flood past the cap that buries the real block) is bounded by mempool admission limits
// (P7.3), which cap how many txids a slot can accumulate. A cap hit is logged (never silent).
// Generous vs any honest slot (1-2 txids); pinning it in the manifest keeps proposal deterministic
// network-wide under a flood (P7.2).
func (e *Engine) buildCandidateList(epoch uint64, snap *Snapshot) (*CandidateList, [][32]byte) {
	// Snapshot the conflict pool + the raw bytes it references under the lock; validate OUTSIDE the lock
	// (ValidateTxAgainstSnapshot is a pure function of snap and holds no engine state).
	e.mu.Lock()
	slots := make([][][32]byte, 0, len(e.conflictPool))
	rawByID := make(map[[32]byte][]byte)
	for _, txids := range e.conflictPool {
		slots = append(slots, append([][32]byte(nil), txids...))
		for _, id := range txids {
			if raw, ok := e.txPool[id]; ok {
				rawByID[id] = raw
			}
		}
	}
	e.mu.Unlock()

	// Per conflict slot, propose the LOWEST-txid candidate that VALIDATES against snap — NOT the
	// blindly-lowest txid. A validity-blind pick lets a ground-low junk block (in particular a junk
	// opening relabelled TRANSFER/ESCROW, which the stateless front-door gate must defer) starve a slot:
	// it is proposed alone, fails the epoch-close validate, and the real (higher-txid) block for the
	// same slot — which is never proposed — can never win. Skipping invalid candidates so the lowest
	// VALID one is proposed closes that opening-slot DoS regardless of how the junk is labelled. This is
	// deterministic given snap (all synced nodes hold the same finalized snapshot → same verdict, even
	// if they hold different junk); a node too far behind to validate the real block yet simply proposes
	// nothing for that slot and relies on the synced quorum (pre-existing lagging-node behaviour). It is
	// LIVENESS-only: ApplyTx and the authoritative dry-run validate (which re-checks the union) are
	// unchanged, so it cannot fork or affect resync. (It supersedes the raw lowest-txid e.approved cache
	// for proposal; e.approved is still maintained as the incremental per-slot lowest-txid tracker.)
	ids := make([][32]byte, 0, len(slots))
	for _, txids := range slots {
		sort.Slice(txids, func(i, j int) bool { return bytes.Compare(txids[i][:], txids[j][:]) < 0 })
		scanned := 0
		for _, id := range txids {
			if uint64(scanned) >= e.cfg.MaxCandidateScanPerSlot {
				log.Printf("[epoch=%d] candidate scan cap (%d) hit for a conflict slot; deferring it (mempool bounding is P7.3)", epoch, e.cfg.MaxCandidateScanPerSlot)
				break
			}
			raw, ok := rawByID[id]
			if !ok {
				continue // bytes not held locally (shouldn't happen for a pooled txid) — skip
			}
			scanned++
			tx, err := ParseTx(raw)
			if err != nil {
				continue
			}
			cid, verr := ValidateTxAgainstSnapshot(tx, snap)
			if verr != nil || cid != id {
				continue // invalid (or txid mismatch) → skip; try the next-lowest txid for this slot
			}
			ids = append(ids, id)
			break
		}
	}

	// stable order for list_hash/signature
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })

	listHash := crypto.CandidatesListHash(ids)
	vid := e.cfg.Signer.PublicKeyCompressed()

	digest := crypto.CandidatesDigestP256(epoch, vid, listHash)
	sigDER, err := e.cfg.Signer.SignDigest(digest)
	if err != nil {
		sigDER = nil
	}

	cl := &CandidateList{
		Epoch:       epoch,
		ValidatorID: vid,
		ListHash:    listHash,
		SigDER:      sigDER,
		TxIDs:       ids, // <-- txids only
	}

	return cl, ids
}

func (e *Engine) broadcastCandidates(epoch uint64, cl *CandidateList) {
	msg := &pb.CandidateListV2{
		Epoch:    cl.Epoch,
		Proposer: &pb.Pub32{V: cl.ValidatorID[:]},
		ListHash: &pb.Hash32{V: cl.ListHash[:]},
		Sig:      &pb.SigDER{V: cl.SigDER}, // DER P-256 over the candidate-list hash
	}
	for _, id := range cl.TxIDs {
		msg.Txid = append(msg.Txid, &pb.Hash32{V: id[:]})
	}

	// P7.4: broadcast over the per-epoch dial list (roster ∪ Fund banker endpoints) so a post-flip
	// joined banker actually receives candidates. Fire-and-forget per peer (2s client). These
	// once-per-epoch consensus broadcasts are deliberately NOT gated by the dial-health cooldown
	// (unlike the 200ms gossip flush, which BLOCKS on its slowest dial): a briefly-flapping peer
	// must keep receiving candidates/finalizations the instant it recovers, and a dead endpoint here
	// costs only a short-lived goroutine bounded by the 2s client timeout. recordDialResult still
	// feeds the health signal the gossip flush consults.
	for _, peer := range e.currentDialPeers() {
		peer = strings.TrimRight(peer, "/")
		go func(p string) {
			defer e.recoverBGPanic("candidates-broadcast") // P7.6
			var buf bytes.Buffer
			_, _ = protodelim.MarshalTo(&buf, msg)

			req, _ := http.NewRequest("POST", p+"/peer/candidates", &buf)
			req.Header.Set("Content-Type", "application/x-protobuf")
			e.setAnosHeaders(req)
			// Optional: include your own URL if you use it for debugging
			// req.Header.Set("X-Validator-URL", e.cfg.SelfURL)

			resp, err := e.cfg.HTTPClient.Do(req)
			if err != nil {
				e.recordDialResult(p, false)
				log.Printf("candidates POST to %s failed: %v", p, err)
				return
			}
			e.recordDialResult(p, true)
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				b, _ := io.ReadAll(resp.Body)
				log.Printf("candidates POST to %s non-2xx: %s body=%q", p, resp.Status, string(b))
			}
		}(peer)
	}

	_ = epoch
}

func (e *Engine) broadcastFinalization(fin *pb.EpochFinalization) {
	if fin == nil {
		return
	}
	// P7.4: same per-epoch dial list as candidates — a joined banker's finalization reception (and
	// therefore its ability to count us toward ITS quorum view) must follow the Fund. Not gated by
	// the dial-health cooldown (see broadcastCandidates): a recovering peer must receive
	// finalizations immediately, and the fire-and-forget goroutine is 2s-bounded.
	for _, peer := range e.currentDialPeers() {
		peer = strings.TrimRight(peer, "/")
		go func(p string) {
			defer e.recoverBGPanic("finalization-broadcast") // P7.6
			var buf bytes.Buffer
			_, _ = protodelim.MarshalTo(&buf, fin)

			req, _ := http.NewRequest("POST", p+"/peer/finalization", &buf)
			req.Header.Set("Content-Type", "application/x-protobuf")
			e.setAnosHeaders(req)
			resp, err := e.cfg.HTTPClient.Do(req)
			if err != nil {
				e.recordDialResult(p, false)
				log.Printf("finalization POST to %s failed: %v", p, err)
				return
			}
			e.recordDialResult(p, true)
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				b, _ := io.ReadAll(resp.Body)
				log.Printf("finalization POST to %s non-2xx: %s body=%q", p, resp.Status, string(b))
			}
		}(peer)
	}
}

func (e *Engine) finalizationQuorum(epoch uint64) (bestAccepted [32]byte, bestRoot [32]byte, count int, need int, txids [][32]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// P4.3: the denominator + membership come from THIS epoch's validator set (manifest list
	// pre-flip, Fund-derived post-flip), and each stored finalization's signer membership + signature
	// is RE-VERIFIED against it, so the quorum is deterministic over the epoch's authoritative set
	// regardless of what the lenient receive-time gate stored. Pre-flip the cached set == the env
	// list and every stored fin was already verified against it, so this matches prior behaviour.
	// Fail CLOSED if the per-epoch set was somehow not cached: the sole caller runs in the epoch
	// loop right after setEpochValidatorSet(epoch), so this is unreachable today, but falling back to
	// the static manifest could undercount a POST-flip quorum, so we return "no quorum" (the loop
	// retries) rather than risk counting against the wrong set.
	vset := e.epochSets[epoch]
	if vset == nil {
		return [32]byte{}, [32]byte{}, 0, 1, nil
	}
	total := len(vset)
	need = (total*e.cfg.FinalizationQuorumPercent + 99) / 100
	if need < 1 {
		need = 1
	}

	m := e.peerFinals[epoch]
	if m == nil {
		return [32]byte{}, [32]byte{}, 0, need, nil
	}

	type key struct {
		accepted [32]byte
		root     [32]byte
	}
	verified := func(fin *pb.EpochFinalization) (key, bool) {
		if fin == nil || fin.Signer == nil || len(fin.Signer.V) != 33 ||
			fin.AcceptedTxidsHash == nil || len(fin.AcceptedTxidsHash.V) != 32 ||
			fin.FrontiersRoot == nil || len(fin.FrontiersRoot.V) != 32 || fin.Sig == nil {
			return key{}, false
		}
		var signer [33]byte
		copy(signer[:], fin.Signer.V)
		pub := vset[signer]
		if pub == nil {
			return key{}, false
		}
		var a, r [32]byte
		copy(a[:], fin.AcceptedTxidsHash.V)
		copy(r[:], fin.FrontiersRoot.V)
		digest := crypto.FinalizationDigestP256(fin.Epoch, a, r)
		if !crypto.VerifyFinalizationSigP256(pub, digest, fin.Sig.V) {
			return key{}, false
		}
		return key{accepted: a, root: r}, true
	}

	counts := make(map[key]int)
	for _, fin := range m {
		if k, ok := verified(fin); ok {
			counts[k]++ // m is keyed by signer, so this counts DISTINCT validators
		}
	}

	bestK := key{}
	bestC := 0
	for k, c := range counts {
		if c > bestC {
			bestC = c
			bestK = k
		}
	}

	// Find the txid list from a verified finalization matching the quorum winner.
	var bestTxids [][32]byte
	for _, fin := range m {
		k, ok := verified(fin)
		if !ok || k != bestK || len(fin.AcceptedTxids) == 0 {
			continue
		}
		bestTxids = make([][32]byte, 0, len(fin.AcceptedTxids))
		for _, raw := range fin.AcceptedTxids {
			if len(raw) == 32 {
				var id [32]byte
				copy(id[:], raw)
				bestTxids = append(bestTxids, id)
			}
		}
		break
	}

	return bestK.accepted, bestK.root, bestC, need, bestTxids
}

func (e *Engine) getPeerLists(epoch uint64) map[[33]byte]*CandidateList {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[[33]byte]*CandidateList)
	if m, ok := e.peerLists[epoch]; ok {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// errCommitAborted rolls back a commitEpoch Update whose winner set had failures; commitEpoch
// swallows it (the caller distinguishes that outcome via the failed map, as it did pre-P7.6).
var errCommitAborted = errors.New("commitEpoch: aborted on failed winners")

// commitEpoch persists a finalized epoch — every winner's ApplyTx, the epoch-frontier snapshot,
// and the list→Fund flip latch — in ONE atomic bbolt Update. Pre-P7.6 these were three separate
// transactions, leaving a window (a crash, kill -9, or a P7.6-recovered panic between them) where
// winners were applied but BEpochFrontiers/flip were missing — a state no finalization describes,
// which a continuing loop would then serve. Any failed winner aborts and rolls back the WHOLE
// epoch: pre-P7.6 the partial subset committed and the triggered resync wiped it moments later;
// now the partial state never exists (the pool still holds the bytes — GetTxBytes serves peers
// fetching quorum txids either way). applied is non-empty only on full success; failed carries
// the per-tx reasons for the caller's logging.
func (e *Engine) commitEpoch(epoch uint64, winners map[[32]byte][32]byte, txBytesByID map[[32]byte][]byte, parsed map[[32]byte]*pb.Tx) (map[[32]byte]struct{}, map[[32]byte]error, error) {
	applied := make(map[[32]byte]struct{})
	failed := make(map[[32]byte]error)

	err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		view := &bboltTxView{tx: tx}

		for _, id := range winners {
			raw := txBytesByID[id]
			p := parsed[id]

			if raw == nil || p == nil {
				if raw != nil {
					pp, perr := ParseTx(raw)
					if perr == nil {
						p = pp
					}
				}
			}
			if raw == nil || p == nil {
				failed[id] = errors.New("missing tx bytes/parse")
				continue
			}

			if aerr := ApplyTx(view, raw, p, id, e.cfg.FundAccount, e.cfg.Econ, epoch); aerr != nil {
				failed[id] = aerr
				continue
			}
			applied[id] = struct{}{}
		}
		if len(failed) > 0 {
			return errCommitAborted
		}

		// Snapshot the post-apply frontiers + latch the flip INSIDE the same transaction: the
		// Update sees its own uncommitted writes, so both read exactly the state the pre-P7.6
		// post-commit calls read — now atomically with the apply.
		if err := saveEpochFrontiersInTx(tx, epoch); err != nil {
			return fmt.Errorf("SaveEpochFrontiers: %w", err)
		}
		return e.maybeLatchFlipInTx(tx, epoch)
	})

	if err != nil {
		// Rolled back — nothing persisted, so report nothing applied.
		applied = make(map[[32]byte]struct{})
		if errors.Is(err, errCommitAborted) {
			err = nil
		}
	}
	return applied, failed, err
}

// noteLoopPanic records a recovered epoch-loop panic (counter + last message for /health, loud
// CRITICAL log with the stack). The RECOVERY action — a resync that rebuilds canonical state and
// clears the volatile pools, including any poison mempool tx — is driven by loop() on the panicked
// return, NOT here: noteLoopPanic runs inside guardIteration's recover, and keeping it to bookkeeping
// (no triggerResync, no pool surgery) keeps the recovery in one clean, e.mu-free-context place.
func (e *Engine) noteLoopPanic(r any) {
	stack := debug.Stack()
	e.mu.Lock()
	e.panicTotal++
	e.lastPanic = fmt.Sprintf("epoch-loop: %v", r)
	total := e.panicTotal
	e.mu.Unlock()
	log.Printf("CRITICAL: epoch-loop PANIC recovered (total=%d) — resyncing to shed any skipped-commit divergence: %v\n%s", total, r, stack)
}

// recoverBGPanic guards a background send goroutine (the gossip tick, the per-peer gossip
// fan-out, the candidate/finalization broadcasts): deferred at the top of each. These marshal our
// OWN data and POST it, so a panic there is an invariant break rather than hostile input — but
// pre-P7.6 it still killed the whole process. Log it loudly, count it for /health, keep running.
// No pool purge: senders don't consume pool bytes that could be poison (the loop's consecutive
// counter owns that).
func (e *Engine) recoverBGPanic(name string) {
	if r := recover(); r != nil {
		stack := debug.Stack()
		e.mu.Lock()
		e.panicTotal++
		e.lastPanic = fmt.Sprintf("%s: %v", name, r)
		total := e.panicTotal
		e.mu.Unlock()
		log.Printf("CRITICAL: %s PANIC recovered (total=%d): %v\n%s", name, total, r, stack)
	}
}

// PanicStats surfaces the recovered-panic count + last message for /health: a node that is alive
// but recovering (or that ever panicked) must be observable, not silent — the P7.6 goal is "never
// silently stop making progress", and the recover guards remove the "stop"; this removes the
// "silently".
func (e *Engine) PanicStats() (total uint64, last string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.panicTotal, e.lastPanic
}

// EpochNow exposes the wall-clock epoch for /health (alongside LatestFinalizedEpoch, the pair
// lets an operator see a stalled or lagging node at a glance).
func (e *Engine) EpochNow() uint64 { return e.epochNow() }

// ResyncActive exposes whether the verifying resync is in progress for /health (a resyncing node
// legitimately lags; without this bit a lag would read as a stall).
func (e *Engine) ResyncActive() bool { return e.resync.IsActive() }

func conflictKeyHash(tx *pb.Tx) ([32]byte, bool) {
	if tx.Account == nil || len(tx.Account.V) != 32 {
		return [32]byte{}, false
	}
	if tx.Prev == nil || len(tx.Prev.V) != 32 {
		return [32]byte{}, false
	}
	seq := tx.Seq

	// hash(account || prev || seqBE)
	buf := make([]byte, 32+32+8)
	copy(buf[:32], tx.Account.V)
	copy(buf[32:64], tx.Prev.V)
	binary.BigEndian.PutUint64(buf[64:], seq)
	return sha256.Sum256(buf), true
}

func appendUnique32(list [][32]byte, v [32]byte) [][32]byte {
	for _, x := range list {
		if bytes.Equal(x[:], v[:]) {
			return list
		}
	}
	return append(list, v)
}

func (e *Engine) fetchMissingTxs(epoch uint64, missing [][32]byte) {
	if len(missing) == 0 {
		return
	}

	// P7.4: pull from the per-epoch dial list — a tx proposed ONLY by a post-flip joined banker
	// exists only on that banker, so the epoch union is completable only if we can dial it.
	peers := e.currentDialPeers()
	log.Printf("[fetch] starting: need=%d peers=%d", len(missing), len(peers))

	resolved := make(map[[32]byte]struct{})

	for i, peer := range peers {
		// Build list of still-missing txids
		var still [][32]byte
		for _, id := range missing {
			if _, ok := resolved[id]; !ok {
				still = append(still, id)
			}
		}
		if len(still) == 0 {
			log.Printf("[fetch] all resolved after %d peers", i)
			break
		}

		peer = strings.TrimRight(peer, "/")
		if !e.dialAllowed(peer) {
			continue // cooling down (dead Fund endpoint) — don't spend a 2s timeout on it here
		}
		log.Printf("[fetch] trying peer=%s still_missing=%d", peer, len(still))

		vid := e.cfg.Signer.PublicKeyCompressed()
		want := &pb.TxWant{
			Epoch: epoch,
			From:  &pb.Pub32{V: vid[:]},
		}
		for _, id := range still {
			want.Txid = append(want.Txid, &pb.Hash32{V: id[:]})
		}

		var buf bytes.Buffer
		_, _ = protodelim.MarshalTo(&buf, want)

		req, _ := http.NewRequest("POST", peer+"/peer/tx/get", &buf)
		req.Header.Set("Content-Type", "application/x-protobuf")
		e.setAnosHeaders(req)
		resp, err := e.cfg.HTTPClient.Do(req)
		if err != nil || resp == nil {
			e.recordDialResult(peer, false)
			log.Printf("[fetch] peer=%s failed: %v", peer, err)
			continue
		}
		e.recordDialResult(peer, true)

		got := 0
		func() {
			defer resp.Body.Close()

			var push pb.TxPush
			br := bufio.NewReader(resp.Body)
			if err := protodelim.UnmarshalFrom(br, &push); err != nil {
				log.Printf("[fetch] peer=%s proto error: %v", peer, err)
				return
			}

			for _, tx := range push.Tx {
				if tx == nil {
					continue
				}
				raw, err := CanonicalTxBytes(tx)
				if err != nil {
					continue
				}
				// SOLICITED: these are txs the epoch union needs, so bypass the mempool admission caps.
				if err := e.receiveGossipedTx(raw, true); err == nil {
					txid, _ := crypto.TxID(tx)
					resolved[txid] = struct{}{}
					got++
				}
			}
		}()

		log.Printf("[fetch] peer=%s returned=%d resolved_so_far=%d/%d", peer, got, len(resolved), len(missing))
	}

	log.Printf("[fetch] done: resolved=%d/%d", len(resolved), len(missing))
}

// probeBehind polls the ROSTER peers' /sync/latest (the resync anchor set — deliberately NOT the
// dial list) with the short gossip client, and triggers a resync when a peer's committed tip is
// beyond our intake window. Called only while presence-skipping (an idle node), so the sequential
// 2s-bounded probes cannot delay a live epoch. This is what lets a freshly-booted non-roster
// follower converge BEFORE anyone dials it: boot → probe → verifying resync → follow → stake.
// Genesis cold-start safe: peers at tip 0 can never exceed latest+lag.
//
// triggerResync WIPES local state, so this must not fire on an implausible or already-suspect tip:
// it applies the SAME wall-clock plausibility cap + resync blacklist pickResyncTarget uses. A lone
// roster peer lying with a huge /sync/latest (e.g. 10^12) is therefore capped out and cannot drive
// a wiped observer into re-downloading the chain every probe interval (a cheap griefing / livelock
// lever on the join path). A slow LOCAL clock degrades the probe (it may not auto-fire) rather than
// stranding — a member still resyncs via the normal finalization-mismatch path.
func (e *Engine) probeBehind(ctx context.Context, epoch uint64) {
	capEp := e.epochNow() + maxIntakeEpochAhead
	best := uint64(0)
	for _, p := range e.cfg.Peers {
		p = strings.TrimRight(p, "/")
		if e.resyncPeerBlacklisted(p) {
			continue // a peer that already failed us / lied is not a trigger source
		}
		req, err := http.NewRequestWithContext(ctx, "GET", p+"/sync/latest", nil)
		if err != nil {
			continue
		}
		e.setAnosHeaders(req)
		resp, err := e.cfg.HTTPClient.Do(req)
		if err != nil || resp == nil {
			continue
		}
		var out pb.SyncLatestResponse
		func() {
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return
			}
			if e.checkAnosResponseHeader(resp.Header) != nil {
				return
			}
			_ = protodelim.UnmarshalFrom(bufio.NewReader(resp.Body), &out)
		}()
		if out.LatestEpoch > capEp {
			continue // implausible tip (beyond wall-clock) — never trigger a destructive resync on it
		}
		if out.LatestEpoch > best {
			best = out.LatestEpoch
		}
	}
	if lat := e.LatestFinalizedEpoch(); best > lat+maxIntakeEpochLag {
		e.elog(epoch, "behind-probe: roster reports committed tip %d, local tip %d — triggering resync", best, lat)
		e.triggerResync(best, [32]byte{}, [32]byte{})
	}
}

func (e *Engine) epochAtUnixMs(nowMs int64) uint64 {
	genesisMs := e.cfg.GenesisUnixMs
	epochMs := int64(e.cfg.EpochDuration / time.Millisecond)
	if epochMs <= 0 {
		epochMs = 1
	}
	return uint64((nowMs-genesisMs)/epochMs) + 1
}

func (e *Engine) epochNow() uint64 {
	return e.epochAtUnixMs(time.Now().UnixMilli())
}

func (e *Engine) cleanupAfterEpoch(
	epoch uint64,
	accepted map[[32]byte]struct{},
	failedApplied map[[32]byte]error,
	postSnap *Snapshot,
) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Option 2 (boundary-safe):
	// - Drop txs that were first seen in the epoch that just closed (seenEpoch <= epoch).
	//   This enforces: "if not accepted by an epoch, delete entirely" (no retry).
	// - Keep txs seen AFTER the boundary (seenEpoch > epoch). Those belong to the next epoch
	//   and have not been decided yet (so it's not a retry).
	// - Also drop any accepted-but-failed-applied txs to prevent "wins forever" loops.

	// If maps are nil, just clear per-epoch caches
	if e.txSeenEpoch == nil {
		if e.peerLists != nil {
			delete(e.peerLists, epoch)
		}
		if e.peerFinals != nil {
			delete(e.peerFinals, epoch)
		}
		return
	}

	// --- diagnostic: detect txs being dropped without ever being applied ---
	droppedUnapplied := 0
	for txid, seen := range e.txSeenEpoch {
		if seen <= epoch {
			if _, wasAccepted := accepted[txid]; !wasAccepted {
				if _, wasFailed := failedApplied[txid]; !wasFailed {
					droppedUnapplied++
				}
			}
		}
	}
	if droppedUnapplied > 0 {
		log.Printf("[epoch=%d] phase:cleanup WARNING dropping %d unapplied txs (never made it to any candidate list)", epoch, droppedUnapplied)
	}
	// --- end diagnostic ---

	// 1) Drop everything from the closed epoch window (seenEpoch <= epoch)
	for txid, seen := range e.txSeenEpoch {
		if seen <= epoch {
			delete(e.txSeenEpoch, txid)
			if e.txPool != nil {
				delete(e.txPool, txid)
			}
			if e.gossipPending != nil {
				delete(e.gossipPending, txid)
			}
			if e.gossipMask != nil {
				delete(e.gossipMask, txid)
			}
		}
	}

	// 2) Drop accepted-but-failed-applied (even if their seenEpoch was > epoch due to timing)
	for txid := range failedApplied {
		delete(e.txSeenEpoch, txid)
		if e.txPool != nil {
			delete(e.txPool, txid)
		}
		if e.gossipPending != nil {
			delete(e.gossipPending, txid)
		}
		if e.gossipMask != nil {
			delete(e.gossipMask, txid)
		}
	}

	// Drop applied txs no matter when they were "seen", to avoid re-advertising.
	for txid := range accepted {
		delete(e.txSeenEpoch, txid)
		if e.txPool != nil {
			delete(e.txPool, txid)
		}
		if e.gossipPending != nil {
			delete(e.gossipPending, txid)
		}
		if e.gossipMask != nil {
			delete(e.gossipMask, txid)
		}
	}

	// 3) Rebuild conflictPool + approved from remaining txPool,
	// but FIRST prune carry-over txs using post-commit snapshot tip rules:
	// carry only if prev==head AND seq==headSeq+1 (no pipelining).
	e.conflictPool = make(map[[32]byte][][32]byte)
	e.approved = make(map[[32]byte][32]byte)

	for txid, raw := range e.txPool {
		tx, err := ParseTx(raw)
		if err != nil {
			// malformed; drop it
			delete(e.txPool, txid)
			delete(e.txSeenEpoch, txid)
			if e.gossipPending != nil {
				delete(e.gossipPending, txid)
			}
			if e.gossipMask != nil {
				delete(e.gossipMask, txid)
			}
			continue
		}

		// Must have account/prev to evaluate carry rule
		if tx.Account == nil || len(tx.Account.V) != 32 || tx.Prev == nil || len(tx.Prev.V) != 32 {
			delete(e.txPool, txid)
			delete(e.txSeenEpoch, txid)
			if e.gossipPending != nil {
				delete(e.gossipPending, txid)
			}
			if e.gossipMask != nil {
				delete(e.gossipMask, txid)
			}
			continue
		}

		var acct [32]byte
		copy(acct[:], tx.Account.V)

		var prev [32]byte
		copy(prev[:], tx.Prev.V)

		// Unknown account defaults to zero head/seq.
		as, ok := postSnap.Accounts[acct]
		if !ok {
			as = AccountSnap{}
		}

		// Carry rule: prev==current head AND seq==current seq + 1
		if prev != as.Head || tx.Seq != as.Seq+1 {
			delete(e.txPool, txid)
			delete(e.txSeenEpoch, txid)
			if e.gossipPending != nil {
				delete(e.gossipPending, txid)
			}
			if e.gossipMask != nil {
				delete(e.gossipMask, txid)
			}
			continue
		}

		// Keep it: rebuild conflict structures for next epoch
		if key, ok := conflictKeyHash(tx); ok {
			e.conflictPool[key] = appendUnique32(e.conflictPool[key], txid)

			// Deterministic approval: lowest txid wins
			if cur, exists := e.approved[key]; !exists {
				e.approved[key] = txid
			} else if bytes.Compare(txid[:], cur[:]) < 0 {
				e.approved[key] = txid
			}
		}
	}

	// 4) Clear per-epoch caches so they don't grow forever
	if e.peerLists != nil {
		delete(e.peerLists, epoch)
	}
	if e.peerFinals != nil {
		delete(e.peerFinals, epoch)
	}

}

func (e *Engine) ensureGenesisOnBoot() error {
	gen := e.cfg.GenesisAccount
	return e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}

		// --- Regular account genesis ---
		// The genesis account is seeded directly (no key-registering opening block), so
		// its hybrid auth pubkey is manifest-pinned and seeded into the AUTH_PUBKEY TLV
		// here — otherwise its hybrid-verified distribution SENDs could not be checked
		// (spec-18 §8). The id stays the GENESIS_HEX constant, exempt from §6.4.
		head, bal, seq, _ := getAccount(tx, gen)
		var zero [32]byte
		if head == zero || seq < 1 {
			if len(e.cfg.GenesisAuthPubKey) != crypto.HybridPubKeySize {
				return fmt.Errorf("GenesisAuthPubKey (GENESIS_AUTH_PUBKEY_HEX) must be a %d-byte hybrid pubkey, got %d",
					crypto.HybridPubKeySize, len(e.cfg.GenesisAuthPubKey))
			}
			if bal == 0 {
				bal = e.cfg.GenesisSupply
			}
			h := sha256.Sum256(append([]byte("ANOS_GENESIS_HEAD_V1:"), gen[:]...))
			head = h
			if seq < 1 {
				seq = 1
			}
			if err := putAccountRecord(tx, gen, AccountRecord{
				Head:       head,
				Balance:    bal,
				Seq:        seq,
				Class:      pb.AccountClass_ACCOUNT_CLASS_SPENDING,
				AuthPubKey: append([]byte(nil), e.cfg.GenesisAuthPubKey...),
			}); err != nil {
				return err
			}
		}

		// --- Fund genesis seed (spec-18 §7.1, build-plan P2.1) ---
		// Alt A credits the Fund's balance directly (no lazy-materializing RECEIVE),
		// so the keyless Fund must be seeded here, mirroring the genesis-account seed.
		// This gives the Fund a stable, deterministic frontier entry from epoch 0
		// (SaveEpochFrontiers writes EVERY record, so an unseeded Fund would surface as
		// a surprising zero-head entry the moment it is first credited). The Fund holds
		// NO keys (metadata_len 0) — inflow is the Alt A direct credit and the only
		// outflow is a weighted-Guardian SEND (P2.3). Idempotent: seed only if absent,
		// so a resync wipe+reseed restores the Fund (balance 0) before chain replay
		// re-credits it. The head stays this synthetic seed (seq 1) until the first
		// Guardian SEND advances the chain; balance credits never touch head/seq.
		fund := e.cfg.FundAccount
		if fund == zero {
			return errors.New("FundAccount must be set (FUND_ACCOUNT_HEX)")
		}
		fundHead, _, fundSeq, _ := getAccount(tx, fund)
		if fundHead == zero || fundSeq < 1 {
			fh := sha256.Sum256(append([]byte("ANOS_FUND_HEAD_V1:"), fund[:]...))
			if err := putAccountRecord(tx, fund, AccountRecord{
				Head:    fh,
				Balance: 0,
				Seq:     1,
				Class:   pb.AccountClass_ACCOUNT_CLASS_FUND,
			}); err != nil {
				return err
			}
			log.Printf("[genesis] fund account seeded id=%x head=%x seq=1 class=FUND", fund[:4], fh[:4])
		}

		return nil
	})
}
