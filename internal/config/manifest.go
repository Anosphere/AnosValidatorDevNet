// Package config defines the Anos network manifest: the single, version-controlled
// source of the public, network-wide config that MUST be byte-identical on every
// validator (consensus timing/economics + genesis identity + the bootstrap validator
// roster). P7.2 content-addresses it: NetworkID is a hash over the canonical manifest,
// carried on the wire so a mismatched peer is rejected up front, and every consensus
// scalar that used to be a hardcoded Go const now lives here so a differently-tuned
// network is a DIFFERENT network_id rather than a silent fork.
//
// The validator consumes a manifest by SETTING the same environment variables its
// (tested) env path already reads for the timing fields, and by reading the newer
// economic/consensus scalars + NetworkID/ProtocolVersion directly off the struct into
// EngineConfig. See cmd/validator/manifest.go and cmd/validator/main.go.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// SupportedVersion is the manifest SCHEMA version this binary understands — the SHAPE of
// the JSON (which fields exist). A manifest carrying any other version is rejected
// (refuse-to-boot) rather than silently mis-parsed. Bumped whenever the manifest gains or
// loses a field. P7.2 bumps it 1 -> 2 (adds protocol_version, kat_digest, economics,
// consensus).
const SupportedVersion = 2

// SupportedProtocolVersion is the consensus RULESET version this binary implements — the
// structural rules that are algorithms/byte-formats, NOT config scalars (the SignBytesACTE
// signing preimage, crypto.TxID folding, account-id derivation, the hybrid-AND verify rule,
// the TLV record encoding, the frontier-root, the conflict-slot key + lowest-VALID-txid
// candidate selection, the proto wire schema). It is a HAND-MAINTAINED integer bumped
// whenever any of those structural rules changes. The manifest declares the ruleset it
// targets (Manifest.ProtocolVersion); the binary refuses to boot unless it can speak that
// ruleset. This is the language-neutral label a future non-Go banker would also carry.
// v1 == the current post-P7.1 ruleset (validity-aware candidate proposal included).
const SupportedProtocolVersion = 1

// networkIDDomain domain-separates the network_id preimage (magic bytes; bump only alongside
// a preimage-layout change, which is itself a protocol_version-worthy flag day).
const networkIDDomain = "ANOS_MANIFEST_V1:"

// Manifest is the whole public network descriptor. Everything here is public (no
// secrets): validator PRIVATE keys and the genesis seed never appear in a manifest.
type Manifest struct {
	Version int `json:"version"`
	// ProtocolVersion is the consensus ruleset this manifest targets; the binary refuses to
	// boot unless it equals SupportedProtocolVersion (Validate). It is part of the network_id
	// preimage, so two nets with different rulesets get different ids even if every scalar
	// matches.
	ProtocolVersion int `json:"protocol_version"`
	// NetworkID is the network's content identity — SHA-256 over the canonical manifest
	// (every field EXCEPT NetworkID itself; see ComputeNetworkID). It is DERIVED, not trusted
	// from the file: Load recomputes it and, if the file carries a non-empty value that
	// differs, refuses to boot (a tripwire against a stale hand-edit). Carried on the wire as
	// X-Anos-Network-Id so a mismatched peer is rejected.
	NetworkID string `json:"network_id"`
	// KatDigest is a RESERVED (P7.2) known-answer-test digest field — empty for now. It is IN
	// the network_id preimage, so filling it later is a deliberate flag day paired with a
	// protocol_version bump (the intended behavior). Reserving it now keeps that from being a
	// schema change. If non-empty it must be valid hex.
	KatDigest string `json:"kat_digest"`
	// FundAccountHex is the reserved keyless Fund account id (the ff..ff constant).
	FundAccountHex string    `json:"fund_account_hex"`
	Timing         Timing    `json:"timing"`
	Economics      Economics `json:"economics"`
	Consensus      Consensus `json:"consensus"`
	Genesis        Genesis   `json:"genesis"`
	// Roster is the ordered bootstrap validator set (the pre-flip "banker list").
	Roster []Node `json:"roster"`
}

// Timing holds the consensus-critical timing/delay constants (epoch-denominated). Every
// field must be byte-identical on all validators or they fork; the manifest is how we
// guarantee that. These genuinely VARY per network (a testnet shrinks them to seconds), so
// the validator READS them at runtime (via the env bridge in cmd/validator).
type Timing struct {
	EpochMs                      int64  `json:"epoch_ms"`
	TimelockedDelayEpochs        uint64 `json:"timelocked_delay_epochs"`
	GuardianActiveWindowEpochs   uint64 `json:"guardian_active_window_epochs"`
	StakeLock1moEpochs           uint64 `json:"stake_lock_1mo_epochs"`
	StakeLock1yrEpochs           uint64 `json:"stake_lock_1yr_epochs"`
	GuardedDelayEpochs           uint64 `json:"guarded_delay_epochs"`
	VaultDelayEpochs             uint64 `json:"vault_delay_epochs"`
	AttestorQuorumM              uint64 `json:"attestor_quorum_m"`
	EscrowAttestationDelayEpochs uint64 `json:"escrow_attestation_delay_epochs"`
	BreakglassExtraEpochs        uint64 `json:"breakglass_extra_epochs"`
}

// Economics holds the consensus-critical monetary/role scalars that used to be hardcoded Go
// consts in internal/core (fees.go, fund_table.go). The validator READS them at runtime so
// network_id provably reflects what it enforces. Amounts denominated "in anos" are whole
// anos (the engine scales by UnitsPerAnos at comparison time, matching the old consts).
type Economics struct {
	// Fee schedule (SEND): fee = clamp(ceil(amount * FeeBps / 10000), MinFee, MaxFee), in
	// base units. AttestedEscrowFee is the flat extra charged at an attested escrow's opening.
	MinFee            uint64 `json:"min_fee"`
	MaxFee            uint64 `json:"max_fee"`
	AttestedEscrowFee uint64 `json:"attested_escrow_fee"`
	FeeBps            uint64 `json:"fee_bps"`
	// Role floors + Guardian derivation (whole anos / bps).
	BankerStakeFloorAnos             uint64 `json:"banker_stake_floor_anos"`
	AttestorStakeFloorAnos           uint64 `json:"attestor_stake_floor_anos"`
	GuardianDivisorAnos              uint64 `json:"guardian_divisor_anos"`
	GuardianSendThresholdBps         uint64 `json:"guardian_send_threshold_bps"`
	GuardianFundSendEpochSlackEpochs uint64 `json:"guardian_fund_send_epoch_slack_epochs"`
}

// Consensus holds the finalization/proposal tuning scalars. QuorumPercent (conflict
// resolution) and FinalizationQuorumPercent (epoch finalization agreement) determine the
// finalized set, so a divergent value forks — they belong in network_id. MaxCandidateScanPerSlot
// bounds the per-slot validity scan in candidate proposal (P7.1); pinning it network-wide keeps
// proposal deterministic under a flood.
type Consensus struct {
	QuorumPercent             int    `json:"quorum_percent"`
	FinalizationQuorumPercent int    `json:"finalization_quorum_percent"`
	MaxCandidateScanPerSlot   uint64 `json:"max_candidate_scan_per_slot"`
}

// Genesis identifies the genesis account (seeded directly at boot with no opening
// block) and the total supply. The genesis PRIVATE seed is never in here.
type Genesis struct {
	Hex           string `json:"hex"`             // 32-byte account id (hex)
	AuthPubkeyHex string `json:"auth_pubkey_hex"` // 2625-byte hybrid auth pubkey (hex)
	UnixMs        int64  `json:"unix_ms"`         // fixed genesis timestamp (epoch anchor)
	SupplyUnits   uint64 `json:"supply_units"`
}

// Node is one validator's public roster entry.
type Node struct {
	Pubkey   string `json:"pubkey"`             // 33-byte compressed P-256 consensus pubkey (hex)
	URL      string `json:"url"`                // base URL peers reach it at, e.g. http://IP:PORT
	Identity string `json:"identity,omitempty"` // optional 32-byte Banker account id (post-flip); unset pre-flip
}

// Load reads, strictly parses, validates, and content-addresses a manifest file. Guards
// against a silently-wrong config: strict parsing (DisallowUnknownFields) rejects a
// MISSPELLED key, Validate() rejects a MISSING or out-of-range consensus-critical field
// (an omitted key just decodes to a zero value), and the network_id tripwire rejects a
// stale hand-edit (a file network_id that no longer matches the canonical hash of its own
// body). On success m.NetworkID holds the authoritative computed id.
func Load(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	computed, err := ComputeNetworkID(&m)
	if err != nil {
		return nil, fmt.Errorf("compute network_id: %w", err)
	}
	if got := strings.ToLower(strings.TrimSpace(m.NetworkID)); got != "" && got != computed {
		return nil, fmt.Errorf(
			"network_id in file (%s) does not match the canonical hash of the manifest (%s): "+
				"the manifest was edited without recomputing network_id", got, computed)
	}
	m.NetworkID = computed
	return &m, nil
}

// Validate enforces the refuse-to-boot invariants: supported schema + ruleset version,
// present/well-formed genesis + fund identity, sane timing, present-and-valid economic +
// consensus scalars (no legit zero — a missing key would decode to 0 and silently fork),
// and a non-empty roster of well-formed entries.
func (m *Manifest) Validate() error {
	if m.Version != SupportedVersion {
		return fmt.Errorf("unsupported manifest schema version %d (this binary supports %d)", m.Version, SupportedVersion)
	}
	if m.ProtocolVersion != SupportedProtocolVersion {
		return fmt.Errorf("manifest targets protocol_version %d which this binary does not implement (supports %d)", m.ProtocolVersion, SupportedProtocolVersion)
	}
	if s := strings.TrimSpace(m.KatDigest); s != "" {
		if _, err := hex.DecodeString(s); err != nil {
			return fmt.Errorf("kat_digest is set but not valid hex: %w", err)
		}
	}
	if err := hexLen("fund_account_hex", m.FundAccountHex, 32); err != nil {
		return err
	}
	if err := hexLen("genesis.hex", m.Genesis.Hex, 32); err != nil {
		return err
	}
	if strings.TrimSpace(m.Genesis.AuthPubkeyHex) == "" {
		return fmt.Errorf("genesis.auth_pubkey_hex is required")
	}
	if _, err := hex.DecodeString(strings.TrimSpace(m.Genesis.AuthPubkeyHex)); err != nil {
		return fmt.Errorf("genesis.auth_pubkey_hex is not valid hex: %w", err)
	}
	if m.Genesis.UnixMs <= 0 {
		return fmt.Errorf("genesis.unix_ms must be > 0")
	}
	if m.Genesis.SupplyUnits == 0 {
		return fmt.Errorf("genesis.supply_units must be > 0")
	}
	if err := m.validateTiming(); err != nil {
		return err
	}
	if err := m.validateEconomics(); err != nil {
		return err
	}
	if err := m.validateConsensus(); err != nil {
		return err
	}
	return m.validateRoster()
}

// validateTiming requires every consensus-critical timing field to be explicitly > 0. A
// JSON key that is simply OMITTED decodes to 0 (strict parsing rejects a misspelled key,
// not a missing one) — and the loader then setenv's that "0", OVERRIDING the engine's env
// default and silently forking. None of these has a legitimate zero value.
func (m *Manifest) validateTiming() error {
	if m.Timing.EpochMs <= 0 {
		return fmt.Errorf("timing.epoch_ms must be > 0")
	}
	if m.Timing.AttestorQuorumM < 1 {
		return fmt.Errorf("timing.attestor_quorum_m must be >= 1")
	}
	if m.Timing.BreakglassExtraEpochs < 1 {
		return fmt.Errorf("timing.breakglass_extra_epochs must be >= 1")
	}
	for _, f := range []struct {
		name string
		val  uint64
	}{
		{"timing.timelocked_delay_epochs", m.Timing.TimelockedDelayEpochs},
		{"timing.guardian_active_window_epochs", m.Timing.GuardianActiveWindowEpochs},
		{"timing.stake_lock_1mo_epochs", m.Timing.StakeLock1moEpochs},
		{"timing.stake_lock_1yr_epochs", m.Timing.StakeLock1yrEpochs},
		{"timing.guarded_delay_epochs", m.Timing.GuardedDelayEpochs},
		{"timing.vault_delay_epochs", m.Timing.VaultDelayEpochs},
		{"timing.escrow_attestation_delay_epochs", m.Timing.EscrowAttestationDelayEpochs},
	} {
		if f.val == 0 {
			return fmt.Errorf("%s must be > 0 (a missing or zero value would silently fork consensus)", f.name)
		}
	}
	return nil
}

// validateEconomics requires every fee/floor/divisor/threshold scalar present-and-sane.
// None has a legitimate zero (a zero divisor would panic; a zero floor/threshold/fee would
// defeat the gate it names). It also enforces the two structural relations MinFee <= MaxFee
// and slack < window (the fund-send epoch slack must keep a recently-stamped signer inside
// the active window).
func (m *Manifest) validateEconomics() error {
	e := m.Economics
	for _, f := range []struct {
		name string
		val  uint64
	}{
		{"economics.min_fee", e.MinFee},
		{"economics.max_fee", e.MaxFee},
		{"economics.attested_escrow_fee", e.AttestedEscrowFee},
		{"economics.fee_bps", e.FeeBps},
		{"economics.banker_stake_floor_anos", e.BankerStakeFloorAnos},
		{"economics.attestor_stake_floor_anos", e.AttestorStakeFloorAnos},
		{"economics.guardian_divisor_anos", e.GuardianDivisorAnos},
		{"economics.guardian_send_threshold_bps", e.GuardianSendThresholdBps},
		{"economics.guardian_fund_send_epoch_slack_epochs", e.GuardianFundSendEpochSlackEpochs},
	} {
		if f.val == 0 {
			return fmt.Errorf("%s must be > 0 (a missing or zero value would silently fork consensus)", f.name)
		}
	}
	if e.MinFee > e.MaxFee {
		return fmt.Errorf("economics.min_fee (%d) must be <= economics.max_fee (%d)", e.MinFee, e.MaxFee)
	}
	if e.FeeBps > 10000 {
		return fmt.Errorf("economics.fee_bps (%d) must be <= 10000 (100%%)", e.FeeBps)
	}
	if e.GuardianSendThresholdBps > 10000 {
		return fmt.Errorf("economics.guardian_send_threshold_bps (%d) must be <= 10000 (100%%)", e.GuardianSendThresholdBps)
	}
	if e.GuardianFundSendEpochSlackEpochs >= m.Timing.GuardianActiveWindowEpochs {
		return fmt.Errorf(
			"economics.guardian_fund_send_epoch_slack_epochs (%d) must be < timing.guardian_active_window_epochs (%d)",
			e.GuardianFundSendEpochSlackEpochs, m.Timing.GuardianActiveWindowEpochs)
	}
	// The anos-denominated scalars are multiplied by UnitsPerAnos (1e6) in the engine's role
	// derivations (GuardianWeight divides by divisor*1e6; the floors scale by 1e6). A value near
	// 2^64/1e6 (~1.8e13) would OVERFLOW that uint64 product — a divisor wrapping to 0 panics
	// GuardianWeight (integer divide-by-zero), a floor wrapping small silently confers membership on
	// sub-floor stakes. maxAnosScalar (1e12 anos) is absurdly high for any real floor/divisor yet an
	// order of magnitude below the overflow point, so a Validate-passing manifest never crashes the
	// consensus path. (It cannot reference core.UnitsPerAnos without an import cycle; the ceiling is
	// pinned conservatively.)
	const maxAnosScalar uint64 = 1_000_000_000_000 // 1e12
	for _, f := range []struct {
		name string
		val  uint64
	}{
		{"economics.banker_stake_floor_anos", e.BankerStakeFloorAnos},
		{"economics.attestor_stake_floor_anos", e.AttestorStakeFloorAnos},
		{"economics.guardian_divisor_anos", e.GuardianDivisorAnos},
	} {
		if f.val > maxAnosScalar {
			return fmt.Errorf("%s (%d) exceeds the max %d (it is scaled by 1e6 units; a larger value overflows uint64)", f.name, f.val, maxAnosScalar)
		}
	}
	return nil
}

// validateConsensus requires the finalization/proposal scalars present-and-sane. Both
// quorum percents must exceed 50 (a majority that can conflict below that) and not exceed
// 100; the candidate scan cap must be >= 1.
func (m *Manifest) validateConsensus() error {
	c := m.Consensus
	if c.QuorumPercent <= 50 || c.QuorumPercent > 100 {
		return fmt.Errorf("consensus.quorum_percent (%d) must be in (50, 100]", c.QuorumPercent)
	}
	if c.FinalizationQuorumPercent <= 50 || c.FinalizationQuorumPercent > 100 {
		return fmt.Errorf("consensus.finalization_quorum_percent (%d) must be in (50, 100]", c.FinalizationQuorumPercent)
	}
	if c.MaxCandidateScanPerSlot < 1 {
		return fmt.Errorf("consensus.max_candidate_scan_per_slot must be >= 1")
	}
	return nil
}

func (m *Manifest) validateRoster() error {
	if len(m.Roster) == 0 {
		return fmt.Errorf("roster must have at least one validator")
	}
	seen := make(map[string]bool, len(m.Roster))
	for i, n := range m.Roster {
		if err := hexLen(fmt.Sprintf("roster[%d].pubkey", i), n.Pubkey, 33); err != nil {
			return err
		}
		key := strings.ToLower(strings.TrimSpace(n.Pubkey))
		if seen[key] {
			return fmt.Errorf("roster[%d].pubkey is a duplicate", i)
		}
		seen[key] = true
		u := strings.TrimSpace(n.URL)
		if u == "" {
			return fmt.Errorf("roster[%d].url is required", i)
		}
		parsed, err := url.Parse(u)
		if err != nil || parsed.Host == "" {
			return fmt.Errorf("roster[%d].url %q is not a valid URL", i, n.URL)
		}
		if n.Identity != "" {
			if err := hexLen(fmt.Sprintf("roster[%d].identity", i), n.Identity, 32); err != nil {
				return err
			}
		}
	}
	return nil
}

// ComputeNetworkID returns the network's content identity: the hex SHA-256 over a canonical
// encoding of the whole manifest EXCEPT the NetworkID field. The encoding (canonicalBytes)
// is deliberately FROM-STRUCT (never raw JSON): explicit fixed field order, uint32-BE length
// framing of every variable field, hex fields decoded to raw bytes (kills hex-casing/length
// ambiguity), and the roster sorted by consensus pubkey. Pinned byte-for-byte by
// manifest_canonical_test.go.
func ComputeNetworkID(m *Manifest) (string, error) {
	enc, err := m.canonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(enc)
	return hex.EncodeToString(sum[:]), nil
}

func (m *Manifest) canonicalBytes() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(networkIDDomain)

	putU32(&b, uint32(m.Version))
	putU32(&b, uint32(m.ProtocolVersion))
	if err := frameHex(&b, m.KatDigest); err != nil {
		return nil, fmt.Errorf("kat_digest: %w", err)
	}
	if err := frameHex(&b, m.FundAccountHex); err != nil {
		return nil, fmt.Errorf("fund_account_hex: %w", err)
	}

	// timing (fixed order)
	putU64(&b, uint64(m.Timing.EpochMs))
	putU64(&b, m.Timing.TimelockedDelayEpochs)
	putU64(&b, m.Timing.GuardianActiveWindowEpochs)
	putU64(&b, m.Timing.StakeLock1moEpochs)
	putU64(&b, m.Timing.StakeLock1yrEpochs)
	putU64(&b, m.Timing.GuardedDelayEpochs)
	putU64(&b, m.Timing.VaultDelayEpochs)
	putU64(&b, m.Timing.AttestorQuorumM)
	putU64(&b, m.Timing.EscrowAttestationDelayEpochs)
	putU64(&b, m.Timing.BreakglassExtraEpochs)

	// economics (fixed order)
	putU64(&b, m.Economics.MinFee)
	putU64(&b, m.Economics.MaxFee)
	putU64(&b, m.Economics.AttestedEscrowFee)
	putU64(&b, m.Economics.FeeBps)
	putU64(&b, m.Economics.BankerStakeFloorAnos)
	putU64(&b, m.Economics.AttestorStakeFloorAnos)
	putU64(&b, m.Economics.GuardianDivisorAnos)
	putU64(&b, m.Economics.GuardianSendThresholdBps)
	putU64(&b, m.Economics.GuardianFundSendEpochSlackEpochs)

	// consensus (fixed order)
	putU64(&b, uint64(m.Consensus.QuorumPercent))
	putU64(&b, uint64(m.Consensus.FinalizationQuorumPercent))
	putU64(&b, m.Consensus.MaxCandidateScanPerSlot)

	// genesis
	if err := frameHex(&b, m.Genesis.Hex); err != nil {
		return nil, fmt.Errorf("genesis.hex: %w", err)
	}
	if err := frameHex(&b, m.Genesis.AuthPubkeyHex); err != nil {
		return nil, fmt.Errorf("genesis.auth_pubkey_hex: %w", err)
	}
	putU64(&b, uint64(m.Genesis.UnixMs))
	putU64(&b, m.Genesis.SupplyUnits)

	// roster, sorted by consensus pubkey (fixed-length hex sorts identically to raw bytes)
	sorted := make([]Node, len(m.Roster))
	copy(sorted, m.Roster)
	sort.Slice(sorted, func(i, j int) bool {
		return strings.ToLower(strings.TrimSpace(sorted[i].Pubkey)) < strings.ToLower(strings.TrimSpace(sorted[j].Pubkey))
	})
	putU32(&b, uint32(len(sorted)))
	for _, n := range sorted {
		if err := frameHex(&b, n.Pubkey); err != nil {
			return nil, fmt.Errorf("roster pubkey: %w", err)
		}
		frameBytes(&b, []byte(strings.TrimSpace(n.URL)))
		if err := frameHex(&b, n.Identity); err != nil {
			return nil, fmt.Errorf("roster identity: %w", err)
		}
	}
	return b.Bytes(), nil
}

func putU32(b *bytes.Buffer, v uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	b.Write(buf[:])
}

func putU64(b *bytes.Buffer, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	b.Write(buf[:])
}

// frameBytes writes uint32-BE length ‖ bytes.
func frameBytes(b *bytes.Buffer, p []byte) {
	putU32(b, uint32(len(p)))
	b.Write(p)
}

// frameHex decodes a (possibly empty) hex string to raw bytes and length-frames them. An
// empty/blank string frames zero bytes (a 4-byte zero length), so a reserved-empty field
// still contributes deterministically.
func frameHex(b *bytes.Buffer, hexStr string) error {
	s := strings.TrimSpace(hexStr)
	if s == "" {
		frameBytes(b, nil)
		return nil
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	frameBytes(b, raw)
	return nil
}

// ValidatorSetCSV renders the roster pubkeys as the comma-separated form the engine's
// existing VALIDATOR_SET_PUBKEYS parser expects.
func (m *Manifest) ValidatorSetCSV() string {
	pubs := make([]string, len(m.Roster))
	for i, n := range m.Roster {
		pubs[i] = strings.TrimSpace(n.Pubkey)
	}
	return strings.Join(pubs, ",")
}

// URLList renders every roster URL as the comma-separated form the sims' VALIDATOR_URL_LIST expects.
func (m *Manifest) URLList() string {
	urls := make([]string, len(m.Roster))
	for i, n := range m.Roster {
		urls[i] = strings.TrimSpace(n.URL)
	}
	return strings.Join(urls, ",")
}

// Self returns the roster entry whose pubkey matches selfHex (case-insensitive), or false.
func (m *Manifest) Self(selfHex string) (*Node, bool) {
	want := strings.ToLower(strings.TrimSpace(selfHex))
	for i := range m.Roster {
		if strings.ToLower(strings.TrimSpace(m.Roster[i].Pubkey)) == want {
			return &m.Roster[i], true
		}
	}
	return nil, false
}

// PeersExcluding returns every roster URL except the entry matching selfHex.
func (m *Manifest) PeersExcluding(selfHex string) []string {
	want := strings.ToLower(strings.TrimSpace(selfHex))
	var peers []string
	for _, n := range m.Roster {
		if strings.ToLower(strings.TrimSpace(n.Pubkey)) == want {
			continue
		}
		peers = append(peers, strings.TrimSpace(n.URL))
	}
	return peers
}

// PortFor returns the port component of the given roster node's URL (empty if none).
func PortFor(n *Node) string {
	u, err := url.Parse(strings.TrimSpace(n.URL))
	if err != nil {
		return ""
	}
	return u.Port()
}

func hexLen(field, s string, wantBytes int) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("%s is required", field)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("%s is not valid hex: %w", field, err)
	}
	if len(b) != wantBytes {
		return fmt.Errorf("%s must decode to exactly %d bytes, got %d", field, wantBytes, len(b))
	}
	return nil
}
