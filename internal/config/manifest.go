// Package config defines the Anos network manifest: the single, version-controlled
// source of the public, network-wide config that MUST be byte-identical on every
// validator (consensus timing/economics + genesis identity + the bootstrap validator
// roster). It is the hand-rolled precursor to the P7 network manifest — deliberately
// shaped so P7 can later content-address it (fill NetworkID with a hash over the file)
// and refuse to boot on mismatch, rather than replace it.
//
// The validator consumes a manifest by SETTING the same environment variables its
// (tested) env path already reads — the loader reimplements no parsing — so a manifest
// boot produces a byte-identical EngineConfig to an env boot. See cmd/validator/manifest.go.
package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// SupportedVersion is the manifest schema version this binary understands. A manifest
// carrying any other version is rejected (refuse-to-boot) rather than silently
// mis-parsed — P7 bumps this when it adds content-addressing/signature fields.
const SupportedVersion = 1

// Manifest is the whole public network descriptor. Everything here is public (no
// secrets): validator PRIVATE keys and the genesis seed never appear in a manifest.
type Manifest struct {
	Version int `json:"version"`
	// NetworkID is the network's content identity. Empty in this hand-rolled testnet
	// precursor; P7 fills it with a hash over the canonical manifest and refuses to
	// join a peer whose NetworkID differs.
	NetworkID string `json:"network_id"`
	// FundAccountHex is the reserved keyless Fund account id (the ff..ff constant).
	// Pinned explicitly so P7 content-addresses it with everything else.
	FundAccountHex string  `json:"fund_account_hex"`
	Timing         Timing  `json:"timing"`
	Genesis        Genesis `json:"genesis"`
	// Roster is the ordered bootstrap validator set (the pre-flip "banker list").
	Roster []Node `json:"roster"`
}

// Timing holds the consensus-critical timing/economics constants. Every field must be
// byte-identical on all validators or they fork; the manifest is how we guarantee that.
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
	URL      string `json:"url"`               // base URL peers reach it at, e.g. http://IP:PORT
	Identity string `json:"identity,omitempty"` // optional 32-byte Banker account id (post-flip); unset pre-flip
}

// Load reads, strictly parses, and validates a manifest file. Two layers guard against a
// silently-wrong config: strict parsing (DisallowUnknownFields) rejects a MISSPELLED key
// like "epoch_mss" as unknown, and Validate() rejects a MISSING or zero consensus-critical
// field (which strict parsing does not catch — an omitted key just decodes to 0). Both are
// needed: neither alone stops a "silently-zero value that forks the network".
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
	return &m, nil
}

// Validate enforces the refuse-to-boot invariants: known version, present/well-formed
// genesis + fund identity, sane timing, and a non-empty roster of well-formed entries.
func (m *Manifest) Validate() error {
	if m.Version != SupportedVersion {
		return fmt.Errorf("unsupported manifest version %d (this binary supports %d)", m.Version, SupportedVersion)
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
	if m.Timing.EpochMs <= 0 {
		return fmt.Errorf("timing.epoch_ms must be > 0")
	}
	if m.Timing.AttestorQuorumM < 1 {
		return fmt.Errorf("timing.attestor_quorum_m must be >= 1")
	}
	if m.Timing.BreakglassExtraEpochs < 1 {
		return fmt.Errorf("timing.breakglass_extra_epochs must be >= 1")
	}
	// The remaining timing fields are consensus-critical delays/windows the manifest
	// exists specifically to pin. A JSON key that is simply OMITTED decodes to 0 (strict
	// parsing rejects a misspelled key, not a missing one) — and the loader then setenv's
	// that "0", OVERRIDING the engine's safe env default and silently forking the network.
	// None of these has a legitimate zero value (a zero defeats the delay it names), so
	// require every one to be explicitly > 0.
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
