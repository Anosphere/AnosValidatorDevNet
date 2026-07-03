package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// validManifest returns a complete, well-formed manifest for mutation in tests.
func validManifest() Manifest {
	return Manifest{
		Version:         SupportedVersion,
		ProtocolVersion: SupportedProtocolVersion,
		FundAccountHex:  strings.Repeat("ff", 32),
		Timing: Timing{
			EpochMs:                      2000,
			TimelockedDelayEpochs:        6,
			GuardianActiveWindowEpochs:   20,
			StakeLock1moEpochs:           4,
			StakeLock1yrEpochs:           8,
			GuardedDelayEpochs:           8,
			VaultDelayEpochs:             12,
			AttestorQuorumM:              2,
			EscrowAttestationDelayEpochs: 6,
			BreakglassExtraEpochs:        5,
		},
		Economics: Economics{
			MinFee:                           1_000,
			MaxFee:                           3_000_000,
			AttestedEscrowFee:                100_000,
			FeeBps:                           50,
			BankerStakeFloorAnos:             50_000,
			AttestorStakeFloorAnos:           5_000,
			GuardianDivisorAnos:              2_000,
			GuardianSendThresholdBps:         7_000,
			GuardianFundSendEpochSlackEpochs: 8,
		},
		Consensus: Consensus{
			QuorumPercent:             80,
			FinalizationQuorumPercent: 60,
			MaxCandidateScanPerSlot:   64,
		},
		Genesis: Genesis{
			Hex:           strings.Repeat("ab", 32),
			AuthPubkeyHex: strings.Repeat("cd", 64),
			UnixMs:        1_700_000_000_000,
			SupplyUnits:   1_000_000_000_000_000,
		},
		Roster: []Node{
			{Pubkey: "02" + strings.Repeat("11", 32), URL: "http://10.0.0.1:30303"},
			{Pubkey: "03" + strings.Repeat("22", 32), URL: "http://10.0.0.2:30303"},
		},
	}
}

func TestValidateAcceptsComplete(t *testing.T) {
	m := validManifest()
	if err := m.Validate(); err != nil {
		t.Fatalf("complete manifest rejected: %v", err)
	}
}

// A zeroed (i.e. omitted-in-JSON) consensus-critical timing field must be rejected — this
// is the fork-on-a-missing-field footgun. Every timing field is asserted individually so a
// future field can't quietly escape the check.
func TestValidateRejectsZeroTimingField(t *testing.T) {
	cases := map[string]func(*Timing){
		"epoch_ms":                        func(t *Timing) { t.EpochMs = 0 },
		"timelocked_delay_epochs":         func(t *Timing) { t.TimelockedDelayEpochs = 0 },
		"guardian_active_window_epochs":   func(t *Timing) { t.GuardianActiveWindowEpochs = 0 },
		"stake_lock_1mo_epochs":           func(t *Timing) { t.StakeLock1moEpochs = 0 },
		"stake_lock_1yr_epochs":           func(t *Timing) { t.StakeLock1yrEpochs = 0 },
		"guarded_delay_epochs":            func(t *Timing) { t.GuardedDelayEpochs = 0 },
		"vault_delay_epochs":              func(t *Timing) { t.VaultDelayEpochs = 0 },
		"attestor_quorum_m":               func(t *Timing) { t.AttestorQuorumM = 0 },
		"escrow_attestation_delay_epochs": func(t *Timing) { t.EscrowAttestationDelayEpochs = 0 },
		"breakglass_extra_epochs":         func(t *Timing) { t.BreakglassExtraEpochs = 0 },
	}
	for name, zero := range cases {
		m := validManifest()
		zero(&m.Timing)
		if err := m.Validate(); err == nil {
			t.Errorf("Validate accepted a manifest with %s=0 (must reject)", name)
		}
	}
}

// A manifest JSON that OMITS a timing key (the realistic hand-edit mistake) must not load:
// strict parsing won't catch the omission, so Validate must.
func TestLoadRejectsOmittedTimingKeyViaValidate(t *testing.T) {
	m := validManifest()
	raw, err := json.Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	delete(obj["timing"].(map[string]any), "vault_delay_epochs")
	pruned, _ := json.Marshal(obj)

	var m2 Manifest
	if err := json.Unmarshal(pruned, &m2); err != nil {
		t.Fatalf("unmarshal (missing key should decode, not error): %v", err)
	}
	if err := m2.Validate(); err == nil {
		t.Fatal("Validate accepted a manifest missing vault_delay_epochs")
	}
}

func TestValidateRejectsUnknownVersionAndBadRoster(t *testing.T) {
	m := validManifest()
	m.Version = 999
	if err := m.Validate(); err == nil {
		t.Error("Validate accepted an unsupported version")
	}

	m = validManifest()
	m.Roster = nil
	if err := m.Validate(); err == nil {
		t.Error("Validate accepted an empty roster")
	}

	m = validManifest()
	m.Roster[1].Pubkey = m.Roster[0].Pubkey // duplicate
	if err := m.Validate(); err == nil {
		t.Error("Validate accepted a duplicate roster pubkey")
	}
}

func TestSelfAndPeers(t *testing.T) {
	m := validManifest()
	self, ok := m.Self(strings.ToUpper(m.Roster[1].Pubkey)) // case-insensitive
	if !ok || self.URL != "http://10.0.0.2:30303" {
		t.Fatalf("Self did not resolve roster[1] case-insensitively: ok=%v self=%+v", ok, self)
	}
	if _, ok := m.Self("00" + strings.Repeat("99", 32)); ok {
		t.Error("Self matched a key not in the roster")
	}
	peers := m.PeersExcluding(m.Roster[0].Pubkey)
	if len(peers) != 1 || peers[0] != "http://10.0.0.2:30303" {
		t.Fatalf("PeersExcluding wrong: %v", peers)
	}
	if p := PortFor(&m.Roster[0]); p != "30303" {
		t.Errorf("PortFor = %q, want 30303", p)
	}
}

// Every economic scalar is fork-critical: an omitted key decodes to 0 and would silently
// change the fee/floor/threshold the validator enforces. Each is asserted individually.
func TestValidateRejectsZeroEconomicField(t *testing.T) {
	cases := map[string]func(*Economics){
		"min_fee":                        func(e *Economics) { e.MinFee = 0 },
		"max_fee":                        func(e *Economics) { e.MaxFee = 0 },
		"attested_escrow_fee":            func(e *Economics) { e.AttestedEscrowFee = 0 },
		"fee_bps":                        func(e *Economics) { e.FeeBps = 0 },
		"banker_stake_floor_anos":        func(e *Economics) { e.BankerStakeFloorAnos = 0 },
		"attestor_stake_floor_anos":      func(e *Economics) { e.AttestorStakeFloorAnos = 0 },
		"guardian_divisor_anos":          func(e *Economics) { e.GuardianDivisorAnos = 0 },
		"guardian_send_threshold_bps":    func(e *Economics) { e.GuardianSendThresholdBps = 0 },
		"guardian_fund_send_epoch_slack": func(e *Economics) { e.GuardianFundSendEpochSlackEpochs = 0 },
	}
	for name, zero := range cases {
		m := validManifest()
		zero(&m.Economics)
		if err := m.Validate(); err == nil {
			t.Errorf("Validate accepted a manifest with economics.%s=0 (must reject)", name)
		}
	}
}

// The structural relations MinFee<=MaxFee, bps<=10000, and slack<window are enforced.
func TestValidateRejectsEconomicRelations(t *testing.T) {
	m := validManifest()
	m.Economics.MinFee = m.Economics.MaxFee + 1
	if err := m.Validate(); err == nil {
		t.Error("Validate accepted min_fee > max_fee")
	}

	m = validManifest()
	m.Economics.FeeBps = 10_001
	if err := m.Validate(); err == nil {
		t.Error("Validate accepted fee_bps > 10000")
	}

	m = validManifest()
	m.Economics.GuardianSendThresholdBps = 10_001
	if err := m.Validate(); err == nil {
		t.Error("Validate accepted guardian_send_threshold_bps > 10000")
	}

	m = validManifest()
	m.Economics.GuardianFundSendEpochSlackEpochs = m.Timing.GuardianActiveWindowEpochs // not <
	if err := m.Validate(); err == nil {
		t.Error("Validate accepted slack >= guardian_active_window_epochs")
	}

	// An anos-denominated scalar large enough to overflow scalar*UnitsPerAnos in the engine must be
	// rejected — a Validate-passing manifest must never divide-by-zero / mis-scale a floor.
	for _, over := range []func(*Economics){
		func(e *Economics) { e.GuardianDivisorAnos = 288230376151711744 }, // 2^58 -> *1e6 wraps to 0
		func(e *Economics) { e.BankerStakeFloorAnos = 1_000_000_000_001 },
		func(e *Economics) { e.AttestorStakeFloorAnos = 2_000_000_000_000 },
	} {
		m = validManifest()
		over(&m.Economics)
		if err := m.Validate(); err == nil {
			t.Error("Validate accepted an over-large anos scalar (overflow risk)")
		}
	}
}

// Both quorum percents must be a real majority (> 50) and <= 100; the scan cap >= 1.
func TestValidateRejectsBadConsensus(t *testing.T) {
	for _, bad := range []int{0, 50, 101} {
		m := validManifest()
		m.Consensus.QuorumPercent = bad
		if err := m.Validate(); err == nil {
			t.Errorf("Validate accepted quorum_percent=%d", bad)
		}
		m = validManifest()
		m.Consensus.FinalizationQuorumPercent = bad
		if err := m.Validate(); err == nil {
			t.Errorf("Validate accepted finalization_quorum_percent=%d", bad)
		}
	}
	m := validManifest()
	m.Consensus.MaxCandidateScanPerSlot = 0
	if err := m.Validate(); err == nil {
		t.Error("Validate accepted max_candidate_scan_per_slot=0")
	}
}

// A manifest targeting a protocol_version the binary does not implement must refuse to boot.
func TestValidateRejectsUnsupportedProtocolVersion(t *testing.T) {
	m := validManifest()
	m.ProtocolVersion = SupportedProtocolVersion + 1
	if err := m.Validate(); err == nil {
		t.Error("Validate accepted an unsupported protocol_version")
	}
}
