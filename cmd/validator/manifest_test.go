package main

// P7.4 non-roster ("non-founder") boot: a consensus key OUTSIDE the manifest roster must be able to
// load the manifest (same network_id!), deriving PEERS = the FULL roster, with an explicit port
// required (the roster cannot supply one). This is the open-net join path — boot, resync-follow,
// stake Banker, become a member post-flip — and was a hard refusal pre-P7.4.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"anos/internal/config"
	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// writeTestKey generates a P-256 key file (hex-D form, as _livesetup writes) and returns its
// compressed-pubkey hex.
func writeTestKey(t *testing.T, path string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	var d [32]byte
	priv.D.FillBytes(d[:])
	if err := os.WriteFile(path, []byte(hex.EncodeToString(d[:])), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	comp := crypto.CompressP256PublicKey(&priv.PublicKey)
	return hex.EncodeToString(comp[:])
}

// writeTestManifest builds a minimal-but-valid manifest whose roster holds the given pubkeys.
func writeTestManifest(t *testing.T, dir string, rosterPubs []string) string {
	t.Helper()
	var seed [32]byte
	_, genPub := crypto.GenerateHybridKeyFromSeed(seed)
	genID := crypto.BaseAccountID(crypto.AccountTypeByteForClass(pb.AccountClass_ACCOUNT_CLASS_SPENDING), genPub.Encode())

	m := config.Manifest{
		Version:         config.SupportedVersion,
		ProtocolVersion: config.SupportedProtocolVersion,
		FundAccountHex:  strings.Repeat("ff", 32),
		Timing: config.Timing{
			EpochMs: 2000, TimelockedDelayEpochs: 6, GuardianActiveWindowEpochs: 20,
			StakeLock1moEpochs: 4, StakeLock1yrEpochs: 8, GuardedDelayEpochs: 8, VaultDelayEpochs: 12,
			AttestorQuorumM: 2, EscrowAttestationDelayEpochs: 6, BreakglassExtraEpochs: 5,
		},
		Economics: config.Economics{
			MinFee: 1_000, MaxFee: 3_000_000, AttestedEscrowFee: 100_000, FeeBps: 50,
			BankerStakeFloorAnos: 50_000, AttestorStakeFloorAnos: 5_000,
			GuardianDivisorAnos: 2_000, GuardianSendThresholdBps: 7_000, GuardianFundSendEpochSlackEpochs: 8,
		},
		Consensus: config.Consensus{QuorumPercent: 80, FinalizationQuorumPercent: 60, MaxCandidateScanPerSlot: 64},
		Genesis: config.Genesis{
			Hex: hex.EncodeToString(genID[:]), AuthPubkeyHex: hex.EncodeToString(genPub.Encode()),
			UnixMs: 1_700_000_000_000, SupplyUnits: 1_000_000,
		},
	}
	for i, p := range rosterPubs {
		m.Roster = append(m.Roster, config.Node{Pubkey: p, URL: "http://127.0.0.1:909" + string(rune('0'+i))})
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("test manifest invalid: %v", err)
	}
	path := filepath.Join(dir, "manifest.json")
	data, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

func TestLoadManifestNonRosterBoot(t *testing.T) {
	dir := t.TempDir()

	rosterPub0 := writeTestKey(t, filepath.Join(dir, "val0.key"))
	rosterPub1 := writeTestKey(t, filepath.Join(dir, "val1.key"))
	_ = writeTestKey(t, filepath.Join(dir, "val3.key")) // NOT in the roster
	maniPath := writeTestManifest(t, dir, []string{rosterPub0, rosterPub1})

	// Non-roster key + no port → a clear refusal naming the requirement.
	t.Setenv("VALIDATOR_KEY_PATH", filepath.Join(dir, "val3.key"))
	t.Setenv("PORT", "")
	t.Setenv("PEERS", "")
	t.Setenv("VALIDATOR_IDENTITY_HEX", "")
	if _, err := loadManifest(maniPath); err == nil || !strings.Contains(err.Error(), "-port") {
		t.Fatalf("non-roster boot without a port must fail mentioning -port, got %v", err)
	}

	// Non-roster key + explicit port → boots, PEERS = the FULL roster.
	t.Setenv("PORT", "9093")
	m, err := loadManifest(maniPath)
	if err != nil {
		t.Fatalf("non-roster boot with a port must succeed: %v", err)
	}
	peers := os.Getenv("PEERS")
	if !strings.Contains(peers, "9090") || !strings.Contains(peers, "9091") {
		t.Fatalf("non-roster PEERS must be the full roster, got %q", peers)
	}
	if m.NetworkID == "" {
		t.Fatalf("manifest must carry its computed network_id")
	}

	// A roster member still self-locates and derives its port.
	t.Setenv("VALIDATOR_KEY_PATH", filepath.Join(dir, "val1.key"))
	t.Setenv("PORT", "")
	if _, err := loadManifest(maniPath); err != nil {
		t.Fatalf("roster boot must still work: %v", err)
	}
	if p := os.Getenv("PORT"); p != "9091" {
		t.Fatalf("roster member should derive PORT from its URL, got %q", p)
	}
	if peers := os.Getenv("PEERS"); strings.Contains(peers, "9091") || !strings.Contains(peers, "9090") {
		t.Fatalf("roster member PEERS must exclude self, got %q", peers)
	}
}

// TestClampFinRange pins the P7.4 ranged /sync/finalization bound, incl. the CRITICAL uint64
// overflow (from=0&to=MaxUint64): the span `to-from+1` wraps to 0, so the tip clamp is what caps
// the work — the window clamp alone would be bypassed.
func TestClampFinRange(t *testing.T) {
	const span = maxFinRangeSpan
	cases := []struct {
		name             string
		from, to, latest uint64
		wantTo           uint64
	}{
		{"overflow-to-maxuint", 0, ^uint64(0), 500, 500},          // clamp to tip 500 (<span) — no spin
		{"overflow-huge-tip", 0, ^uint64(0), 10 * span, span - 1}, // clamp to tip then to the span window
		{"normal-within-span", 100, 200, 100000, 200},             // untouched
		{"normal-over-span", 100, 100000, 100000, 100 + span - 1}, // window-clamped
		{"to-beyond-tip", 10, 50, 30, 30},                         // clamp to tip
		{"from-beyond-tip", 100, 200, 50, 50},                     // to<from after clamp → loop runs 0x
		{"exactly-span", 0, span - 1, 100000, span - 1},           // boundary: unchanged
		{"one-over-span", 0, span, 100000, span - 1},              // boundary: clamped
	}
	for _, c := range cases {
		if got := clampFinRange(c.from, c.to, c.latest); got != c.wantTo {
			t.Errorf("%s: clampFinRange(%d,%d,%d)=%d, want %d", c.name, c.from, c.to, c.latest, got, c.wantTo)
		}
		// Invariant: the resulting iteration count is always bounded by the span (the DoS property).
		to := clampFinRange(c.from, c.to, c.latest)
		if to >= c.from && to-c.from >= span {
			t.Errorf("%s: span %d not bounded by %d", c.name, to-c.from+1, span)
		}
	}
}
