package config

import (
	"bytes"
	"strings"
	"testing"
)

// wantCanonicalNetworkID pins the exact network_id of validManifest(). If this changes, the
// canonical preimage layout changed — which is a DELIBERATE flag day (every existing manifest's
// id shifts, peers on the old layout are rejected). Re-pin it ONLY when that is intended, and
// bump SupportedProtocolVersion alongside. A surprise diff here means an accidental,
// fork-inducing change to canonicalBytes().
//
// forquinn INTERIM re-pin (phase 2): the timing block gained guarded_send_min_interval_epochs
// (appended last), an intended preimage-layout change. The paired version/domain bumps (D10:
// SupportedProtocolVersion 1→2, schema 2→3, ANOS_MANIFEST_V2 domain) land together in the
// phase-6 cutover, which re-pins this once more — nothing ships between phases.
const wantCanonicalNetworkID = "fe7bb2d3f8b54435a01780374e724a9355a49ac8376ba3be700146c1caf20e04"

func TestNetworkIDPinned(t *testing.T) {
	m := validManifest()
	got, err := ComputeNetworkID(&m)
	if err != nil {
		t.Fatalf("ComputeNetworkID: %v", err)
	}
	if got != wantCanonicalNetworkID {
		t.Fatalf("network_id drifted: got %s, want %s\n"+
			"if this is an intended preimage/scalar change, re-pin wantCanonicalNetworkID and bump SupportedProtocolVersion",
			got, wantCanonicalNetworkID)
	}
}

// The id is deterministic and the NetworkID field itself is EXCLUDED from the preimage
// (Load recomputes it; the file value is only a tripwire, never an input).
func TestNetworkIDExcludesItselfAndIsDeterministic(t *testing.T) {
	m := validManifest()
	id1, err := ComputeNetworkID(&m)
	if err != nil {
		t.Fatal(err)
	}
	m.NetworkID = "deadbeef" // must not affect the hash
	id2, err := ComputeNetworkID(&m)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("network_id changed when the NetworkID field changed: %s vs %s (field must be excluded)", id1, id2)
	}
}

// Roster ORDER must not affect the id (the preimage sorts by consensus pubkey), so two
// operators listing the same validators in a different order get the same network_id.
func TestNetworkIDRosterOrderIndependent(t *testing.T) {
	m := validManifest()
	id1, err := ComputeNetworkID(&m)
	if err != nil {
		t.Fatal(err)
	}
	// reverse the roster
	r := m.Roster
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	id2, err := ComputeNetworkID(&m)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("network_id depends on roster order: %s vs %s", id1, id2)
	}
}

// Changing ANY hashed scalar changes the id — a differently-tuned network is a different id.
func TestNetworkIDCoversEveryScalarClass(t *testing.T) {
	base := validManifest()
	baseID, _ := ComputeNetworkID(&base)
	mutators := map[string]func(*Manifest){
		"protocol_version":  func(m *Manifest) { m.ProtocolVersion = 999 }, // hashed even though Validate would reject
		"kat_digest":        func(m *Manifest) { m.KatDigest = "aa" },
		"timing.epoch_ms":   func(m *Manifest) { m.Timing.EpochMs = 3000 },
		"economics.min_fee": func(m *Manifest) { m.Economics.MinFee = 2 },
		"economics.floor":   func(m *Manifest) { m.Economics.BankerStakeFloorAnos = 60_000 },
		"consensus.quorum":  func(m *Manifest) { m.Consensus.QuorumPercent = 81 },
		"consensus.scan":    func(m *Manifest) { m.Consensus.MaxCandidateScanPerSlot = 128 },
		"genesis.supply":    func(m *Manifest) { m.Genesis.SupplyUnits += 1 },
		"roster.url":        func(m *Manifest) { m.Roster[0].URL = "http://10.9.9.9:30303" },
	}
	for name, mut := range mutators {
		m := validManifest()
		mut(&m)
		id, err := ComputeNetworkID(&m)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if id == baseID {
			t.Errorf("network_id unchanged after mutating %s (field is not in the preimage)", name)
		}
	}
}

// The preimage is FROM-STRUCT: it starts with the domain tag and length-frames the head
// fields exactly (version, protocol_version, empty kat, 32-byte fund id). This documents the
// framing and catches a head-layout regression with a clearer signal than the opaque hash.
func TestCanonicalPreimageHead(t *testing.T) {
	m := validManifest()
	enc, err := m.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(enc), networkIDDomain) {
		t.Fatalf("preimage does not start with the domain tag %q", networkIDDomain)
	}
	var want bytes.Buffer
	want.WriteString(networkIDDomain)
	putU32(&want, uint32(SupportedVersion))         // version = 2
	putU32(&want, uint32(SupportedProtocolVersion)) // protocol_version = 1
	putU32(&want, 0)                                // kat_digest: 0-length frame
	putU32(&want, 32)                               // fund_account: 32-byte frame length
	for i := 0; i < 32; i++ {
		want.WriteByte(0xff) // fund id = ff..ff
	}
	if !bytes.HasPrefix(enc, want.Bytes()) {
		t.Fatalf("canonical preimage head mismatch:\n got %x\nwant prefix %x", enc[:want.Len()], want.Bytes())
	}
}
