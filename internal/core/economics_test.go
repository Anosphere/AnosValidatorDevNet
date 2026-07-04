package core

import (
	"testing"

	"anos/internal/config"
)

// testEcon is the canonical Economics used across core tests — the exact values the shipped
// manifests carry (config/testnet.json and the run_livetest harness). Its fee fields ARE the
// client-side fees.go consts by construction, so TestRequiredFeeMatchesExpectedFee proves the
// validator's manifest-driven fee and the client's reference calculator agree.
var testEcon = Economics{
	MinFee:                           MinFee,
	MaxFee:                           MaxFee,
	AttestedEscrowFee:                AttestedEscrowFee,
	FeeBps:                           feeBps,
	BankerStakeFloorAnos:             50_000,
	AttestorStakeFloorAnos:           5_000,
	GuardianDivisorAnos:              2_000,
	GuardianSendThresholdBps:         7_000,
	GuardianFundSendEpochSlackEpochs: 8,
}

// TestRequiredFeeMatchesExpectedFee pins that the two fee IMPLEMENTATIONS agree in shape: the
// validator's Economics.RequiredFee and the client-side ExpectedFee compute the identical
// clamp(ceil(amt*bps/10000),Min,Max) across the clamp boundaries. (Because testEcon's fee fields ARE
// the fees.go consts, this can only catch a divergence between the two METHOD BODIES — a change to one
// formula but not the other. The manifest-VALUE drift axis is guarded by
// TestShippedManifestFeesMatchClientConsts below.)
func TestRequiredFeeMatchesExpectedFee(t *testing.T) {
	for _, amt := range []uint64{0, 1, 999, 1000, 200_000, 1_000_000, 599_999_999, 600_000_000, 1 << 40} {
		if got, want := testEcon.RequiredFee(amt), ExpectedFee(amt); got != want {
			t.Errorf("RequiredFee(%d)=%d != ExpectedFee=%d", amt, got, want)
		}
	}
	if testEcon.AttestedEscrowFee != AttestedEscrowFee {
		t.Errorf("testEcon.AttestedEscrowFee=%d != AttestedEscrowFee=%d", testEcon.AttestedEscrowFee, AttestedEscrowFee)
	}
}

// TestShippedManifestFeesMatchClientConsts loads the COMMITTED testnet manifest and asserts its fee
// economics equal the fees.go client consts — the drift axis that actually matters. The validator
// requires Economics.RequiredFee (manifest values) under an exact-equality check (verify_apply.go),
// while every simulator/client attaches core.ExpectedFee (consts); if a manifest edit moves the fee
// schedule away from the consts (without also updating the consts + sims), mid-range SENDs get rejected
// network-wide. (The floors/divisor/threshold/slack have no client const to drift against — the
// manifest is their only source, so there is nothing to cross-check for them.)
func TestShippedManifestFeesMatchClientConsts(t *testing.T) {
	m, err := config.Load("../../config/testnet.json")
	if err != nil {
		t.Fatalf("load testnet.json: %v", err)
	}
	e := m.Economics
	if e.MinFee != MinFee || e.MaxFee != MaxFee || e.AttestedEscrowFee != AttestedEscrowFee || e.FeeBps != feeBps {
		t.Fatalf("testnet.json fee economics drifted from the fees.go client consts:\n manifest{min=%d max=%d attested=%d bps=%d}\n consts  {min=%d max=%d attested=%d bps=%d}\nupdate them together (and the sims), or the sims will attach fees a manifest-booted validator rejects",
			e.MinFee, e.MaxFee, e.AttestedEscrowFee, e.FeeBps, MinFee, MaxFee, AttestedEscrowFee, feeBps)
	}
	// End-to-end: the validator builds this Economics from the manifest; confirm its RequiredFee
	// reproduces the client ExpectedFee exactly.
	ec := Economics{MinFee: e.MinFee, MaxFee: e.MaxFee, AttestedEscrowFee: e.AttestedEscrowFee, FeeBps: e.FeeBps}
	for _, amt := range []uint64{1, 1000, 1_000_000, 600_000_000} {
		if ec.RequiredFee(amt) != ExpectedFee(amt) {
			t.Errorf("manifest RequiredFee(%d)=%d != client ExpectedFee=%d", amt, ec.RequiredFee(amt), ExpectedFee(amt))
		}
	}
}
