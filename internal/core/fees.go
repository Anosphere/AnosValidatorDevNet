package core

// Monetary base units:
// 1 Anos = 1,000,000 units
const (
	UnitsPerAnos uint64 = 1_000_000

	// Fee policy (SEND only):
	// 0.5% with min 0.001 Anos and max 3 Anos
	MinFee uint64 = 1_000            // 0.001 Anos
	MaxFee uint64 = 3 * UnitsPerAnos // 3 Anos

	// AttestedEscrowFee is the additional fee for an ATTESTED escrow (spec-18 §5.6.4, P3.3).
	// It is charged at funding — deducted from the escrow's credited balance at the opening
	// RECEIVE and credited to the Fund — on top of the normal first-hop send fee the funder
	// already paid on the funding SEND. (It cannot be charged on the funding SEND itself: at
	// SEND time the escrow does not yet exist, so a validator cannot tell the destination is an
	// attested escrow; the attested flag is only known at the opening RECEIVE.) A plain escrow
	// pays nothing extra.
	AttestedEscrowFee uint64 = 100_000 // 0.1 Anos

	// feeBps is the SEND fee rate in basis points (50 bps = 0.5%). Used by the client-side
	// ExpectedFee below.
	feeBps uint64 = 50
)

// Fee policy, source-of-truth note (P7.2): the VALIDATOR requires a fee via
// Economics.RequiredFee, whose fields come from the network manifest (so network_id reflects
// the fee schedule the validator enforces). The consts above + ExpectedFee below are the
// CLIENT-side reference calculator used by the simulators/tools to attach a correct fee to a
// SEND; a client that computes a wrong fee only gets its own tx rejected (never a fork).
// TestRequiredFeeMatchesExpectedFee pins that the two agree, and the live harness exercises
// real sims against a manifest-booted validator end-to-end.

// ExpectedFee computes the CLIENT-side reference fee for a SEND amount, in base units:
// clamp(ceil(amount * feeBps / 10000), MinFee, MaxFee). It mirrors Economics.RequiredFee
// exactly (same bps formula) so a sim's attached fee matches what the validator requires.
func ExpectedFee(amount uint64) uint64 {
	fee := (amount*feeBps + 9_999) / 10_000 // ceil of amount*feeBps/10000

	if fee < MinFee {
		fee = MinFee
	}
	if fee > MaxFee {
		fee = MaxFee
	}
	return fee
}
