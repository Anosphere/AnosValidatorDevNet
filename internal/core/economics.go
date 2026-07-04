package core

// Economics bundles the consensus-critical monetary + role scalars that the network manifest
// pins (P7.2). Before P7.2 these were hardcoded Go consts (fees.go, fund_table.go); now the
// validator carries this struct on EngineConfig and Snapshot and READS every value at runtime,
// so network_id provably reflects what the validator enforces — nothing here is a hardcoded
// fallback. Amounts named "...Anos" are whole anos (scaled by UnitsPerAnos at comparison time,
// matching the retired consts). It is a plain value (copied into every snapshot), so the fee/
// role methods below are pure functions of the fields + their explicit arguments.
type Economics struct {
	// Fee schedule (SEND): RequiredFee = clamp(ceil(amount*FeeBps/10000), MinFee, MaxFee), in
	// base units. AttestedEscrowFee is the flat extra charged at an attested escrow's opening.
	MinFee            uint64
	MaxFee            uint64
	AttestedEscrowFee uint64
	FeeBps            uint64

	// Role floors + Guardian derivation. Floors/divisor are whole anos; the two Bps values are
	// basis points.
	BankerStakeFloorAnos             uint64
	AttestorStakeFloorAnos           uint64
	GuardianDivisorAnos              uint64
	GuardianSendThresholdBps         uint64
	GuardianFundSendEpochSlackEpochs uint64
}

// RequiredFee is the fee the VALIDATOR requires for a SEND of `amount` base units:
// clamp(ceil(amount * FeeBps / 10000), MinFee, MaxFee). It is byte-identical in shape to the
// client-side ExpectedFee (fees.go); TestRequiredFeeMatchesExpectedFee pins that they agree
// so a sim's attached fee is never rejected by a validator booted from a matching manifest.
func (ec Economics) RequiredFee(amount uint64) uint64 {
	fee := (amount*ec.FeeBps + 9_999) / 10_000 // ceil of amount*FeeBps/10000
	if fee < ec.MinFee {
		fee = ec.MinFee
	}
	if fee > ec.MaxFee {
		fee = ec.MaxFee
	}
	return fee
}

// unset reports whether this Economics is a zero value. A zero GuardianDivisorAnos would panic
// GuardianWeight (divide by zero) and zero floors would make everyone a Banker, so NewEngine
// fails closed rather than run with an empty economics (it is a manifest-required field).
func (ec Economics) unset() bool { return ec.GuardianDivisorAnos == 0 }
