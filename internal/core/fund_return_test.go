package core

// P2.3b return-stake + kick (spec-19 §6.2, build-plan §P2.3). Pins: a kick Fund SEND flips a
// stake to Kicked (dropping its Guardian weight); a return Fund SEND flips it to Returned, debits
// the Fund, and mints a TRANSFER-restricted receivable carrying the staker as key_source + the
// tier; the opened chain copies the STAKER's keys with an id created by the keyless Fund (distinct
// from a staker-originated transfer at the same nonce) and locks for the staked tier; a
// return/kick whose deposit row is absent defers via the retryable ErrUnknownStake. Uses simkit
// for tx construction (no import cycle: simkit imports crypto+proto, not core).

import (
	"bytes"
	"errors"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

// seedStakeRow writes an Active stake row directly (DB apply tests).
func seedStakeRow(t *testing.T, db *bbolt.DB, depositTxid, staker [32]byte, amount uint64, tier pb.StakeTimeDelay) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putStakeRecord(tx, depositTxid, StakeRecord{
			StakerID: staker, Amount: amount, TimeDelay: tier, Status: StakeStatusActive, StakedFor: "guardian",
		})
	}); err != nil {
		t.Fatalf("seed stake row: %v", err)
	}
}

func stakeStatusOf(t *testing.T, db *bbolt.DB, depositTxid [32]byte) (StakeStatus, bool) {
	t.Helper()
	var st StakeStatus
	var found bool
	_ = db.View(func(tx *bbolt.Tx) error {
		if r, ok := getStakeRecord(tx, depositTxid); ok {
			st, found = r.Status, true
		}
		return nil
	})
	return st, found
}

func seedFundWithBalance(t *testing.T, db *bbolt.DB, bal uint64) [32]byte {
	t.Helper()
	fh := seedFundRecord(t, db, testFund)
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, testFund, AccountRecord{Head: fh, Seq: 1, Balance: bal, Class: pb.AccountClass_ACCOUNT_CLASS_FUND})
	}); err != nil {
		t.Fatal(err)
	}
	return fh
}

// seedSimAccount stores a simkit account's record (keyed, SPENDING) so it can be a key source.
func seedSimAccount(t *testing.T, db *bbolt.DB, a *simkit.Account) {
	t.Helper()
	var head [32]byte
	head[0] = a.ID[0]
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, a.ID, AccountRecord{
			Head: head, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
			AuthPubKey: a.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), a.Commit...),
		})
	}); err != nil {
		t.Fatalf("seed sim account: %v", err)
	}
}

// --- apply: kick ---

func TestApplyKickFlipsStatusAndDropsWeight(t *testing.T) {
	db := newFundTestDB(t)
	fh := seedFundWithBalance(t, db, anosUnits(100_000))
	g := newGuardian(1)
	seedKeyedGuardian(t, db, g)
	var dtx [32]byte
	dtx[0] = 0xde
	seedStakeRow(t, db, dtx, g.id, anosUnits(6_000), oneYear) // weight 3 while active

	if w := GuardianWeight(listStakes(t, db), g.id); w != 3 {
		t.Fatalf("pre-kick weight = %d, want 3", w)
	}
	kick := buildFundSend(testFund, fh, 2, testFund, 0, 55, []*tGuardian{g})
	kick.GetSend().ReturnDepositTxid = &pb.Hash32{V: dtx[:]}
	if err := applyFundSend(t, db, kick, txidFor(testFund, 2)); err != nil {
		t.Fatalf("apply kick: %v", err)
	}
	st, ok := stakeStatusOf(t, db, dtx)
	if !ok || st != StakeStatusKicked {
		t.Fatalf("stake status = %v (ok %v), want Kicked", st, ok)
	}
	if w := GuardianWeight(listStakes(t, db), g.id); w != 0 {
		t.Errorf("post-kick weight = %d, want 0 (kicked stake excluded)", w)
	}
	// Fund balance unchanged (kick moves nothing).
	if bal := fundRecord(t, db, testFund).Balance; bal != anosUnits(100_000) {
		t.Errorf("fund balance changed by kick: %d", bal)
	}
}

// --- apply: return ---

func TestApplyReturnFlipsStatusDebitsAndMintsKeyedReceivable(t *testing.T) {
	db := newFundTestDB(t)
	fh := seedFundWithBalance(t, db, anosUnits(100_000))
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x53}, [32]byte{0x54})
	seedSimAccount(t, db, staker)
	var dtx [32]byte
	dtx[0] = 0xab
	amount := anosUnits(6_000)
	seedStakeRow(t, db, dtx, staker.ID, amount, oneYear)

	const fundSeq = 2
	chain := simkit.DerivedReturnChain(staker, testFund, fundSeq)
	g := newGuardian(1)
	ret := simkit.BuildFundReturnSend(testFund, fh, fundSeq, chain.ID, amount, 55, dtx)
	// apply does not verify the quorum, but recordGuardianActivity reads the entries; sign with g.
	signFundSend(ret, []*tGuardian{g})
	txid := txidFor(testFund, fundSeq)
	if err := applyFundSend(t, db, ret, txid); err != nil {
		t.Fatalf("apply return: %v", err)
	}

	// Stake → Returned; Fund debited by the amount.
	if st, ok := stakeStatusOf(t, db, dtx); !ok || st != StakeStatusReturned {
		t.Fatalf("stake status = %v (ok %v), want Returned", st, ok)
	}
	if bal := fundRecord(t, db, testFund).Balance; bal != anosUnits(94_000) {
		t.Errorf("fund balance = %d, want 94000 anos (debited 6000)", bal)
	}
	// Receivable minted to the chain id, carrying key_source=staker + return_tier + TRANSFER.
	rid := crypto.ReceivableIDFromTxID(txid)
	var rec pb.Receivable
	if err := db.View(func(tx *bbolt.Tx) error {
		raw, err := getReceivableRaw(tx, rid)
		if err != nil {
			return err
		}
		return proto.Unmarshal(raw, &rec)
	}); err != nil {
		t.Fatalf("return receivable missing: %v", err)
	}
	if !bytesEq32(rec.To.V, chain.ID) {
		t.Errorf("receivable To = %x, want chain id %x", rec.To.V[:4], chain.ID[:4])
	}
	if rec.RequiredDestClass != pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
		t.Errorf("return receivable RequiredDestClass = %v, want TRANSFER", rec.RequiredDestClass)
	}
	if rec.KeySourceId == nil || !bytesEq32(rec.KeySourceId.V, staker.ID) {
		t.Errorf("return receivable key_source = %v, want staker %x", rec.KeySourceId, staker.ID[:4])
	}
	if rec.ReturnTier != oneYear {
		t.Errorf("return receivable tier = %v, want 1yr", rec.ReturnTier)
	}
}

func TestApplyReturnUnknownStakeIsRetryable(t *testing.T) {
	db := newFundTestDB(t)
	fh := seedFundWithBalance(t, db, anosUnits(100_000))
	g := newGuardian(1)
	var dtx [32]byte
	dtx[0] = 0x99 // no stake row seeded
	kick := buildFundSend(testFund, fh, 2, testFund, 0, 55, []*tGuardian{g})
	kick.GetSend().ReturnDepositTxid = &pb.Hash32{V: dtx[:]}
	err := applyFundSend(t, db, kick, txidFor(testFund, 2))
	if !errors.Is(err, ErrUnknownStake) {
		t.Fatalf("apply with absent stake row = %v, want ErrUnknownStake (retryable)", err)
	}
}

// --- the return chain's id derivation (creator = Fund, keys = staker) ---

func TestReturnChainIDCreatorIsFundNotStaker(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x11}, [32]byte{0x22})
	const nonce = 7
	returnChain := simkit.DerivedReturnChain(staker, testFund, nonce)
	// A staker-originated transfer at the SAME nonce derives with creator = staker id.
	stakerOriginated := simkit.DerivedTransferAccount(staker, nonce)
	if returnChain.ID == stakerOriginated.ID {
		t.Fatal("return-chain id (creator=Fund) must differ from a staker-originated transfer id (creator=staker) at the same nonce")
	}
	// Sanity: the return chain id equals the direct derivation with creator=Fund.
	want := crypto.DerivedAccountID(crypto.AccountTypeTransfer, staker.AuthPubKeyBytes(), testFund, nonce)
	if returnChain.ID != want {
		t.Fatalf("return chain id %x != DerivedAccountID(..., Fund, nonce) %x", returnChain.ID[:4], want[:4])
	}
}

// --- validate: return-stake gating ---

// returnValidateSetup builds a snapshot with the Fund seeded, a guardian able to authorize, and an
// active stake by `staker`. Returns the snapshot and the deposit_txid.
func returnValidateSetup(t *testing.T, staker *simkit.Account, g *tGuardian, amount uint64, tier pb.StakeTimeDelay) (*Snapshot, [32]byte, [32]byte) {
	t.Helper()
	var fundHead [32]byte
	fundHead[0] = 0xfd
	var dtx [32]byte
	dtx[0] = 0xcd
	rows := []StakeRow{
		guardianStake(g, 0x10, 8_000), // the authorizer (weight 4)
		{DepositTxid: dtx, StakeRecord: StakeRecord{StakerID: staker.ID, Amount: amount, TimeDelay: tier, Status: StakeStatusActive, StakedFor: "guardian"}},
	}
	snap := snapWithGuardians(testFund, fundHead, 1, rows, 0 /*M=0 bootstrap*/, g)
	snap.StakeLock1moEpochs = 4
	snap.StakeLock1yrEpochs = 8
	// The staker must be key-registered in the snapshot (for the derived id).
	snap.Accounts[staker.ID] = AccountSnap{Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: staker.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), staker.Commit...)}
	return snap, fundHead, dtx
}

func TestValidateReturnEnforcesDerivedDestAndAmount(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x31}, [32]byte{0x32})
	g := newGuardian(1)
	amount := anosUnits(6_000)
	snap, fundHead, dtx := returnValidateSetup(t, staker, g, amount, oneYear)
	const fundSeq = 2
	chain := simkit.DerivedReturnChain(staker, testFund, fundSeq)

	// Correct return → accepted.
	ok := simkit.BuildFundReturnSend(testFund, fundHead, fundSeq, chain.ID, amount, snap.Epoch, dtx)
	signFundSend(ok, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(ok, snap); err != nil {
		t.Fatalf("valid return rejected: %v", err)
	}

	// Wrong destination (not the derived chain id) → rejected.
	badDest := simkit.BuildFundReturnSend(testFund, fundHead, fundSeq, [32]byte{0xbe, 0xef}, amount, snap.Epoch, dtx)
	signFundSend(badDest, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(badDest, snap); err == nil {
		t.Error("return to a non-derived destination accepted")
	}

	// Wrong amount (≠ staked amount) → rejected.
	badAmt := simkit.BuildFundReturnSend(testFund, fundHead, fundSeq, chain.ID, amount+1, snap.Epoch, dtx)
	signFundSend(badAmt, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(badAmt, snap); err == nil {
		t.Error("return with wrong amount accepted")
	}
}

func TestValidateKickRequiresZeroAmount(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x41}, [32]byte{0x42})
	g := newGuardian(1)
	snap, fundHead, dtx := returnValidateSetup(t, staker, g, anosUnits(6_000), oneYear)

	// Kick with zero amount → accepted.
	ok := simkit.BuildFundKickSend(testFund, fundHead, 2, snap.Epoch, dtx)
	signFundSend(ok, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(ok, snap); err != nil {
		t.Fatalf("valid kick rejected: %v", err)
	}
	// Kick with nonzero amount → rejected.
	bad := simkit.BuildFundKickSend(testFund, fundHead, 2, snap.Epoch, dtx)
	bad.GetSend().Amount = 1
	signFundSend(bad, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(bad, snap); err == nil {
		t.Error("kick with nonzero amount accepted")
	}
}

// A return/kick must not also carry stake-deposit fields (would otherwise append a spurious row).
func TestValidateReturnKickRejectsStakeFields(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x71}, [32]byte{0x72})
	g := newGuardian(1)
	snap, fundHead, dtx := returnValidateSetup(t, staker, g, anosUnits(6_000), oneYear)
	kick := simkit.BuildFundKickSend(testFund, fundHead, 2, snap.Epoch, dtx)
	kick.GetSend().StakedFor = "guardian"
	kick.GetSend().TimeDelay = oneYear
	signFundSend(kick, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(kick, snap); err == nil {
		t.Error("kick carrying stake-deposit fields accepted (must be rejected)")
	}
}

// --- validate: P5.4 C2 generalized return (dest = a new beneficiary B) + owner_auth ---

// setupC2 extends returnValidateSetup with a base-owner beneficiary B registered in the snapshot and
// the B-keyed return chain. Returns the snapshot, fund head, deposit_txid, and the chain.
func setupC2(t *testing.T, staker, bene *simkit.Account, g *tGuardian, amount uint64, fundSeq uint64) (*Snapshot, [32]byte, [32]byte, *simkit.Account) {
	t.Helper()
	snap, fundHead, dtx := returnValidateSetup(t, staker, g, amount, oneYear)
	snap.Accounts[bene.ID] = AccountSnap{Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: bene.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), bene.Commit...)}
	chain := simkit.DerivedReturnChain(bene, testFund, fundSeq) // the chain copies B's keys
	return snap, fundHead, dtx, chain
}

func TestValidateGeneralizedReturnToBeneficiary(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x81}, [32]byte{0x82})
	bene := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x83}, [32]byte{0x84})
	g := newGuardian(1)
	amount := anosUnits(6_000)
	const fundSeq = 2
	snap, fundHead, dtx, chain := setupC2(t, staker, bene, g, amount, fundSeq)

	build := func(oa *pb.StakeOwnerAuth) *pb.Tx {
		tx := simkit.BuildFundGeneralizedReturnSend(testFund, fundHead, fundSeq, chain.ID, amount, snap.Epoch, dtx, bene.ID, 5, oa)
		signFundSend(tx, []*tGuardian{g})
		return tx
	}

	// Correct C2 return with the owner's (auth-key) owner_auth → accepted; chain copies B's keys.
	if _, err := ValidateTxAgainstSnapshot(build(staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, dtx, bene.ID, false)), snap); err != nil {
		t.Fatalf("valid generalized return rejected: %v", err)
	}
	// Missing owner_auth → rejected (a quorum can enact but never redirect).
	if _, err := ValidateTxAgainstSnapshot(build(nil), snap); err == nil {
		t.Error("generalized return without owner_auth accepted (theft guard breached)")
	}
	// owner_auth signed by a NON-owner (B signs) → rejected.
	if _, err := ValidateTxAgainstSnapshot(build(bene.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, dtx, bene.ID, false)), snap); err == nil {
		t.Error("generalized return with a non-owner owner_auth accepted")
	}
	// owner_auth bound to a DIFFERENT beneficiary (over staker.ID, tx redirects to bene) → rejected.
	if _, err := ValidateTxAgainstSnapshot(build(staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, dtx, staker.ID, false)), snap); err == nil {
		t.Error("generalized return with owner_auth bound to a different B accepted")
	}
	// owner_auth under the RE-ATTRIBUTE op (wrong op for a to!=Fund return) → rejected.
	if _, err := ValidateTxAgainstSnapshot(build(staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReattribute, dtx, bene.ID, false)), snap); err == nil {
		t.Error("generalized return with a re-attribution-op owner_auth accepted")
	}
	// owner_auth via the owner's BREAKGLASS key (auth key lost) → accepted.
	if _, err := ValidateTxAgainstSnapshot(build(staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, dtx, bene.ID, true)), snap); err != nil {
		t.Fatalf("generalized return via breakglass owner_auth rejected: %v", err)
	}
}

// A recovery return whose `to` is not derived from B's keys is rejected (the chain must copy B).
func TestValidateGeneralizedReturnEnforcesBeneficiaryKeyedDest(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x85}, [32]byte{0x86})
	bene := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x87}, [32]byte{0x88})
	g := newGuardian(1)
	amount := anosUnits(6_000)
	const fundSeq = 2
	snap, fundHead, dtx, _ := setupC2(t, staker, bene, g, amount, fundSeq)
	// Derive the chain from the STAKER's keys (wrong — a C2 return must key the chain to B).
	stakerChain := simkit.DerivedReturnChain(staker, testFund, fundSeq)
	oa := staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, dtx, bene.ID, false)
	tx := simkit.BuildFundGeneralizedReturnSend(testFund, fundHead, fundSeq, stakerChain.ID, amount, snap.Epoch, dtx, bene.ID, 5, oa)
	signFundSend(tx, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(tx, snap); err == nil {
		t.Error("generalized return whose dest is keyed to the staker (not B) accepted")
	}
}

// A beneficiary that is not a base-owner, key-registered account is rejected.
func TestValidateGeneralizedReturnRejectsNonBaseOwnerBeneficiary(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x89}, [32]byte{0x8a})
	bene := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x8b}, [32]byte{0x8c})
	g := newGuardian(1)
	amount := anosUnits(6_000)
	const fundSeq = 2
	snap, fundHead, dtx, chain := setupC2(t, staker, bene, g, amount, fundSeq)
	// Demote B to a TRANSFER account (not a base-owner class).
	snap.Accounts[bene.ID] = AccountSnap{Class: pb.AccountClass_ACCOUNT_CLASS_TRANSFER, AuthPubKey: bene.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), bene.Commit...)}
	oa := staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, dtx, bene.ID, false)
	tx := simkit.BuildFundGeneralizedReturnSend(testFund, fundHead, fundSeq, chain.ID, amount, snap.Epoch, dtx, bene.ID, 5, oa)
	signFundSend(tx, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(tx, snap); err == nil {
		t.Error("generalized return to a non-base-owner beneficiary accepted")
	}
}

// Stake-recovery fields on a non-return send are rejected (they are folded → txid-grindable).
func TestValidateRejectsStrayRecoveryFields(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x91}, [32]byte{0x92})
	g := newGuardian(1)
	snap, fundHead, dtx := returnValidateSetup(t, staker, g, anosUnits(6_000), oneYear)

	// A kick carrying recovery fields → rejected.
	kick := simkit.BuildFundKickSend(testFund, fundHead, 2, snap.Epoch, dtx)
	kick.GetSend().RecoveryBeneficiary = &pb.AccountId{V: staker.IDBytes()}
	signFundSend(kick, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(kick, snap); err == nil {
		t.Error("kick carrying recovery_beneficiary accepted")
	}

	// A plain Fund payout (to a user) carrying a stray owner_auth → rejected.
	payout := simkit.BuildFundSend(testFund, fundHead, 2, staker.ID, anosUnits(1), snap.Epoch)
	payout.GetSend().OwnerAuth = staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, dtx, staker.ID, false)
	signFundSend(payout, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(payout, snap); err == nil {
		t.Error("fund payout carrying a stray owner_auth accepted")
	}
}

// apply: a C2 generalized return stamps B as the key source + the Guardian-chosen delay.
func TestApplyGeneralizedReturnStampsBeneficiary(t *testing.T) {
	db := newFundTestDB(t)
	fh := seedFundWithBalance(t, db, anosUnits(100_000))
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x93}, [32]byte{0x94})
	bene := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x95}, [32]byte{0x96})
	seedSimAccount(t, db, staker)
	var dtx [32]byte
	dtx[0] = 0xac
	amount := anosUnits(6_000)
	seedStakeRow(t, db, dtx, staker.ID, amount, oneYear)

	const fundSeq = 2
	chain := simkit.DerivedReturnChain(bene, testFund, fundSeq)
	g := newGuardian(1)
	oa := staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, dtx, bene.ID, false)
	ret := simkit.BuildFundGeneralizedReturnSend(testFund, fh, fundSeq, chain.ID, amount, 55, dtx, bene.ID, 5, oa)
	signFundSend(ret, []*tGuardian{g})
	txid := txidFor(testFund, fundSeq)
	if err := applyFundSend(t, db, ret, txid); err != nil {
		t.Fatalf("apply generalized return: %v", err)
	}
	if st, ok := stakeStatusOf(t, db, dtx); !ok || st != StakeStatusReturned {
		t.Fatalf("stake status = %v (ok %v), want Returned", st, ok)
	}
	rid := crypto.ReceivableIDFromTxID(txid)
	var rec pb.Receivable
	if err := db.View(func(tx *bbolt.Tx) error {
		raw, err := getReceivableRaw(tx, rid)
		if err != nil {
			return err
		}
		return proto.Unmarshal(raw, &rec)
	}); err != nil {
		t.Fatalf("return receivable missing: %v", err)
	}
	if rec.KeySourceId == nil || !bytesEq32(rec.KeySourceId.V, bene.ID) {
		t.Errorf("key_source = %v, want beneficiary B %x", rec.KeySourceId, bene.ID[:4])
	}
	if rec.ReturnDelayEpochs != 5 {
		t.Errorf("return_delay_epochs = %d, want 5 (Guardian-chosen)", rec.ReturnDelayEpochs)
	}
}

// validate: a Guardian-chosen return_delay_epochs overrides the tier-lock on the opening RECEIVE.
func TestValidateReturnDelayEpochsOverridesTierLock(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x97}, [32]byte{0x98})
	g := newGuardian(1)
	amount := anosUnits(6_000)
	snap, _, _ := returnValidateSetup(t, staker, g, amount, oneYear) // tier-lock 1yr = 8
	const fundSeq = 2
	chain := simkit.DerivedReturnChain(staker, testFund, fundSeq)
	var rid [32]byte
	rid[0] = 0x78
	// Guardian chose a delay of 3 (shorter than the 8-epoch tier lock).
	snap.Receivables[rid] = ReceivableSnap{
		From: testFund, To: chain.ID, Amount: amount, RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
		FromSeq: fundSeq, KeySourceID: staker.ID, ReturnTier: oneYear, ReturnDelayEpochs: 3,
	}
	// unlock below creation+3 → rejected.
	low := simkit.BuildOpeningReceive(chain, rid, &staker.ID, snap.Epoch+2)
	chain.MustSign(low)
	if _, err := ValidateTxAgainstSnapshot(low, snap); err == nil {
		t.Error("opening RECEIVE below the Guardian-chosen delay accepted")
	}
	// unlock at creation+3 → accepted (the override, not the 8-epoch tier lock, governs).
	okrx := simkit.BuildOpeningReceive(chain, rid, &staker.ID, snap.Epoch+3)
	chain.MustSign(okrx)
	if _, err := ValidateTxAgainstSnapshot(okrx, snap); err != nil {
		t.Fatalf("opening RECEIVE at the Guardian-chosen delay rejected: %v", err)
	}
}

// TestBestEffortFundRecoveryGate pins the submit/gossip DoS closure for P5.4 recovery Fund SENDs: a
// Guardian-signed-but-never-finalizable variant (junk owner_auth, or a stray owner_auth on a kick) is
// rejected at the gate so it can't grind a low txid into the Fund's conflict slot; a legitimate return
// passes; a not-at-position tx defers (nil).
func TestBestEffortFundRecoveryGate(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t), newTValidator(t), newTValidator(t)})
	fund := e.cfg.FundAccount
	var fh [32]byte
	fh[0] = 0xfe
	g := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xa1}, [32]byte{0xa2})
	a := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xa3}, [32]byte{0xa4})
	b := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xa5}, [32]byte{0xa6})
	var aDep, gDep [32]byte
	aDep[0], gDep[0] = 0xda, 0xd6
	if err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		if err := putAccountRecord(tx, fund, AccountRecord{Head: fh, Seq: 1, Balance: anosUnits(100_000), Class: pb.AccountClass_ACCOUNT_CLASS_FUND}); err != nil {
			return err
		}
		putKeyed := func(acc *simkit.Account) error {
			var h [32]byte
			h[0] = acc.ID[0]
			return putAccountRecord(tx, acc.ID, AccountRecord{Head: h, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: acc.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), acc.Commit...)})
		}
		for _, acc := range []*simkit.Account{g, a, b} {
			if err := putKeyed(acc); err != nil {
				return err
			}
		}
		if err := putStakeRecord(tx, gDep, StakeRecord{StakerID: g.ID, Amount: anosUnits(8_000), TimeDelay: oneYear, Status: StakeStatusActive, StakedFor: "guardian"}); err != nil {
			return err
		}
		return putStakeRecord(tx, aDep, StakeRecord{StakerID: a.ID, Amount: anosUnits(6_000), TimeDelay: oneYear, Status: StakeStatusActive, StakedFor: "guardian"})
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const fundSeq = 2
	chain := simkit.DerivedReturnChain(b, fund, fundSeq)
	buildReturn := func(prev [32]byte, oa *pb.StakeOwnerAuth) *pb.Tx {
		tx := simkit.BuildFundGeneralizedReturnSend(fund, prev, fundSeq, chain.ID, anosUnits(6_000), 1, aDep, b.ID, 5, oa)
		if err := simkit.SignFundSend(tx, []*simkit.Account{g}); err != nil {
			t.Fatalf("sign: %v", err)
		}
		return tx
	}

	// Junk owner_auth (B signs, not the owner A) + a valid quorum → rejected at the gate.
	if err := e.bestEffortFundSendCheck(buildReturn(fh, b.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, aDep, b.ID, false))); err == nil {
		t.Fatal("recovery return with junk owner_auth accepted at the gate (DoS)")
	}
	// Legit owner_auth (A signs) → accepted.
	if err := e.bestEffortFundSendCheck(buildReturn(fh, a.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, aDep, b.ID, false))); err != nil {
		t.Fatalf("legit recovery return rejected at the gate: %v", err)
	}
	// Not at position (wrong prev) → defers (nil) even with junk owner_auth.
	var wrong [32]byte
	wrong[0] = 0xee
	if err := e.bestEffortFundSendCheck(buildReturn(wrong, b.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, aDep, b.ID, false))); err != nil {
		t.Fatalf("not-at-position recovery return must defer (nil): %v", err)
	}
	// A KICK carrying a stray owner_auth (valid quorum) → rejected.
	kick := simkit.BuildFundKickSend(fund, fh, fundSeq, 1, aDep)
	kick.GetSend().OwnerAuth = a.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReattribute, aDep, b.ID, false)
	if err := simkit.SignFundSend(kick, []*simkit.Account{g}); err != nil {
		t.Fatalf("sign kick: %v", err)
	}
	if err := e.bestEffortFundSendCheck(kick); err == nil {
		t.Fatal("kick with a stray owner_auth accepted at the gate (DoS)")
	}
}

// TestOwnerAuthNilVsEmptyNoAlias pins the fold-vs-validity consistency for owner_auth: a present-but-
// empty StakeOwnerAuth folds BYTE-IDENTICALLY to a nil one (appendStakeRecovery folds only Sig +
// RevealedBreakglassPubkey, by value), so they share a txid — therefore the validity classifier
// (hasStakeRecoveryFields / hasOwnerAuth) MUST treat them identically, else two honest nodes holding the
// two raws would validate the SAME txid differently (a consensus fork). Regression for the P5.4 review's
// CRITICAL finding.
func TestOwnerAuthNilVsEmptyNoAlias(t *testing.T) {
	from := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xe1}, [32]byte{0xe2})
	var prev [32]byte
	prev[0] = 0x01
	mk := func(oa *pb.StakeOwnerAuth) *pb.Tx {
		tx := simkit.BuildSend(from, prev, 2, [32]byte{0x09}, 100, ExpectedFee(100))
		tx.GetSend().OwnerAuth = oa
		return tx
	}
	nilTx := mk(nil)
	emptyTx := mk(&pb.StakeOwnerAuth{})
	// The fold is content-based → identical sign-bytes.
	sbNil, err := crypto.SignBytesACTE(nilTx)
	if err != nil {
		t.Fatalf("sign bytes (nil): %v", err)
	}
	sbEmpty, err := crypto.SignBytesACTE(emptyTx)
	if err != nil {
		t.Fatalf("sign bytes (empty): %v", err)
	}
	if !bytes.Equal(sbNil, sbEmpty) {
		t.Fatal("nil vs present-empty owner_auth must fold to identical sign-bytes")
	}
	// A signature valid for one is valid for the other (same digest) → they share a txid.
	from.MustSign(nilTx)
	emptyTx.Sig = nilTx.Sig
	idNil, err := crypto.TxID(nilTx)
	if err != nil {
		t.Fatalf("txid (nil): %v", err)
	}
	idEmpty, err := crypto.TxID(emptyTx)
	if err != nil {
		t.Fatalf("txid (empty): %v", err)
	}
	if idNil != idEmpty {
		t.Fatal("nil vs present-empty owner_auth must share a txid (they fold identically)")
	}
	// Therefore the validity classifier MUST agree for both (else same-txid divergent validity = fork).
	if hasStakeRecoveryFields(nilTx.GetSend()) != hasStakeRecoveryFields(emptyTx.GetSend()) {
		t.Fatal("hasStakeRecoveryFields must classify nil and present-empty owner_auth identically")
	}
	if hasOwnerAuth(emptyTx.GetSend()) {
		t.Fatal("present-empty owner_auth must classify as absent (matches the content-based fold)")
	}
}

// --- P5.4b C1 re-attribution (flip StakerID A→B in place) ---

func TestValidateReattribution(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xb1}, [32]byte{0xb2})
	bene := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xb3}, [32]byte{0xb4})
	g := newGuardian(1)
	snap, fundHead, dtx := returnValidateSetup(t, staker, g, anosUnits(6_000), oneYear)
	snap.Accounts[bene.ID] = AccountSnap{Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: bene.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), bene.Commit...)}

	build := func(oa *pb.StakeOwnerAuth, beneID [32]byte) *pb.Tx {
		tx := simkit.BuildFundReattributeSend(testFund, fundHead, 2, snap.Epoch, dtx, beneID, nil, "", oa)
		signFundSend(tx, []*tGuardian{g})
		return tx
	}
	// Valid re-attribution with the owner's (re-attribute op) owner_auth → accepted.
	if _, err := ValidateTxAgainstSnapshot(build(staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReattribute, dtx, bene.ID, false), bene.ID), snap); err != nil {
		t.Fatalf("valid re-attribution rejected: %v", err)
	}
	// Missing owner_auth → rejected (theft guard).
	if _, err := ValidateTxAgainstSnapshot(build(nil, bene.ID), snap); err == nil {
		t.Error("re-attribution without owner_auth accepted")
	}
	// owner_auth under the RETURN op (wrong for a to==Fund re-attribution) → rejected.
	if _, err := ValidateTxAgainstSnapshot(build(staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, dtx, bene.ID, false), bene.ID), snap); err == nil {
		t.Error("re-attribution with a return-op owner_auth accepted")
	}
	// Re-attribution naming the current staker (no-op redirect) → rejected.
	if _, err := ValidateTxAgainstSnapshot(build(staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReattribute, dtx, staker.ID, false), staker.ID), snap); err == nil {
		t.Error("re-attribution to the current staker accepted")
	}
	// A stray return_delay_epochs (re-attribution has no chain) → rejected.
	withDelay := simkit.BuildFundReattributeSend(testFund, fundHead, 2, snap.Epoch, dtx, bene.ID, nil, "", staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReattribute, dtx, bene.ID, false))
	withDelay.GetSend().ReturnDelayEpochs = 3
	signFundSend(withDelay, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(withDelay, snap); err == nil {
		t.Error("re-attribution carrying return_delay_epochs accepted")
	}
	// owner_auth via the owner's BREAKGLASS key → accepted.
	if _, err := ValidateTxAgainstSnapshot(build(staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReattribute, dtx, bene.ID, true), bene.ID), snap); err != nil {
		t.Fatalf("re-attribution via breakglass owner_auth rejected: %v", err)
	}
}

// apply: a C1 re-attribution flips StakerID A→B in place and B inherits the carried banker descriptor.
func TestApplyReattributionFlipsStakerAndInheritsBanker(t *testing.T) {
	db := newFundTestDB(t)
	fh := seedFundWithBalance(t, db, anosUnits(100_000))
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xc1}, [32]byte{0xc2})
	bene := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xc3}, [32]byte{0xc4})
	seedSimAccount(t, db, staker)
	seedSimAccount(t, db, bene)
	var dtx [32]byte
	dtx[0] = 0xbe
	amount := anosUnits(60_000) // >= the 50k banker floor
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putStakeRecord(tx, dtx, StakeRecord{StakerID: staker.ID, Amount: amount, TimeDelay: oneYear, Status: StakeStatusActive, StakedFor: StakedForBanker})
	}); err != nil {
		t.Fatal(err)
	}

	consKey := simkit.RandomConsensusKey()
	oa := staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReattribute, dtx, bene.ID, false)
	reat := simkit.BuildFundReattributeSend(testFund, fh, 2, 55, dtx, bene.ID, consKey, "b:9000", oa)
	signFundSend(reat, []*tGuardian{newGuardian(1)})
	if err := applyFundSend(t, db, reat, txidFor(testFund, 2)); err != nil {
		t.Fatalf("apply re-attribution: %v", err)
	}

	rows := listStakes(t, db)
	r, ok := findStakeRow(rows, dtx)
	if !ok || r.StakerID != bene.ID || r.Status != StakeStatusActive || r.Amount != amount || r.StakedFor != StakedForBanker {
		t.Fatalf("re-attributed row = %+v, want StakerID=B Active banker %d", r, amount)
	}
	if IsBanker(rows, staker.ID) {
		t.Error("A still IsBanker after re-attribution")
	}
	if !IsBanker(rows, bene.ID) {
		t.Error("B not IsBanker after re-attribution")
	}
	// Fund balance unchanged (re-attribution moves nothing).
	if bal := fundRecord(t, db, testFund).Balance; bal != anosUnits(100_000) {
		t.Errorf("fund balance changed by re-attribution: %d", bal)
	}
	// B inherited the carried descriptor at the sentinel seq 0, and is in the validator set.
	infos, _ := ListBankerInfo(db)
	var bi *BankerInfo
	for i := range infos {
		if infos[i].Identity == bene.ID {
			bi = &infos[i]
		}
	}
	if bi == nil || !bytes.Equal(bi.ConsensusKey, consKey) || bi.SendSeq != 0 || bi.Endpoint != "b:9000" {
		t.Fatalf("B descriptor = %+v, want carried key at seq 0", bi)
	}
	inSet := false
	for _, vd := range BankerValidatorSet(rows, infos) {
		if vd.Identity == bene.ID {
			inSet = true
		}
	}
	if !inSet {
		t.Error("B not in the Fund validator set after inheriting the descriptor")
	}
}

// The inherited seq-0 descriptor is order-independent: B's own deposit (seq >= 2) always wins, and a
// same-epoch inherited write never overrides it, regardless of apply order (the P4.1 BBankerInfo invariant).
func TestReattributionBankerDescriptorSeqZeroOrderIndependent(t *testing.T) {
	b := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xd1}, [32]byte{0xd2})
	inherited := simkit.RandomConsensusKey()
	own := simkit.RandomConsensusKey()
	writePair := func(k1 []byte, e1 string, s1 uint64, k2 []byte, e2 string, s2 uint64) BankerInfo {
		db := newFundTestDB(t)
		if err := db.Update(func(tx *bbolt.Tx) error {
			if err := recordBankerInfo(tx, b.ID, k1, e1, s1); err != nil {
				return err
			}
			return recordBankerInfo(tx, b.ID, k2, e2, s2)
		}); err != nil {
			t.Fatal(err)
		}
		infos, _ := ListBankerInfo(db)
		for _, bi := range infos {
			if bi.Identity == b.ID {
				return bi
			}
		}
		return BankerInfo{}
	}
	// inherited(seq 0) then own(seq 2), and own(seq 2) then inherited(seq 0): both → own at seq 2.
	fwd := writePair(inherited, "e-inh", 0, own, "e-own", 2)
	rev := writePair(own, "e-own", 2, inherited, "e-inh", 0)
	for _, got := range []BankerInfo{fwd, rev} {
		if !bytes.Equal(got.ConsensusKey, own) || got.SendSeq != 2 || got.Endpoint != "e-own" {
			t.Fatalf("own deposit must win over inherited seq-0 regardless of order: got %+v", got)
		}
	}
}

// --- validate: the return chain's opening RECEIVE (key copy + tier lock) ---

func TestValidateReturnChainOpeningReceive(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x61}, [32]byte{0x62})
	g := newGuardian(1)
	amount := anosUnits(6_000)
	snap, _, _ := returnValidateSetup(t, staker, g, amount, oneYear)
	const fundSeq = 2
	chain := simkit.DerivedReturnChain(staker, testFund, fundSeq)

	// Put the return receivable into the snapshot (as ApplyTx would have minted it).
	var rid [32]byte
	rid[0] = 0x77
	snap.Receivables[rid] = ReceivableSnap{
		From: testFund, To: chain.ID, Amount: amount, RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
		FromSeq: fundSeq, KeySourceID: staker.ID, ReturnTier: oneYear,
	}
	// The chain account does not yet exist (opening). snap.Epoch is 100; lock 1yr = 8.

	// unlock below creation+lock → rejected.
	low := simkit.BuildOpeningReceive(chain, rid, &staker.ID, snap.Epoch+7)
	chain.MustSign(low)
	if _, err := ValidateTxAgainstSnapshot(low, snap); err == nil {
		t.Error("opening RECEIVE with unlock below creation+STAKE_LOCK_1YR accepted")
	}
	// unlock at the minimum → accepted (chain copies the staker's keys; id matches creator=Fund).
	okrx := simkit.BuildOpeningReceive(chain, rid, &staker.ID, snap.Epoch+8)
	chain.MustSign(okrx)
	if _, err := ValidateTxAgainstSnapshot(okrx, snap); err != nil {
		t.Fatalf("valid return-chain opening RECEIVE rejected: %v", err)
	}
}
