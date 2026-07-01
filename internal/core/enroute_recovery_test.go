package core

// P5.5 en-route stake recovery (spec-18 §7.5, working notes §3.4 "(D) En-route stake").
//
// A stake RETURNED (P2.3b/P5.4) mints a TRANSFER-restricted receivable whose opening chain copies the
// STAKER's keys; if the staker LOST the auth key before draining it, the value is stranded on a chain
// only the (lost) staker key controls. P5.5 recovers it: the staker's BREAKGLASS key (1) OPENS the
// stuck return chain and (2) RETURNS it to the keyless Fund — UNGATED (mirroring P5.3), because the
// value only flows BACK to the safe pool. The chain threads the original deposit_txid (echoed from the
// authorizing Fund SEND's already-signed return_deposit_txid onto the receivable + TRANSFER_META), so
// ApplyTx marks the BFundStakes row Reverted. The real theft gate is the P5.4 C2 recovery to a new
// owner B (Guardian quorum + the owner's auth/breakglass sig), which flips Reverted → the terminal
// Recovered so the value can never be paid twice.
//
// P5.5 adds NO new signed field / SignBytesACTE / crypto.TxID change: the deposit_txid link is a
// validator-DERIVED echo of the already-folded Fund-SEND field, and the bg-open/return reuse the
// P5.1-folded revealed_breakglass_pubkey. So these tests exercise validate authority, the apply-time
// derived side-effects, the submit gate, and the on-disk round-trip — not a fold.

import (
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func addrPtr(x [32]byte) *[32]byte { return &x }

// fundSourcedChainSnap builds a snapshot with a Fund-sourced RETURN-STAKE transfer chain (copies the
// staker's keys, TransferSource == Fund) carrying return-deposit link `link` (zero to omit), plus the
// keyed staker (the chain's copied-key source, so return-to-source commitment binds pass).
func fundSourcedChainSnap(chain, staker *simkit.Account, chHead, dest [32]byte, unlock, bal, epoch uint64, link [32]byte) *Snapshot {
	return &Snapshot{
		Accounts: map[[32]byte]AccountSnap{
			chain.ID: {
				Head: chHead, Balance: bal, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
				TransferSource: testFund, TransferDest: dest, TransferUnlock: unlock,
				TransferReturnDepositTxid: link,
				AuthPubKey:                chain.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), chain.Commit...),
			},
			staker.ID: {Class: staker.Class, AuthPubKey: staker.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), staker.Commit...)},
		},
		Receivables:     map[[32]byte]ReceivableSnap{},
		Epoch:           epoch,
		FundAccount:     testFund,
		AttestorQuorumM: 2,
	}
}

// TestEnrouteBgReturnToFundValidate pins the P5.5 relaxation at the consensus authority: a revealed
// breakglass key MAY return a Fund-sourced return-stake chain to the (keyless) Fund when the chain
// carries the threaded return-deposit link; a link-LESS Fund-sourced chain is rejected (invariant),
// and a bg release-to-dest on such a chain stays rejected (breakglass-origin only).
func TestEnrouteBgReturnToFundValidate(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xe1}, [32]byte{0xe2})
	chain := simkit.DerivedReturnChain(staker, testFund, 7) // Fund-created chain copying the staker's keys
	var chHead, dtx [32]byte
	chHead[0], dtx[0] = 0xc0, 0xcd
	const unlock, bal, epoch = uint64(1000), uint64(6_000), uint64(5) // epoch << unlock: still locked

	// --- linked chain: the en-route recovery is accepted ---
	snap := fundSourcedChainSnap(chain, staker, chHead, staker.ID, unlock, bal, epoch, dtx)

	// POSITIVE: the staker's revealed breakglass key returns the chain to the Fund, well before unlock.
	ret := simkit.BuildSend(chain, chHead, 2, testFund, bal, 0)
	chain.MustSignBreakglass(ret)
	if _, err := ValidateTxAgainstSnapshot(ret, snap); err != nil {
		t.Fatalf("P5.5: breakglass return of a linked Fund-sourced chain must be accepted: %v", err)
	}

	// The auth key also returns to the Fund source (an owner cancel; the same state transition).
	authRet := simkit.BuildSend(chain, chHead, 2, testFund, bal, 0)
	chain.MustSign(authRet)
	if _, err := ValidateTxAgainstSnapshot(authRet, snap); err != nil {
		t.Fatalf("P5.5: auth-key return of a linked Fund-sourced chain must be accepted: %v", err)
	}

	// NEGATIVE: a forged revealed key (a stranger's) fails the chain-commitment bind.
	stranger := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xe3}, [32]byte{0xe4})
	forged := simkit.BuildSend(chain, chHead, 2, testFund, bal, 0)
	stranger.MustSignBreakglass(forged)
	if _, err := ValidateTxAgainstSnapshot(forged, snap); err == nil {
		t.Fatal("a forged breakglass return must be rejected (commitment mismatch)")
	}

	// NEGATIVE: a breakglass RELEASE-to-dest on a return-stake chain is rejected (breakglass-origin only;
	// a return-stake chain is Fund-origin, so release via a revealed key is never allowed).
	past := *snap
	past.Epoch = unlock + 1
	rel := simkit.BuildSend(chain, chHead, 2, staker.ID, bal, 0) // dest == staker
	chain.MustSignBreakglass(rel)
	if _, err := ValidateTxAgainstSnapshot(rel, &past); err == nil {
		t.Fatal("P5.5: a breakglass release-to-dest on a return-stake chain must be rejected (breakglass-origin only)")
	}

	// --- link-LESS Fund-sourced chain: rejected (invariant; every real return-stake chain threads it) ---
	nolink := fundSourcedChainSnap(chain, staker, chHead, staker.ID, unlock, bal, epoch, [32]byte{})
	bad := simkit.BuildSend(chain, chHead, 2, testFund, bal, 0)
	chain.MustSignBreakglass(bad)
	if _, err := ValidateTxAgainstSnapshot(bad, nolink); err == nil {
		t.Fatal("P5.5: a return of a link-less Fund-sourced chain must be rejected (missing return-deposit link)")
	}
	badAuth := simkit.BuildSend(chain, chHead, 2, testFund, bal, 0)
	chain.MustSign(badAuth)
	if _, err := ValidateTxAgainstSnapshot(badAuth, nolink); err == nil {
		t.Fatal("P5.5: an auth-key return of a link-less Fund-sourced chain must also be rejected")
	}
}

// TestEnrouteBgOpenReturnStakeReceivableValidate pins that a revealed breakglass key may OPEN a stuck
// return-stake chain (the not-yet-opened edge): the reveal binds to the KEY SOURCE's (staker's)
// commitment — NOT the keyless Fund's (rs.From) — and both the auth key and the breakglass key can open.
func TestEnrouteBgOpenReturnStakeReceivableValidate(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x91}, [32]byte{0x92})
	const nonce = 4
	chain := simkit.DerivedReturnChain(staker, testFund, nonce) // copies staker keys; created by the Fund
	var rid [32]byte
	rid[0] = 0x77
	const epoch, delay, bal = uint64(5), uint64(8), uint64(6_000)
	unlock := epoch + delay

	snap := &Snapshot{
		Accounts: map[[32]byte]AccountSnap{
			// chain.ID is ABSENT (this is its opening block).
			staker.ID: {Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: staker.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), staker.Commit...)},
		},
		Receivables: map[[32]byte]ReceivableSnap{
			rid: {
				From: testFund, To: chain.ID, Amount: bal,
				RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
				FromSeq:           nonce, KeySourceID: staker.ID, ReturnTier: oneYear, ReturnDelayEpochs: delay,
			},
		},
		Epoch: epoch, FundAccount: testFund, StakeLock1yrEpochs: 8,
	}

	// POSITIVE: the staker's breakglass key opens the stuck return chain (auth key lost).
	bgOpen := simkit.BuildOpeningReceive(chain, rid, addrPtr(staker.ID), unlock)
	chain.MustSignBreakglass(bgOpen) // chain shares the staker's breakglass key
	if _, err := ValidateTxAgainstSnapshot(bgOpen, snap); err != nil {
		t.Fatalf("P5.5: breakglass-opening a return-stake chain must be accepted: %v", err)
	}

	// The auth key still opens it (both keys can open; e.g. a not-yet-lost key).
	authOpen := simkit.BuildOpeningReceive(chain, rid, addrPtr(staker.ID), unlock)
	chain.MustSign(authOpen)
	if _, err := ValidateTxAgainstSnapshot(authOpen, snap); err != nil {
		t.Fatalf("P5.5: auth-key opening a return-stake chain must still be accepted: %v", err)
	}

	// NEGATIVE: a forged revealed key (a stranger's) fails the key-source commitment bind.
	stranger := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x93}, [32]byte{0x94})
	forged := simkit.BuildOpeningReceive(chain, rid, addrPtr(staker.ID), unlock)
	stranger.MustSignBreakglass(forged) // reveals the stranger's key — not the staker's commitment
	if _, err := ValidateTxAgainstSnapshot(forged, snap); err == nil {
		t.Fatal("P5.5: a forged breakglass opening must be rejected (key-source commitment mismatch)")
	}
}

// TestEnrouteRecoveryOnRevertedRowValidate pins the P5.5 recovery gate at the authority: a C2
// generalized return may act on a REVERTED row (not just Active) with the owner's authorization (theft
// guard intact); a KICK or RE-ATTRIBUTION of a Reverted row is rejected (only C2 recovery applies).
func TestEnrouteRecoveryOnRevertedRowValidate(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xa1}, [32]byte{0xa2})
	bene := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xa3}, [32]byte{0xa4})
	g := newGuardian(1)
	amount := anosUnits(6_000)
	const fundSeq = 2

	snap, fundHead, dtx := returnValidateSetup(t, staker, g, amount, oneYear)
	// Flip the staker's row to Reverted — the en-route-recovery precondition.
	for i := range snap.FundStakeRows {
		if snap.FundStakeRows[i].DepositTxid == dtx {
			snap.FundStakeRows[i].Status = StakeStatusReverted
		}
	}
	snap.Accounts[bene.ID] = AccountSnap{Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: bene.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), bene.Commit...)}
	chain := simkit.DerivedReturnChain(bene, testFund, fundSeq) // recovery chain copies B's keys

	buildReturn := func(oa *pb.StakeOwnerAuth) *pb.Tx {
		tx := simkit.BuildFundGeneralizedReturnSend(testFund, fundHead, fundSeq, chain.ID, amount, snap.Epoch, dtx, bene.ID, 5, oa)
		signFundSend(tx, []*tGuardian{g})
		return tx
	}

	// POSITIVE: recover a Reverted stake to B with the owner's (auth-key) owner_auth.
	if _, err := ValidateTxAgainstSnapshot(buildReturn(staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, dtx, bene.ID, false)), snap); err != nil {
		t.Fatalf("P5.5: C2 recovery of a Reverted row rejected: %v", err)
	}
	// POSITIVE: the staker lost the auth key → recover via the owner's BREAKGLASS key.
	if _, err := ValidateTxAgainstSnapshot(buildReturn(staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, dtx, bene.ID, true)), snap); err != nil {
		t.Fatalf("P5.5: C2 recovery via breakglass owner_auth rejected: %v", err)
	}
	// NEGATIVE: missing owner_auth → rejected (a quorum can enact but never redirect the recovered value).
	if _, err := ValidateTxAgainstSnapshot(buildReturn(nil), snap); err == nil {
		t.Fatal("P5.5: C2 recovery of a Reverted row without owner_auth accepted (theft guard breached)")
	}

	// NEGATIVE: a KICK of a Reverted row is rejected (only a C2 return recovers a Reverted stake).
	kick := simkit.BuildFundKickSend(testFund, fundHead, fundSeq, snap.Epoch, dtx)
	signFundSend(kick, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(kick, snap); err == nil {
		t.Fatal("P5.5: a KICK of a Reverted row must be rejected (non-recoverable via kick)")
	}
	// NEGATIVE: a RE-ATTRIBUTION of a Reverted row is rejected (its value is no longer an Active stake).
	reattr := simkit.BuildFundReattributeSend(testFund, fundHead, fundSeq, snap.Epoch, dtx, bene.ID, nil, "", staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReattribute, dtx, bene.ID, false))
	signFundSend(reattr, []*tGuardian{g})
	if _, err := ValidateTxAgainstSnapshot(reattr, snap); err == nil {
		t.Fatal("P5.5: a RE-ATTRIBUTION of a Reverted row must be rejected (not an Active stake)")
	}
}

// TestEnroutePhantomFundStakeRejected pins that a return-to-source of a return-stake chain (source == the
// keyless Fund) carrying stake-deposit fields is REJECTED at BOTH validate and apply — otherwise the
// to==Fund stake-append would mint a PHANTOM stake row attributed to the Fund (StakerID == Fund). Mirrors
// the P3.3 escrow-outflow guard. Surfaced by the P5.5 adversarial review.
func TestEnroutePhantomFundStakeRejected(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xf1}, [32]byte{0xf2})
	chain := simkit.DerivedReturnChain(staker, testFund, 7)
	var chHead, dtx [32]byte
	chHead[0], dtx[0] = 0xc0, 0xcd
	const bal = uint64(6_000)

	// --- validate: a bg return-to-Fund carrying staked_for is rejected ---
	snap := fundSourcedChainSnap(chain, staker, chHead, staker.ID, 1000, bal, 5, dtx)
	poison := simkit.BuildSend(chain, chHead, 2, testFund, bal, 0)
	poison.GetSend().StakedFor = "guardian"
	poison.GetSend().TimeDelay = oneYear
	chain.MustSignBreakglass(poison)
	if _, err := ValidateTxAgainstSnapshot(poison, snap); err == nil {
		t.Fatal("a return-to-Fund carrying staked_for must be rejected (would mint a phantom Fund stake)")
	}

	// --- apply: even if one reached apply, it fail-closes AND mints no phantom row ---
	db := newFundTestDB(t)
	seedFundWithBalance(t, db, anosUnits(50_000))
	setStakeStatus(t, db, dtx, staker.ID, bal, StakeStatusReturned)
	seedFundSourcedChain(t, db, chain, chHead, staker.ID, 1000, bal, dtx)
	poison2 := simkit.BuildSend(chain, chHead, 2, testFund, bal, 0)
	poison2.GetSend().StakedFor = "guardian"
	poison2.GetSend().TimeDelay = oneYear
	chain.MustSignBreakglass(poison2)
	if err := applyFundSend(t, db, poison2, txidFor(chain.ID, 2)); err == nil {
		t.Fatal("apply of a return-to-Fund with staked_for must fail closed")
	}
	// No stake row may be attributed to the Fund.
	rows, _ := ListAllStakes(db)
	for _, r := range rows {
		if r.StakerID == testFund {
			t.Fatalf("phantom Fund-attributed stake row created: %+v", r)
		}
	}
}

// seedFundSourcedChain persists a Fund-sourced return-stake chain record (copied keys + link) for the
// apply/gate tests that read the account record straight from the DB.
func seedFundSourcedChain(t *testing.T, db *bbolt.DB, chain *simkit.Account, head, dest [32]byte, unlock, bal uint64, link [32]byte) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, chain.ID, AccountRecord{
			Head: head, Balance: bal, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			TransferSource: testFund, TransferDest: dest, TransferUnlock: unlock, TransferReturnDepositTxid: link,
			AuthPubKey: chain.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), chain.Commit...),
		})
	}); err != nil {
		t.Fatalf("seed fund-sourced chain: %v", err)
	}
}

func setStakeStatus(t *testing.T, db *bbolt.DB, dtx, staker [32]byte, amount uint64, st StakeStatus) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putStakeRecord(tx, dtx, StakeRecord{StakerID: staker, Amount: amount, TimeDelay: oneYear, Status: st, StakedFor: "guardian"})
	}); err != nil {
		t.Fatalf("set stake status: %v", err)
	}
}

// TestEnrouteFullCycleApply runs the whole en-route recovery through ApplyTx and asserts every derived
// side-effect: return → the receivable carries the deposit link; bg-open → the chain's TRANSFER_META
// carries it; bg-return → the row flips Reverted + the Fund is credited back; C2 recovery → the row
// flips to the terminal Recovered + the Fund is debited again + a new B-keyed chain is minted.
func TestEnrouteFullCycleApply(t *testing.T) {
	db := newFundTestDB(t)
	fh := seedFundWithBalance(t, db, anosUnits(100_000))
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x53}, [32]byte{0x54})
	seedSimAccount(t, db, staker)
	var dtx [32]byte
	dtx[0] = 0xab
	amount := anosUnits(6_000)
	setStakeStatus(t, db, dtx, staker.ID, amount, StakeStatusActive)

	// (1) RETURN the stake to the staker → row Returned, Fund debited, receivable carries the link.
	const fundSeq = 2
	chain := simkit.DerivedReturnChain(staker, testFund, fundSeq)
	g := newGuardian(1)
	ret := simkit.BuildFundReturnSend(testFund, fh, fundSeq, chain.ID, amount, 55, dtx)
	signFundSend(ret, []*tGuardian{g})
	returnTxid := txidFor(testFund, fundSeq)
	if err := applyFundSend(t, db, ret, returnTxid); err != nil {
		t.Fatalf("apply return: %v", err)
	}
	if st, _ := stakeStatusOf(t, db, dtx); st != StakeStatusReturned {
		t.Fatalf("after return: status = %v, want Returned", st)
	}
	if bal := fundRecord(t, db, testFund).Balance; bal != anosUnits(94_000) {
		t.Fatalf("after return: fund balance = %d, want 94000 anos", bal)
	}
	rid := crypto.ReceivableIDFromTxID(returnTxid)
	var rec pb.Receivable
	readRecv(t, db, rid, &rec)
	if rec.GetReturnDepositTxid().GetV() == nil || !bytesEq32(rec.GetReturnDepositTxid().GetV(), dtx) {
		t.Fatalf("return receivable return_deposit_txid = %x, want dtx %x", rec.GetReturnDepositTxid().GetV(), dtx[:])
	}

	// (2) BREAKGLASS-OPEN the stuck chain → chain created, TRANSFER_META carries the link.
	openRx := simkit.BuildOpeningReceive(chain, rid, addrPtr(staker.ID), 100)
	chain.MustSignBreakglass(openRx)
	openTxid := txidFor(chain.ID, 1)
	if err := applyFundSend(t, db, openRx, openTxid); err != nil {
		t.Fatalf("apply bg-open: %v", err)
	}
	var chRec AccountRecord
	if err := db.View(func(tx *bbolt.Tx) error {
		r, ok := getAccountRecord(tx, chain.ID)
		if !ok {
			t.Fatal("chain record missing after open")
		}
		chRec = r
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if chRec.TransferReturnDepositTxid != dtx {
		t.Fatalf("chain TRANSFER_META link = %x, want dtx %x", chRec.TransferReturnDepositTxid[:4], dtx[:4])
	}
	if chRec.Balance != amount || chRec.Class != pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
		t.Fatalf("chain after open: balance=%d class=%v, want %d TRANSFER", chRec.Balance, chRec.Class, amount)
	}

	// (3) BREAKGLASS-RETURN the chain to the Fund → row Reverted, Fund credited back.
	bgRet := simkit.BuildSend(chain, openTxid, 2, testFund, amount, 0)
	chain.MustSignBreakglass(bgRet)
	if err := applyFundSend(t, db, bgRet, txidFor(chain.ID, 2)); err != nil {
		t.Fatalf("apply bg-return: %v", err)
	}
	if st, _ := stakeStatusOf(t, db, dtx); st != StakeStatusReverted {
		t.Fatalf("after bg-return: status = %v, want Reverted", st)
	}
	if bal := fundRecord(t, db, testFund).Balance; bal != anosUnits(100_000) {
		t.Fatalf("after bg-return: fund balance = %d, want 100000 anos (credited back)", bal)
	}

	// (4) C2 RECOVERY of the Reverted row to a new owner B → row Recovered (terminal), Fund debited,
	//     a new B-keyed return chain minted carrying the same link. (Apply does not verify owner_auth.)
	bene := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x63}, [32]byte{0x64})
	chain2 := simkit.DerivedReturnChain(bene, testFund, 3)
	oa := staker.SignStakeOwnerAuth(crypto.StakeOwnerAuthOpReturn, dtx, bene.ID, true)
	c2 := simkit.BuildFundGeneralizedReturnSend(testFund, returnTxid, 3, chain2.ID, amount, 56, dtx, bene.ID, 5, oa)
	signFundSend(c2, []*tGuardian{g})
	c2Txid := txidFor(testFund, 3)
	if err := applyFundSend(t, db, c2, c2Txid); err != nil {
		t.Fatalf("apply C2 recovery: %v", err)
	}
	if st, _ := stakeStatusOf(t, db, dtx); st != StakeStatusRecovered {
		t.Fatalf("after C2 recovery: status = %v, want Recovered (terminal)", st)
	}
	if bal := fundRecord(t, db, testFund).Balance; bal != anosUnits(94_000) {
		t.Fatalf("after C2 recovery: fund balance = %d, want 94000 anos (debited again)", bal)
	}
	var rec2 pb.Receivable
	readRecv(t, db, crypto.ReceivableIDFromTxID(c2Txid), &rec2)
	if rec2.GetKeySourceId().GetV() == nil || !bytesEq32(rec2.GetKeySourceId().GetV(), bene.ID) {
		t.Fatalf("recovery receivable key_source = %x, want B %x", rec2.GetKeySourceId().GetV(), bene.ID[:4])
	}
	if !bytesEq32(rec2.GetReturnDepositTxid().GetV(), dtx) {
		t.Fatalf("recovery receivable return_deposit_txid = %x, want dtx %x", rec2.GetReturnDepositTxid().GetV(), dtx[:])
	}
}

// TestEnrouteRevertedMarkOnlyFromReturned pins that the Reverted marking fires ONLY on a Returned row
// (idempotent, never clobbers a terminal status): a bg-return of a chain whose row is already Recovered
// leaves the row untouched.
func TestEnrouteRevertedMarkOnlyFromReturned(t *testing.T) {
	db := newFundTestDB(t)
	seedFundWithBalance(t, db, anosUnits(50_000))
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x71}, [32]byte{0x72})
	var dtx, chHead [32]byte
	dtx[0], chHead[0] = 0x5a, 0xc7
	amount := anosUnits(6_000)
	setStakeStatus(t, db, dtx, staker.ID, amount, StakeStatusRecovered) // already terminal
	chain := simkit.DerivedReturnChain(staker, testFund, 9)
	seedFundSourcedChain(t, db, chain, chHead, staker.ID, 1000, amount, dtx)

	bgRet := simkit.BuildSend(chain, chHead, 2, testFund, amount, 0)
	chain.MustSignBreakglass(bgRet)
	if err := applyFundSend(t, db, bgRet, txidFor(chain.ID, 2)); err != nil {
		t.Fatalf("apply bg-return: %v", err)
	}
	if st, _ := stakeStatusOf(t, db, dtx); st != StakeStatusRecovered {
		t.Fatalf("Reverted mark clobbered a terminal Recovered row: status = %v", st)
	}
}

// TestTransferReturnDepositTxidRoundTrip pins the on-disk TRANSFER_RETURN_DEPOSIT TLV: it round-trips
// when set, and is absent (record byte-identical to pre-P5.5) when zero.
func TestTransferReturnDepositTxidRoundTrip(t *testing.T) {
	var head, src, dest, link [32]byte
	head[0], src[0], dest[0], link[0] = 0x11, 0x22, 0x33, 0x44
	base := AccountRecord{
		Head: head, Balance: 7, Seq: 3, Class: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
		TransferSource: src, TransferDest: dest, TransferUnlock: 42, TransferFlags: 0x03,
	}

	withLink := base
	withLink.TransferReturnDepositTxid = link
	got, ok := unpackAccountRecord(packAccountRecord(withLink))
	if !ok || got.TransferReturnDepositTxid != link {
		t.Fatalf("with-link round-trip: got %x (ok %v), want %x", got.TransferReturnDepositTxid[:4], ok, link[:4])
	}
	// Sanity: the other transfer fields survive too.
	if got.TransferSource != src || got.TransferDest != dest || got.TransferUnlock != 42 || got.TransferFlags != 0x03 {
		t.Fatal("with-link round-trip corrupted the base TRANSFER_META fields")
	}

	// Zero link → the tag is omitted, so the packed record equals the pre-P5.5 record byte-for-byte.
	noLink := base // TransferReturnDepositTxid stays zero
	if a, b := packAccountRecord(noLink), packAccountRecord(base); string(a) != string(b) {
		t.Fatal("zero return-deposit link must not change the packed record")
	}
	got2, ok := unpackAccountRecord(packAccountRecord(noLink))
	if !ok || got2.TransferReturnDepositTxid != ([32]byte{}) {
		t.Fatalf("no-link round-trip: got %x (ok %v), want zero", got2.TransferReturnDepositTxid[:4], ok)
	}
}

// TestRevertedRecoveredInertToRoleWeight pins that Reverted and Recovered rows confer NO role/Guardian
// weight — only Active stakes count (the value is out of active staking once returned/recovered).
func TestRevertedRecoveredInertToRoleWeight(t *testing.T) {
	var id [32]byte
	id[0] = 0x99
	mk := func(st StakeStatus) []StakeRow {
		return []StakeRow{{DepositTxid: [32]byte{0x01}, StakeRecord: StakeRecord{
			StakerID: id, Amount: anosUnits(50_000), TimeDelay: oneYear, Status: st, StakedFor: StakedForBanker,
		}}}
	}
	for _, st := range []StakeStatus{StakeStatusReverted, StakeStatusRecovered} {
		rows := mk(st)
		if IsBanker(rows, id) {
			t.Errorf("status %v: IsBanker must be false", st)
		}
		if GuardianWeight(rows, id) != 0 {
			t.Errorf("status %v: GuardianWeight must be 0", st)
		}
	}
	// Control: the same stake ACTIVE does confer both.
	active := mk(StakeStatusActive)
	if !IsBanker(active, id) || GuardianWeight(active, id) == 0 {
		t.Fatal("Active control: IsBanker + GuardianWeight must be set")
	}
}

// TestEnrouteGate pins the submit/gossip best-effort gate (engine.bestEffortBreakglassCheck): it accepts
// a bg return of a LINKED Fund-sourced chain and a bg-open of a return-stake receivable, and rejects a
// bg return of a link-LESS Fund-sourced chain (never-finalizable).
func TestEnrouteGate(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t), newTValidator(t), newTValidator(t)})
	fund := e.cfg.FundAccount

	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xb1}, [32]byte{0xb2})
	var dtx, chHead [32]byte
	dtx[0], chHead[0] = 0xda, 0xcb

	// (1) LINKED Fund-sourced chain: a bg return-to-Fund is LEGIT (P5.5) → gate must NOT reject.
	chain := simkit.DerivedReturnChain(staker, fund, 7)
	seedFundSourcedChainOn(t, e.cfg.DB, fund, chain, chHead, staker.ID, 1000, 500, dtx)
	ret := simkit.BuildSend(chain, chHead, 2, fund, 500, 0)
	chain.MustSignBreakglass(ret)
	if err := e.bestEffortBreakglassCheck(ret); err != nil {
		t.Fatalf("P5.5: gate must accept a bg return of a linked Fund-sourced chain: %v", err)
	}

	// (2) LINK-LESS Fund-sourced chain: a bg return can never finalize → gate rejects.
	chain2 := simkit.DerivedReturnChain(staker, fund, 8)
	var chHead2 [32]byte
	chHead2[0] = 0xcc
	seedFundSourcedChainOn(t, e.cfg.DB, fund, chain2, chHead2, staker.ID, 1000, 500, [32]byte{})
	ret2 := simkit.BuildSend(chain2, chHead2, 2, fund, 500, 0)
	chain2.MustSignBreakglass(ret2)
	if err := e.bestEffortBreakglassCheck(ret2); err == nil {
		t.Fatal("P5.5: gate must reject a bg return of a link-less Fund-sourced chain")
	}

	// (3) A bg-OPEN of a return-stake receivable: the gate resolves the key source (staker), not the
	//     keyless Fund, for the commitment bind → accepted.
	const nonce = 5
	openChain := simkit.DerivedReturnChain(staker, fund, nonce)
	var rid [32]byte
	rid[0] = 0x66
	seedReturnStakeReceivable(t, e.cfg.DB, rid, fund, openChain.ID, staker.ID, nonce, 500)
	seedSimAccountOn(t, e.cfg.DB, staker)
	bgOpen := simkit.BuildOpeningReceive(openChain, rid, addrPtr(staker.ID), 100)
	openChain.MustSignBreakglass(bgOpen)
	if err := e.bestEffortBreakglassCheck(bgOpen); err != nil {
		t.Fatalf("P5.5: gate must accept a bg-open of a return-stake receivable: %v", err)
	}
}

// --- gate-test DB seeders (operate on the engine's fund, not the package testFund) ---

func seedFundSourcedChainOn(t *testing.T, db *bbolt.DB, fund [32]byte, chain *simkit.Account, head, dest [32]byte, unlock, bal uint64, link [32]byte) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, chain.ID, AccountRecord{
			Head: head, Balance: bal, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			TransferSource: fund, TransferDest: dest, TransferUnlock: unlock, TransferReturnDepositTxid: link,
			AuthPubKey: chain.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), chain.Commit...),
		})
	}); err != nil {
		t.Fatalf("seed fund-sourced chain: %v", err)
	}
}

func seedSimAccountOn(t *testing.T, db *bbolt.DB, a *simkit.Account) {
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

func seedReturnStakeReceivable(t *testing.T, db *bbolt.DB, rid, fund, chainID, staker [32]byte, nonce, amount uint64) {
	t.Helper()
	rec := &pb.Receivable{
		Id:                &pb.Hash32{V: rid[:]},
		From:              &pb.AccountId{V: fund[:]},
		To:                &pb.AccountId{V: chainID[:]},
		Amount:            amount,
		RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
		FromSeq:           nonce,
		KeySourceId:       &pb.AccountId{V: staker[:]},
		ReturnTier:        oneYear,
		ReturnDelayEpochs: 8,
	}
	raw, _ := proto.Marshal(rec)
	if err := db.Update(func(tx *bbolt.Tx) error { return putReceivableRaw(tx, rid, raw) }); err != nil {
		t.Fatalf("seed return-stake receivable: %v", err)
	}
}

func readRecv(t *testing.T, db *bbolt.DB, rid [32]byte, out *pb.Receivable) {
	t.Helper()
	if err := db.View(func(tx *bbolt.Tx) error {
		raw, err := getReceivableRaw(tx, rid)
		if err != nil {
			return err
		}
		return proto.Unmarshal(raw, out)
	}); err != nil {
		t.Fatalf("read receivable %x: %v", rid[:4], err)
	}
}
