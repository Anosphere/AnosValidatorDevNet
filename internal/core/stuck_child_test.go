package core

// P5.3 stuck-child recovery (spec-19 §6.4, Working Notes §3.4 "(B) Stuck ordinary transfer chain").
// A revealed breakglass key may RETURN-to-source on ANY ordinary (keyed-source) transfer chain — not
// just a breakglass-origin one — UNGATED (no attestors, any epoch, zero-fee). Release-to-dest via a
// revealed key stays breakglass-origin-ONLY, and a return on a Fund-sourced return-stake chain (whose
// source is the keyless Fund) is out of scope here (P5.5) and rejected. These tests pin the relaxed
// policy at both the ValidateTxAgainstSnapshot authority and the submit/gossip best-effort gate.
//
// The change is validate-only: ApplyTx never branches on the reveal for a hop-2 outbound (it reads the
// reveal only for a hop-1 base-owner drain), so a breakglass-signed return-to-source is byte-identical
// to an auth-key one — the P4.3b verifying walk replays it unchanged (no proto/fold change).

import (
	"testing"

	"go.etcd.io/bbolt"

	pb "anos/internal/proto"
	"anos/internal/simkit"
)

// ordinaryChainSnap builds a snapshot with an ORDINARY transfer chain (keyed source, NOT
// breakglass-origin) that copies `src`'s auth+breakglass keys, plus the keyed source account. `flags`
// toggles release_requires_attestor (a GUARDED/VAULT chain) while staying non-breakglass-origin.
func ordinaryChainSnap(src, chain *simkit.Account, chHead, dest [32]byte, unlock, bal, epoch uint64, flags byte) *Snapshot {
	return &Snapshot{Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			chain.ID: {
				Head: chHead, Balance: bal, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
				TransferSource: src.ID, TransferDest: dest, TransferUnlock: unlock, TransferFlags: flags,
				AuthPubKey: chain.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), chain.Commit...),
			},
			src.ID: {Class: src.Class, AuthPubKey: src.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), src.Commit...)},
		},
		Receivables:     map[[32]byte]ReceivableSnap{},
		Epoch:           epoch,
		FundAccount:     testFund,
		AttestorQuorumM: 2,
	}
}

// TestStuckChildReturnToSourceValidate pins the P5.3 relaxation at the consensus authority: a revealed
// breakglass key returns to the source on an ordinary chain (TIMELOCKED and GUARDED), ungated and well
// before unlock, while a breakglass release-to-dest on such a chain stays rejected.
func TestStuckChildReturnToSourceValidate(t *testing.T) {
	src := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, [32]byte{0xa1}, [32]byte{0xa2})
	chain := simkit.DerivedTransferAccount(src, 2) // copies src's auth+breakglass keys
	var chHead, dest [32]byte
	chHead[0], dest[0] = 0xc0, 0xd0
	const unlock, bal, epoch = uint64(1000), uint64(500), uint64(5) // epoch << unlock: still locked

	// --- ordinary TIMELOCKED chain (no attestor flag) ---
	snap := ordinaryChainSnap(src, chain, chHead, dest, unlock, bal, epoch, 0)

	// POSITIVE: the revealed breakglass key returns to the source, well before unlock, no attestors.
	ret := simkit.BuildSend(chain, chHead, 2, src.ID, bal, 0)
	chain.MustSignBreakglass(ret) // the chain shares src's breakglass key; reveals it
	if _, err := ValidateTxAgainstSnapshot(ret, snap); err != nil {
		t.Fatalf("P5.3: breakglass return-to-source on an ordinary chain must be accepted: %v", err)
	}

	// The auth key still returns to source (the pre-existing owner-cancel path is unchanged).
	authRet := simkit.BuildSend(chain, chHead, 2, src.ID, bal, 0)
	chain.MustSign(authRet)
	if _, err := ValidateTxAgainstSnapshot(authRet, snap); err != nil {
		t.Fatalf("auth-key return-to-source must still be accepted: %v", err)
	}

	// NEGATIVE: a breakglass release-to-dest on an ordinary chain is rejected even PAST unlock — the
	// rejection is on the breakglass-origin rule, not the timelock (release stays the source's power).
	past := *snap
	past.Epoch = unlock + 1
	rel := simkit.BuildSend(chain, chHead, 2, dest, bal, 0)
	chain.MustSignBreakglass(rel)
	if _, err := ValidateTxAgainstSnapshot(rel, &past); err == nil {
		t.Fatal("P5.3: a breakglass release-to-dest on an ordinary chain must be rejected (breakglass-origin only)")
	}

	// A forged revealed key (a stranger's) fails the commitment bind even for a return-to-source.
	stranger := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xa3}, [32]byte{0xa4})
	forged := simkit.BuildSend(chain, chHead, 2, src.ID, bal, 0)
	stranger.MustSignBreakglass(forged) // reveals the stranger's key — does not match the chain commitment
	if _, err := ValidateTxAgainstSnapshot(forged, snap); err == nil {
		t.Fatal("a forged breakglass return must be rejected (commitment mismatch)")
	}

	// --- ordinary GUARDED chain (release_requires_attestor set, still NOT breakglass-origin) ---
	gsnap := ordinaryChainSnap(src, chain, chHead, dest, unlock, bal, epoch, transferFlagReleaseRequiresAttestor)
	gret := simkit.BuildSend(chain, chHead, 2, src.ID, bal, 0)
	chain.MustSignBreakglass(gret)
	if _, err := ValidateTxAgainstSnapshot(gret, gsnap); err != nil {
		t.Fatalf("P5.3: breakglass return-to-source on an ordinary GUARDED chain must be accepted: %v", err)
	}
	// A breakglass release-to-dest on the GUARDED chain is still rejected (breakglass-origin only); the
	// rejection lands on the origin rule before the attestor quorum is even consulted.
	gpast := *gsnap
	gpast.Epoch = unlock + 1
	grel := simkit.BuildSend(chain, chHead, 2, dest, bal, 0)
	chain.MustSignBreakglass(grel)
	if _, err := ValidateTxAgainstSnapshot(grel, &gpast); err == nil {
		t.Fatal("P5.3: a breakglass release-to-dest on an ordinary GUARDED chain must be rejected")
	}
}

// TestStuckChildFundSourcedReturnRejected pins that a revealed breakglass key may not return a
// Fund-sourced chain that lacks the threaded return-deposit link. P5.5 lifted the blanket P5.3
// rejection: a Fund-sourced RETURN-STAKE chain that carries the link IS now bg-returnable to the Fund
// (the en-route-recovery flow, covered in enroute_recovery_test.go). A link-LESS Fund-sourced chain is
// an invariant violation (every real return-stake chain threads the link at creation), so it stays
// rejected — fail-closed, so a link-less Fund-return can never strand a Returned row. The chain copies
// the STAKER's keys, so the commitment bind PASSES — only the missing-link guard blocks it.
func TestStuckChildFundSourcedReturnRejected(t *testing.T) {
	staker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xb1}, [32]byte{0xb2})
	chain := simkit.DerivedReturnChain(staker, testFund, 7) // Fund-created chain copying the staker's keys
	var chHead [32]byte
	chHead[0] = 0xc1
	const bal = uint64(500)

	snap := &Snapshot{Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			chain.ID: {
				Head: chHead, Balance: bal, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
				TransferSource: testFund, TransferDest: staker.ID, TransferUnlock: 1000, TransferFlags: 0,
				AuthPubKey: chain.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), chain.Commit...),
			},
		},
		Receivables: map[[32]byte]ReceivableSnap{},
		Epoch:       5,
		FundAccount: testFund,
	}

	// return-to-source == to the keyless Fund, signed by the staker's revealed breakglass key, on a chain
	// with NO return-deposit link (snap sets no TransferReturnDepositTxid) → rejected (missing link).
	ret := simkit.BuildSend(chain, chHead, 2, testFund, bal, 0)
	chain.MustSignBreakglass(ret)
	if _, err := ValidateTxAgainstSnapshot(ret, snap); err == nil {
		t.Fatal("a breakglass return on a link-less Fund-sourced chain must be rejected (missing return-deposit link)")
	}
}

// TestStuckChildGate pins the destination-aware best-effort gate (engine.bestEffortBreakglassCheck): it
// accepts a legit breakglass return-to-source on an ordinary chain and rejects only never-finalizable
// variants (release-to-dest on an ordinary chain, an outbound to neither endpoint, a Fund-sourced
// return, a commitment mismatch).
func TestStuckChildGate(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t), newTValidator(t), newTValidator(t)})
	fund := e.cfg.FundAccount

	// (1) An ORDINARY transfer chain (keyed source, NOT breakglass-origin) copying src's keys.
	src := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, [32]byte{0xd1}, [32]byte{0xd2})
	chain := simkit.DerivedTransferAccount(src, 2)
	var chHead, dest [32]byte
	chHead[0], dest[0] = 0xce, 0xde
	seedBreakglassChain(t, e.cfg.DB, chain, chHead, src.ID, dest, 1000, 500, 0)

	// return-to-source via the breakglass key: LEGIT (P5.3) → gate must NOT reject.
	ret := simkit.BuildSend(chain, chHead, 2, src.ID, 500, 0)
	chain.MustSignBreakglass(ret)
	if err := e.bestEffortBreakglassCheck(ret); err != nil {
		t.Fatalf("P5.3: gate must accept a breakglass return-to-source on an ordinary chain: %v", err)
	}

	// release-to-dest via the breakglass key on an ordinary chain: can NEVER finalize → gate rejects.
	rel := simkit.BuildSend(chain, chHead, 2, dest, 500, 0)
	chain.MustSignBreakglass(rel)
	if err := e.bestEffortBreakglassCheck(rel); err == nil {
		t.Fatal("P5.3: gate must reject a breakglass release-to-dest on an ordinary chain")
	}

	// outbound to neither source nor dest → gate rejects (validate would too).
	var somewhere [32]byte
	somewhere[0] = 0x77
	other := simkit.BuildSend(chain, chHead, 2, somewhere, 500, 0)
	chain.MustSignBreakglass(other)
	if err := e.bestEffortBreakglassCheck(other); err == nil {
		t.Fatal("P5.3: gate must reject a breakglass outbound to neither source nor dest")
	}

	// forged breakglass key (wrong commitment) return → gate rejects (commitment mismatch, the P5.1 DoS).
	stranger := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xd3}, [32]byte{0xd4})
	forged := simkit.BuildSend(chain, chHead, 2, src.ID, 500, 0)
	stranger.MustSignBreakglass(forged) // reveals stranger's key — does not match the chain commitment
	if err := e.bestEffortBreakglassCheck(forged); err == nil {
		t.Fatal("gate must reject a breakglass return whose revealed key does not match the chain commitment")
	}

	// not-at-position (wrong prev): the gate can't confidently judge → defers (nil).
	var wrongPrev [32]byte
	wrongPrev[0] = 0xee
	off := simkit.BuildSend(chain, wrongPrev, 2, dest, 500, 0)
	chain.MustSignBreakglass(off)
	if err := e.bestEffortBreakglassCheck(off); err != nil {
		t.Fatalf("not-at-position breakglass tx must defer (nil): %v", err)
	}

	// (2) A Fund-sourced chain with NO return-deposit link: a bg return-to-Fund can never finalize
	// (validate rejects the missing link), so the gate rejects it too. (A LINKED Fund-sourced chain is
	// now accepted — the P5.5 en-route recovery, covered in enroute_recovery_test.go.)
	fstaker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0xd5}, [32]byte{0xd6})
	fchain := simkit.DerivedReturnChain(fstaker, fund, 7)
	var fHead [32]byte
	fHead[0] = 0xcf
	seedBreakglassChain(t, e.cfg.DB, fchain, fHead, fund, fstaker.ID, 1000, 500, 0)
	fret := simkit.BuildSend(fchain, fHead, 2, fund, 500, 0)
	fchain.MustSignBreakglass(fret)
	if err := e.bestEffortBreakglassCheck(fret); err == nil {
		t.Fatal("gate must reject a breakglass return on a link-less Fund-sourced chain (missing return-deposit link)")
	}
}

// seedBreakglassChain persists a TRANSFER-chain record (copied keys + source/dest/unlock/flags) for the
// best-effort-gate tests, which read the account record straight from the DB.
func seedBreakglassChain(t *testing.T, db *bbolt.DB, chain *simkit.Account, head, source, dest [32]byte, unlock, bal uint64, flags byte) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, chain.ID, AccountRecord{
			Head: head, Balance: bal, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			TransferSource: source, TransferDest: dest, TransferUnlock: unlock, TransferFlags: flags,
			AuthPubKey: chain.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), chain.Commit...),
		})
	}); err != nil {
		t.Fatalf("seed transfer chain: %v", err)
	}
}
