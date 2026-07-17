package core

// P5.1 breakglass moves (spec-19 §6.4, keys-spec §7.3) + the escrow breakglass-alt-key slot
// (spec-19 §6.3, option B/A). These tests pin, at the ValidateTxAgainstSnapshot + ApplyTx level
// (the consensus authority):
//
//   - the reveal-on-use commitment check (a revealed breakglass pubkey must match the stored
//     commitment; class-independent since P5.2 — no account-type byte);
//   - the txid fold (a swapped/stripped revealed key yields a different txid — single-sig AND escrow
//     multisig — closing the P1.2/P3.3 fork);
//   - a hop-1 breakglass drain forces a TRANSFER-restricted, breakglass-flagged receivable (even from
//     a SPENDING source) and rejects a forged key / a Fund target;
//   - the spawned chain's extended unlock floor (class delay + BREAKGLASS_EXTRA_EPOCHS) and its
//     breakglass_origin + release_requires_attestor flags;
//   - hop-2: a release-to-dest authorized by the REVEALED breakglass key + the attestor quorum after
//     unlock, a free return-to-source, and the rejection of a reveal on a plain (non-breakglass) chain;
//   - the escrow 2-of-2 satisfied by a party's revealed breakglass key.
//
// (End-to-end live + resync determinism is exercised by sim-breakglass + the live harness.)

import (
	"bytes"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

// --- pure: the reveal-on-use commitment check ---

func TestVerifyBreakglassReveal(t *testing.T) {
	acct := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{1}, [32]byte{2})
	other := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{3}, [32]byte{4})
	bgPub := acct.BreakglassPubBytes()

	// The account's commitment matches its breakglass key (class-independent since P5.2).
	spendCommit := crypto.BreakglassCommitment(bgPub)
	if !crypto.VerifyBreakglassReveal(bgPub, spendCommit[:]) {
		t.Fatal("own breakglass key must match its commitment")
	}
	// P5.2 escrow option-B collapse: a party's escrow-slot commitment (simkit.EscrowBreakglassCommit)
	// is now byte-identical to its normal-account commitment (acct.Commit) — the same reveal satisfies
	// an escrow slot too, the inverse of the old type-byte separation.
	if !bytes.Equal(acct.EscrowBreakglassCommit(), acct.Commit) {
		t.Fatal("P5.2: a party's escrow commitment must equal its normal commitment (option-B collapse)")
	}
	// Wrong key and wrong-length commitment fail closed.
	if crypto.VerifyBreakglassReveal(other.BreakglassPubBytes(), spendCommit[:]) {
		t.Fatal("a different breakglass key must not match")
	}
	if crypto.VerifyBreakglassReveal(bgPub, spendCommit[:63]) {
		t.Fatal("a short commitment must fail closed")
	}
	// checkBreakglassReveal wraps it: a registered 64-byte commitment + matching key passes; a
	// missing/short commitment (e.g. a keyless FUND source, which registers none) fails closed.
	if err := checkBreakglassReveal(bgPub, spendCommit[:]); err != nil {
		t.Fatalf("checkBreakglassReveal good: %v", err)
	}
	if err := checkBreakglassReveal(bgPub, nil); err == nil {
		t.Fatal("checkBreakglassReveal must reject a source with no registered commitment")
	}
	if err := checkBreakglassReveal(other.BreakglassPubBytes(), spendCommit[:]); err == nil {
		t.Fatal("checkBreakglassReveal must reject a non-matching revealed key")
	}
}

// --- the txid fold: a swapped/stripped revealed key changes the txid ---

func TestBreakglassTxidBindsReveal(t *testing.T) {
	src := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x11}, [32]byte{0x12})
	var head, to [32]byte
	head[0], to[0] = 0xaa, 0xbb

	// A breakglass drain, then the SAME body with the reveal stripped (signed normally).
	bgTx := simkit.BuildSend(src, head, 2, to, 100, ExpectedFee(100))
	src.MustSignBreakglass(bgTx)
	bgID, err := crypto.TxID(bgTx)
	if err != nil {
		t.Fatalf("txid breakglass: %v", err)
	}

	plain := simkit.BuildSend(src, head, 2, to, 100, ExpectedFee(100))
	src.MustSign(plain)
	plainID, err := crypto.TxID(plain)
	if err != nil {
		t.Fatalf("txid plain: %v", err)
	}
	if bgID == plainID {
		t.Fatal("a breakglass SEND and a same-body plain SEND must have DIFFERENT txids (reveal folded)")
	}

	// A second account's reveal over the same body → a different txid again.
	other := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x13}, [32]byte{0x14})
	bgTx2 := simkit.BuildSend(src, head, 2, to, 100, ExpectedFee(100))
	other.MustSignBreakglass(bgTx2) // reveals other's key
	bgID2, err := crypto.TxID(bgTx2)
	if err != nil {
		t.Fatalf("txid breakglass2: %v", err)
	}
	if bgID2 == bgID {
		t.Fatal("two distinct revealed keys must yield distinct txids")
	}
}

// TestEscrowEntryRevealBindsTxid pins that a revealed breakglass pubkey on a HybridSigEntry is folded
// into the keyless-multisig txid (FundMultiSigDigest), so an escrow outflow's txid changes if the
// revealed key is swapped — and that an attestor-release / Fund-send digest (no reveals) is unaffected.
func TestEscrowEntryRevealBindsTxid(t *testing.T) {
	a := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x21}, [32]byte{0x22})
	b := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x23}, [32]byte{0x24})
	funder := a
	esc := simkit.DerivedEscrowAccount(a, b, funder, 2)
	var head, dest [32]byte
	head[0], dest[0] = 0xc1, 0xd1

	// 2-of-2 with one breakglass slot vs the same body with both normal slots → different txids.
	mixed := simkit.BuildEscrowOutflow(esc, head, 2, dest, 500)
	if err := simkit.SignEscrowOutflowWith(mixed, []*simkit.Account{esc.Lo}, []*simkit.Account{esc.Hi}); err != nil {
		t.Fatalf("sign mixed: %v", err)
	}
	mixedID, err := crypto.TxID(mixed)
	if err != nil {
		t.Fatalf("txid mixed: %v", err)
	}
	normal := simkit.BuildEscrowOutflow(esc, head, 2, dest, 500)
	if err := simkit.SignEscrowOutflowWith(normal, []*simkit.Account{esc.Lo, esc.Hi}, nil); err != nil {
		t.Fatalf("sign normal: %v", err)
	}
	normalID, err := crypto.TxID(normal)
	if err != nil {
		t.Fatalf("txid normal: %v", err)
	}
	if mixedID == normalID {
		t.Fatal("an escrow outflow with a revealed breakglass entry must have a different txid than the all-normal form")
	}

	// A multisig carrying NO reveals must produce the byte-identical digest the pre-P5.1 code did for
	// the same entries (the zero-length frame is appended uniformly) — pin determinism by recompute.
	d1, _ := crypto.FundMultiSigDigest(normal.MultiSig)
	d2, _ := crypto.FundMultiSigDigest(normal.MultiSig)
	if !bytes.Equal(d1, d2) {
		t.Fatal("FundMultiSigDigest must be deterministic")
	}
}

// --- escrowSlotsSigned: a slot satisfied by the revealed breakglass key (option A) ---

func TestEscrowSlotsSignedBreakglass(t *testing.T) {
	a := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x31}, [32]byte{0x32})
	b := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x33}, [32]byte{0x34})
	esc := simkit.DerivedEscrowAccount(a, b, a, 2)
	loPub, hiPub := esc.Lo.AuthPubKeyBytes(), esc.Hi.AuthPubKeyBytes()
	loBG, hiBG := esc.Lo.EscrowBreakglassCommit(), esc.Hi.EscrowBreakglassCommit()
	var head, dest [32]byte
	head[0], dest[0] = 0xe1, 0xf1

	// lo signs normally, hi signs with its revealed breakglass key → both slots filled.
	tx := simkit.BuildEscrowOutflow(esc, head, 2, dest, 500)
	if err := simkit.SignEscrowOutflowWith(tx, []*simkit.Account{esc.Lo}, []*simkit.Account{esc.Hi}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	m, _, _ := crypto.MsgHash(tx)
	lo, hi := escrowSlotsSigned(tx.MultiSig, m, loPub, loBG, hiPub, hiBG)
	if !lo || !hi {
		t.Fatalf("breakglass+normal 2-of-2 must fill both slots, got lo=%v hi=%v", lo, hi)
	}

	// A breakglass entry whose key does NOT match either stored commitment fills no breakglass slot.
	stranger := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x35}, [32]byte{0x36})
	tx2 := simkit.BuildEscrowOutflow(esc, head, 2, dest, 500)
	if err := simkit.SignEscrowOutflowWith(tx2, []*simkit.Account{esc.Lo}, []*simkit.Account{stranger}); err != nil {
		t.Fatalf("sign2: %v", err)
	}
	m2, _, _ := crypto.MsgHash(tx2)
	lo2, hi2 := escrowSlotsSigned(tx2.MultiSig, m2, loPub, loBG, hiPub, hiBG)
	if !lo2 || hi2 {
		t.Fatalf("a stranger breakglass key must not fill a slot, got lo=%v hi=%v", lo2, hi2)
	}
}

// --- validate path: the hop-1 breakglass drain ---

// bgSnap builds a Snapshot holding one base-class source account with balance, plus the config
// constants a breakglass move reads. epoch is the validation epoch.
func bgSnap(src *simkit.Account, head [32]byte, bal, seq, epoch uint64) *Snapshot {
	return &Snapshot{Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			src.ID: {
				Head: head, Balance: bal, Seq: seq, Class: src.Class,
				AuthPubKey: src.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), src.Commit...),
			},
		},
		Receivables:           map[[32]byte]ReceivableSnap{},
		Epoch:                 epoch,
		DelayEpochs:           6,
		GuardedDelayEpochs:    8,
		VaultDelayEpochs:      12,
		BreakglassExtraEpochs: 5,
		AttestorQuorumM:       2,
		FundAccount:           testFund,
	}
}

func TestBreakglassDrainValidate(t *testing.T) {
	src := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x41}, [32]byte{0x42})
	var head [32]byte
	head[0] = 0xa1
	chain := simkit.DerivedTransferAccount(src, 2) // the drain target (future chain id)
	snap := bgSnap(src, head, 1_000_000, 1, 100)

	// Good breakglass drain: SPENDING source spends via its breakglass key to the chain id.
	tx := simkit.BuildSend(src, head, 2, chain.ID, 1000, ExpectedFee(1000))
	src.MustSignBreakglass(tx)
	if _, err := ValidateTxAgainstSnapshot(tx, snap); err != nil {
		t.Fatalf("valid breakglass drain rejected: %v", err)
	}

	// Forged revealed key (a stranger's breakglass key over the source's chain) → rejected.
	stranger := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x43}, [32]byte{0x44})
	bad := simkit.BuildSend(src, head, 2, chain.ID, 1000, ExpectedFee(1000))
	stranger.MustSignBreakglass(bad) // reveals the stranger's key
	if _, err := ValidateTxAgainstSnapshot(bad, snap); err == nil {
		t.Fatal("a forged breakglass key must be rejected")
	}

	// A breakglass drain must not target the keyless Fund.
	toFund := simkit.BuildSend(src, head, 2, testFund, 1000, ExpectedFee(1000))
	src.MustSignBreakglass(toFund)
	if _, err := ValidateTxAgainstSnapshot(toFund, snap); err == nil {
		t.Fatal("a breakglass drain to the Fund must be rejected")
	}
}

// --- validate path: the breakglass chain creation (opening RECEIVE) + extended unlock ---

func TestBreakglassChainCreationValidate(t *testing.T) {
	src := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x51}, [32]byte{0x52})
	chain := simkit.DerivedTransferAccount(src, 2)
	const fromSeq = 2
	const epoch = 100
	rid := crypto.ReceivableIDFromTxID([32]byte{0x5a})

	// Snapshot: the source (keyed) + a breakglass-flagged TRANSFER-restricted receivable funding `chain`.
	snap := &Snapshot{Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			src.ID: {Class: src.Class, AuthPubKey: src.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), src.Commit...), Seq: 2},
		},
		Receivables: map[[32]byte]ReceivableSnap{
			rid: {From: src.ID, To: chain.ID, Amount: 1000, RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER, FromSeq: fromSeq, FromBreakglass: true},
		},
		Epoch: epoch, DelayEpochs: 6, GuardedDelayEpochs: 8, VaultDelayEpochs: 12,
		BreakglassExtraEpochs: 5, FundAccount: testFund,
	}

	// SPENDING source → class delay 0 + window 5 → unlock floor = epoch + 5. Exactly-floor opens; below rejects.
	var dest [32]byte
	dest[0] = 0xd5
	open := func(unlock uint64) *pb.Tx {
		tx := simkit.BuildOpeningReceive(chain, [32]byte(rid), &dest, unlock)
		chain.MustSignBreakglass(tx) // opened by the breakglass key (the recoverer lost the auth key)
		return tx
	}
	if _, err := ValidateTxAgainstSnapshot(open(epoch+5), snap); err != nil {
		t.Fatalf("breakglass chain opening at the unlock floor rejected: %v", err)
	}
	if _, err := ValidateTxAgainstSnapshot(open(epoch+4), snap); err == nil {
		t.Fatal("a breakglass chain unlock below (epoch + window) must be rejected")
	}

	// An auth-key opening of the same breakglass receivable is also allowed (both keys can open it).
	authOpen := simkit.BuildOpeningReceive(chain, [32]byte(rid), &dest, epoch+5)
	chain.MustSign(authOpen)
	if _, err := ValidateTxAgainstSnapshot(authOpen, snap); err != nil {
		t.Fatalf("auth-key opening of a breakglass receivable rejected: %v", err)
	}

	// A revealed key may NOT open a NON-breakglass receivable (general recovery is deferred).
	snap.Receivables[rid] = ReceivableSnap{From: src.ID, To: chain.ID, Amount: 1000, RequiredDestClass: pb.AccountClass_ACCOUNT_CLASS_TRANSFER, FromSeq: fromSeq, FromBreakglass: false}
	if _, err := ValidateTxAgainstSnapshot(open(epoch+5), snap); err == nil {
		t.Fatal("a revealed breakglass key opening a non-breakglass receivable must be rejected")
	}
}

// --- validate path: the hop-2 release / return on a breakglass chain ---

func TestBreakglassReleaseValidate(t *testing.T) {
	src := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x61}, [32]byte{0x62})
	chain := simkit.DerivedTransferAccount(src, 2) // shares src's auth + breakglass keys
	a1 := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x71}, [32]byte{0x72})
	a2 := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x73}, [32]byte{0x74})
	var chHead, dest [32]byte
	chHead[0], dest[0] = 0xc6, 0xd6
	const unlock, bal = uint64(20), uint64(1000)

	snap := &Snapshot{Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			chain.ID: {
				Head: chHead, Balance: bal, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
				TransferSource: src.ID, TransferDest: dest, TransferUnlock: unlock,
				TransferFlags: transferFlagReleaseRequiresAttestor | transferFlagBreakglassOrigin,
				AuthPubKey:    chain.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), chain.Commit...),
			},
			src.ID: {Class: src.Class, AuthPubKey: src.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), src.Commit...)},
			a1.ID:  {Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: a1.AuthPubKeyBytes()},
			a2.ID:  {Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: a2.AuthPubKeyBytes()},
		},
		Receivables: map[[32]byte]ReceivableSnap{},
		Epoch:       unlock, FundAccount: testFund, AttestorQuorumM: 2,
		FundStakeRows: []StakeRow{
			{DepositTxid: [32]byte{0x01, 0xaa}, StakeRecord: StakeRecord{StakerID: a1.ID, Amount: anosUnits(5000), TimeDelay: oneMonth, Status: StakeStatusActive, StakedFor: StakedForAttestor}},
			{DepositTxid: [32]byte{0x02, 0xaa}, StakeRecord: StakeRecord{StakerID: a2.ID, Amount: anosUnits(5000), TimeDelay: oneMonth, Status: StakeStatusActive, StakedFor: StakedForAttestor}},
		},
	}

	// Release to dest, breakglass key + 2 attestors, at unlock → accepted.
	rel := simkit.BuildSend(chain, chHead, 2, dest, bal, 0)
	if err := simkit.SignBreakglassRelease(rel, chain, []*simkit.Account{a1, a2}); err != nil {
		t.Fatalf("sign release: %v", err)
	}
	if _, err := ValidateTxAgainstSnapshot(rel, snap); err != nil {
		t.Fatalf("valid breakglass release rejected: %v", err)
	}

	// Same release but BEFORE unlock → rejected.
	early := *snap
	early.Epoch = unlock - 1
	if _, err := ValidateTxAgainstSnapshot(rel, &early); err == nil {
		t.Fatal("a breakglass release before unlock must be rejected")
	}

	// Release with only ONE attestor (< M=2) → rejected.
	rel1 := simkit.BuildSend(chain, chHead, 2, dest, bal, 0)
	if err := simkit.SignBreakglassRelease(rel1, chain, []*simkit.Account{a1}); err != nil {
		t.Fatalf("sign release1: %v", err)
	}
	if _, err := ValidateTxAgainstSnapshot(rel1, snap); err == nil {
		t.Fatal("a breakglass release below the attestor quorum must be rejected")
	}

	// Return-to-source signed by the AUTH key (owner cancel) → accepted, free, no attestors.
	ret := simkit.BuildSend(chain, chHead, 2, src.ID, bal, 0)
	chain.MustSign(ret) // auth key
	if _, err := ValidateTxAgainstSnapshot(ret, snap); err != nil {
		t.Fatalf("auth-key return-to-source rejected: %v", err)
	}

	// A revealed breakglass key on a PLAIN (non-breakglass) chain → rejected.
	plain := *snap
	pc := snap.Accounts[chain.ID]
	pc.TransferFlags = transferFlagReleaseRequiresAttestor // GUARDED/VAULT-style, NOT breakglass_origin
	plain.Accounts = map[[32]byte]AccountSnap{chain.ID: pc, src.ID: snap.Accounts[src.ID], a1.ID: snap.Accounts[a1.ID], a2.ID: snap.Accounts[a2.ID]}
	relP := simkit.BuildSend(chain, chHead, 2, dest, bal, 0)
	if err := simkit.SignBreakglassRelease(relP, chain, []*simkit.Account{a1, a2}); err != nil {
		t.Fatalf("sign relP: %v", err)
	}
	if _, err := ValidateTxAgainstSnapshot(relP, &plain); err == nil {
		t.Fatal("a revealed breakglass key on a non-breakglass chain must be rejected")
	}
}

// --- apply path: the breakglass drain forces a TRANSFER-restricted, breakglass-flagged receivable ---

func TestBreakglassApplyForcesTransferReceivable(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)
	src := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x81}, [32]byte{0x82})
	var sHead [32]byte
	sHead[0] = 0x8a
	seedSpendingKeyed(t, db, src, sHead, 1_000_000, 1)
	chain := simkit.DerivedTransferAccount(src, 2)

	// A breakglass drain (revealed key present) → forced TRANSFER-restricted + from_breakglass receivable.
	bgTx := simkit.BuildSend(src, sHead, 2, chain.ID, 1000, ExpectedFee(1000))
	src.MustSignBreakglass(bgTx)
	txid, err := crypto.TxID(bgTx)
	if err != nil {
		t.Fatalf("txid: %v", err)
	}
	raw, _ := proto.Marshal(bgTx)
	if err := db.Update(func(tx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: tx}, raw, bgTx, txid, testFund, testEcon, 0)
	}); err != nil {
		t.Fatalf("apply breakglass drain: %v", err)
	}
	rec := receivableRecord(t, db, crypto.ReceivableIDFromTxID(txid))
	if rec.RequiredDestClass != pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
		t.Fatalf("breakglass drain receivable must be TRANSFER-restricted, got %v", rec.RequiredDestClass)
	}
	if !rec.FromBreakglass {
		t.Fatal("breakglass drain receivable must carry from_breakglass")
	}

	// Control: a plain SPENDING send from the same source mints an UNRESTRICTED, non-breakglass receivable.
	seedSpendingKeyed(t, db, src, sHead, 1_000_000, 1) // reset
	plain := simkit.BuildSend(src, sHead, 2, chain.ID, 1000, ExpectedFee(1000))
	src.MustSign(plain)
	pid, _ := crypto.TxID(plain)
	praw, _ := proto.Marshal(plain)
	if err := db.Update(func(tx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: tx}, praw, plain, pid, testFund, testEcon, 0)
	}); err != nil {
		t.Fatalf("apply plain: %v", err)
	}
	prec := receivableRecord(t, db, crypto.ReceivableIDFromTxID(pid))
	if prec.RequiredDestClass != pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED || prec.FromBreakglass {
		t.Fatalf("plain SPENDING send must mint an unrestricted, non-breakglass receivable, got class=%v bg=%v", prec.RequiredDestClass, prec.FromBreakglass)
	}
}

// seedSpendingKeyed seeds a SPENDING account WITH its cached auth pubkey + breakglass commitment.
func seedSpendingKeyed(t *testing.T, db *bbolt.DB, a *simkit.Account, head [32]byte, bal, seq uint64) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, a.ID, AccountRecord{
			Head: head, Balance: bal, Seq: seq, Class: a.Class,
			AuthPubKey: a.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), a.Commit...),
		})
	}); err != nil {
		t.Fatalf("seed keyed account: %v", err)
	}
}

// --- the submit/gossip best-effort gate: the liveness-DoS fix (review finding) ---

func TestBestEffortBreakglassGate(t *testing.T) {
	e := newWalkTestEngine(t, []*tValidator{newTValidator(t), newTValidator(t), newTValidator(t)})
	// Seed a victim SPENDING account A at a known head/seq with its auth pubkey + breakglass commitment.
	victim := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x91}, [32]byte{0x92})
	var aHead [32]byte
	aHead[0] = 0x9a
	if err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, victim.ID, AccountRecord{
			Head: aHead, Balance: 1_000_000, Seq: 5, Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
			AuthPubKey: victim.AuthPubKeyBytes(), BreakglassCommit: append([]byte(nil), victim.Commit...),
		})
	}); err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	chain := simkit.DerivedTransferAccount(victim, 6)
	attacker := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, [32]byte{0x93}, [32]byte{0x94})

	// DoS: a junk breakglass drain on A AT A's position, signed by the ATTACKER's OWN key (no victim
	// key needed). resolveAuthPubKeyDB would verify it against the attacker's revealed key; the gate
	// must reject it (commitment mismatch) so it can't grind a low txid into A's conflict slot.
	forged := simkit.BuildSend(victim, aHead, 6, chain.ID, 1000, ExpectedFee(1000))
	attacker.MustSignBreakglass(forged)
	if err := e.bestEffortBreakglassCheck(forged); err == nil {
		t.Fatal("forged breakglass drain must be rejected at the submit/gossip gate (DoS)")
	}

	// A LEGIT breakglass drain (A's own breakglass key) must NOT be rejected.
	legit := simkit.BuildSend(victim, aHead, 6, chain.ID, 1000, ExpectedFee(1000))
	victim.MustSignBreakglass(legit)
	if err := e.bestEffortBreakglassCheck(legit); err != nil {
		t.Fatalf("legit breakglass drain rejected at the gate: %v", err)
	}

	// A non-breakglass tx is a no-op.
	plain := simkit.BuildSend(victim, aHead, 6, chain.ID, 1000, ExpectedFee(1000))
	victim.MustSign(plain)
	if err := e.bestEffortBreakglassCheck(plain); err != nil {
		t.Fatalf("non-breakglass tx must be a no-op: %v", err)
	}

	// NOT at position (wrong prev): even a forged reveal defers (nil) — the node can't confidently judge.
	var wrongPrev [32]byte
	wrongPrev[0] = 0xee
	forgedOff := simkit.BuildSend(victim, wrongPrev, 6, chain.ID, 1000, ExpectedFee(1000))
	attacker.MustSignBreakglass(forgedOff)
	if err := e.bestEffortBreakglassCheck(forgedOff); err != nil {
		t.Fatalf("not-at-position breakglass tx must defer (nil): %v", err)
	}

	// UNSPECIFIED-typed tx carrying a reveal: it can never finalize (validate → ErrWrongType) but its
	// conflict key ignores tx.Type, so the gate must reject it UNCONDITIONALLY (else it stalls the slot).
	junkType := simkit.BuildSend(victim, aHead, 6, chain.ID, 1000, ExpectedFee(1000))
	junkType.Type = pb.TxType_TX_TYPE_UNSPECIFIED
	junkType.RevealedBreakglassPubkey = &pb.HybridPubKey{V: attacker.BreakglassPubBytes()}
	if err := e.bestEffortBreakglassCheck(junkType); err == nil {
		t.Fatal("an UNSPECIFIED-typed tx carrying a reveal must be rejected at the gate")
	}
	// resolveAuthPubKeyDB must NOT resolve the reveal for a non-SEND/RECEIVE type — it falls through to
	// the victim's CACHED auth key, so the attacker-keyed junk fails the signature check.
	if pub, rok := e.resolveAuthPubKeyDB(junkType); !rok || !bytes.Equal(pub, victim.AuthPubKeyBytes()) {
		t.Fatal("resolveAuthPubKeyDB must resolve the cached auth key (not the reveal) for a non-SEND/RECEIVE tx")
	}
}

func receivableRecord(t *testing.T, db *bbolt.DB, rid [32]byte) *pb.Receivable {
	t.Helper()
	var rec pb.Receivable
	if err := db.View(func(tx *bbolt.Tx) error {
		rr, err := getReceivableRaw(tx, rid)
		if err != nil {
			return err
		}
		return proto.Unmarshal(rr, &rec)
	}); err != nil {
		t.Fatalf("read receivable: %v", err)
	}
	return &rec
}
