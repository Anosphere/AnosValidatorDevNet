package core

// P2.3a weighted-Guardian Fund SENDs (spec-18 §7.3, spec-19 §6.2, build-plan §P2.3).
//
// Pure-math tests pin the active-denominator + ceil-threshold logic. verifyFundSendQuorum
// tests pin the verify-only authorization (bootstrap M=0 floor, ≥70% pass / below-threshold
// fail, duplicate-signer dedupe, bad/keyless/non-eligible signers ignored). DB-backed ApplyTx
// tests pin the Fund debit, the recipient receivable, the Guardian-activity projection (incl.
// no-double on re-apply and order-independent rebuild), and the keyless authorization carried
// solely by the HybridMultiSig. A crypto test pins that the Fund-SEND txid binds the exact
// signer set order-independently. Shares newFundTestDB/seedFundRecord/seedSpending/testFund.

import (
	"reflect"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// --- test guardian (a hybrid-keyed identity that can sign a Fund SEND) ---

type tGuardian struct {
	priv *crypto.HybridPrivateKey
	pub  *crypto.HybridPubKey
	id   [32]byte
}

func newGuardian(seed byte) *tGuardian {
	priv, pub := crypto.GenerateHybridKeyFromSeed([32]byte{seed, 0x9a})
	id := crypto.BaseAccountID(crypto.AccountTypeByteForClass(pb.AccountClass_ACCOUNT_CLASS_SPENDING), pub.Encode())
	return &tGuardian{priv: priv, pub: pub, id: id}
}

// guardianStake returns a StakeRow giving `g` `anos` whole-anos of 1-year stake (so
// testEcon.GuardianWeight(g) = floor(anos/2000)).
func guardianStake(g *tGuardian, depositSeed byte, whoAnos uint64) StakeRow {
	return StakeRow{
		DepositTxid: [32]byte{depositSeed},
		StakeRecord: StakeRecord{
			StakerID:  g.id,
			Amount:    anosUnits(whoAnos),
			TimeDelay: oneYear,
			Status:    StakeStatusActive,
			StakedFor: "guardian",
		},
	}
}

// buildFundSend assembles a (real, signed) Fund SEND: account == fund, zero-fee, class FUND,
// authorized by the signers' HybridMultiSig over m. The multisig is NOT part of m.
func buildFundSend(fund, prev [32]byte, seq uint64, to [32]byte, amount, fundEpoch uint64, signers []*tGuardian) *pb.Tx {
	tx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: append([]byte(nil), fund[:]...)},
		Prev:    &pb.Hash32{V: append([]byte(nil), prev[:]...)},
		Seq:     seq,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:            &pb.AccountId{V: append([]byte(nil), to[:]...)},
			Amount:        amount,
			Fee:           0,
			AccountClass:  pb.AccountClass_ACCOUNT_CLASS_FUND,
			FundSendEpoch: fundEpoch,
		}},
	}
	signFundSend(tx, signers)
	return tx
}

func signFundSend(tx *pb.Tx, signers []*tGuardian) {
	m, _, err := crypto.MsgHash(tx)
	if err != nil {
		panic(err)
	}
	ms := &pb.HybridMultiSig{}
	for _, g := range signers {
		sig, err := g.priv.Sign(m)
		if err != nil {
			panic(err)
		}
		ms.Entries = append(ms.Entries, &pb.HybridSigEntry{
			SignerId: &pb.AccountId{V: append([]byte(nil), g.id[:]...)},
			Sig:      &pb.HybridSig{V: sig.Encode()},
		})
	}
	tx.MultiSig = ms
}

// snapWithGuardians builds a Snapshot whose Accounts carry each guardian's auth pubkey, whose
// FundStakeRows give the stated weights, and whose GuardianActiveWeight is M.
func snapWithGuardians(fund, fundHead [32]byte, fundSeq uint64, rows []StakeRow, M uint64, gs ...*tGuardian) *Snapshot {
	snap := &Snapshot{Econ: testEcon,
		Accounts:             map[[32]byte]AccountSnap{},
		Receivables:          map[[32]byte]ReceivableSnap{},
		Epoch:                100,
		FundAccount:          fund,
		FundStakeRows:        rows,
		GuardianActiveWeight: M,
	}
	snap.Accounts[fund] = AccountSnap{Head: fundHead, Seq: fundSeq, Balance: anosUnits(1_000_000), Class: pb.AccountClass_ACCOUNT_CLASS_FUND}
	for _, g := range gs {
		snap.Accounts[g.id] = AccountSnap{Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: g.pub.Encode()}
	}
	return snap
}

// ---- pure math ----

func TestGuardianQuorumThreshold(t *testing.T) {
	cases := []struct{ M, want uint64 }{
		{0, 0},   // genesis / dormant → only the N>=1 floor governs
		{1, 1},   // ceil(0.7) = 1
		{3, 3},   // ceil(2.1) = 3
		{10, 7},  // ceil(7.0) = 7
		{20, 14}, // exact
		{100, 70},
	}
	for _, c := range cases {
		if got := testEcon.GuardianQuorumThreshold(c.M); got != c.want {
			t.Errorf("testEcon.GuardianQuorumThreshold(%d) = %d, want %d", c.M, got, c.want)
		}
	}
}

func TestActiveGuardianWeight(t *testing.T) {
	g1, g2, g3 := newGuardian(1), newGuardian(2), newGuardian(3)
	rows := []StakeRow{
		guardianStake(g1, 0x10, 8_000), // weight 4
		guardianStake(g2, 0x20, 6_000), // weight 3
		guardianStake(g3, 0x30, 2_000), // weight 1
	}
	const window = 20
	epoch := uint64(100)
	active := []GuardianActiveRow{
		{GuardianID: g1.id, LastActiveEpoch: 100}, // in window
		{GuardianID: g2.id, LastActiveEpoch: 81},  // 100-81=19 <= 20 → in window
		{GuardianID: g3.id, LastActiveEpoch: 79},  // 100-79=21 > 20 → expired
	}
	// Only g1 (4) + g2 (3) are active = 7. g3 expired. (g3's weight 1 excluded.)
	if got := testEcon.ActiveGuardianWeight(rows, active, epoch, window); got != 7 {
		t.Errorf("ActiveGuardianWeight = %d, want 7 (g1+g2 active, g3 expired)", got)
	}
	// A "lastActive" row for a now-non-Guardian (no stake) contributes 0.
	stranger := newGuardian(9)
	active = append(active, GuardianActiveRow{GuardianID: stranger.id, LastActiveEpoch: 100})
	if got := testEcon.ActiveGuardianWeight(rows, active, epoch, window); got != 7 {
		t.Errorf("ActiveGuardianWeight with non-Guardian active row = %d, want 7", got)
	}
}

// forquinn item 5, the quorum DENOMINATOR: ActiveGuardianWeight flows through GuardianWeight,
// so an in-window identity holding an active staff-tagged stake contributes 0 to M.
func TestActiveGuardianWeightStaffExclusion(t *testing.T) {
	g1, g2 := newGuardian(1), newGuardian(2)
	rows := []StakeRow{
		guardianStake(g1, 0x10, 8_000), // would be weight 4...
		stakeRowFor(g1.id, 0x11, 100, oneMonth, StakedForModerator, StakeStatusActive), // ...but g1 is staff → 0
		guardianStake(g2, 0x20, 6_000), // weight 3
	}
	active := []GuardianActiveRow{
		{GuardianID: g1.id, LastActiveEpoch: 100},
		{GuardianID: g2.id, LastActiveEpoch: 100},
	}
	if got := testEcon.ActiveGuardianWeight(rows, active, 100, 20); got != 3 {
		t.Errorf("ActiveGuardianWeight = %d, want 3 (staff g1 contributes 0; only g2 counts)", got)
	}
}

func TestIsGuardianActiveBoundary(t *testing.T) {
	if !isGuardianActive(80, 100, 20) {
		t.Error("gap == window must be active (inclusive)")
	}
	if isGuardianActive(79, 100, 20) {
		t.Error("gap > window must be inactive")
	}
	if !isGuardianActive(100, 100, 20) {
		t.Error("active this epoch must be active")
	}
	if !isGuardianActive(105, 100, 20) {
		t.Error("future lastActive must be active (overflow-safe)")
	}
}

// ---- verifyFundSendQuorum ----

func TestFundSendBootstrapSingleGuardian(t *testing.T) {
	g := newGuardian(1)
	fund := testFund
	rows := []StakeRow{guardianStake(g, 0x10, 2_000)} // weight 1
	// M == 0 (no one active yet) → threshold 0 → pass iff N>=1.
	snap := snapWithGuardians(fund, [32]byte{0xaa}, 1, rows, 0, g)
	tx := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g})
	if err := verifyFundSendQuorum(tx, snap); err != nil {
		t.Fatalf("bootstrap Fund SEND (M=0, 1 eligible Guardian) rejected: %v", err)
	}
}

func TestFundSendBootstrapNonGuardianFails(t *testing.T) {
	g := newGuardian(1) // signs but has NO stake → weight 0 → not eligible
	fund := testFund
	snap := snapWithGuardians(fund, [32]byte{0xaa}, 1, nil, 0, g)
	tx := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g})
	if err := verifyFundSendQuorum(tx, snap); err == nil {
		t.Fatal("Fund SEND signed only by a non-eligible identity (N=0) must fail the N>=1 floor")
	}
}

// forquinn item 5, the quorum NUMERATOR: a signer holding an active staff-tagged stake
// contributes weight 0 to a Fund SEND, even though its year-locked "guardian" stake alone
// would carry the send. The counterfactual (same send, staff row dropped) passes — proving
// the exclusion, not signature/threshold mechanics, is what rejects.
func TestFundSendStaffSignerExcluded(t *testing.T) {
	g1, g2 := newGuardian(1), newGuardian(2)
	fund := testFund
	rows := []StakeRow{
		guardianStake(g1, 0x10, 8_000), // would be weight 4...
		stakeRowFor(g1.id, 0x11, 5_000, oneYear, StakedForAttestor, StakeStatusActive), // ...but g1 is staff → 0
		guardianStake(g2, 0x20, 6_000), // weight 3
	}

	// g1 alone (M=0 → threshold 0): N = 0 → the N>=1 floor rejects.
	snap := snapWithGuardians(fund, [32]byte{0xaa}, 1, rows, 0, g1, g2)
	tx := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1})
	if err := verifyFundSendQuorum(tx, snap); err == nil {
		t.Fatal("fund send signed only by a staff-tagged identity passed (its weight must be 0)")
	}

	// g1+g2 with M=6 (threshold ceil(0.7*6)=5): approved = 0+3 = 3 < 5 → rejected.
	snap = snapWithGuardians(fund, [32]byte{0xaa}, 1, rows, 6, g1, g2)
	tx = buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1, g2})
	if err := verifyFundSendQuorum(tx, snap); err == nil {
		t.Fatal("staff co-signer's zeroed weight still counted toward the threshold")
	}

	// Counterfactual: no staff row → g1 counts 4 again; 4+3 = 7 >= 5 → passes.
	clean := []StakeRow{rows[0], rows[2]}
	snap = snapWithGuardians(fund, [32]byte{0xaa}, 1, clean, 6, g1, g2)
	tx = buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1, g2})
	if err := verifyFundSendQuorum(tx, snap); err != nil {
		t.Fatalf("counterfactual (no staff row) fund send rejected: %v", err)
	}
}

// DOCUMENTED, deliberately not "fixed" (plan §3 phase 5): if EVERY weight-holding identity is
// staff-tagged, total Guardian weight is 0, the threshold collapses to the N>=1 floor, and no
// signer can satisfy even that — the Fund freezes until a non-staff identity stakes >= the
// divisor @ 1yr. That freeze is the intended fail-safe (better a frozen Fund than staff spend
// power); the phase-6 deploy preflight verifies the bootstrap tags bankers only, so the live
// net never ships in this state.
func TestFundSendAllWeightStaffFreezes(t *testing.T) {
	g1, g2 := newGuardian(1), newGuardian(2)
	fund := testFund
	rows := []StakeRow{
		guardianStake(g1, 0x10, 8_000),
		stakeRowFor(g1.id, 0x11, 5_000, oneYear, StakedForAttestor, StakeStatusActive),
		guardianStake(g2, 0x20, 6_000),
		stakeRowFor(g2.id, 0x21, 5_000, oneMonth, StakedForModerator, StakeStatusActive),
	}
	// The recomputed active denominator is 0 even with both identities in-window...
	active := []GuardianActiveRow{
		{GuardianID: g1.id, LastActiveEpoch: 100},
		{GuardianID: g2.id, LastActiveEpoch: 100},
	}
	if got := testEcon.ActiveGuardianWeight(rows, active, 100, 20); got != 0 {
		t.Fatalf("all-staff ActiveGuardianWeight = %d, want 0", got)
	}
	// ...so threshold(0) = 0 and only the N>=1 floor governs — which nobody can meet: even
	// every weight-holder co-signing yields N = 0 → rejected. The Fund is frozen by design.
	snap := snapWithGuardians(fund, [32]byte{0xaa}, 1, rows, 0, g1, g2)
	tx := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1, g2})
	if err := verifyFundSendQuorum(tx, snap); err == nil {
		t.Fatal("all-weight-staff fund send passed (must fail the N>=1 floor — the documented freeze)")
	}
}

func TestFundSendThresholdPassAndFail(t *testing.T) {
	g1, g2, g3 := newGuardian(1), newGuardian(2), newGuardian(3)
	fund := testFund
	rows := []StakeRow{
		guardianStake(g1, 0x10, 8_000), // weight 4
		guardianStake(g2, 0x20, 6_000), // weight 3
		guardianStake(g3, 0x30, 6_000), // weight 3
	}
	const M = 10 // all three active
	snap := snapWithGuardians(fund, [32]byte{0xaa}, 1, rows, M, g1, g2, g3)
	// threshold = ceil(0.7*10) = 7.
	// g1+g2 = 7 → pass.
	pass := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1, g2})
	if err := verifyFundSendQuorum(pass, snap); err != nil {
		t.Errorf("N=7 >= threshold 7 should pass: %v", err)
	}
	// g2+g3 = 6 < 7 → fail.
	fail := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g2, g3})
	if err := verifyFundSendQuorum(fail, snap); err == nil {
		t.Error("N=6 < threshold 7 should fail")
	}
	// g1 alone = 4 < 7 → fail.
	solo := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1})
	if err := verifyFundSendQuorum(solo, snap); err == nil {
		t.Error("N=4 < threshold 7 should fail")
	}
}

func TestFundSendDuplicateSignerCountsOnce(t *testing.T) {
	g1, g2 := newGuardian(1), newGuardian(2)
	fund := testFund
	rows := []StakeRow{
		guardianStake(g1, 0x10, 8_000), // weight 4
		guardianStake(g2, 0x20, 6_000), // weight 3
	}
	const M = 7
	snap := snapWithGuardians(fund, [32]byte{0xaa}, 1, rows, M, g1, g2)
	// threshold = ceil(0.7*7) = 5. g1 listed twice + g2 once: distinct weight = 4+3 = 7 >= 5 pass.
	// But g1 twice must NOT count as 4+4+3 = 11 in a way that lets g1-only (4, listed twice = "8") pass.
	dupOnly := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1, g1})
	if err := verifyFundSendQuorum(dupOnly, snap); err == nil {
		t.Error("g1 listed twice (distinct weight 4 < threshold 5) must fail — duplicates count once")
	}
	ok := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1, g1, g2})
	if err := verifyFundSendQuorum(ok, snap); err != nil {
		t.Errorf("g1,g1,g2 distinct weight 7 >= 5 should pass: %v", err)
	}
}

func TestFundSendBadAndUnknownSignersIgnored(t *testing.T) {
	g1, g2 := newGuardian(1), newGuardian(2)
	fund := testFund
	rows := []StakeRow{
		guardianStake(g1, 0x10, 8_000), // weight 4
		guardianStake(g2, 0x20, 6_000), // weight 3
	}
	const M = 7
	snap := snapWithGuardians(fund, [32]byte{0xaa}, 1, rows, M, g1, g2)

	// Valid quorum from g1+g2 (7 >= ceil(0.7*7)=5)...
	tx := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1, g2})
	// ...plus a corrupted entry (g1's sig flipped) and an unknown signer — both must be ignored,
	// not fatal, and the tx still passes on the two good signatures.
	bad := proto.Clone(tx.MultiSig.Entries[0]).(*pb.HybridSigEntry)
	bad.Sig.V[0] ^= 0xff
	unknown := newGuardian(7) // not in snap.Accounts → no pubkey
	mUnknown, _, _ := crypto.MsgHash(tx)
	uSig, _ := unknown.priv.Sign(mUnknown)
	tx.MultiSig.Entries = append(tx.MultiSig.Entries, bad, &pb.HybridSigEntry{
		SignerId: &pb.AccountId{V: unknown.id[:]}, Sig: &pb.HybridSig{V: uSig.Encode()},
	})
	if err := verifyFundSendQuorum(tx, snap); err != nil {
		t.Errorf("quorum should survive a corrupted + an unknown entry (both ignored): %v", err)
	}

	// A signer who verifies but is NOT an eligible Guardian (weight 0) does not count toward N.
	stranger := newGuardian(8)
	snap.Accounts[stranger.id] = AccountSnap{Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING, AuthPubKey: stranger.pub.Encode()}
	soloStranger := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{stranger})
	if err := verifyFundSendQuorum(soloStranger, snap); err == nil {
		t.Error("an eligible-weight-0 signer alone (N=0) must fail the N>=1 floor")
	}
}

func TestFundSendWrongDigestFails(t *testing.T) {
	g1, g2 := newGuardian(1), newGuardian(2)
	fund := testFund
	rows := []StakeRow{guardianStake(g1, 0x10, 8_000), guardianStake(g2, 0x20, 6_000)}
	snap := snapWithGuardians(fund, [32]byte{0xaa}, 1, rows, 7, g1, g2)
	tx := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1, g2})
	// Tamper the amount AFTER signing → the signatures no longer match m → all ignored → fail.
	tx.GetSend().Amount = anosUnits(999_999)
	if err := verifyFundSendQuorum(tx, snap); err == nil {
		t.Error("tampering the body after signing must invalidate the quorum")
	}
}

// ---- crypto: Fund-SEND txid binds the signer set, order-independently ----

func TestFundSendTxIDOrderIndependentBindsSet(t *testing.T) {
	g1, g2, g3 := newGuardian(1), newGuardian(2), newGuardian(3)
	fund := testFund
	tx := buildFundSend(fund, [32]byte{0xaa}, 2, [32]byte{0x42}, anosUnits(10), 100, []*tGuardian{g1, g2, g3})
	id1, err := crypto.TxID(tx)
	if err != nil {
		t.Fatalf("txid: %v", err)
	}
	// Reverse entry order → same txid (sorted canonical multisig).
	e := tx.MultiSig.Entries
	for i, j := 0, len(e)-1; i < j; i, j = i+1, j-1 {
		e[i], e[j] = e[j], e[i]
	}
	id2, err := crypto.TxID(tx)
	if err != nil {
		t.Fatalf("txid (reordered): %v", err)
	}
	if id1 != id2 {
		t.Error("Fund-SEND txid must be independent of multisig entry order")
	}
	// Drop a signer → DIFFERENT txid (the txid pins the exact set).
	tx.MultiSig.Entries = e[:2]
	id3, err := crypto.TxID(tx)
	if err != nil {
		t.Fatalf("txid (subset): %v", err)
	}
	if id3 == id1 {
		t.Error("Fund-SEND txid must change when the signer set changes")
	}
}

// ---- DB-backed ApplyTx ----

// seedKeyedAccount seeds a SPENDING account carrying an auth pubkey (so it can be looked up as
// a Fund-SEND signer).
func seedKeyedGuardian(t *testing.T, db *bbolt.DB, g *tGuardian) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, g.id, AccountRecord{
			Head: [32]byte{g.id[0]}, Balance: 0, Seq: 1,
			Class:      pb.AccountClass_ACCOUNT_CLASS_SPENDING,
			AuthPubKey: g.pub.Encode(),
		})
	}); err != nil {
		t.Fatalf("seed guardian: %v", err)
	}
}

func applyFundSend(t *testing.T, db *bbolt.DB, tx *pb.Tx, txid [32]byte) error {
	t.Helper()
	raw, _ := proto.Marshal(tx)
	return db.Update(func(btx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: btx}, raw, tx, txid, testFund, testEcon, 0)
	})
}

func guardianActiveMap(t *testing.T, db *bbolt.DB) map[[32]byte]uint64 {
	t.Helper()
	rows, err := ListGuardianActive(db)
	if err != nil {
		t.Fatalf("ListGuardianActive: %v", err)
	}
	out := map[[32]byte]uint64{}
	for _, r := range rows {
		out[r.GuardianID] = r.LastActiveEpoch
	}
	return out
}

func TestApplyFundSendDebitsAndRecordsActivity(t *testing.T) {
	db := newFundTestDB(t)
	fundHead := seedFundRecord(t, db, testFund)
	// Give the Fund a balance to spend (creditFund-style, but seed directly).
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, testFund, AccountRecord{Head: fundHead, Seq: 1, Balance: anosUnits(1_000), Class: pb.AccountClass_ACCOUNT_CLASS_FUND})
	}); err != nil {
		t.Fatal(err)
	}
	g1, g2 := newGuardian(1), newGuardian(2)
	seedKeyedGuardian(t, db, g1)
	seedKeyedGuardian(t, db, g2)

	var to [32]byte
	to[0] = 0x42
	amt := anosUnits(300)
	const fundEpoch = 55
	tx := buildFundSend(testFund, fundHead, 2, to, amt, fundEpoch, []*tGuardian{g1, g2})
	txid := txidFor(testFund, 2)
	if err := applyFundSend(t, db, tx, txid); err != nil {
		t.Fatalf("apply fund send: %v", err)
	}

	// Fund debited by exactly amt; head/seq advanced to the real tx.
	rec := fundRecord(t, db, testFund)
	if rec.Balance != anosUnits(700) {
		t.Errorf("fund balance = %d, want %d", rec.Balance, anosUnits(700))
	}
	if rec.Head != txid || rec.Seq != 2 {
		t.Errorf("fund chain head/seq = %x/%d, want %x/2", rec.Head[:4], rec.Seq, txid[:4])
	}
	// Recipient receivable minted (the user claims it normally).
	rid := crypto.ReceivableIDFromTxID(txid)
	var got pb.Receivable
	if err := db.View(func(btx *bbolt.Tx) error {
		raw, err := getReceivableRaw(btx, rid)
		if err != nil {
			return err
		}
		return proto.Unmarshal(raw, &got)
	}); err != nil {
		t.Fatalf("recipient receivable missing: %v", err)
	}
	if got.Amount != amt || !bytesEq32(got.To.V, to) {
		t.Errorf("receivable = {amt %d, to %x}, want {%d, %x}", got.Amount, got.To.V[:4], amt, to[:4])
	}
	// Both signers marked active at fundEpoch.
	active := guardianActiveMap(t, db)
	if active[g1.id] != fundEpoch || active[g2.id] != fundEpoch {
		t.Errorf("guardian-active = %v, want both at %d", active, fundEpoch)
	}
}

// recordGuardianActivity must NOT depend on the signer accounts being present in the DB: during
// resync the Fund's debiting chain can replay before the signer accounts are established, and a
// verify-at-apply would then drop those signers and diverge from the live path. This pins that
// the projection records the listed signer ids purely from the tx, even with NO signer accounts
// seeded. (Regression guard for the resync guardian-projection divergence found in P2.3a live.)
func TestApplyFundSendRecordsActivityWithoutSignerAccounts(t *testing.T) {
	db := newFundTestDB(t)
	fundHead := seedFundRecord(t, db, testFund)
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, testFund, AccountRecord{Head: fundHead, Seq: 1, Balance: anosUnits(1_000), Class: pb.AccountClass_ACCOUNT_CLASS_FUND})
	}); err != nil {
		t.Fatal(err)
	}
	g1, g2 := newGuardian(1), newGuardian(2)
	// Deliberately do NOT seed g1/g2 accounts (simulate them not yet replayed on resync).
	var to [32]byte
	to[0] = 0x42
	const fundEpoch = 55
	tx := buildFundSend(testFund, fundHead, 2, to, anosUnits(300), fundEpoch, []*tGuardian{g1, g2})
	if err := applyFundSend(t, db, tx, txidFor(testFund, 2)); err != nil {
		t.Fatalf("apply fund send: %v", err)
	}
	active := guardianActiveMap(t, db)
	if active[g1.id] != fundEpoch || active[g2.id] != fundEpoch {
		t.Errorf("guardian-active = %v, want both signers at %d even with no signer accounts seeded", active, fundEpoch)
	}
}

func TestApplyFundSendIdempotentNoDoubleDebit(t *testing.T) {
	db := newFundTestDB(t)
	fundHead := seedFundRecord(t, db, testFund)
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, testFund, AccountRecord{Head: fundHead, Seq: 1, Balance: anosUnits(1_000), Class: pb.AccountClass_ACCOUNT_CLASS_FUND})
	}); err != nil {
		t.Fatal(err)
	}
	g := newGuardian(1)
	seedKeyedGuardian(t, db, g)
	var to [32]byte
	to[0] = 0x42
	tx := buildFundSend(testFund, fundHead, 2, to, anosUnits(300), 55, []*tGuardian{g})
	txid := txidFor(testFund, 2)
	if err := applyFundSend(t, db, tx, txid); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	// Re-apply (resync replay): the head==txid && seq guard makes it a no-op.
	if err := applyFundSend(t, db, tx, txid); err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if got := fundRecord(t, db, testFund).Balance; got != anosUnits(700) {
		t.Errorf("re-apply double-debited: balance %d, want %d", got, anosUnits(700))
	}
}

// The Guardian-activity projection rebuilds identically regardless of the order Fund SENDs are
// replayed (keep-the-max keying → order-independent, the resync guarantee).
func TestGuardianActiveOrderIndependentRebuild(t *testing.T) {
	g := newGuardian(1)
	build := func(reverse bool) map[[32]byte]uint64 {
		db := newFundTestDB(t)
		fundHead := seedFundRecord(t, db, testFund)
		if err := db.Update(func(tx *bbolt.Tx) error {
			return putAccountRecord(tx, testFund, AccountRecord{Head: fundHead, Seq: 1, Balance: anosUnits(1_000), Class: pb.AccountClass_ACCOUNT_CLASS_FUND})
		}); err != nil {
			t.Fatal(err)
		}
		seedKeyedGuardian(t, db, g)
		var to [32]byte
		to[0] = 0x42
		// Two Fund SENDs on the Fund chain at epochs 40 then 60. Applying out of seq order is
		// not physically possible on one chain, so we simulate by recording activity directly in
		// both orders via putGuardianActive (the projection primitive), asserting the max wins.
		lo, hi := uint64(40), uint64(60)
		_ = to
		if err := db.Update(func(tx *bbolt.Tx) error {
			if reverse {
				if err := putGuardianActive(tx, g.id, hi); err != nil {
					return err
				}
				return putGuardianActive(tx, g.id, lo)
			}
			if err := putGuardianActive(tx, g.id, lo); err != nil {
				return err
			}
			return putGuardianActive(tx, g.id, hi)
		}); err != nil {
			t.Fatal(err)
		}
		return guardianActiveMap(t, db)
	}
	fwd, rev := build(false), build(true)
	if !reflect.DeepEqual(fwd, rev) {
		t.Fatalf("guardian-active differs by order: fwd=%v rev=%v", fwd, rev)
	}
	if fwd[g.id] != 60 {
		t.Errorf("keep-the-max failed: got %d, want 60", fwd[g.id])
	}
}

func TestApplyFundSendZeroFeeAndBalanceGuards(t *testing.T) {
	db := newFundTestDB(t)
	fundHead := seedFundRecord(t, db, testFund)
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, testFund, AccountRecord{Head: fundHead, Seq: 1, Balance: anosUnits(100), Class: pb.AccountClass_ACCOUNT_CLASS_FUND})
	}); err != nil {
		t.Fatal(err)
	}
	g := newGuardian(1)
	seedKeyedGuardian(t, db, g)
	var to [32]byte
	to[0] = 0x42

	// Non-zero fee → rejected at apply.
	feeTx := buildFundSend(testFund, fundHead, 2, to, anosUnits(10), 55, []*tGuardian{g})
	feeTx.GetSend().Fee = 1
	signFundSend(feeTx, []*tGuardian{g}) // re-sign after mutating
	if err := applyFundSend(t, db, feeTx, txidFor(testFund, 2)); err == nil {
		t.Error("fund send with non-zero fee must be rejected at apply")
	}

	// Over-balance → ErrInsufficientBal.
	bigTx := buildFundSend(testFund, fundHead, 2, to, anosUnits(1_000), 55, []*tGuardian{g})
	if err := applyFundSend(t, db, bigTx, txidFor(testFund, 2)); err == nil {
		t.Error("fund send exceeding balance must fail")
	}
}

// ---- end-to-end ValidateTxAgainstSnapshot ----

func TestValidateFundSendEndToEnd(t *testing.T) {
	g1, g2 := newGuardian(1), newGuardian(2)
	fund := testFund
	var fundHead [32]byte
	fundHead[0] = 0xaa
	rows := []StakeRow{guardianStake(g1, 0x10, 8_000), guardianStake(g2, 0x20, 6_000)} // 4, 3
	snap := snapWithGuardians(fund, fundHead, 1, rows, 7, g1, g2)                      // M=7, threshold 5

	// g1+g2 = 7 >= 5 → accepted; returns the txid computed by crypto.TxID.
	tx := buildFundSend(fund, fundHead, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1, g2})
	gotID, err := ValidateTxAgainstSnapshot(tx, snap)
	if err != nil {
		t.Fatalf("valid Fund SEND rejected: %v", err)
	}
	wantID, _ := crypto.TxID(tx)
	if gotID != wantID {
		t.Errorf("returned txid %x != crypto.TxID %x", gotID[:4], wantID[:4])
	}

	// Below threshold (g2 alone, weight 3 < 5) → rejected.
	low := buildFundSend(fund, fundHead, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g2})
	if _, err := ValidateTxAgainstSnapshot(low, snap); err == nil {
		t.Error("below-threshold Fund SEND accepted")
	}

	// fund_send_epoch in the future → rejected (cannot claim future activeness).
	future := buildFundSend(fund, fundHead, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch+1, []*tGuardian{g1, g2})
	if _, err := ValidateTxAgainstSnapshot(future, snap); err == nil {
		t.Error("Fund SEND with future fund_send_epoch accepted")
	}

	// Non-zero fee → rejected.
	feeTx := buildFundSend(fund, fundHead, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1, g2})
	feeTx.GetSend().Fee = 5
	signFundSend(feeTx, []*tGuardian{g1, g2})
	if _, err := ValidateTxAgainstSnapshot(feeTx, snap); err == nil {
		t.Error("Fund SEND with non-zero fee accepted")
	}

	// A Fund SEND that smuggles in a Tx.sig → rejected (keeps crypto.TxID's multisig-binding
	// discriminator sound; a Tx.sig-bearing Fund SEND would otherwise get a single-sig txid that
	// does not commit to the multisig → consensus-fork vector).
	sigTx := buildFundSend(fund, fundHead, 2, [32]byte{0x42}, anosUnits(10), snap.Epoch, []*tGuardian{g1, g2})
	sigTx.Sig = &pb.HybridSig{V: make([]byte, crypto.HybridSigSize)}
	if _, err := ValidateTxAgainstSnapshot(sigTx, snap); err == nil {
		t.Error("Fund SEND carrying a Tx.sig accepted (must be keyless)")
	}

	// fund_send_epoch too stale (self-exclude-from-M attack) → rejected.
	staleSnap := snapWithGuardians(fund, fundHead, 1, rows, 7, g1, g2)
	staleSnap.Epoch = 100 + testEcon.GuardianFundSendEpochSlackEpochs + 5
	stale := buildFundSend(fund, fundHead, 2, [32]byte{0x42}, anosUnits(10), 100, []*tGuardian{g1, g2})
	if _, err := ValidateTxAgainstSnapshot(stale, staleSnap); err == nil {
		t.Error("Fund SEND with stale fund_send_epoch accepted (self-exclusion vector)")
	}
	// ...but within the slack it is accepted.
	freshSnap := snapWithGuardians(fund, fundHead, 1, rows, 7, g1, g2)
	freshSnap.Epoch = 100 + testEcon.GuardianFundSendEpochSlackEpochs
	fresh := buildFundSend(fund, fundHead, 2, [32]byte{0x42}, anosUnits(10), 100, []*tGuardian{g1, g2})
	if _, err := ValidateTxAgainstSnapshot(fresh, freshSnap); err != nil {
		t.Errorf("Fund SEND at the staleness boundary rejected: %v", err)
	}
}
