package core

// P2.2 stake reference table (spec-18 §7, spec-19 §5, build-plan §P2.2). DB-backed
// ApplyTx tests pin: a stake deposit is recorded keyed by deposit_txid; an unknown tag is
// stored (never rejected); a sub-floor interpreted-tag stake is stored but NOT role-eligible;
// a stake routed through a TRANSFER chain attributes to the chain's source (the original
// owner); a plain pool contribution records no row; re-apply does not double-insert; the
// table rebuilds byte-identically regardless of apply order. Snapshot-based validate tests
// pin the require-routing + valid-tier gates. Pure-function tests pin the role/weight
// derivations. Shares newFundTestDB/seedFundRecord/seedSpending/txidFor with fund_credit_test.go.

import (
	"encoding/hex"
	"reflect"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

const (
	oneMonth = pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_MONTH
	oneYear  = pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_YEAR
)

func anosUnits(n uint64) uint64 { return n * UnitsPerAnos }

// applyStakeSend builds a stake-deposit SEND (with stake metadata + the sender's stored
// class) and runs it through ApplyTx, returning the txid and any apply error.
func applyStakeSend(t *testing.T, db *bbolt.DB, from, fromHead [32]byte, seq uint64, to [32]byte, amt, fee uint64, senderClass pb.AccountClass, stakedFor string, delay pb.StakeTimeDelay, fund [32]byte) ([32]byte, error) {
	t.Helper()
	txid := txidFor(from, seq)
	ptx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: from[:]},
		Prev:    &pb.Hash32{V: fromHead[:]},
		Seq:     seq,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: to[:]},
			Amount:       amt,
			Fee:          fee,
			AccountClass: senderClass,
			StakedFor:    stakedFor,
			TimeDelay:    delay,
		}},
	}
	raw, _ := proto.Marshal(ptx)
	err := db.Update(func(tx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: tx}, raw, ptx, txid, fund, testEcon, 0)
	})
	return txid, err
}

func seedTransferChain(t *testing.T, db *bbolt.DB, acct, head, source [32]byte, bal, seq uint64) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, acct, AccountRecord{
			Head: head, Balance: bal, Seq: seq,
			Class:          pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			TransferSource: source,
			TransferDest:   [32]byte{0xfe}, // unused by ApplyTx's transfer-outbound branch
		})
	}); err != nil {
		t.Fatalf("seed transfer chain: %v", err)
	}
}

func listStakes(t *testing.T, db *bbolt.DB) []StakeRow {
	t.Helper()
	rows, err := ListAllStakes(db)
	if err != nil {
		t.Fatalf("ListAllStakes: %v", err)
	}
	return rows
}

func dumpStakeBucket(t *testing.T, db *bbolt.DB) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BFundStakes)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			out[hex.EncodeToString(k)] = hex.EncodeToString(v)
			return nil
		})
	})
	return out
}

// A direct SPENDING stake deposit is recorded under the sender's id, with the right
// amount/tag/tier/status, and the Fund still receives amount+fee.
func TestStakeRecordedDirectSpending(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)

	var staker, head [32]byte
	staker[0], head[0] = 0x11, 0xb1
	amt := anosUnits(60_000)
	fee := ExpectedFee(amt)
	seedSpending(t, db, staker, head, amt+fee, 1)

	txid, err := applyStakeSend(t, db, staker, head, 2, testFund, amt, fee, pb.AccountClass_ACCOUNT_CLASS_SPENDING, StakedForBanker, oneYear, testFund)
	if err != nil {
		t.Fatalf("apply stake: %v", err)
	}

	rows := listStakes(t, db)
	if len(rows) != 1 {
		t.Fatalf("want 1 stake row, got %d", len(rows))
	}
	r := rows[0]
	if r.DepositTxid != txid {
		t.Errorf("stake keyed by %x, want deposit_txid %x", r.DepositTxid[:4], txid[:4])
	}
	if r.StakerID != staker || r.StakedFor != StakedForBanker || r.Amount != amt || r.TimeDelay != oneYear || r.Status != StakeStatusActive {
		t.Errorf("stake row = %+v, want staker=%x banker/%d/1yr/active", r.StakeRecord, staker[:4], amt)
	}
	if got := fundRecord(t, db, testFund).Balance; got != amt+fee {
		t.Errorf("fund balance = %d, want amount+fee %d", got, amt+fee)
	}
}

// An UNKNOWN staked_for tag is stored verbatim, never rejected (open namespace).
func TestStakeUnknownTagStored(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)

	var staker, head [32]byte
	staker[0], head[0] = 0x22, 0xb2
	amt := anosUnits(100)
	fee := ExpectedFee(amt)
	seedSpending(t, db, staker, head, amt+fee, 1)

	if _, err := applyStakeSend(t, db, staker, head, 2, testFund, amt, fee, pb.AccountClass_ACCOUNT_CLASS_SPENDING, "masterpod", oneMonth, testFund); err != nil {
		t.Fatalf("unknown-tag stake rejected (must be stored): %v", err)
	}
	rows := listStakes(t, db)
	if len(rows) != 1 || rows[0].StakedFor != "masterpod" {
		t.Fatalf("unknown tag not stored verbatim: %+v", rows)
	}
}

// A sub-floor Attestor stake is STORED but not role-eligible; a same-amount unknown-tag
// stake is equally accepted (the floor is a membership predicate, not a deposit gate).
func TestStakeSubFloorAttestorStoredNotEligible(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)

	var att, attHead, unk, unkHead [32]byte
	att[0], attHead[0], unk[0], unkHead[0] = 0x33, 0xb3, 0x44, 0xb4
	amt := anosUnits(4_999) // below the 5,000-anos Attestor floor
	fee := ExpectedFee(amt)
	seedSpending(t, db, att, attHead, amt+fee, 1)
	seedSpending(t, db, unk, unkHead, amt+fee, 1)

	if _, err := applyStakeSend(t, db, att, attHead, 2, testFund, amt, fee, pb.AccountClass_ACCOUNT_CLASS_SPENDING, StakedForAttestor, oneMonth, testFund); err != nil {
		t.Fatalf("sub-floor attestor stake rejected (must be stored): %v", err)
	}
	if _, err := applyStakeSend(t, db, unk, unkHead, 2, testFund, amt, fee, pb.AccountClass_ACCOUNT_CLASS_SPENDING, "weird-role", oneMonth, testFund); err != nil {
		t.Fatalf("same-amount unknown-tag stake rejected: %v", err)
	}

	rows := listStakes(t, db)
	if len(rows) != 2 {
		t.Fatalf("want 2 stored stakes, got %d", len(rows))
	}
	if testEcon.IsAttestor(rows, att) {
		t.Error("sub-floor attestor stake must NOT confer Attestor membership")
	}
}

// A stake that routed through a TRANSFER chain attributes to the chain's stored source
// (the original owner), NOT the chain id.
func TestStakeRoutedAttributesToSource(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)

	var chain, chainHead, source [32]byte
	chain[0], chainHead[0], source[0] = 0x55, 0xc5, 0x99
	bal := anosUnits(8_000)
	seedTransferChain(t, db, chain, chainHead, source, bal, 1)

	// TRANSFER outbound = zero-fee full-balance drain to the Fund, carrying stake metadata.
	if _, err := applyStakeSend(t, db, chain, chainHead, 2, testFund, bal, 0, pb.AccountClass_ACCOUNT_CLASS_TRANSFER, StakedForAttestor, oneYear, testFund); err != nil {
		t.Fatalf("routed stake apply: %v", err)
	}
	rows := listStakes(t, db)
	if len(rows) != 1 {
		t.Fatalf("want 1 stake row, got %d", len(rows))
	}
	if rows[0].StakerID != source {
		t.Errorf("routed stake attributed to %x, want the chain's source %x", rows[0].StakerID[:4], source[:4])
	}
	if rows[0].Amount != bal {
		t.Errorf("routed stake amount = %d, want the drained balance %d", rows[0].Amount, bal)
	}
	if !testEcon.IsAttestor(rows, source) {
		t.Error("the routed 8,000-anos attestor stake should make the SOURCE an Attestor")
	}
}

// A plain pool contribution (to == Fund, no staked_for) records NO stake row.
func TestPlainPoolContributionNoStakeRow(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)

	var s, head [32]byte
	s[0], head[0] = 0x66, 0xb6
	amt := anosUnits(500)
	fee := ExpectedFee(amt)
	seedSpending(t, db, s, head, amt+fee, 1)

	if _, err := applyStakeSend(t, db, s, head, 2, testFund, amt, fee, pb.AccountClass_ACCOUNT_CLASS_SPENDING, "" /*no tag*/, pb.StakeTimeDelay_STAKE_TIME_DELAY_UNSPECIFIED, testFund); err != nil {
		t.Fatalf("plain pool contribution rejected: %v", err)
	}
	if rows := listStakes(t, db); len(rows) != 0 {
		t.Fatalf("plain pool contribution recorded a stake row: %+v", rows)
	}
	if got := fundRecord(t, db, testFund).Balance; got != amt+fee {
		t.Errorf("fund balance = %d, want amount+fee %d", got, amt+fee)
	}
}

// Re-applying the same stake SEND (resync replay) does not double-insert: the row is
// written once and is byte-identical.
func TestStakeNoDoubleInsertOnReapply(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)

	var s, head [32]byte
	s[0], head[0] = 0x77, 0xb7
	amt := anosUnits(7_000)
	fee := ExpectedFee(amt)
	seedSpending(t, db, s, head, amt+fee, 1)

	_, err := applyStakeSend(t, db, s, head, 2, testFund, amt, fee, pb.AccountClass_ACCOUNT_CLASS_SPENDING, StakedForAttestor, oneYear, testFund)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	before := dumpStakeBucket(t, db)
	// Re-apply the identical SEND; the ApplyTx idempotency guard makes it a no-op.
	if _, err := applyStakeSend(t, db, s, head, 2, testFund, amt, fee, pb.AccountClass_ACCOUNT_CLASS_SPENDING, StakedForAttestor, oneYear, testFund); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	after := dumpStakeBucket(t, db)
	if len(after) != 1 || !reflect.DeepEqual(before, after) {
		t.Fatalf("re-apply changed the table: before=%v after=%v", before, after)
	}
}

// The table rebuilds byte-identically regardless of the order stakes are applied
// (rows keyed by deposit_txid → set-equal; this is the resync replay-order guarantee).
func TestStakeTableOrderIndependentRebuild(t *testing.T) {
	build := func(reverse bool) map[string]string {
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)
		var x, xh, y, yh [32]byte
		x[0], xh[0], y[0], yh[0] = 0x88, 0xd8, 0xaa, 0xda
		ax, ay := anosUnits(3_000), anosUnits(5_000)
		seedSpending(t, db, x, xh, ax+ExpectedFee(ax), 1)
		seedSpending(t, db, y, yh, ay+ExpectedFee(ay), 1)
		apply := []func(){
			func() {
				applyStakeSend(t, db, x, xh, 2, testFund, ax, ExpectedFee(ax), pb.AccountClass_ACCOUNT_CLASS_SPENDING, StakedForBanker, oneMonth, testFund)
			},
			func() {
				applyStakeSend(t, db, y, yh, 2, testFund, ay, ExpectedFee(ay), pb.AccountClass_ACCOUNT_CLASS_SPENDING, StakedForAttestor, oneYear, testFund)
			},
		}
		if reverse {
			apply[1]()
			apply[0]()
		} else {
			apply[0]()
			apply[1]()
		}
		return dumpStakeBucket(t, db)
	}
	if !reflect.DeepEqual(build(false), build(true)) {
		t.Fatal("stake table differs by apply order (must be order-independent for resync)")
	}
}

// Guardian weight = floor(Σ identity's active 1-year stake / 2000 anos); 1-month stakes
// and other identities' stakes are excluded. Also exercises IsBanker/IsAttestor/
// StakesByRole/BankerIdentities over a constructed row set.
func TestRoleDerivations(t *testing.T) {
	var g, h [32]byte
	g[0], h[0] = 0x01, 0x02
	rows := []StakeRow{
		{DepositTxid: [32]byte{1}, StakeRecord: StakeRecord{StakerID: g, Amount: anosUnits(30_000), TimeDelay: oneYear, StakedFor: StakedForBanker}},
		{DepositTxid: [32]byte{2}, StakeRecord: StakeRecord{StakerID: g, Amount: anosUnits(25_000), TimeDelay: oneYear, StakedFor: StakedForAttestor}},
		{DepositTxid: [32]byte{3}, StakeRecord: StakeRecord{StakerID: g, Amount: anosUnits(99_000), TimeDelay: oneMonth, StakedFor: StakedForAttestor}}, // 1mo: excluded from weight
		{DepositTxid: [32]byte{4}, StakeRecord: StakeRecord{StakerID: h, Amount: anosUnits(1_000), TimeDelay: oneYear, StakedFor: "moderator"}},
	}

	// floor((30000+25000)/2000) = 27; h's 1,000 → floor(1000/2000) = 0.
	if w := testEcon.GuardianWeight(rows, g); w != 27 {
		t.Errorf("testEcon.GuardianWeight(g) = %d, want 27", w)
	}
	if w := testEcon.GuardianWeight(rows, h); w != 0 {
		t.Errorf("testEcon.GuardianWeight(h) = %d, want 0", w)
	}
	// g: banker stake 30k < 50k floor → NOT a banker; attestor 25k >= 5k → attestor.
	if testEcon.IsBanker(rows, g) {
		t.Error("g must NOT be a Banker (30k < 50k floor)")
	}
	if !testEcon.IsAttestor(rows, g) {
		t.Error("g must be an Attestor (25k >= 5k floor)")
	}
	if got := len(StakesByRole(rows, StakedForBanker)); got != 1 {
		t.Errorf("StakesByRole(banker) = %d rows, want 1 (the single banker-tagged stake, floor not applied here)", got)
	}
	if ids := testEcon.BankerIdentities(rows); len(ids) != 0 {
		t.Errorf("BankerIdentities = %v, want none (no banker stake meets the 50k floor)", ids)
	}
}

func TestPackUnpackStakeRecordRoundTrip(t *testing.T) {
	in := StakeRecord{StakerID: [32]byte{0xab, 0xcd}, Amount: 123456789, TimeDelay: oneYear, Status: StakeStatusKicked, StakedFor: "some-open-tag"}
	out, ok := unpackStakeRecord(packStakeRecord(in))
	if !ok || !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch: in=%+v out=%+v ok=%v", in, out, ok)
	}
	if _, ok := unpackStakeRecord([]byte{1, 2, 3}); ok {
		t.Error("unpack of a too-short record must fail closed")
	}

	// A large tag (> 64 KiB) must round-trip — the on-disk length prefix is uint32, matching
	// SignBytesACTE's framing, so the open namespace imposes no silent length truncation.
	big := StakeRecord{StakerID: [32]byte{0x01}, Amount: 1, TimeDelay: oneMonth, StakedFor: string(make([]byte, 70_000))}
	if out, ok := unpackStakeRecord(packStakeRecord(big)); !ok || !reflect.DeepEqual(big, out) {
		t.Fatalf("large-tag round-trip failed: ok=%v len(in)=%d len(out)=%d", ok, len(big.StakedFor), len(out.StakedFor))
	}
}

// --- Validate-path gates (require-routing + valid-tier), with real signed txs. ---

type stakeValidateFixture struct {
	snap *Snapshot
	priv *crypto.HybridPrivateKey
	id   [32]byte
}

func newStakeValidateFixture(t *testing.T, senderClass pb.AccountClass, seed byte) *stakeValidateFixture {
	t.Helper()
	priv, pub := crypto.GenerateHybridKeyFromSeed([32]byte{seed})
	tb := crypto.AccountTypeByteForClass(senderClass)
	id := crypto.BaseAccountID(tb, pub.Encode())
	snap := &Snapshot{Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			id: {Balance: anosUnits(1_000_000), Seq: 0, Class: senderClass, AuthPubKey: pub.Encode()},
		},
		Receivables: map[[32]byte]ReceivableSnap{},
		Epoch:       10,
		DelayEpochs: 6,
		FundAccount: testFund,
	}
	return &stakeValidateFixture{snap: snap, priv: priv, id: id}
}

func (f *stakeValidateFixture) stakeSend(t *testing.T, to [32]byte, amt, fee uint64, class pb.AccountClass, stakedFor string, delay pb.StakeTimeDelay) *pb.Tx {
	t.Helper()
	tx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: append([]byte(nil), f.id[:]...)},
		Prev:    &pb.Hash32{V: make([]byte, 32)},
		Seq:     1,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: append([]byte(nil), to[:]...)},
			Amount:       amt,
			Fee:          fee,
			AccountClass: class,
			StakedFor:    stakedFor,
			TimeDelay:    delay,
		}},
	}
	if err := crypto.SignTxHybrid(tx, f.priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tx
}

func TestValidateStakeRequiresRouting(t *testing.T) {
	// SPENDING direct stake: accepted (both tiers).
	for _, d := range []pb.StakeTimeDelay{oneMonth, oneYear} {
		f := newStakeValidateFixture(t, pb.AccountClass_ACCOUNT_CLASS_SPENDING, 1)
		amt := anosUnits(60_000)
		tx := f.stakeSend(t, testFund, amt, ExpectedFee(amt), pb.AccountClass_ACCOUNT_CLASS_SPENDING, StakedForBanker, d)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
			t.Errorf("SPENDING direct stake (tier %v) rejected: %v", d, err)
		}
	}

	// Restricted-class direct stake: rejected (must route through a transfer chain).
	for _, cls := range []pb.AccountClass{
		pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED,
		pb.AccountClass_ACCOUNT_CLASS_GUARDED,
		pb.AccountClass_ACCOUNT_CLASS_VAULT,
	} {
		f := newStakeValidateFixture(t, cls, 2)
		amt := anosUnits(60_000)
		tx := f.stakeSend(t, testFund, amt, ExpectedFee(amt), cls, StakedForBanker, oneYear)
		if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
			t.Errorf("%v direct stake accepted (must route through a transfer chain)", cls)
		}
	}

	// Restricted-class PLAIN pool contribution (no staked_for): still allowed (P2.1 behavior).
	f := newStakeValidateFixture(t, pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, 3)
	amt := anosUnits(100)
	tx := f.stakeSend(t, testFund, amt, ExpectedFee(amt), pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, "", pb.StakeTimeDelay_STAKE_TIME_DELAY_UNSPECIFIED)
	if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err != nil {
		t.Errorf("restricted-class plain pool contribution rejected: %v", err)
	}
}

func TestValidateStakeRequiresValidTier(t *testing.T) {
	f := newStakeValidateFixture(t, pb.AccountClass_ACCOUNT_CLASS_SPENDING, 4)
	amt := anosUnits(60_000)
	// staked_for set but tier UNSPECIFIED → rejected.
	tx := f.stakeSend(t, testFund, amt, ExpectedFee(amt), pb.AccountClass_ACCOUNT_CLASS_SPENDING, StakedForBanker, pb.StakeTimeDelay_STAKE_TIME_DELAY_UNSPECIFIED)
	if _, err := ValidateTxAgainstSnapshot(tx, f.snap); err == nil {
		t.Error("stake with no lock tier accepted (must require 1mo/1yr)")
	}
}
