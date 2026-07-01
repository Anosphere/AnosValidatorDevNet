package core

// P2.1 Alt A direct Fund credit (spec-18 §7.2, build-plan P2.1). DB-backed tests over
// ApplyTx pin: a fee-bearing normal send credits the Fund by exactly the fee (and still
// mints the recipient receivable); a send whose to == Fund credits amount+fee and mints
// NO recipient receivable; the credit is a pure, order-independent += across same-epoch
// senders; a re-applied SEND does not double-credit (resync replay parity); the Fund's
// record shape (class FUND, seq 1, synthetic seed head) survives crediting; and a
// TRANSFER chain draining to the Fund credits its full balance with no receivable.

import (
	"crypto/sha256"
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

var testFund = func() [32]byte {
	var f [32]byte
	for i := range f {
		f[i] = 0xff
	}
	return f
}()

func fundSeedHead(fund [32]byte) [32]byte {
	return sha256.Sum256(append([]byte("ANOS_FUND_HEAD_V1:"), fund[:]...))
}

func newFundTestDB(t *testing.T) *bbolt.DB {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "fund.db"), 0600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Update(func(tx *bbolt.Tx) error { return ensureBuckets(tx) }); err != nil {
		t.Fatalf("ensure buckets: %v", err)
	}
	return db
}

func seedFundRecord(t *testing.T, db *bbolt.DB, fund [32]byte) [32]byte {
	t.Helper()
	fh := fundSeedHead(fund)
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, fund, AccountRecord{Head: fh, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_FUND})
	}); err != nil {
		t.Fatalf("seed fund: %v", err)
	}
	return fh
}

func seedSpending(t *testing.T, db *bbolt.DB, acct, head [32]byte, bal, seq uint64) {
	t.Helper()
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, acct, AccountRecord{Head: head, Balance: bal, Seq: seq, Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING})
	}); err != nil {
		t.Fatalf("seed account: %v", err)
	}
}

// txidFor derives a deterministic, head-distinct txid from (acct, seq) so chained sends
// and re-applies are reproducible. ApplyTx takes the txid as an argument (it does not
// re-hash), so it need not be the real wire hash for these apply-path tests.
func txidFor(acct [32]byte, seq uint64) [32]byte {
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	return sha256.Sum256(append(append([]byte("test-txid:"), acct[:]...), s[:]...))
}

// applySendThrough builds a SPENDING/TRANSFER SEND and runs it through ApplyTx in one
// bbolt tx, returning the txid. class selects the sender's stored class branch.
func applySendThrough(t *testing.T, db *bbolt.DB, from, fromHead [32]byte, seq uint64, to [32]byte, amt, fee uint64, fund [32]byte) [32]byte {
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
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
		}},
	}
	raw, _ := proto.Marshal(ptx)
	if err := db.Update(func(tx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: tx}, raw, ptx, txid, fund)
	}); err != nil {
		t.Fatalf("ApplyTx send seq=%d: %v", seq, err)
	}
	return txid
}

func fundRecord(t *testing.T, db *bbolt.DB, fund [32]byte) AccountRecord {
	t.Helper()
	var rec AccountRecord
	if err := db.View(func(tx *bbolt.Tx) error {
		r, ok := getAccountRecord(tx, fund)
		if !ok {
			t.Fatal("fund record missing")
		}
		rec = r
		return nil
	}); err != nil {
		t.Fatalf("read fund: %v", err)
	}
	return rec
}

func receivableMinted(t *testing.T, db *bbolt.DB, rid [32]byte) bool {
	t.Helper()
	var present bool
	_ = db.View(func(tx *bbolt.Tx) error {
		present = hasReceivable(tx, rid)
		return nil
	})
	return present
}

// A normal fee'd send to a non-Fund recipient: the Fund balance rises by exactly the
// fee, and the recipient still gets a user→user receivable for the amount.
func TestFundFeeCreditExact(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)

	var sender, sHead, recipient [32]byte
	sender[0], sHead[0], recipient[0] = 0x01, 0xa1, 0x02
	const amt = uint64(1_000_000)
	fee := ExpectedFee(amt)
	seedSpending(t, db, sender, sHead, amt+fee, 1)

	txid := applySendThrough(t, db, sender, sHead, 2, recipient, amt, fee, testFund)

	if got := fundRecord(t, db, testFund).Balance; got != fee {
		t.Errorf("fund balance = %d, want exactly the fee %d", got, fee)
	}
	rid := crypto.ReceivableIDFromTxID(txid)
	if !receivableMinted(t, db, rid) {
		t.Error("recipient receivable was not minted for a normal (non-Fund) send")
	}
}

// A send whose destination IS the Fund: the Fund balance rises by amount+fee, NO
// recipient receivable is minted, and the Fund's record shape is preserved.
func TestFundDirectAmountCreditNoReceivable(t *testing.T) {
	db := newFundTestDB(t)
	seedHead := seedFundRecord(t, db, testFund)

	var sender, sHead [32]byte
	sender[0], sHead[0] = 0x11, 0xb1
	const amt = uint64(2_000_000)
	fee := ExpectedFee(amt)
	seedSpending(t, db, sender, sHead, amt+fee, 1)

	txid := applySendThrough(t, db, sender, sHead, 2, testFund, amt, fee, testFund)

	rec := fundRecord(t, db, testFund)
	if rec.Balance != amt+fee {
		t.Errorf("fund balance = %d, want amount+fee %d", rec.Balance, amt+fee)
	}
	if rec.Class != pb.AccountClass_ACCOUNT_CLASS_FUND || rec.Seq != 1 || rec.Head != seedHead || len(rec.AuthPubKey) != 0 {
		t.Errorf("fund record shape changed by crediting: class=%v seq=%d head==seed:%v keyed:%v",
			rec.Class, rec.Seq, rec.Head == seedHead, len(rec.AuthPubKey) != 0)
	}
	rid := crypto.ReceivableIDFromTxID(txid)
	if receivableMinted(t, db, rid) {
		t.Error("a send to the Fund must NOT mint a recipient receivable (Alt A)")
	}
}

// Two distinct senders each pay a fee into the Fund in the same epoch. Applying them in
// either order yields the identical Fund balance — the credit is a pure, commutative +=.
func TestFundCreditOrderIndependent(t *testing.T) {
	build := func(order int) uint64 {
		db := newFundTestDB(t)
		seedFundRecord(t, db, testFund)

		var a, aHead, b, bHead, rcpt [32]byte
		a[0], aHead[0], b[0], bHead[0], rcpt[0] = 0x21, 0xc1, 0x22, 0xc2, 0x23
		const amtA, amtB = uint64(1_500_000), uint64(700_000)
		feeA, feeB := ExpectedFee(amtA), ExpectedFee(amtB)
		seedSpending(t, db, a, aHead, amtA+feeA, 1)
		seedSpending(t, db, b, bHead, amtB+feeB, 1)

		if order == 0 {
			applySendThrough(t, db, a, aHead, 2, rcpt, amtA, feeA, testFund)
			applySendThrough(t, db, b, bHead, 2, rcpt, amtB, feeB, testFund)
		} else {
			applySendThrough(t, db, b, bHead, 2, rcpt, amtB, feeB, testFund)
			applySendThrough(t, db, a, aHead, 2, rcpt, amtA, feeA, testFund)
		}
		return fundRecord(t, db, testFund).Balance
	}

	ab, ba := build(0), build(1)
	if ab != ba {
		t.Errorf("order-dependent Fund balance: A-then-B=%d, B-then-A=%d", ab, ba)
	}
	want := ExpectedFee(1_500_000) + ExpectedFee(700_000)
	if ab != want {
		t.Errorf("fund balance = %d, want sum of fees %d", ab, want)
	}
}

// Re-applying the identical SEND (as a resync replay would attempt) must not
// double-credit the Fund: the early idempotency return (head == txid && seq matches)
// short-circuits before the credit.
func TestFundCreditNoDoubleCreditOnReapply(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)

	var sender, sHead, rcpt [32]byte
	sender[0], sHead[0], rcpt[0] = 0x31, 0xd1, 0x32
	const amt = uint64(900_000)
	fee := ExpectedFee(amt)
	seedSpending(t, db, sender, sHead, amt+fee, 1)

	// First apply credits the Fund by the fee.
	applySendThrough(t, db, sender, sHead, 2, rcpt, amt, fee, testFund)
	// Re-apply the byte-identical tx (same account/seq/txid) — must be a no-op.
	applySendThrough(t, db, sender, sHead, 2, rcpt, amt, fee, testFund)

	if got := fundRecord(t, db, testFund).Balance; got != fee {
		t.Errorf("fund balance = %d after re-apply, want the fee once %d (no double credit)", got, fee)
	}
}

// FUND is a reserved keyless class (keys-spec §6.5, spec-18 §7): an opening RECEIVE that
// declares it must be rejected on the apply (resync) path, so no keyed Class==FUND record
// can ever be minted at a vanity id.
func TestApplyRejectsFundClassOpeningReceive(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)

	var newAcct, source [32]byte
	newAcct[0], source[0] = 0x51, 0x52

	// A receivable destined to the fresh account (so the RECEIVE gets past the claim check).
	var rid [32]byte
	rid[0] = 0x53
	recv := &pb.Receivable{
		Id:     &pb.Hash32{V: rid[:]},
		From:   &pb.AccountId{V: source[:]},
		To:     &pb.AccountId{V: newAcct[:]},
		Amount: 1_000,
	}
	rr, _ := proto.Marshal(recv)
	if err := db.Update(func(tx *bbolt.Tx) error { return putReceivableRaw(tx, rid, rr) }); err != nil {
		t.Fatalf("seed receivable: %v", err)
	}

	ptx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: &pb.AccountId{V: newAcct[:]},
		Prev:    &pb.Hash32{V: make([]byte, 32)},
		Seq:     1,
		Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
			ReceivableId:         &pb.Hash32{V: rid[:]},
			AccountClass:         pb.AccountClass_ACCOUNT_CLASS_FUND,
			AuthPubkey:           &pb.HybridPubKey{V: make([]byte, crypto.HybridPubKeySize)},
			BreakglassCommitment: &pb.Hash64{V: make([]byte, 64)},
		}},
	}
	raw, _ := proto.Marshal(ptx)
	txid := txidFor(newAcct, 1)
	err := db.Update(func(tx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: tx}, raw, ptx, txid, testFund)
	})
	if err == nil || !strings.Contains(err.Error(), "FUND is a reserved keyless class") {
		t.Fatalf("opening RECEIVE with class FUND must be rejected, got err=%v", err)
	}
}

// A TRANSFER chain draining to the Fund: zero-fee, full-balance, no receivable, full
// amount credited to the Fund.
func TestFundCreditFromTransferDrain(t *testing.T) {
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)

	var chain, chainHead, source [32]byte
	chain[0], chainHead[0], source[0] = 0x41, 0xe1, 0x42
	const bal = uint64(5_000_000)
	// Seed a TRANSFER chain whose stored destination is the Fund (drain target).
	if err := db.Update(func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, chain, AccountRecord{
			Head:           chainHead,
			Balance:        bal,
			Seq:            1,
			Class:          pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			TransferSource: source,
			TransferDest:   testFund,
		})
	}); err != nil {
		t.Fatalf("seed transfer chain: %v", err)
	}

	txid := applySendThrough(t, db, chain, chainHead, 2, testFund, bal, 0, testFund)

	if got := fundRecord(t, db, testFund).Balance; got != bal {
		t.Errorf("fund balance = %d after transfer drain, want full balance %d", got, bal)
	}
	rid := crypto.ReceivableIDFromTxID(txid)
	if receivableMinted(t, db, rid) {
		t.Error("a transfer drain to the Fund must NOT mint a recipient receivable")
	}
}
