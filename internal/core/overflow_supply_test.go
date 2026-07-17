package core

// forquinn phase 4, §2.7: the uint64-wrap supply mint is closed at BOTH enforcement sites.
// Pre-fix, `Balance < amt+fee` wrapped for amt=2^64-1 (RequiredFee clamps the wrapped product
// to MinFee, so amt+fee ≡ 999), letting any account funded with ≥999 units mint a ~2^64
// receivable. These tests pin the validate-side supply cap + subtract form, the apply-side
// subtract form (the no-revalidation resync path), and their lockstep.

import (
	"errors"
	"math"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

// overflowSnapshot funds a signing sender in a snapshot with the given supply cap.
func overflowSnapshot(sender *simkit.Account, head [32]byte, seq, balance, genesisSupply uint64) *Snapshot {
	var fund [32]byte
	fund[0] = 0xFD
	return &Snapshot{
		Econ: testEcon,
		Accounts: map[[32]byte]AccountSnap{
			sender.ID: {
				Head:             head,
				Balance:          balance,
				Seq:              seq,
				Class:            pb.AccountClass_ACCOUNT_CLASS_SPENDING,
				AuthPubKey:       sender.AuthPubKeyBytes(),
				BreakglassCommit: sender.Commit,
			},
		},
		FundAccount:   fund,
		GenesisSupply: genesisSupply,
	}
}

func signedSend(t *testing.T, sender *simkit.Account, head [32]byte, seq uint64, to [32]byte, amt, fee uint64) *pb.Tx {
	t.Helper()
	tx := simkit.BuildSend(sender, head, seq, to, amt, fee)
	if err := sender.Sign(tx); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tx
}

func TestValidateRejectsWrapAmountViaSupplyCap(t *testing.T) {
	sender, receiver := fuzzSeedAccounts()
	var head [32]byte
	head[0] = 0x77
	const supply = uint64(1_000_000_000)

	// The attack shape: amt=2^64-1 with the exact manifest fee (the wrapped RequiredFee), from
	// an account holding far more than the wrapped amt+fee. Pre-fix this VALIDATED.
	amt := uint64(math.MaxUint64)
	fee := testEcon.RequiredFee(amt)
	snap := overflowSnapshot(sender, head, 3, supply, supply)
	tx := signedSend(t, sender, head, 4, receiver.ID, amt, fee)
	_, err := ValidateTxAgainstSnapshot(tx, snap)
	wantErrContaining(t, err, "amount exceeds total supply", "2^64-1 send with supply cap set")
}

func TestValidateSubtractFormAloneStopsTheWrap(t *testing.T) {
	// Even with GenesisSupply unset (0 == the hand-built-test-snapshot escape hatch), the
	// subtract-form balance guard must reject the wrap shape — the cap is defense-in-depth,
	// not the only wall.
	sender, receiver := fuzzSeedAccounts()
	var head [32]byte
	head[0] = 0x78
	amt := uint64(math.MaxUint64)
	fee := testEcon.RequiredFee(amt)
	snap := overflowSnapshot(sender, head, 3, 1_000_000_000, 0)
	tx := signedSend(t, sender, head, 4, receiver.ID, amt, fee)
	_, err := ValidateTxAgainstSnapshot(tx, snap)
	if !errors.Is(err, ErrInsufficientBal) {
		t.Fatalf("wrap send with cap unset: err=%v, want ErrInsufficientBal (subtract form)", err)
	}
}

func TestValidateSupplyCapBoundaries(t *testing.T) {
	sender, receiver := fuzzSeedAccounts()
	var head [32]byte
	head[0] = 0x79
	const supply = uint64(1_000_000_000)

	// amt == GenesisSupply passes the cap (it is a cap, not a strict bound) and fails on the
	// honest balance arithmetic instead — distinguishable errors prove which guard fired.
	amt := supply
	fee := testEcon.RequiredFee(amt)
	snap := overflowSnapshot(sender, head, 3, supply, supply) // balance == amt, so amt fits but fee doesn't
	tx := signedSend(t, sender, head, 4, receiver.ID, amt, fee)
	_, err := ValidateTxAgainstSnapshot(tx, snap)
	if !errors.Is(err, ErrInsufficientBal) {
		t.Fatalf("amt==supply, balance==amt: err=%v, want ErrInsufficientBal (cap must not fire)", err)
	}

	// Exactly-funded send (balance == amt+fee) still validates — the subtract form must not
	// over-tighten the boundary.
	amt = 10_000
	fee = testEcon.RequiredFee(amt)
	snap = overflowSnapshot(sender, head, 3, amt+fee, supply)
	tx = signedSend(t, sender, head, 4, receiver.ID, amt, fee)
	if _, err := ValidateTxAgainstSnapshot(tx, snap); err != nil {
		t.Fatalf("exactly-funded send must validate, got %v", err)
	}
}

func TestApplyRejectsWrapAmountAndMintsNothing(t *testing.T) {
	// The apply mirror (§2.7): resync replays winners WITHOUT re-validating, so the subtract
	// form must hold at ApplyTx too — and the failed apply must leave no partial state (no
	// receivable, sender untouched).
	db := newFundTestDB(t)
	seedFundRecord(t, db, testFund)
	var acct, head, to [32]byte
	acct[0], head[0], to[0] = 0xA7, 0x57, 0xB7
	const bal = uint64(1_000_000)
	seedSpending(t, db, acct, head, bal, 3)

	amt := uint64(math.MaxUint64)
	fee := testEcon.RequiredFee(amt)
	txid := txidFor(acct, 4)
	ptx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: acct[:]},
		Prev:    &pb.Hash32{V: head[:]},
		Seq:     4,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: to[:]},
			Amount:       amt,
			Fee:          fee,
			AccountClass: pb.AccountClass_ACCOUNT_CLASS_SPENDING,
		}},
	}
	raw, _ := proto.Marshal(ptx)

	aerr := db.Update(func(btx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: btx}, raw, ptx, txid, testFund, testEcon, 0)
	})
	if !errors.Is(aerr, ErrInsufficientBal) {
		t.Fatalf("apply of 2^64-1 send: err=%v, want ErrInsufficientBal", aerr)
	}

	// Nothing minted, nothing debited (the Update rolled back).
	if receivableMinted(t, db, crypto.ReceivableIDFromTxID(txid)) {
		t.Fatalf("failed apply minted a receivable")
	}
	var rec AccountRecord
	if err := db.View(func(btx *bbolt.Tx) error {
		r, ok := getAccountRecord(btx, acct)
		if !ok {
			t.Fatal("sender record missing")
		}
		rec = r
		return nil
	}); err != nil {
		t.Fatalf("read sender: %v", err)
	}
	if rec.Balance != bal || rec.Seq != 3 || rec.Head != head {
		t.Fatalf("failed apply mutated the sender: bal=%d seq=%d", rec.Balance, rec.Seq)
	}
}
