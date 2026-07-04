package core

// P4.1 Fund-derived validator set (spec-18 §3.7, build-plan §P4.1).
//
// These tests pin the Banker validator-descriptor projection: the BBankerInfo pack/unpack round-trip,
// last-write-wins by deposit send-seq (order-independent, like BGuardianActive's keep-max),
// recordBankerInfo skipping a malformed consensus key (membership-not-rejection), and the pure
// BankerValidatorSet derivation (requires active >=50k Banker membership AND a valid-key descriptor).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

func validConsensusKey(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	c := crypto.CompressP256PublicKey(&priv.PublicKey)
	return append([]byte(nil), c[:]...)
}

func mustUpdate(t *testing.T, db *bbolt.DB, fn func(tx *bbolt.Tx) error) {
	t.Helper()
	if err := db.Update(fn); err != nil {
		t.Fatalf("db update: %v", err)
	}
}

func TestBankerInfoRoundTrip(t *testing.T) {
	key := validConsensusKey(t)
	bi, ok := unpackBankerInfo(packBankerInfo(key, "1.2.3.4:9090", 7))
	if !ok {
		t.Fatal("unpack failed")
	}
	if !bytes.Equal(bi.ConsensusKey, key) || bi.Endpoint != "1.2.3.4:9090" || bi.SendSeq != 7 {
		t.Errorf("round-trip mismatch: %+v", bi)
	}
	// Empty endpoint round-trips.
	bi2, ok := unpackBankerInfo(packBankerInfo(key, "", 1))
	if !ok || bi2.Endpoint != "" || bi2.SendSeq != 1 {
		t.Error("empty-endpoint round-trip failed")
	}
	// Truncated value fails closed.
	if _, ok := unpackBankerInfo(packBankerInfo(key, "x", 1)[:bankerInfoFixedLen-1]); ok {
		t.Error("truncated value accepted")
	}
}

func TestPutBankerInfoLastWriteWins(t *testing.T) {
	db := newFundTestDB(t)
	var id [32]byte
	id[0] = 0xb1
	k1, k2 := validConsensusKey(t), validConsensusKey(t)
	// Apply in REVERSE seq order to prove keep-max is order-independent: seq 5 (k2) then seq 3 (k1).
	mustUpdate(t, db, func(tx *bbolt.Tx) error { return putBankerInfo(tx, id, k2, "e2", 5) })
	mustUpdate(t, db, func(tx *bbolt.Tx) error { return putBankerInfo(tx, id, k1, "e1", 3) })
	infos, _ := ListBankerInfo(db)
	if len(infos) != 1 {
		t.Fatalf("want 1 info, got %d", len(infos))
	}
	if !bytes.Equal(infos[0].ConsensusKey, k2) || infos[0].Endpoint != "e2" || infos[0].SendSeq != 5 {
		t.Errorf("last-write-wins (max-seq) failed: got seq %d endpoint %q", infos[0].SendSeq, infos[0].Endpoint)
	}
	// A strictly higher seq overwrites.
	mustUpdate(t, db, func(tx *bbolt.Tx) error { return putBankerInfo(tx, id, k1, "e3", 7) })
	infos, _ = ListBankerInfo(db)
	if infos[0].SendSeq != 7 || infos[0].Endpoint != "e3" {
		t.Error("higher seq did not overwrite")
	}
}

func TestRecordBankerInfoSkipsMalformedKey(t *testing.T) {
	db := newFundTestDB(t)
	var id [32]byte
	id[0] = 0xb2
	good := validConsensusKey(t)
	mustUpdate(t, db, func(tx *bbolt.Tx) error { return recordBankerInfo(tx, id, good, "e1", 3) })
	// A malformed key at a higher seq must NOT overwrite (and must not error).
	mustUpdate(t, db, func(tx *bbolt.Tx) error { return recordBankerInfo(tx, id, make([]byte, 33), "e2", 5) })
	infos, _ := ListBankerInfo(db)
	if len(infos) != 1 || !bytes.Equal(infos[0].ConsensusKey, good) || infos[0].SendSeq != 3 {
		t.Error("malformed-key deposit changed the descriptor")
	}
	// An absent key on the FIRST deposit creates no descriptor.
	var id2 [32]byte
	id2[0] = 0xb3
	mustUpdate(t, db, func(tx *bbolt.Tx) error { return recordBankerInfo(tx, id2, nil, "e", 1) })
	infos, _ = ListBankerInfo(db)
	for _, bi := range infos {
		if bi.Identity == id2 {
			t.Error("absent-key deposit created a descriptor")
		}
	}
}

func TestBankerValidatorSet(t *testing.T) {
	// B1 = active >=50k banker + valid key → in set.
	// B2 = sub-floor (1k) banker + valid key → NOT in set (not IsBanker).
	// B3 = active >=50k banker but malformed key → NOT in set.
	var b1, b2, b3 [32]byte
	b1[0], b2[0], b3[0] = 0x01, 0x02, 0x03
	k1, k2 := validConsensusKey(t), validConsensusKey(t)
	rows := []StakeRow{
		{DepositTxid: [32]byte{0xa1}, StakeRecord: StakeRecord{StakerID: b1, Amount: anosUnits(60_000), TimeDelay: oneMonth, Status: StakeStatusActive, StakedFor: StakedForBanker}},
		{DepositTxid: [32]byte{0xa2}, StakeRecord: StakeRecord{StakerID: b2, Amount: anosUnits(1_000), TimeDelay: oneMonth, Status: StakeStatusActive, StakedFor: StakedForBanker}},
		{DepositTxid: [32]byte{0xa3}, StakeRecord: StakeRecord{StakerID: b3, Amount: anosUnits(60_000), TimeDelay: oneMonth, Status: StakeStatusActive, StakedFor: StakedForBanker}},
	}
	infos := []BankerInfo{
		{Identity: b1, ConsensusKey: k1, Endpoint: "e1", SendSeq: 1},
		{Identity: b2, ConsensusKey: k2, Endpoint: "e2", SendSeq: 1},
		{Identity: b3, ConsensusKey: make([]byte, 33), Endpoint: "e3", SendSeq: 1}, // malformed key
	}
	set := testEcon.BankerValidatorSet(rows, infos)
	if len(set) != 1 {
		t.Fatalf("want 1 validator, got %d", len(set))
	}
	if set[0].Identity != b1 || !bytes.Equal(set[0].ConsensusKey[:], k1) || set[0].Endpoint != "e1" {
		t.Errorf("wrong validator descriptor: %+v", set[0])
	}
	// Kicking B1's stake drops it from the set (membership gate).
	rows[0].Status = StakeStatusKicked
	if got := testEcon.BankerValidatorSet(rows, infos); len(got) != 0 {
		t.Errorf("kicked banker still in the set: %d entries", len(got))
	}
}

// TestRoutedBankerStakeRecordsNoDescriptor pins the review fix: a "banker" stake ROUTED through a
// transfer chain (existingClass == TRANSFER) records the stake (for weight/voting) but contributes
// NO validator descriptor. This is consensus-critical for the projection's determinism — every
// transfer-chain drain is seq 2, so two routed banker deposits for one identity would collide on
// send-seq and make keep-max replay-order-dependent (a cross-node / resync divergence).
func TestRoutedBankerStakeRecordsNoDescriptor(t *testing.T) {
	db := newFundTestDB(t)
	fund := testFund
	seedFundRecord(t, db, fund)

	var source, chain, chainHead [32]byte
	source[0], chain[0], chainHead[0] = 0x51, 0xcc, 0x71
	const bal = uint64(60_000) * UnitsPerAnos
	// Seed a TRANSFER chain whose stored source is `source`, holding the full balance.
	mustUpdate(t, db, func(tx *bbolt.Tx) error {
		return putAccountRecord(tx, chain, AccountRecord{
			Head: chainHead, Balance: bal, Seq: 1,
			Class: pb.AccountClass_ACCOUNT_CLASS_TRANSFER, TransferSource: source,
		})
	})
	// The chain drains its full balance to the Fund as a "banker" stake carrying a VALID consensus key.
	key := validConsensusKey(t)
	ptx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: chain[:]},
		Prev:    &pb.Hash32{V: chainHead[:]},
		Seq:     2,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To: &pb.AccountId{V: fund[:]}, Amount: bal, Fee: 0,
			AccountClass:    pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
			StakedFor:       StakedForBanker,
			TimeDelay:       oneMonth,
			ConsensusPubkey: key,
			Endpoint:        "10.0.0.7:9090",
		}},
	}
	raw, _ := proto.Marshal(ptx)
	mustUpdate(t, db, func(tx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: tx}, raw, ptx, txidFor(chain, 2), fund, testEcon)
	})

	// The STAKE row IS recorded under the source identity (weight/voting attribution).
	stakes, _ := ListAllStakes(db)
	found := false
	for _, s := range stakes {
		if s.StakerID == source && s.StakedFor == StakedForBanker {
			found = true
		}
	}
	if !found {
		t.Error("routed banker stake row not recorded for the source identity")
	}
	// ...but it contributes NO validator descriptor.
	infos, _ := ListBankerInfo(db)
	for _, bi := range infos {
		if bi.Identity == source {
			t.Error("routed banker stake set a validator descriptor (determinism / cold-class violation)")
		}
	}
}

// --- P4.2 self-signed key/IP rotation (build-plan §P4.2, working notes §3.7) ---
//
// Rotation reuses the P4.1 mechanism: a banker rotates its consensus key/endpoint by sending a
// small additive self-signed Banker deposit carrying the new descriptor, and the keep-max-by-send-seq
// BBankerInfo projection REPLACES (never appends) the identity's single descriptor. These tests pin
// the P4.2 contract at the derived-set level: after a rotation the new key is in BankerValidatorSet
// and the OLD key is gone, an endpoint-only rotation updates the address, and a SUB-FLOOR rotation
// deposit preserves membership via the original >=50k stake.

// TestBankerRotationReplacesDescriptorInSet drives the projection functions directly (the exact
// calls the apply path makes) and asserts the rotation contract on BankerValidatorSet.
func TestBankerRotationReplacesDescriptorInSet(t *testing.T) {
	db := newFundTestDB(t)
	var b [32]byte
	b[0] = 0xb1
	k1, k2 := validConsensusKey(t), validConsensusKey(t)

	// Initial >=50k Banker stake (deposit a1) + descriptor K1/e1 at the staking send-seq (2).
	mustUpdate(t, db, func(tx *bbolt.Tx) error {
		return putStakeRecord(tx, [32]byte{0xa1}, StakeRecord{
			StakerID: b, Amount: anosUnits(60_000), TimeDelay: oneMonth,
			Status: StakeStatusActive, StakedFor: StakedForBanker,
		})
	})
	mustUpdate(t, db, func(tx *bbolt.Tx) error { return recordBankerInfo(tx, b, k1, "e1", 2) })

	assertSetKey := func(label string, wantKey []byte, wantEndpoint string) {
		t.Helper()
		rows, _ := ListAllStakes(db)
		infos, _ := ListBankerInfo(db)
		// Exactly one descriptor per identity — a rotation REPLACES, never appends.
		nForB := 0
		for _, bi := range infos {
			if bi.Identity == b {
				nForB++
			}
		}
		if nForB != 1 {
			t.Fatalf("[%s] want exactly 1 descriptor for the identity, got %d", label, nForB)
		}
		set := testEcon.BankerValidatorSet(rows, infos)
		if len(set) != 1 {
			t.Fatalf("[%s] want 1 validator in the set, got %d", label, len(set))
		}
		if !bytes.Equal(set[0].ConsensusKey[:], wantKey) {
			t.Errorf("[%s] set has the wrong consensus key", label)
		}
		if set[0].Endpoint != wantEndpoint {
			t.Errorf("[%s] set endpoint = %q, want %q", label, set[0].Endpoint, wantEndpoint)
		}
		// The OLD key must NOT appear anywhere in the derived set.
		if !bytes.Equal(wantKey, k1) {
			for _, vd := range set {
				if bytes.Equal(vd.ConsensusKey[:], k1) {
					t.Errorf("[%s] old key K1 still present in the set after rotation", label)
				}
			}
		}
	}
	assertSetKey("pre-rotate", k1, "e1")

	// ROTATE key+endpoint via a SUB-FLOOR (1 anos) additive deposit at a higher send-seq (3).
	mustUpdate(t, db, func(tx *bbolt.Tx) error {
		return putStakeRecord(tx, [32]byte{0xa2}, StakeRecord{
			StakerID: b, Amount: anosUnits(1), TimeDelay: oneMonth,
			Status: StakeStatusActive, StakedFor: StakedForBanker,
		})
	})
	mustUpdate(t, db, func(tx *bbolt.Tx) error { return recordBankerInfo(tx, b, k2, "e2", 3) })
	assertSetKey("after key+endpoint rotate", k2, "e2")

	// Membership survived the sub-floor rotation purely via the original 60k stake.
	rows, _ := ListAllStakes(db)
	if !testEcon.IsBanker(rows, b) {
		t.Error("sub-floor rotation dropped Banker membership (the original 50k stake should still qualify)")
	}

	// ENDPOINT-ONLY rotation: same key K2, new endpoint, higher send-seq (4).
	mustUpdate(t, db, func(tx *bbolt.Tx) error { return recordBankerInfo(tx, b, k2, "e3", 4) })
	assertSetKey("after endpoint-only rotate", k2, "e3")
}

// TestBankerRotationThroughApply exercises the full ApplyTx path: a SPENDING banker stakes, then
// rotates with a sub-floor additive deposit carrying a new key/endpoint. It pins that the apply
// side-effect (recordBankerInfo at parsed.Seq) replaces the descriptor in the derived set, the old
// key is gone, both stake rows are recorded, and membership persists.
func TestBankerRotationThroughApply(t *testing.T) {
	db := newFundTestDB(t)
	fund := testFund
	seedFundRecord(t, db, fund)

	var b, head0 [32]byte
	b[0], head0[0] = 0xb7, 0x70
	seedSpending(t, db, b, head0, anosUnits(200_000), 1)

	k1, k2 := validConsensusKey(t), validConsensusKey(t)
	const stakeAmt = uint64(60_000) * UnitsPerAnos // >= 50k floor
	const rotAmt = uint64(1) * UnitsPerAnos        // sub-floor additive rotation

	// seq 2: initial Banker stake (K1, e1).
	applyBankerStakeThrough(t, db, b, head0, 2, fund, stakeAmt, ExpectedFee(stakeAmt), k1, "10.0.0.1:9090")
	// seq 3: rotate to (K2, e2) via a small additive deposit; prev = the post-stake head.
	h2 := acctHead(t, db, b)
	applyBankerStakeThrough(t, db, b, h2, 3, fund, rotAmt, ExpectedFee(rotAmt), k2, "10.0.0.2:9090")

	rows, _ := ListAllStakes(db)
	infos, _ := ListBankerInfo(db)

	// Exactly one descriptor for B, now K2/e2 at the rotation send-seq (3).
	nForB := 0
	var got BankerInfo
	for _, bi := range infos {
		if bi.Identity == b {
			nForB++
			got = bi
		}
	}
	if nForB != 1 {
		t.Fatalf("want 1 descriptor for B after apply, got %d", nForB)
	}
	if !bytes.Equal(got.ConsensusKey, k2) || got.Endpoint != "10.0.0.2:9090" || got.SendSeq != 3 {
		t.Errorf("descriptor not rotated through apply: key2=%v ep=%q seq=%d", bytes.Equal(got.ConsensusKey, k2), got.Endpoint, got.SendSeq)
	}
	// Both banker stake rows recorded for B (the 60k membership stake + the 1-anos rotation deposit).
	bankerRows := 0
	for _, s := range rows {
		if s.StakerID == b && s.StakedFor == StakedForBanker {
			bankerRows++
		}
	}
	if bankerRows != 2 {
		t.Errorf("want 2 banker stake rows for B, got %d", bankerRows)
	}
	// Derived set: one validator, the NEW key, old key gone, membership intact.
	set := testEcon.BankerValidatorSet(rows, infos)
	if len(set) != 1 || !bytes.Equal(set[0].ConsensusKey[:], k2) {
		t.Fatalf("derived set did not rotate to K2: %+v", set)
	}
	for _, vd := range set {
		if bytes.Equal(vd.ConsensusKey[:], k1) {
			t.Error("old key K1 still in the derived set after apply-path rotation")
		}
	}
	if !testEcon.IsBanker(rows, b) {
		t.Error("Banker membership lost after the sub-floor rotation deposit")
	}
}

// applyBankerStakeThrough builds a SPENDING Banker stake/rotation deposit (to==Fund, staked_for
// "banker", 1-month tier) carrying a consensus key + endpoint, and runs it through ApplyTx in one
// bbolt tx, returning the txid. Mirrors applySendThrough but with the P4.1 banker descriptor fields.
func applyBankerStakeThrough(t *testing.T, db *bbolt.DB, from, fromHead [32]byte, seq uint64, fund [32]byte, amt, fee uint64, key []byte, endpoint string) [32]byte {
	t.Helper()
	txid := txidFor(from, seq)
	ptx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: from[:]},
		Prev:    &pb.Hash32{V: fromHead[:]},
		Seq:     seq,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:              &pb.AccountId{V: fund[:]},
			Amount:          amt,
			Fee:             fee,
			AccountClass:    pb.AccountClass_ACCOUNT_CLASS_SPENDING,
			StakedFor:       StakedForBanker,
			TimeDelay:       oneMonth,
			ConsensusPubkey: key,
			Endpoint:        endpoint,
		}},
	}
	raw, _ := proto.Marshal(ptx)
	if err := db.Update(func(tx *bbolt.Tx) error {
		return ApplyTx(&bboltTxView{tx: tx}, raw, ptx, txid, fund, testEcon)
	}); err != nil {
		t.Fatalf("apply banker stake seq=%d: %v", seq, err)
	}
	return txid
}

// acctHead reads an account's current head (the prev for its next block).
func acctHead(t *testing.T, db *bbolt.DB, acct [32]byte) [32]byte {
	t.Helper()
	var rec AccountRecord
	if err := db.View(func(tx *bbolt.Tx) error {
		rec, _ = getAccountRecord(tx, acct)
		return nil
	}); err != nil {
		t.Fatalf("read head: %v", err)
	}
	return rec.Head
}
