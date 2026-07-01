package core

// White-box tests for the generalized class-tagged account record (spec-18 §3,
// build-plan P1.1). They pin: base stays 52 B with head at v[0:32]; the TLV blob
// round-trips TRANSFER_META; unknown tags are skipped (forward-compat); and
// malformed blobs fail closed.

import (
	"bytes"
	"encoding/binary"
	"testing"

	pb "anos/internal/proto"
)

// accountRecordEqual compares two records field by field. AccountRecord now holds
// []byte fields (AuthPubKey/BreakglassCommit), so a plain == no longer compiles.
func accountRecordEqual(a, b AccountRecord) bool {
	return a.Head == b.Head &&
		a.Balance == b.Balance &&
		a.Seq == b.Seq &&
		a.Class == b.Class &&
		a.TransferSource == b.TransferSource &&
		a.TransferDest == b.TransferDest &&
		a.TransferUnlock == b.TransferUnlock &&
		a.TransferFlags == b.TransferFlags &&
		bytes.Equal(a.AuthPubKey, b.AuthPubKey) &&
		bytes.Equal(a.BreakglassCommit, b.BreakglassCommit)
}

func sampleTransferRecord() AccountRecord {
	r := AccountRecord{
		Balance: 123456,
		Seq:     7,
		Class:   pb.AccountClass_ACCOUNT_CLASS_TRANSFER,
		TransferUnlock: 999,
		TransferFlags:  0x01,
	}
	for i := range r.Head {
		r.Head[i] = byte(i)
	}
	for i := range r.TransferSource {
		r.TransferSource[i] = byte(0x40 + i)
	}
	for i := range r.TransferDest {
		r.TransferDest[i] = byte(0x80 + i)
	}
	return r
}

func TestAccountRecordBaseRoundTrip(t *testing.T) {
	r := AccountRecord{Balance: 42, Seq: 3, Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING}
	for i := range r.Head {
		r.Head[i] = byte(0xA0 + i)
	}
	enc := packAccountRecord(r)
	if len(enc) != accountBaseLen+metadataLenLen {
		t.Fatalf("base record len = %d, want %d (metadata_len 0)", len(enc), accountBaseLen+metadataLenLen)
	}
	if !bytes.Equal(enc[:32], r.Head[:]) {
		t.Error("head is not at v[0:32]")
	}
	if got := binary.BigEndian.Uint16(enc[52:54]); got != 0 {
		t.Errorf("metadata_len = %d, want 0 for a base record", got)
	}
	back, ok := unpackAccountRecord(enc)
	if !ok {
		t.Fatal("unpack failed")
	}
	if !accountRecordEqual(back, r) {
		t.Errorf("base round-trip mismatch:\n got %+v\nwant %+v", back, r)
	}
}

func TestAccountRecordTransferRoundTrip(t *testing.T) {
	r := sampleTransferRecord()
	enc := packAccountRecord(r)

	// base(52) + metadata_len(2) + TLV header(3) + TRANSFER_META(73) = 130
	wantLen := accountBaseLen + metadataLenLen + tlvHeaderLen + transferMetaLen
	if len(enc) != wantLen {
		t.Fatalf("transfer record len = %d, want %d", len(enc), wantLen)
	}
	if !bytes.Equal(enc[:32], r.Head[:]) {
		t.Error("head is not at v[0:32] for a transfer record")
	}
	// The TLV directly follows the base+len prefix.
	if enc[54] != tlvTransferMeta {
		t.Errorf("first TLV tag = 0x%02x, want TRANSFER_META 0x%02x", enc[54], tlvTransferMeta)
	}
	back, ok := unpackAccountRecord(enc)
	if !ok {
		t.Fatal("unpack failed")
	}
	if !accountRecordEqual(back, r) {
		t.Errorf("transfer round-trip mismatch:\n got %+v\nwant %+v", back, r)
	}
}

// A record carrying an unknown TLV tag (a hypothetical future field) must still
// parse, skipping the unknown field and decoding the known TRANSFER_META.
func TestParseSkipsUnknownTLVTags(t *testing.T) {
	r := sampleTransferRecord()

	// Craft on-disk bytes: base (class TRANSFER) + blob = [unknown TLV][TRANSFER_META].
	var tm [transferMetaLen]byte
	copy(tm[0:32], r.TransferSource[:])
	copy(tm[32:64], r.TransferDest[:])
	binary.BigEndian.PutUint64(tm[64:72], r.TransferUnlock)
	tm[72] = r.TransferFlags

	blob := appendTLV(nil, 0x7F, []byte("future-field-value"))
	blob = appendTLV(blob, tlvTransferMeta, tm[:])

	enc := make([]byte, accountBaseLen+metadataLenLen+len(blob))
	copy(enc[:32], r.Head[:])
	binary.BigEndian.PutUint64(enc[32:40], r.Balance)
	binary.BigEndian.PutUint64(enc[40:48], r.Seq)
	binary.BigEndian.PutUint32(enc[48:52], uint32(r.Class))
	binary.BigEndian.PutUint16(enc[52:54], uint16(len(blob)))
	copy(enc[54:], blob)

	back, ok := unpackAccountRecord(enc)
	if !ok {
		t.Fatal("unpack failed on a record with an unknown TLV tag")
	}
	if !accountRecordEqual(back, r) {
		t.Errorf("unknown-tag round-trip mismatch:\n got %+v\nwant %+v", back, r)
	}
}

func TestUnpackFailsClosedOnMalformed(t *testing.T) {
	good := packAccountRecord(sampleTransferRecord())

	// (1) shorter than base+metadata_len
	if _, ok := unpackAccountRecord(good[:accountBaseLen]); ok {
		t.Error("accepted a record shorter than base+metadata_len")
	}
	// (2) metadata_len longer than the actual blob
	bad := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(bad[52:54], uint16(len(good))) // absurdly large
	if _, ok := unpackAccountRecord(bad); ok {
		t.Error("accepted a record whose metadata_len exceeds the blob")
	}
	// (3) TRANSFER_META with a wrong value length
	short := appendTLV(nil, tlvTransferMeta, make([]byte, transferMetaLen-1))
	rec := make([]byte, accountBaseLen+metadataLenLen+len(short))
	binary.BigEndian.PutUint32(rec[48:52], uint32(pb.AccountClass_ACCOUNT_CLASS_TRANSFER))
	binary.BigEndian.PutUint16(rec[52:54], uint16(len(short)))
	copy(rec[54:], short)
	if _, ok := unpackAccountRecord(rec); ok {
		t.Error("accepted a TRANSFER_META field with the wrong length")
	}
	// (4) truncated TLV header (1 dangling byte in the blob)
	trunc := make([]byte, accountBaseLen+metadataLenLen+1)
	binary.BigEndian.PutUint16(trunc[52:54], 1)
	trunc[54] = tlvTransferMeta
	if _, ok := unpackAccountRecord(trunc); ok {
		t.Error("accepted a record with a truncated TLV header")
	}
}

// A keyed account (the common case after P1.2) round-trips its AUTH_PUBKEY and
// BREAKGLASS_COMMIT TLVs, which are emitted in fixed tag order (0x01 then 0x02).
func TestAccountRecordKeyedRoundTrip(t *testing.T) {
	r := AccountRecord{Balance: 5, Seq: 1, Class: pb.AccountClass_ACCOUNT_CLASS_SPENDING}
	for i := range r.Head {
		r.Head[i] = byte(0x10 + i)
	}
	r.AuthPubKey = make([]byte, authPubkeyLen)
	for i := range r.AuthPubKey {
		r.AuthPubKey[i] = byte(i)
	}
	r.BreakglassCommit = make([]byte, breakglassCommitLen)
	for i := range r.BreakglassCommit {
		r.BreakglassCommit[i] = byte(0xC0 + i)
	}

	enc := packAccountRecord(r)
	if !bytes.Equal(enc[:32], r.Head[:]) {
		t.Error("head must stay at v[0:32] for a keyed record (frontier hot path)")
	}
	// First TLV must be AUTH_PUBKEY (fixed tag order), then BREAKGLASS_COMMIT.
	if enc[54] != tlvAuthPubkey {
		t.Errorf("first TLV tag = 0x%02x, want AUTH_PUBKEY 0x%02x", enc[54], tlvAuthPubkey)
	}
	back, ok := unpackAccountRecord(enc)
	if !ok {
		t.Fatal("unpack failed on a keyed record")
	}
	if !accountRecordEqual(back, r) {
		t.Errorf("keyed round-trip mismatch")
	}

	// A wrong-length AUTH_PUBKEY field must fail closed.
	short := appendTLV(nil, tlvAuthPubkey, make([]byte, authPubkeyLen-1))
	rec := make([]byte, accountBaseLen+metadataLenLen+len(short))
	binary.BigEndian.PutUint32(rec[48:52], uint32(pb.AccountClass_ACCOUNT_CLASS_SPENDING))
	binary.BigEndian.PutUint16(rec[52:54], uint16(len(short)))
	copy(rec[54:], short)
	if _, ok := unpackAccountRecord(rec); ok {
		t.Error("accepted an AUTH_PUBKEY field with the wrong length")
	}
}

// putAccount (base wrapper) must never write transfer metadata, so a base record
// and the genesis-style seed round-trip with metadata_len 0.
func TestPackAccountBaseWrapperHasNoBlob(t *testing.T) {
	var head [32]byte
	for i := range head {
		head[i] = byte(i + 1)
	}
	enc := packAccount(head, 1000, 1, pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	if len(enc) != accountBaseLen+metadataLenLen {
		t.Fatalf("packAccount len = %d, want %d", len(enc), accountBaseLen+metadataLenLen)
	}
	h, bal, seq, class, ok := unpackAccount(enc)
	if !ok || h != head || bal != 1000 || seq != 1 || class != pb.AccountClass_ACCOUNT_CLASS_SPENDING {
		t.Errorf("base wrapper round-trip mismatch: h=%x bal=%d seq=%d class=%v ok=%v", h, bal, seq, class, ok)
	}
}
