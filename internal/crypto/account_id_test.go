package crypto

// White-box tests for the P0.2 account-id and breakglass-commitment primitives
// (keys-spec §3, §6, §7). The committed golden file testdata/keys_account_id_
// vectors.json is the cross-system interop fixture; regenerate it with
// ANOS_EMIT_VECTORS=1 go test ./internal/crypto/ -run TestKnownAnswerVectors.

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Fixed P-256 scalars (32 bytes, all < n) for deterministic test keys.
const (
	scalarA = "1111111111111111111111111111111111111111111111111111111111111111"
	scalarB = "2222222222222222222222222222222222222222222222222222222222222222"
	scalarC = "3333333333333333333333333333333333333333333333333333333333333333"
)

func hx32(a [32]byte) string { return hex.EncodeToString(a[:]) }
func hx64(a [64]byte) string { return hex.EncodeToString(a[:]) }

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func mustHex32(t *testing.T, s string) [32]byte {
	var o [32]byte
	copy(o[:], mustHex(t, s))
	return o
}

// deterministicHybridPub builds a reproducible HybridPubKey from a seed fill byte
// (ML-DSA, via NewKeyFromSeed) and a fixed P-256 scalar.
func deterministicHybridPub(t *testing.T, seedFill byte, p256ScalarHex string) *HybridPubKey {
	t.Helper()
	var seed [mldsaSeedSize]byte
	for i := range seed {
		seed[i] = seedFill
	}
	mlPub, _ := mldsaKeyFromSeed(&seed)
	ec, err := LoadP256PrivateKeyFromHex(p256ScalarHex)
	if err != nil {
		t.Fatalf("scalar: %v", err)
	}
	return &HybridPubKey{mldsa: mlPub, p256: &ec.PublicKey}
}

// --- SHA512_32 anchored to independently-known SHA-512 prefixes. ---

func TestSHA512_32KnownAnswers(t *testing.T) {
	// Real SHA-512("") / SHA-512("abc") prefixes (verified out-of-band via
	// `shasum -a 512`). These do NOT depend on our code.
	cases := map[string]string{
		"":    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
		"abc": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
	}
	for in, want := range cases {
		got := SHA512_32([]byte(in))
		if hx32(got) != want {
			t.Errorf("SHA512_32(%q) = %s, want %s", in, hx32(got), want)
		}
	}
}

func TestSHA512_32IsNotSHA512_256(t *testing.T) {
	in := []byte("anos")
	trunc := SHA512_32(in)
	alt := sha512.Sum512_256(in) // different IV — must differ from left-truncation
	if bytes.Equal(trunc[:], alt[:]) {
		t.Error("SHA512_32 must be left-truncated SHA-512, not the SHA-512/256 variant")
	}
}

// --- Domain & nonce separation (keys-spec §6.2/§6.3). ---

func TestAccountIDDomainAndNonceSeparation(t *testing.T) {
	pub := deterministicHybridPub(t, 0x01, scalarA).Encode()
	creator := [32]byte{1, 2, 3}

	// Per-type domain separation: identical keys, different type → different id.
	seen := map[[32]byte]byte{}
	for _, tb := range []byte{AccountTypeSpending, AccountTypeTimelocked, AccountTypeGuarded, AccountTypeVault} {
		id := BaseAccountID(tb, pub)
		if prev, ok := seen[id]; ok {
			t.Fatalf("types %d and %d produced the same id", prev, tb)
		}
		seen[id] = tb
	}

	// Base vs derived differ even with identical keys and type.
	if BaseAccountID(AccountTypeSpending, pub) == DerivedAccountID(AccountTypeSpending, pub, creator, 1) {
		t.Fatal("base and derived ids collide")
	}

	// The nonce matters in both components.
	if DerivedAccountID(AccountTypeTransfer, pub, creator, 1) == DerivedAccountID(AccountTypeTransfer, pub, creator, 2) {
		t.Fatal("creator_seq does not affect the id")
	}
	other := [32]byte{9, 9, 9}
	if DerivedAccountID(AccountTypeTransfer, pub, creator, 1) == DerivedAccountID(AccountTypeTransfer, pub, other, 1) {
		t.Fatal("creator_id does not affect the id")
	}
}

// --- Escrow canonical key ordering (keys-spec §6.2). ---

func TestEscrowKeyblobCanonicalOrder(t *testing.T) {
	a := deterministicHybridPub(t, 0x01, scalarA).Encode()
	b := deterministicHybridPub(t, 0x02, scalarB).Encode()

	if !bytes.Equal(EscrowKeyblob(a, b), EscrowKeyblob(b, a)) {
		t.Fatal("escrow keyblob is not order-independent")
	}
	// Must be low ‖ high by lexicographic byte order.
	lo, hi := a, b
	if bytes.Compare(a, b) > 0 {
		lo, hi = b, a
	}
	kb := EscrowKeyblob(a, b)
	if !bytes.Equal(kb[:len(lo)], lo) || !bytes.Equal(kb[len(lo):], hi) {
		t.Fatal("escrow keyblob is not low‖high")
	}
	// Therefore the derived escrow id is independent of which party funds.
	creator := [32]byte{7}
	if DerivedAccountID(AccountTypeEscrow, EscrowKeyblob(a, b), creator, 1) !=
		DerivedAccountID(AccountTypeEscrow, EscrowKeyblob(b, a), creator, 1) {
		t.Fatal("escrow id depends on funder order")
	}
}

// --- Breakglass commitment (keys-spec §7.2). ---

func TestBreakglassCommitment(t *testing.T) {
	bp := deterministicHybridPub(t, 0x03, scalarC).Encode()

	c := BreakglassCommitment(bp)
	if len(c) != 64 {
		t.Fatalf("commitment len = %d, want 64 (full SHA-512)", len(c))
	}
	if c != BreakglassCommitment(bp) {
		t.Fatal("commitment is not deterministic")
	}
	// P5.2: the commitment is CLASS-INDEPENDENT (no type byte). The same breakglass key copied onto
	// a child (transfer/escrow) commits IDENTICALLY — that is exactly what lets a child verify its
	// copied commitment with no look-back to the source's class. (There is no type argument left to
	// separate on.)
	// Distinct keys → distinct commitments.
	bp2 := deterministicHybridPub(t, 0x04, scalarA).Encode()
	if BreakglassCommitment(bp) == BreakglassCommitment(bp2) {
		t.Fatal("commitment collides across keys")
	}
}

// --- Frozen interop vectors (golden file). ---

type s512Vector struct {
	InputUTF8   string `json:"input_utf8"`
	ExpectedHex string `json:"expected_hex"`
}

type accountIDVector struct {
	Desc         string `json:"desc"`
	TypeByte     byte   `json:"type_byte"`
	KeyblobHex   string `json:"keyblob_hex"`
	Derived      bool   `json:"derived"`
	CreatorIDHex string `json:"creator_id_hex,omitempty"`
	CreatorSeq   uint64 `json:"creator_seq"`
	AccountIDHex string `json:"expected_account_id_hex"`
}

type breakglassVector struct {
	Desc          string `json:"desc"`
	BreakglassHex string `json:"breakglass_pub_hex"`
	CommitmentHex string `json:"expected_commitment_hex"`
}

type vectorFile struct {
	Note       string             `json:"note"`
	SHA512_32  []s512Vector       `json:"sha512_32"`
	AccountID  []accountIDVector  `json:"account_id"`
	Breakglass []breakglassVector `json:"breakglass"`
}

func buildVectors(t *testing.T) vectorFile {
	pubA := deterministicHybridPub(t, 0x01, scalarA).Encode()
	pubB := deterministicHybridPub(t, 0x02, scalarB).Encode()
	bgA := deterministicHybridPub(t, 0x03, scalarC).Encode()

	funder := BaseAccountID(AccountTypeSpending, pubA)
	escrowKb := EscrowKeyblob(pubA, pubB)

	mk := func(desc string, tb byte, kb []byte, derived bool, cid [32]byte, seq uint64) accountIDVector {
		v := accountIDVector{Desc: desc, TypeByte: tb, KeyblobHex: hex.EncodeToString(kb), Derived: derived, CreatorSeq: seq}
		if derived {
			v.CreatorIDHex = hx32(cid)
			v.AccountIDHex = hx32(DerivedAccountID(tb, kb, cid, seq))
		} else {
			v.AccountIDHex = hx32(BaseAccountID(tb, kb))
		}
		return v
	}

	return vectorFile{
		Note: `Anos keys-spec interop known-answer vectors. ` +
			`SHA512_32(x) = SHA-512(x)[0:32] (left-truncated, NOT SHA-512/256). ` +
			`keyblob = HybridPubKey = mldsa87_pub(2592) || p256_compressed(33); escrow keyblob = the two parties' HybridPubKeys in ascending byte order (low||high). ` +
			`account_id = SHA512_32("ANOSv2-AcctID\x00" || type_byte || keyblob [|| creator_id(32) || creator_seq(8, little-endian)]); base accounts omit the nonce. ` +
			`breakglass_commitment = SHA-512("ANOSv2-Breakglass\x00" || hybrid_pub) (full 64 bytes; class-independent since P5.2 — no type byte). ` +
			`type_byte (account_id only): SPENDING=1 TIMELOCKED=2 GUARDED=3 VAULT=4 TRANSFER=5 ESCROW=6.`,
		SHA512_32: []s512Vector{
			{InputUTF8: "", ExpectedHex: hx32(SHA512_32(nil))},
			{InputUTF8: "abc", ExpectedHex: hx32(SHA512_32([]byte("abc")))},
		},
		AccountID: []accountIDVector{
			mk("SPENDING base (party A)", AccountTypeSpending, pubA, false, [32]byte{}, 0),
			mk("TIMELOCKED base, same keys as SPENDING (per-type domain separation)", AccountTypeTimelocked, pubA, false, [32]byte{}, 0),
			mk("TRANSFER derived from party A, creator_seq=7", AccountTypeTransfer, pubA, true, funder, 7),
			mk("ESCROW derived, parties A+B in canonical order, creator_seq=3", AccountTypeEscrow, escrowKb, true, funder, 3),
		},
		Breakglass: []breakglassVector{
			{Desc: "breakglass commitment (class-independent since P5.2)", BreakglassHex: hex.EncodeToString(bgA), CommitmentHex: hx64(BreakglassCommitment(bgA))},
			{Desc: "breakglass commitment, a different key", BreakglassHex: hex.EncodeToString(pubB), CommitmentHex: hx64(BreakglassCommitment(pubB))},
		},
	}
}

func TestKnownAnswerVectors(t *testing.T) {
	got := buildVectors(t)
	data, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')

	path := filepath.Join("testdata", "keys_account_id_vectors.json")

	if os.Getenv("ANOS_EMIT_VECTORS") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(data))
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden vectors (create with ANOS_EMIT_VECTORS=1): %v", err)
	}
	if !bytes.Equal(want, data) {
		t.Errorf("golden vectors differ from freshly-computed; if intentional, regenerate with ANOS_EMIT_VECTORS=1")
	}

	// Independently re-derive every output from the committed inputs via the
	// public API, so the test exercises the functions — not just byte equality.
	var vf vectorFile
	if err := json.Unmarshal(want, &vf); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	for _, v := range vf.SHA512_32 {
		if g := hx32(SHA512_32([]byte(v.InputUTF8))); g != v.ExpectedHex {
			t.Errorf("SHA512_32(%q) = %s, want %s", v.InputUTF8, g, v.ExpectedHex)
		}
	}
	for _, v := range vf.AccountID {
		kb := mustHex(t, v.KeyblobHex)
		var id [32]byte
		if v.Derived {
			id = DerivedAccountID(v.TypeByte, kb, mustHex32(t, v.CreatorIDHex), v.CreatorSeq)
		} else {
			id = BaseAccountID(v.TypeByte, kb)
		}
		if hx32(id) != v.AccountIDHex {
			t.Errorf("account_id %q = %s, want %s", v.Desc, hx32(id), v.AccountIDHex)
		}
	}
	for _, v := range vf.Breakglass {
		if g := hx64(BreakglassCommitment(mustHex(t, v.BreakglassHex))); g != v.CommitmentHex {
			t.Errorf("breakglass %q = %s, want %s", v.Desc, g, v.CommitmentHex)
		}
	}
}
