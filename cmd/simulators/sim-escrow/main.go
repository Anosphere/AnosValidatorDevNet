// sim-escrow demonstrates the P3.3 ESCROW + attested-escrow lifecycle end to end on hybrid keys
// (spec-18 §5.6, spec-19 §6.3):
//
//  1. Two SPENDING parties A and B are funded + opened. A is the funder.
//  2. PLAIN escrow: A funds a 2-of-2 escrow of {A,B} and opens it (funder-signed). A 2-of-2 outflow
//     (both parties sign) drains the full balance to a destination D, which receives it. A 1-of-1
//     outflow on a plain escrow never finalizes; a plain-escrow 1-of-2 → Fund never finalizes (a
//     plain escrow has NO attestation trigger).
//  3. ATTESTED escrow: A funds + opens an attested escrow (the attested fee is deducted to the Fund).
//     Before the trigger epoch a 1-of-2 → Fund does not finalize; at/after the trigger epoch a single
//     party's 1-of-2 → Fund drains the full balance to the Fund.
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, GENESIS_UNIX_MS, EPOCH_MS,
// FUND_ACCOUNT_HEX, ESCROW_ATTESTATION_DELAY_EPOCHS.
package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"anos/internal/core"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func main() {
	urls := mustEnv("VALIDATOR_URL_LIST")
	c := simkit.NewClient(urls)

	genSeed := simkit.MustSeedFromHex(mustEnv("GENESIS_SEED_HEX"))
	genIDHex := strings.ToLower(mustEnv("GENESIS_HEX"))
	genesis := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, genSeed, genSeed)
	if hex.EncodeToString(genesis.IDBytes()) != genIDHex {
		log.Fatalf("config mismatch: GENESIS_SEED_HEX derives id %s but GENESIS_HEX=%s",
			hex.EncodeToString(genesis.IDBytes()), genIDHex)
	}

	genesisMs := getenvInt64("GENESIS_UNIX_MS", 0)
	epochMs := getenvInt64("EPOCH_MS", 5000)
	escrowDelay := getenvUint64("ESCROW_ATTESTATION_DELAY_EPOCHS", 6)
	if genesisMs == 0 {
		log.Fatal("GENESIS_UNIX_MS is required")
	}
	fund := fundAccountID()
	log.Printf("epoch params: genesisMs=%d epochMs=%d escrowDelay=%d (epoch=%d) fund=%x",
		genesisMs, epochMs, escrowDelay, currentEpoch(genesisMs, epochMs), fund[:4])

	const (
		partyFund   = uint64(2_000) * core.UnitsPerAnos
		escrowAmt   = uint64(300) * core.UnitsPerAnos
		attestedAmt = uint64(300) * core.UnitsPerAnos
	)

	// ---------------------------------------------------------------
	// STEP 0: fund + open two SPENDING parties A (funder) and B, and a destination D.
	// ---------------------------------------------------------------
	banner("STEP 0: fund parties A, B and destination D")
	A := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	B := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	D := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	for _, p := range []*simkit.Account{A, B} {
		normalSend(c, genesis, p.ID, partyFund)
		rid := c.WaitForReceivable(p.IDBytes(), nil, 1*time.Second, 120*time.Second)
		openReceive(c, p, rid)
	}
	log.Printf("OK: A=%x B=%x D=%x", A.IDBytes()[:4], B.IDBytes()[:4], D.IDBytes()[:4])

	// ---------------------------------------------------------------
	// STEP 1: PLAIN escrow — fund + open.
	// ---------------------------------------------------------------
	banner("STEP 1: open a plain 2-of-2 escrow of {A,B} funded by A")
	esc := fundEscrow(c, A, B, escrowAmt)
	trigger := currentEpoch(genesisMs, epochMs) + escrowDelay + 3
	openEscrow(c, esc, trigger, false)
	st := mustAccount(c, esc.IDBytes())
	assert(st.AccountClass == pb.AccountClass_ACCOUNT_CLASS_ESCROW, "escrow should be ESCROW class")
	assert(st.Balance == escrowAmt, "plain escrow should hold the full funded amount")
	assertEscrowMeta(c, esc.IDBytes(), trigger, false)
	log.Printf("OK: plain escrow %x holds %d units (trigger epoch %d, not attested)", esc.IDBytes()[:4], st.Balance, trigger)

	// ---------------------------------------------------------------
	// STEP 2: NEGATIVE — a 1-of-1 outflow on a plain escrow never finalizes.
	// ---------------------------------------------------------------
	banner("STEP 2: NEGATIVE — 1-of-1 outflow on a plain escrow must not finalize")
	escrowOutflow(c, esc, D.ID, escrowAmt, []*simkit.Account{esc.Lo}) // only one party signs
	if waitSeqOrTimeout(c, esc.IDBytes(), 2, 4, genesisMs, epochMs) {
		log.Fatal("FAIL: a 1-of-1 escrow outflow finalized (2-of-2 not enforced)")
	}
	log.Printf("OK: 1-of-1 outflow did not finalize")

	// ---------------------------------------------------------------
	// STEP 3: NEGATIVE — a plain-escrow 1-of-2 → Fund never finalizes (no trigger).
	// ---------------------------------------------------------------
	banner("STEP 3: NEGATIVE — plain-escrow 1-of-2 → Fund must not finalize")
	waitUntilEpoch(trigger+1, genesisMs, epochMs) // even past the (would-be) trigger
	escrowOutflow(c, esc, fund, escrowAmt, []*simkit.Account{esc.Lo})
	if waitSeqOrTimeout(c, esc.IDBytes(), 2, 4, genesisMs, epochMs) {
		log.Fatal("FAIL: plain-escrow 1-of-2 → Fund finalized (only attested escrows have a trigger)")
	}
	log.Printf("OK: plain-escrow 1-of-2 → Fund did not finalize")

	// ---------------------------------------------------------------
	// STEP 4: POSITIVE — a 2-of-2 outflow drains the plain escrow to D.
	// ---------------------------------------------------------------
	banner("STEP 4: POSITIVE — 2-of-2 outflow drains the plain escrow to D")
	escrowOutflow(c, esc, D.ID, escrowAmt, []*simkit.Account{esc.Lo, esc.Hi})
	c.WaitForSeqAtLeast(esc.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, esc.IDBytes()).Balance == 0, "escrow should be drained after the 2-of-2")
	dRID := c.WaitForReceivable(D.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, D, dRID)
	assert(mustAccount(c, D.IDBytes()).Balance == escrowAmt, "D should have received the escrow balance")
	log.Printf("OK: 2-of-2 drained %d units to D", escrowAmt)

	// ---------------------------------------------------------------
	// STEP 5: ATTESTED escrow — fund + open (the attested fee is deducted to the Fund).
	// ---------------------------------------------------------------
	banner("STEP 5: open an ATTESTED escrow of {A,B} funded by A")
	fundBalBefore := mustAccount(c, fund[:]).Balance
	esc2 := fundEscrow(c, A, B, attestedAmt)
	trigger2 := currentEpoch(genesisMs, epochMs) + escrowDelay + 3
	openEscrow(c, esc2, trigger2, true)
	st2 := mustAccount(c, esc2.IDBytes())
	wantBal := attestedAmt - core.AttestedEscrowFee
	assert(st2.Balance == wantBal, "attested escrow balance should be amount - AttestedEscrowFee")
	assertEscrowMeta(c, esc2.IDBytes(), trigger2, true)
	// The Fund got the attested fee (plus the funding-send fee + the opening-funding-send fee). We
	// only assert it grew by at LEAST the attested fee (other fee credits are also folded in).
	fundBalAfterOpen := mustAccount(c, fund[:]).Balance
	assert(fundBalAfterOpen >= fundBalBefore+core.AttestedEscrowFee, "Fund should have received at least the attested fee")
	log.Printf("OK: attested escrow %x holds %d units (= %d - fee %d); Fund grew by >= the attested fee",
		esc2.IDBytes()[:4], st2.Balance, attestedAmt, core.AttestedEscrowFee)

	// ---------------------------------------------------------------
	// STEP 6: NEGATIVE — attested 1-of-2 → Fund BEFORE the trigger epoch must not finalize.
	// ---------------------------------------------------------------
	banner("STEP 6: NEGATIVE — attested 1-of-2 → Fund before the trigger must not finalize")
	if currentEpoch(genesisMs, epochMs) < trigger2 {
		escrowOutflow(c, esc2, fund, wantBal, []*simkit.Account{esc2.Lo})
		if waitSeqOrTimeout(c, esc2.IDBytes(), 2, 2, genesisMs, epochMs) {
			log.Fatal("FAIL: attested 1-of-2 → Fund finalized before the trigger epoch")
		}
		log.Printf("OK: pre-trigger 1-of-2 → Fund did not finalize (epoch=%d < trigger=%d)", currentEpoch(genesisMs, epochMs), trigger2)
	} else {
		log.Printf("SKIP: already past the trigger epoch")
	}

	// ---------------------------------------------------------------
	// STEP 7: POSITIVE — attested 1-of-2 → Fund AT/AFTER the trigger drains to the Fund.
	// ---------------------------------------------------------------
	banner("STEP 7: POSITIVE — attested 1-of-2 → Fund at/after the trigger")
	waitUntilEpoch(trigger2+1, genesisMs, epochMs)
	fundBeforeTrigger := mustAccount(c, fund[:]).Balance
	escrowOutflow(c, esc2, fund, wantBal, []*simkit.Account{esc2.Hi}) // a single party (the trigger)
	c.WaitForSeqAtLeast(esc2.IDBytes(), 2, 500*time.Millisecond, 120*time.Second)
	assert(mustAccount(c, esc2.IDBytes()).Balance == 0, "attested escrow should be drained after the trigger")
	fundAfterTrigger := mustAccount(c, fund[:]).Balance
	assert(fundAfterTrigger == fundBeforeTrigger+wantBal, "Fund should have received the escrow balance via the trigger")
	log.Printf("OK: attested 1-of-2 → Fund trigger drained %d units to the Fund", wantBal)

	banner("ALL CHECKS PASSED")
}

// --- flow helpers ---

// fundEscrow has `funder` send `amount` to the escrow id the SEND spawns, returning the escrow
// (funder + counterparty, canonical-ordered) and its funder-relative creation nonce.
func fundEscrow(c *simkit.Client, funder, other *simkit.Account, amount uint64) *simkit.EscrowAccount {
	head, seq, err := c.Head(funder.IDBytes())
	if err != nil {
		log.Fatalf("read funder: %v", err)
	}
	sendSeq := seq + 1
	esc := simkit.DerivedEscrowAccount(funder, other, funder, sendSeq)
	tx := simkit.BuildSend(funder, head, sendSeq, esc.ID, amount, core.ExpectedFee(amount))
	funder.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(funder.IDBytes(), sendSeq, 500*time.Millisecond, 120*time.Second)
	return esc
}

// openEscrow waits for the escrow's funding receivable, then submits the funder-signed opening.
func openEscrow(c *simkit.Client, esc *simkit.EscrowAccount, trigger uint64, attested bool) {
	rid := c.WaitForReceivable(esc.IDBytes(), nil, 1*time.Second, 120*time.Second)
	tx := simkit.BuildEscrowOpening(esc, rid, trigger, attested)
	if err := esc.Funder.Sign(tx); err != nil {
		log.Fatalf("sign escrow opening: %v", err)
	}
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(esc.IDBytes(), 1, 500*time.Millisecond, 120*time.Second)
}

// escrowOutflow submits a keyless full-balance escrow outflow signed by `signers` (2 for a 2-of-2,
// 1 for a trigger / negative case). It does NOT wait — callers decide whether it should finalize.
func escrowOutflow(c *simkit.Client, esc *simkit.EscrowAccount, to [32]byte, amount uint64, signers []*simkit.Account) {
	head, seq, err := c.Head(esc.IDBytes())
	if err != nil {
		log.Fatalf("read escrow: %v", err)
	}
	tx := simkit.BuildEscrowOutflow(esc, head, seq+1, to, amount)
	if err := simkit.SignEscrowOutflow(tx, signers); err != nil {
		log.Fatalf("sign escrow outflow: %v", err)
	}
	_ = c.Submit(tx)
}

func normalSend(c *simkit.Client, from *simkit.Account, to [32]byte, amount uint64) {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read sender: %v", err)
	}
	tx := simkit.BuildSend(from, head, seq+1, to, amount, core.ExpectedFee(amount))
	from.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(from.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
}

func openReceive(c *simkit.Client, acct *simkit.Account, rid [32]byte) {
	tx := simkit.BuildOpeningReceive(acct, rid, nil, 0)
	acct.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(acct.IDBytes(), 1, 500*time.Millisecond, 120*time.Second)
}

func mustAccount(c *simkit.Client, acct []byte) *pb.AccountState {
	st, err := c.GetAccount(acct)
	if err != nil {
		return &pb.AccountState{Account: &pb.AccountId{V: acct}, Head: &pb.Hash32{V: make([]byte, 32)}}
	}
	return st
}

// --- epoch helpers (validator-identical) ---

func currentEpoch(genesisMs, epochMs int64) uint64 {
	now := time.Now().UnixMilli()
	if now < genesisMs {
		return 1
	}
	return uint64((now-genesisMs)/epochMs) + 1
}

func waitUntilEpoch(target uint64, genesisMs, epochMs int64) {
	for currentEpoch(genesisMs, epochMs) < target {
		time.Sleep(time.Duration(epochMs) * time.Millisecond / 2)
	}
}

func waitSeqOrTimeout(c *simkit.Client, acct []byte, wantSeq, epochs uint64, genesisMs, epochMs int64) bool {
	deadline := currentEpoch(genesisMs, epochMs) + epochs
	for currentEpoch(genesisMs, epochMs) <= deadline {
		if mustAccount(c, acct).Seq >= wantSeq {
			return true
		}
		time.Sleep(time.Duration(epochMs) * time.Millisecond / 2)
	}
	return mustAccount(c, acct).Seq >= wantSeq
}

// --- misc ---

func fundAccountID() [32]byte {
	h := strings.TrimSpace(os.Getenv("FUND_ACCOUNT_HEX"))
	if h == "" {
		log.Fatal("FUND_ACCOUNT_HEX is required")
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		log.Fatalf("FUND_ACCOUNT_HEX must be 32 hex-encoded bytes: %v", err)
	}
	var f [32]byte
	copy(f[:], b)
	return f
}

// assertEscrowMeta checks the /debug/accounts/heads read API reports the expected escrow trigger
// epoch + attested flag (a live cross-check that the ESCROW_META projection is surfaced + agrees
// across nodes, since the heads JSON feeds the harness's 3-node agreement hash).
func assertEscrowMeta(c *simkit.Client, acct []byte, wantTrigger uint64, wantAttested bool) {
	if len(c.URLs) == 0 {
		log.Fatal("no validator URLs configured")
	}
	resp, err := http.Get(c.URLs[0] + "/debug/accounts/heads")
	if err != nil {
		log.Fatalf("GET /debug/accounts/heads: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var rows []struct {
		Account       string `json:"account"`
		EscrowTrigger uint64 `json:"escrow_trigger_epoch"`
		EscrowAttsted bool   `json:"escrow_attested"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		log.Fatalf("decode heads: %v", err)
	}
	want := hex.EncodeToString(acct)
	for _, r := range rows {
		if r.Account == want {
			if r.EscrowTrigger != wantTrigger || r.EscrowAttsted != wantAttested {
				log.Fatalf("escrow %x read API: trigger=%d attested=%v, want trigger=%d attested=%v",
					acct[:4], r.EscrowTrigger, r.EscrowAttsted, wantTrigger, wantAttested)
			}
			return
		}
	}
	log.Fatalf("escrow %x not found in /debug/accounts/heads", acct[:4])
}

func assert(cond bool, msg string) {
	if !cond {
		log.Fatalf("ASSERT FAILED: %s", msg)
	}
}

func banner(s string) {
	log.Printf("────────────────────────────────────────")
	log.Printf("  %s", s)
}

func mustEnv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}

func getenvInt64(k string, def int64) int64 {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func getenvUint64(k string, def uint64) uint64 {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}
