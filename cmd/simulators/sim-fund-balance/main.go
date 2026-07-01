// sim-fund-balance exercises the P2.1 Alt A direct Fund credit end-to-end on a live
// network (spec-18 §7, build-plan P2.1):
//
//  0. The Fund (FUND_ACCOUNT_HEX) is queryable from epoch 0 — a seeded record with
//     class FUND, seq 1, and a non-zero synthetic head (genesis seed worked).
//  1. A normal fee'd send (genesis -> U) raises the Fund balance by EXACTLY the fee.
//  2. A direct stake (U -> Fund) raises the Fund balance by amount + fee, mints NO
//     receivable to the keyless Fund, and leaves the Fund's head/seq/class untouched.
//
// It prints `FUND_BALANCE=<n>`, `FUND_HEAD=<hex>`, `FUND_SEQ=<n>` so the live harness
// can compare the Fund across nodes and across a wipe+resync.
//
// Env: VALIDATOR_URL_LIST, GENESIS_SEED_HEX, GENESIS_HEX, FUND_ACCOUNT_HEX.
package main

import (
	"encoding/hex"
	"log"
	"os"
	"strings"
	"time"

	"anos/internal/core"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func main() {
	c := simkit.NewClient(mustEnv("VALIDATOR_URL_LIST"))

	genSeed := simkit.MustSeedFromHex(mustEnv("GENESIS_SEED_HEX"))
	genIDHex := strings.ToLower(mustEnv("GENESIS_HEX"))
	genesis := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, genSeed, genSeed)
	if hex.EncodeToString(genesis.IDBytes()) != genIDHex {
		log.Fatalf("config mismatch: GENESIS_SEED_HEX derives id %s but GENESIS_HEX=%s",
			hex.EncodeToString(genesis.IDBytes()), genIDHex)
	}

	fund := mustHex32(mustEnv("FUND_ACCOUNT_HEX"))

	// ── Step 0: the Fund is queryable from epoch 0 (seeded record). ──
	banner("STEP 0: Fund queryable from epoch 0")
	f0, err := c.GetAccount(fund[:])
	if err != nil {
		log.Fatalf("Fund not queryable at epoch 0 (seed missing?): %v", err)
	}
	assert(f0.AccountClass == pb.AccountClass_ACCOUNT_CLASS_FUND, "Fund class must be FUND")
	assert(f0.Seq == 1, "Fund seq must be 1 at the synthetic seed head")
	assert(len(f0.Head.GetV()) == 32 && !isZero(f0.Head.GetV()), "Fund head must be the non-zero synthetic seed")
	b0 := f0.Balance
	log.Printf("OK: Fund seeded — class=%s seq=%d head=%x balance=%d", f0.AccountClass, f0.Seq, f0.Head.GetV()[:4], b0)

	// ── Step 1: a normal fee'd send raises the Fund by exactly the fee. ──
	banner("STEP 1: normal fee'd send credits the Fund by exactly the fee")
	U := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	const fundAmount = uint64(1000) * core.UnitsPerAnos
	fee1 := core.ExpectedFee(fundAmount)
	normalSend(c, genesis, U.ID, fundAmount, fee1)

	b1 := fundBalance(c, fund)
	assertEq("fee credit", b1-b0, fee1)
	log.Printf("OK: Fund += %d (the fee); balance %d -> %d", fee1, b0, b1)

	// U claims the funds so it can stake from them next.
	ridU := c.WaitForReceivable(U.IDBytes(), nil, 1*time.Second, 120*time.Second)
	openReceive(c, U, ridU)
	uSt := mustAccount(c, U.IDBytes())
	assert(uSt.Balance == fundAmount, "U should hold the funded amount after receiving")

	// ── Step 2: a direct stake (to == Fund) credits amount + fee, no receivable. ──
	banner("STEP 2: direct send to the Fund credits amount + fee (Alt A, no receivable)")
	const stakeAmount = uint64(250) * core.UnitsPerAnos
	fee2 := core.ExpectedFee(stakeAmount)
	normalSend(c, U, fund, stakeAmount, fee2)

	b2 := fundBalance(c, fund)
	assertEq("amount+fee credit", b2-b1, stakeAmount+fee2)

	// The keyless Fund must have NO claimable receivable (Alt A skips the recipient mint).
	frecs, err := c.ListReceivables(fund[:])
	if err != nil {
		log.Fatalf("list Fund receivables: %v", err)
	}
	assert(len(frecs) == 0, "the Fund must have no claimable receivable under Alt A")

	// Fund head/seq/class unchanged by the credits (balance-only mutation).
	fEnd, err := c.GetAccount(fund[:])
	if err != nil {
		log.Fatalf("read Fund: %v", err)
	}
	assert(fEnd.AccountClass == pb.AccountClass_ACCOUNT_CLASS_FUND, "Fund class must stay FUND")
	assert(fEnd.Seq == 1 && hex.EncodeToString(fEnd.Head.GetV()) == hex.EncodeToString(f0.Head.GetV()),
		"Fund head/seq must be unchanged by balance credits")

	log.Printf("OK: Fund += %d (amount+fee); balance %d -> %d, no receivable, head/seq untouched", stakeAmount+fee2, b1, b2)

	log.Printf("ALL CHECKS PASSED")
	log.Printf("FUND_BALANCE=%d", fEnd.Balance)
	log.Printf("FUND_HEAD=%s", hex.EncodeToString(fEnd.Head.GetV()))
	log.Printf("FUND_SEQ=%d", fEnd.Seq)
}

// normalSend submits a fee-bearing SEND and waits for the sender's seq to advance.
func normalSend(c *simkit.Client, from *simkit.Account, to [32]byte, amount, fee uint64) {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read sender: %v", err)
	}
	tx := simkit.BuildSend(from, head, seq+1, to, amount, fee)
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

func fundBalance(c *simkit.Client, fund [32]byte) uint64 {
	st, err := c.GetAccount(fund[:])
	if err != nil {
		log.Fatalf("read Fund balance: %v", err)
	}
	return st.Balance
}

func mustAccount(c *simkit.Client, acct []byte) *pb.AccountState {
	st, err := c.GetAccount(acct)
	if err != nil {
		log.Fatalf("read account %x: %v", acct[:4], err)
	}
	return st
}

func mustHex32(s string) [32]byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		log.Fatalf("expected 32-byte hex, got %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func assertEq(what string, got, want uint64) {
	if got != want {
		log.Fatalf("ASSERT FAILED (%s): got delta %d, want %d", what, got, want)
	}
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
