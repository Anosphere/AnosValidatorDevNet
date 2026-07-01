// sim-genesis-distribute runs a full SPENDING send/receive lifecycle on hybrid
// (post-quantum) keys — the P1.2 GREEN-gate SPENDING scenario:
//
//	genesis --SEND--> userA  (genesis signs hybrid; cached-pubkey verify path)
//	userA   --RECV-->        (account-opening RECEIVE: registers auth pubkey +
//	                          breakglass commitment; validators enforce that the
//	                          account-id == BaseAccountID(class, auth pubkey))
//	userA   --SEND--> userB  (SEND from a freshly-created hybrid account)
//	userB   --RECV-->        (second opening RECEIVE)
//
// It exercises every per-account signature path the cutover touches: the seeded
// genesis account (cached pubkey), an opening RECEIVE (tx-carried pubkey + id
// enforcement), and a SEND from a newly-opened hybrid account.
//
// Env: GENESIS_SEED_HEX (genesis auth seed), GENESIS_HEX (genesis account-id),
// VALIDATOR_URL_LIST (comma-separated). Users are generated fresh each run.
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"anos/internal/core"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func main() {
	genSeedHex := mustEnv("GENESIS_SEED_HEX")
	genIDHex := strings.ToLower(mustEnv("GENESIS_HEX"))
	urls := mustEnv("VALIDATOR_URL_LIST")

	genSeed := simkit.MustSeedFromHex(genSeedHex)
	// The genesis breakglass seed is irrelevant on-chain (genesis is seeded directly
	// and never opens a block); reuse the auth seed so the account derives cleanly.
	genesis := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, genSeed, genSeed)
	if hex.EncodeToString(genesis.IDBytes()) != genIDHex {
		log.Fatalf("config mismatch: GENESIS_SEED_HEX derives id %s but GENESIS_HEX=%s\n(regenerate both with sim-print-keypairs)",
			hex.EncodeToString(genesis.IDBytes()), genIDHex)
	}

	c := simkit.NewClient(urls)
	const poll = 1 * time.Second
	const maxWait = 120 * time.Second
	amtA := uint64(100) * core.UnitsPerAnos
	amtB := uint64(10) * core.UnitsPerAnos

	userA := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	userB := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	log.Printf("genesis=%x userA=%x userB=%x", genesis.IDBytes()[:4], userA.IDBytes()[:4], userB.IDBytes()[:4])

	// 1) genesis --SEND--> userA
	genHead, genSeq, err := c.Head(genesis.IDBytes())
	if err != nil {
		log.Fatalf("read genesis: %v", err)
	}
	send1 := simkit.BuildSend(genesis, genHead, genSeq+1, userA.ID, amtA, core.ExpectedFee(amtA))
	genesis.MustSign(send1)
	c.MustSubmit(send1)
	log.Printf("[1] genesis SEND %d units -> userA (fee %d)", amtA, core.ExpectedFee(amtA))
	ridA := c.WaitForReceivable(userA.IDBytes(), nil, poll, maxWait)
	log.Printf("    userA receivable %x", ridA[:4])

	// 2) userA opening RECEIVE (registers hybrid pubkey + breakglass commitment)
	recvA := simkit.BuildOpeningReceive(userA, ridA, nil, 0)
	userA.MustSign(recvA)
	c.MustSubmit(recvA)
	c.WaitForSeqAtLeast(userA.IDBytes(), 1, poll, maxWait)
	log.Printf("[2] userA opened (RECEIVE)")

	// 3) userA --SEND--> userB
	aHead, aSeq, err := c.Head(userA.IDBytes())
	if err != nil {
		log.Fatalf("read userA: %v", err)
	}
	send2 := simkit.BuildSend(userA, aHead, aSeq+1, userB.ID, amtB, core.ExpectedFee(amtB))
	userA.MustSign(send2)
	c.MustSubmit(send2)
	log.Printf("[3] userA SEND %d units -> userB (fee %d)", amtB, core.ExpectedFee(amtB))
	ridB := c.WaitForReceivable(userB.IDBytes(), nil, poll, maxWait)
	log.Printf("    userB receivable %x", ridB[:4])

	// 4) userB opening RECEIVE
	recvB := simkit.BuildOpeningReceive(userB, ridB, nil, 0)
	userB.MustSign(recvB)
	c.MustSubmit(recvB)
	c.WaitForSeqAtLeast(userB.IDBytes(), 1, poll, maxWait)
	log.Printf("[4] userB opened (RECEIVE)")

	for _, a := range []struct {
		name string
		acct *simkit.Account
	}{{"userA", userA}, {"userB", userB}} {
		st, err := c.GetAccount(a.acct.IDBytes())
		if err != nil {
			log.Fatalf("read %s: %v", a.name, err)
		}
		fmt.Printf("%s: balance=%d seq=%d head=%x\n", a.name, st.Balance, st.Seq, st.Head.V[:4])
	}
	fmt.Println("LIFECYCLE_OK")
}

func mustEnv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}
