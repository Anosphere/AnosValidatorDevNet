// sim-user-receive claims a receivable into a hybrid user account. If the account
// does not exist yet, the RECEIVE is an account-opening block (registers the auth
// pubkey + breakglass commitment); otherwise it is a plain follow-on RECEIVE.
//
// Env: USER_SEED_HEX (auth seed), USER_BREAKGLASS_SEED_HEX (optional; defaults to a
// label of the auth seed), VALIDATOR_URL_LIST.
// Flag: --targetRID <hex> (the receivable to claim).
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func main() {
	targetRIDHex := flag.String("targetRID", "", "Receivable ID (hex-encoded)")
	flag.Parse()
	if *targetRIDHex == "" {
		log.Fatal("--targetRID is required")
	}
	ridBytes, err := hex.DecodeString(strings.TrimSpace(*targetRIDHex))
	if err != nil || len(ridBytes) != 32 {
		log.Fatal("--targetRID must be 32-byte hex")
	}
	var rid [32]byte
	copy(rid[:], ridBytes)

	authSeed := simkit.MustSeedFromHex(mustEnv("USER_SEED_HEX"))
	bgSeed := authSeed
	if v := strings.TrimSpace(os.Getenv("USER_BREAKGLASS_SEED_HEX")); v != "" {
		bgSeed = simkit.MustSeedFromHex(v)
	}
	user := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, authSeed, bgSeed)

	c := simkit.NewClient(mustEnv("VALIDATOR_URL_LIST"))
	fmt.Printf("user=%x receivable=%x\n", user.IDBytes()[:4], rid[:4])

	head, seq, _ := c.Head(user.IDBytes())
	var tx *pb.Tx
	if seq == 0 {
		tx = simkit.BuildOpeningReceive(user, rid, nil, 0) // opening block: registration
	} else {
		tx = simkit.BuildReceive(user, head, seq+1, rid)
	}
	user.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(user.IDBytes(), seq+1, 500*time.Millisecond, 60*time.Second)

	st, err := c.GetAccount(user.IDBytes())
	if err != nil {
		log.Fatalf("read user: %v", err)
	}
	fmt.Printf("done: balance=%d seq=%d head=%x\n", st.Balance, st.Seq, st.Head.V[:4])
}

func mustEnv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}
