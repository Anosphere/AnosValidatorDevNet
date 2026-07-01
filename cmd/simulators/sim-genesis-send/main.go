// sim-genesis-send submits a single hybrid-signed SEND from the genesis account to
// a recipient account-id. (Just the SEND — use sim-user-receive to claim it, or
// sim-genesis-distribute for the full send+receive lifecycle.)
//
// Env: GENESIS_SEED_HEX (genesis auth seed), GENESIS_HEX (genesis account-id),
// USER_HEX (recipient 32-byte account-id), VALIDATOR_URL_LIST.
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"anos/internal/core"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func main() {
	genSeed := simkit.MustSeedFromHex(mustEnv("GENESIS_SEED_HEX"))
	genIDHex := strings.ToLower(mustEnv("GENESIS_HEX"))
	genesis := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, genSeed, genSeed)
	if hex.EncodeToString(genesis.IDBytes()) != genIDHex {
		log.Fatalf("config mismatch: GENESIS_SEED_HEX derives id %s but GENESIS_HEX=%s",
			hex.EncodeToString(genesis.IDBytes()), genIDHex)
	}

	toBytes, err := hex.DecodeString(strings.TrimSpace(mustEnv("USER_HEX")))
	if err != nil || len(toBytes) != 32 {
		log.Fatal("USER_HEX must be a 32-byte hex account-id")
	}
	var to [32]byte
	copy(to[:], toBytes)

	c := simkit.NewClient(mustEnv("VALIDATOR_URL_LIST"))
	amount := uint64(1_000_000) * core.UnitsPerAnos

	head, seq, err := c.Head(genesis.IDBytes())
	if err != nil {
		log.Fatalf("read genesis: %v", err)
	}
	tx := simkit.BuildSend(genesis, head, seq+1, to, amount, core.ExpectedFee(amount))
	genesis.MustSign(tx)
	c.MustSubmit(tx)
	fmt.Printf("genesis SEND %d units -> %x (fee %d)\n", amount, to[:4], core.ExpectedFee(amount))
}

func mustEnv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}
