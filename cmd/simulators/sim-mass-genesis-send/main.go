// cmd/simulators/sim-mass-genesis-send/main.go
//
// Fan-out from the genesis account: send a fixed amount to each of N recipients,
// sequentially (refreshing genesis head/seq between sends), and print the resulting
// receivable ids. Post-P1.2 hybrid model: genesis is a hybrid account derived from
// GENESIS_SEED_HEX; recipients are 32-byte HASH-DERIVED account-ids.
//
// Flags/env:
//
//	--ids       CSV or path to .csv of recipient 32-byte (64-hex) account-ids
//	GENESIS_SEED_HEX  genesis auth seed (32-byte hex)
//	GENESIS_HEX       genesis account-id (validated against the derived id if set)
//	VALIDATOR_URL_LIST  comma-separated validator base URLs
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"anos/internal/core"
	"anos/internal/crypto"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func main() {
	idsCSV := flag.String("ids", "", "CSV or path to .csv of recipient 32-byte hex account-ids")
	flag.Parse()
	if *idsCSV == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --ids is required")
		os.Exit(1)
	}
	urls := getenv("VALIDATOR_URL_LIST", "")
	if strings.TrimSpace(urls) == "" {
		fmt.Fprintln(os.Stderr, "ERROR: VALIDATOR_URL_LIST is empty")
		os.Exit(1)
	}
	c := simkit.NewClient(urls)

	genSeed, err := simkit.SeedFromHex(getenv("GENESIS_SEED_HEX", ""))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: GENESIS_SEED_HEX invalid: %v\n", err)
		os.Exit(1)
	}
	genesis := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, genSeed, genSeed)
	if gh := strings.ToLower(strings.TrimSpace(getenv("GENESIS_HEX", ""))); gh != "" {
		if hex.EncodeToString(genesis.IDBytes()) != gh {
			log.Fatalf("config mismatch: GENESIS_SEED_HEX derives id %s but GENESIS_HEX=%s",
				hex.EncodeToString(genesis.IDBytes()), gh)
		}
	}

	idHexes := loadHexList(*idsCSV)
	recipients := make([][32]byte, 0, len(idHexes))
	for _, h := range idHexes {
		id, err := decodeID(h)
		if err != nil {
			log.Fatalf("bad recipient id %q: %v", h, err)
		}
		recipients = append(recipients, id)
	}
	if len(recipients) == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: no recipients")
		os.Exit(1)
	}

	amount := uint64(100 * core.UnitsPerAnos)
	fee := core.ExpectedFee(amount)

	rids := make([]string, 0, len(recipients))
	for i, to := range recipients {
		head, seq, err := c.Head(genesis.IDBytes())
		if err != nil {
			log.Fatalf("read genesis: %v", err)
		}
		tx := simkit.BuildSend(genesis, head, seq+1, to, amount, fee)
		genesis.MustSign(tx)
		c.MustSubmit(tx)
		txid, _ := crypto.TxID(tx)
		rid := crypto.ReceivableIDFromTxID(txid)
		rids = append(rids, hex.EncodeToString(rid[:]))
		fmt.Printf("Send %02d OK to=%s rid=%s\n", i, hex.EncodeToString(to[:])[:16], hex.EncodeToString(rid[:])[:16])
		c.WaitForSeqAtLeast(genesis.IDBytes(), seq+1, 200*time.Millisecond, 30*time.Second)
		if i != len(recipients)-1 {
			time.Sleep(1 * time.Second)
		}
	}

	fmt.Println("\nRID_LIST (CSV):")
	fmt.Println(strings.Join(rids, ","))
}

// --- small local helpers ---

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func decodeID(s string) ([32]byte, error) {
	var id [32]byte
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return id, err
	}
	if len(b) != 32 {
		return id, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	copy(id[:], b)
	return id, nil
}

func loadHexList(arg string) []string {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return nil
	}
	if strings.HasSuffix(strings.ToLower(arg), ".csv") {
		b, err := os.ReadFile(arg)
		if err != nil {
			panic(err)
		}
		arg = strings.ReplaceAll(string(b), "\n", ",")
	}
	var out []string
	for _, p := range strings.Split(arg, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
