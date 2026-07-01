// cmd/simulators/sim-mass-user-receive/main.go
//
// Throughput sim: N accounts each claim an incoming receivable concurrently. Post-P1.2
// hybrid model: each account is a hybrid account pinned by a 32-byte SEED, and its
// first RECEIVE is an OPENING block that registers the auth pubkey + breakglass
// commitment (validators enforce account-id == BaseAccountID(SPENDING, pubkey)).
//
// Flags/env (paired by index):
//
//	--seeds   CSV or path to .csv of 32-byte (64-hex) account auth seeds
//	--rids    CSV or path to .csv of 32-byte (64-hex) receivable ids destined to each account
//	VALIDATOR_URL_LIST  comma-separated validator base URLs
//
// The i-th account (derived from seeds[i]) claims rids[i]. Each account's id must be
// the destination of its receivable — generate the seeds first (sim-print-keypairs)
// and fund their ids, so the rids here are destined to the derived account-ids.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func main() {
	seedsCSV := flag.String("seeds", "", "CSV or path to .csv of 32-byte hex account seeds")
	ridsCSV := flag.String("rids", "", "CSV or path to .csv of 32-byte hex receivable ids (paired by index)")
	flag.Parse()

	if *seedsCSV == "" || *ridsCSV == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --seeds and --rids are required")
		os.Exit(1)
	}
	urls := getenv("VALIDATOR_URL_LIST", "")
	if strings.TrimSpace(urls) == "" {
		fmt.Fprintln(os.Stderr, "ERROR: VALIDATOR_URL_LIST is empty")
		os.Exit(1)
	}
	c := simkit.NewClient(urls)

	seeds := loadHexList(*seedsCSV)
	rids := loadHexList(*ridsCSV)
	n := len(seeds)
	if len(rids) < n {
		n = len(rids)
	}
	if n == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: empty seeds/rids lists")
		os.Exit(1)
	}

	type acct struct {
		i   int
		a   *simkit.Account
		rid [32]byte
	}
	accts := make([]acct, 0, n)
	for i := 0; i < n; i++ {
		seed, err := simkit.SeedFromHex(seeds[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: bad seed at index %d: %v\n", i, err)
			os.Exit(1)
		}
		rid, err := decodeID(rids[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: bad rid at index %d: %v\n", i, err)
			os.Exit(1)
		}
		accts = append(accts, acct{i, simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, seed, seed), rid})
	}

	const poll = 200 * time.Millisecond
	const maxWait = 30 * time.Second
	var wg sync.WaitGroup
	start := time.Now()
	log.Printf("Starting %d concurrent opening RECEIVEs", n)

	var okCount, failCount int
	var mu sync.Mutex
	for _, a := range accts {
		wg.Add(1)
		go func(a acct) {
			defer wg.Done()
			// Wait until the receivable is visible (avoid racing gossip), then open.
			_ = c.WaitForReceivable(a.a.IDBytes(), a.rid[:], poll, maxWait)
			tx := simkit.BuildOpeningReceive(a.a, a.rid, nil, 0)
			a.a.MustSign(tx)
			if err := c.Submit(tx); err != nil {
				mu.Lock()
				failCount++
				mu.Unlock()
				log.Printf("[%02d] RECEIVE FAIL: %v", a.i, err)
				return
			}
			c.WaitForSeqAtLeast(a.a.IDBytes(), 1, poll, maxWait)
			mu.Lock()
			okCount++
			mu.Unlock()
			log.Printf("[%02d] RECEIVE OK acct=%s", a.i, hex.EncodeToString(a.a.IDBytes())[:16])
		}(a)
	}
	wg.Wait()
	log.Printf("Done in %s. ok=%d fail=%d", time.Since(start), okCount, failCount)
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
