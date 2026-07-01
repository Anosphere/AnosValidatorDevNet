// cmd/simulators/sim-mass-user-send/main.go
//
// Throughput sim: many SPENDING accounts each send a small amount to one recipient,
// concurrently. Post-P1.2 hybrid model: each sender is a hybrid account pinned by a
// 32-byte SEED, and addresses are HASH-DERIVED account-ids (not raw pubkeys).
//
// Flags/env:
//
//	--seeds   CSV string or path to .csv of 32-byte (64-hex) sender auth seeds
//	USER_HEX  recipient 32-byte account-id (hex)
//	VALIDATOR_URL_LIST  comma-separated validator base URLs
//
// Senders must already exist on-chain (opened + funded) for their SENDs to finalize.
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

	"anos/internal/core"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func main() {
	seedsCSV := flag.String("seeds", "", "CSV or path to .csv of 32-byte hex sender seeds")
	flag.Parse()

	if *seedsCSV == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --seeds is required")
		os.Exit(1)
	}
	urls := getenv("VALIDATOR_URL_LIST", "")
	if strings.TrimSpace(urls) == "" {
		fmt.Fprintln(os.Stderr, "ERROR: VALIDATOR_URL_LIST is empty")
		os.Exit(1)
	}
	c := simkit.NewClient(urls)

	toID, err := decodeID(strings.TrimSpace(getenv("USER_HEX", "")))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: USER_HEX must be a 32-byte account-id hex: %v\n", err)
		os.Exit(1)
	}

	seeds := loadHexList(*seedsCSV)
	if len(seeds) == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: empty seed list")
		os.Exit(1)
	}

	senders := make([]*simkit.Account, 0, len(seeds))
	for i, sh := range seeds {
		seed, err := simkit.SeedFromHex(sh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: bad seed at index %d: %v\n", i, err)
			os.Exit(1)
		}
		senders = append(senders, simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, seed, seed))
	}

	amount := uint64(1 * core.UnitsPerAnos)
	fee := core.ExpectedFee(amount)
	log.Printf("Sending %0.6f (+fee %0.6f) from %d accounts to %s",
		float64(amount)/float64(core.UnitsPerAnos), float64(fee)/float64(core.UnitsPerAnos),
		len(senders), hex.EncodeToString(toID[:]))

	const poll = 200 * time.Millisecond
	const maxWait = 30 * time.Second

	var wg sync.WaitGroup
	type result struct {
		i   int
		err error
	}
	resCh := make(chan result, len(senders))
	start := time.Now()

	for i, s := range senders {
		wg.Add(1)
		go func(i int, s *simkit.Account) {
			defer wg.Done()
			if s.ID == toID {
				resCh <- result{i, fmt.Errorf("skipped: sender==recipient")}
				return
			}
			head, seq, err := c.Head(s.IDBytes())
			if err != nil {
				resCh <- result{i, err}
				return
			}
			tx := simkit.BuildSend(s, head, seq+1, toID, amount, fee)
			s.MustSign(tx)
			if err := c.Submit(tx); err != nil {
				resCh <- result{i, err}
				return
			}
			c.WaitForSeqAtLeast(s.IDBytes(), seq+1, poll, maxWait)
			resCh <- result{i, nil}
		}(i, s)
	}
	wg.Wait()
	close(resCh)

	ok, fail := 0, 0
	for r := range resCh {
		if r.err != nil {
			fail++
			log.Printf("[%02d] SEND FAIL: %v", r.i, r.err)
			continue
		}
		ok++
		log.Printf("[%02d] SEND OK", r.i)
	}
	log.Printf("Done in %s. ok=%d fail=%d", time.Since(start), ok, fail)
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
