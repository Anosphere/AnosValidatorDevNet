// sim-join-differential is the P7.4 QUORUM-DIFFERENTIAL proof that a joined non-roster validator's
// vote is actually COUNTED. The harness runs it with ONE FOUNDER KILLED after sim-banker-join-live:
// the Fund set is then 4 members (3 founders + the joined val3), finalization quorum needs
// ceil(4×60%) = 3, and only 3 nodes are alive (2 founders + val3) — so a NEW transaction can only
// finalize if val3's finalization is counted AND val3 received the epoch's candidates/txs via
// Fund-native dialing (it is in nobody's static PEERS). 2 founders alone = 2 < 3 = guaranteed stall.
//
// Steps: submit a genesis SEND via the surviving founder → wait for the seq to advance (advancing
// requires a COMMIT, i.e. a reached quorum) → assert every PROBE_URLS node reports byte-identical
// heads (they all applied the same epoch).
//
// Env: VALIDATOR_URL_LIST (the surviving founder ONLY — never submit to a dead node), PROBE_URLS
// (comma list: surviving founders + the joined validator), GENESIS_SEED_HEX, GENESIS_HEX,
// FUND_ACCOUNT_HEX (unused, kept for the common env), EPOCH_MS (pacing hint only).
package main

import (
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"anos/internal/core"
	pb "anos/internal/proto"
	"anos/internal/simkit"
)

func main() {
	c := simkit.NewClient(mustEnv("VALIDATOR_URL_LIST"))
	probes := splitCSV(mustEnv("PROBE_URLS"))
	if len(probes) < 2 {
		log.Fatalf("PROBE_URLS needs at least 2 nodes to compare")
	}

	genSeed := simkit.MustSeedFromHex(mustEnv("GENESIS_SEED_HEX"))
	genIDHex := strings.ToLower(mustEnv("GENESIS_HEX"))
	genesis := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, genSeed, genSeed)
	if hex.EncodeToString(genesis.IDBytes()) != genIDHex {
		log.Fatalf("config mismatch: GENESIS_SEED_HEX derives id %s but GENESIS_HEX=%s",
			hex.EncodeToString(genesis.IDBytes()), genIDHex)
	}

	banner("DIFFERENTIAL: a new tx must finalize on a 3-of-4 quorum that INCLUDES the joined node")
	to := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	head, seq, err := c.Head(genesis.IDBytes())
	if err != nil {
		log.Fatalf("read genesis: %v", err)
	}
	amount := uint64(1_000) * core.UnitsPerAnos
	tx := simkit.BuildSend(genesis, head, seq+1, to.ID, amount, core.ExpectedFee(amount))
	genesis.MustSign(tx)
	c.MustSubmit(tx)
	// Seq advance == the epoch COMMITTED == a finalization quorum was reached. With one founder
	// dead, that quorum arithmetically requires the joined validator's vote.
	c.WaitForSeqAtLeast(genesis.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
	log.Printf("OK: tx finalized with a founder down — the joined validator's vote was counted")

	banner("PROBE: all surviving nodes hold byte-identical heads")
	waitAllHeadsMatch(probes, 120*time.Second)
	log.Printf("OK: %d nodes agree on heads", len(probes))

	banner("ALL CHECKS PASSED")
}

func headsBody(base string) (string, error) {
	resp, err := http.Get(strings.TrimRight(base, "/") + "/debug/accounts/heads")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		return "", err
	}
	return string(b), nil
}

func waitAllHeadsMatch(urls []string, maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	for {
		ref, err := headsBody(urls[0])
		ok := err == nil && ref != ""
		if ok {
			for _, u := range urls[1:] {
				got, err2 := headsBody(u)
				if err2 != nil || got != ref {
					ok = false
					break
				}
			}
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			log.Fatalf("probe nodes never agreed on heads within %s", maxWait)
		}
		time.Sleep(1 * time.Second)
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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
