// sim-postflip-divergence drives the P4.3b verifying-resync scenario (build-plan §P4.3, working notes
// §3.9): a list→Fund flip FOLLOWED by a post-flip set CHANGE that makes the Fund-derived validator set
// DIVERGE from the manifest list. The P4.3a interim resync could not handle this (a wiped node re-latches
// the flip only when the Fund set still equals the manifest, so after a divergence it would stay on the
// env list); the P4.3b epoch-ordered verifying walk re-derives the TRUE flip + the post-flip set history
// from the manifest anchor, so a wiped node converges AND re-derives the same flip_epoch.
//
//  1. BEFORE: every node reports flipped=false.
//  2. FLIP: stake one banker per manifest key (founders stake their list keys) → the predicate fires;
//     every node flips to source=fund with fund_set_size == manifest_list_size; record flip_epoch.
//  3. DIVERGE: stake a 4th banker carrying a FRESH (non-manifest) consensus key → the Fund-derived set
//     grows to manifest+1 while the latched flip stays put (one-way). The live network keeps finalizing
//     (the 4th key never signs; 3-of-4 >= the 60% finalization quorum).
//  4. AFTER: every node reports flipped=true, source=fund, fund_set_size == manifest+1, and the SAME
//     flip_epoch as in step 2 (the join did not move the flip).
//
// The live harness then wipes a node and confirms its P4.3b verifying resync converges to the diverged
// state AND re-derives the identical flip_epoch. Env: VALIDATOR_URL_LIST, VALIDATOR_SET_PUBKEYS,
// GENESIS_SEED_HEX, GENESIS_HEX, FUND_ACCOUNT_HEX.
package main

import (
	"encoding/hex"
	"encoding/json"
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
	urls := mustEnv("VALIDATOR_URL_LIST")
	c := simkit.NewClient(urls)

	genSeed := simkit.MustSeedFromHex(mustEnv("GENESIS_SEED_HEX"))
	genIDHex := strings.ToLower(mustEnv("GENESIS_HEX"))
	genesis := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, genSeed, genSeed)
	if hex.EncodeToString(genesis.IDBytes()) != genIDHex {
		log.Fatalf("config mismatch: GENESIS_SEED_HEX derives id %s but GENESIS_HEX=%s",
			hex.EncodeToString(genesis.IDBytes()), genIDHex)
	}
	fund := fundAccountID()

	manifestKeys := parseManifestKeys(mustEnv("VALIDATOR_SET_PUBKEYS"))
	log.Printf("manifest list has %d validator keys", len(manifestKeys))

	const (
		bankerStake = uint64(60_000) * core.UnitsPerAnos // > the 50k banker floor
		grant       = uint64(70_000) * core.UnitsPerAnos // genesis grant (stake + fee)
	)
	oneMonth := pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_MONTH

	// STEP 1: BEFORE.
	banner("STEP 1: BEFORE — flipped=false on every node")
	for i, u := range c.URLs {
		if fs := getFlip(u); fs.Flipped {
			log.Fatalf("FAIL: node %d already flipped (flip_epoch=%d)", i, fs.FlipEpoch)
		}
	}

	// STEP 2: founders stake their LIST keys → the flip latches.
	banner("STEP 2: FLIP — stake one banker per manifest key")
	for i, key := range manifestKeys {
		B := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
		fundAndOpen(c, genesis, B, grant)
		bankerStakeSend(c, B, fund, bankerStake, oneMonth, key, "10.0.0."+itoa(10+i)+":9090")
		log.Printf("  founder %d staked banker carrying manifest key %x", i, key[:6])
	}
	waitFlipped(c, len(manifestKeys))
	flipEpoch := getFlip(c.URLs[0]).FlipEpoch
	log.Printf("OK: all nodes flipped to source=fund (flip_epoch=%d, fund_set=%d)", flipEpoch, len(manifestKeys))

	// STEP 3: post-flip DIVERGENCE — a 4th banker with a fresh, non-manifest consensus key.
	banner("STEP 3: DIVERGE — stake a 4th banker (fresh key) so the Fund set != the manifest")
	extra := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	fundAndOpen(c, genesis, extra, grant)
	freshKey := simkit.RandomConsensusKey()
	bankerStakeSend(c, extra, fund, bankerStake, oneMonth, freshKey, "10.0.0.99:9090")
	log.Printf("  staked 4th banker carrying NON-manifest key %x", freshKey[:6])

	// STEP 4: AFTER — the Fund set diverged but the latched flip stayed put.
	banner("STEP 4: AFTER — fund_set == manifest+1, flipped=true, flip_epoch unchanged")
	want := len(manifestKeys) + 1
	waitFundSet(c, want)
	for i, u := range c.URLs {
		fs := getFlip(u)
		log.Printf("  node %d: flipped=%v source=%s flip_epoch=%d fund_set=%d manifest=%d",
			i, fs.Flipped, fs.Source, fs.FlipEpoch, fs.FundSetSize, fs.ManifestSize)
		if !fs.Flipped || fs.Source != "fund" {
			log.Fatalf("FAIL: node %d not on the Fund-derived set after divergence", i)
		}
		if fs.FundSetSize != want {
			log.Fatalf("FAIL: node %d fund_set_size=%d, want %d (post-divergence)", i, fs.FundSetSize, want)
		}
		if fs.FlipEpoch != flipEpoch {
			log.Fatalf("FAIL: node %d flip_epoch moved on a post-flip join: was %d now %d (latch must be one-way)", i, flipEpoch, fs.FlipEpoch)
		}
	}
	log.Printf("OK: Fund set diverged to %d keys; flip stayed latched at epoch %d on every node", want, flipEpoch)

	banner("ALL CHECKS PASSED")
}

// --- flip read API ---

type flipState struct {
	FlipEpoch    uint64 `json:"flip_epoch"`
	Flipped      bool   `json:"flipped"`
	Source       string `json:"live_set_source"`
	ManifestSize int    `json:"manifest_list_size"`
	FundSetSize  int    `json:"fund_set_size"`
}

func getFlip(url string) flipState {
	resp, err := http.Get(url + "/debug/consensus/flip")
	if err != nil {
		log.Fatalf("GET %s/debug/consensus/flip: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var fs flipState
	if err := json.Unmarshal(body, &fs); err != nil {
		log.Fatalf("decode flip state from %s: %v (body=%s)", url, err, string(body))
	}
	return fs
}

func waitFlipped(c *simkit.Client, wantSize int) {
	deadline := time.Now().Add(150 * time.Second)
	for {
		all := true
		for _, u := range c.URLs {
			fs := getFlip(u)
			if !fs.Flipped || fs.FundSetSize != wantSize {
				all = false
				break
			}
		}
		if all {
			return
		}
		if time.Now().After(deadline) {
			log.Fatalf("timed out waiting for all nodes to flip to a %d-key Fund set", wantSize)
		}
		time.Sleep(1 * time.Second)
	}
}

func waitFundSet(c *simkit.Client, wantSize int) {
	deadline := time.Now().Add(150 * time.Second)
	for {
		all := true
		for _, u := range c.URLs {
			if getFlip(u).FundSetSize != wantSize {
				all = false
				break
			}
		}
		if all {
			return
		}
		if time.Now().After(deadline) {
			log.Fatalf("timed out waiting for all nodes to see a %d-key Fund set", wantSize)
		}
		time.Sleep(1 * time.Second)
	}
}

// --- flow helpers (shared shape with sim-list-fund-flip) ---

func fundAndOpen(c *simkit.Client, genesis, acct *simkit.Account, amount uint64) {
	normalSend(c, genesis, acct.ID, amount)
	rid := c.WaitForReceivable(acct.IDBytes(), nil, 1*time.Second, 120*time.Second)
	tx := simkit.BuildOpeningReceive(acct, rid, nil, 0)
	acct.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(acct.IDBytes(), 1, 500*time.Millisecond, 120*time.Second)
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

func bankerStakeSend(c *simkit.Client, from *simkit.Account, fund [32]byte, amount uint64, delay pb.StakeTimeDelay, consensusPubkey []byte, endpoint string) {
	head, seq, err := c.Head(from.IDBytes())
	if err != nil {
		log.Fatalf("read banker: %v", err)
	}
	tx := simkit.BuildBankerStakeSend(from, head, seq+1, fund, amount, core.ExpectedFee(amount), delay, consensusPubkey, endpoint)
	from.MustSign(tx)
	c.MustSubmit(tx)
	c.WaitForSeqAtLeast(from.IDBytes(), seq+1, 500*time.Millisecond, 120*time.Second)
}

// --- misc ---

func parseManifestKeys(csv string) [][]byte {
	var out [][]byte
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		b, err := hex.DecodeString(p)
		if err != nil || len(b) != 33 {
			log.Fatalf("VALIDATOR_SET_PUBKEYS entry %q is not 33 hex-encoded bytes: %v", p, err)
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		log.Fatal("VALIDATOR_SET_PUBKEYS is empty")
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

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
