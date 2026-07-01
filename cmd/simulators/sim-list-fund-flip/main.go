// sim-list-fund-flip demonstrates the P4.3 list→Fund bootstrap flip (build-plan §P4.3, working
// notes §3.9): the live consensus validator-set SOURCE switches from the static manifest list to
// the Fund-derived Banker set at the first finalized epoch where the two EXACTLY match.
//
// The founders stake with their LIST consensus keys: this sim creates one SPENDING banker per
// manifest validator key (read from VALIDATOR_SET_PUBKEYS) and stakes each >= the 50k floor carrying
// that key. Once all are staked + finalized, the Fund-derived Banker key set equals the manifest →
// the deterministic latching predicate fires and /debug/consensus/flip flips to source=fund on every
// node. Because the match requires the full key set, the cutover is byte-identical (seamless): the
// validators keep signing with the very same keys, so consensus never skips a beat.
//
//	1. BEFORE: /debug/consensus/flip reports flipped=false (manifest list drives consensus).
//	2. Stake one banker per manifest key (>= 50k, 1-month tier), carrying that exact consensus key.
//	3. AFTER: every node reports flipped=true, flip_epoch>0, and fund_set_size == manifest_list_size.
//
// The latch is one-way (a later kick can't revert it — pinned by the unit tests); the live harness
// additionally confirms the flip survives a wipe+resync (P4.3a interim re-latch). Env:
// VALIDATOR_URL_LIST, VALIDATOR_SET_PUBKEYS, GENESIS_SEED_HEX, GENESIS_HEX, FUND_ACCOUNT_HEX.
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

	// ---------------------------------------------------------------
	// STEP 1: BEFORE — consensus is still driven by the manifest list.
	// ---------------------------------------------------------------
	banner("STEP 1: BEFORE — flipped=false (manifest list drives consensus)")
	for i, u := range c.URLs {
		fs := getFlip(u)
		if fs.Flipped {
			log.Fatalf("FAIL: node %d already flipped before any banker staked (flip_epoch=%d)", i, fs.FlipEpoch)
		}
	}
	log.Printf("OK: all %d nodes report source=manifest_list", len(c.URLs))

	// ---------------------------------------------------------------
	// STEP 2: founders stake banker with their LIST consensus keys.
	// ---------------------------------------------------------------
	banner("STEP 2: stake one banker per manifest key (founders stake their list keys)")
	for i, key := range manifestKeys {
		B := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
		fundAndOpen(c, genesis, B, grant)
		endpoint := "10.0.0." + itoa(10+i) + ":9090"
		bankerStakeSend(c, B, fund, bankerStake, oneMonth, key, endpoint)
		log.Printf("  founder %d: B=%x staked banker carrying manifest key %x", i, B.IDBytes()[:4], key[:6])
	}

	// ---------------------------------------------------------------
	// STEP 3: AFTER — the Fund set matches the list → the flip latches.
	// ---------------------------------------------------------------
	banner("STEP 3: AFTER — wait for the latch: flipped=true on every node")
	waitFlippedAll(c, len(manifestKeys))
	for i, u := range c.URLs {
		fs := getFlip(u)
		log.Printf("  node %d: flipped=%v source=%s flip_epoch=%d fund_set=%d manifest=%d",
			i, fs.Flipped, fs.Source, fs.FlipEpoch, fs.FundSetSize, fs.ManifestSize)
		if !fs.Flipped || fs.Source != "fund" {
			log.Fatalf("FAIL: node %d did not flip to the Fund-derived set", i)
		}
		if fs.FundSetSize != fs.ManifestSize || fs.FundSetSize != len(manifestKeys) {
			log.Fatalf("FAIL: node %d fund_set_size=%d manifest=%d expected=%d", i, fs.FundSetSize, fs.ManifestSize, len(manifestKeys))
		}
	}
	log.Printf("OK: all %d nodes flipped to the Fund-derived set (consensus is now Fund-native)", len(c.URLs))

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

// waitFlippedAll polls until every node reports flipped=true with the expected Fund set size.
func waitFlippedAll(c *simkit.Client, wantSize int) {
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

// --- flow helpers (shared shape with the other banker sims) ---

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

// parseManifestKeys decodes the comma-separated 33-byte compressed P-256 keys in
// VALIDATOR_SET_PUBKEYS — the founders stake bankers carrying exactly these keys.
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
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
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
