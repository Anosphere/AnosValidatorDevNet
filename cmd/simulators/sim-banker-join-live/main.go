// sim-banker-join-live drives the P7.4 open-net JOIN path against a REAL, RUNNING non-roster
// validator (unlike sim-banker-join, whose bankers are keyless phantoms with no process):
//
//  1. Requires the list→Fund flip to have latched (run sim-list-fund-flip first).
//  2. Waits for the extra validator (val3 — booted by the harness with a key OUTSIDE the manifest
//     roster) to CONVERGE to the founders' heads: nobody dials a non-member, so this exercises the
//     P7.4 behind-probe → verifying-resync → follow path.
//  3. Stakes a fresh Banker identity B3 carrying val3's REAL consensus key + REAL endpoint. From
//     the next epoch every founder's dial list + membership gate must include val3 — Fund-native
//     dialing is the ONLY way traffic reaches it (it is in nobody's static PEERS).
//  4. Waits for all four nodes to agree the Fund banker set includes B3, and for val3 to track the
//     founders' heads THROUGH the join (it keeps finalizing with them).
//
// The quorum-differential proof (kill a founder → 3-of-4 still finalizes ⇒ val3's vote counts) is
// orchestrated by the harness (it owns the processes) via sim-join-differential.
//
// Env: VALIDATOR_URL_LIST (founders), EXTRA_VALIDATOR_URL, EXTRA_VALIDATOR_PUBKEY_HEX,
// GENESIS_SEED_HEX, GENESIS_HEX, FUND_ACCOUNT_HEX.
package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
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
	founder0 := c.URLs[0]
	extraURL := strings.TrimRight(mustEnv("EXTRA_VALIDATOR_URL"), "/")
	extraPub, err := hex.DecodeString(strings.TrimSpace(mustEnv("EXTRA_VALIDATOR_PUBKEY_HEX")))
	if err != nil || len(extraPub) != 33 {
		log.Fatalf("EXTRA_VALIDATOR_PUBKEY_HEX must be 33 bytes hex")
	}

	genSeed := simkit.MustSeedFromHex(mustEnv("GENESIS_SEED_HEX"))
	genIDHex := strings.ToLower(mustEnv("GENESIS_HEX"))
	genesis := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, genSeed, genSeed)
	if hex.EncodeToString(genesis.IDBytes()) != genIDHex {
		log.Fatalf("config mismatch: GENESIS_SEED_HEX derives id %s but GENESIS_HEX=%s",
			hex.EncodeToString(genesis.IDBytes()), genIDHex)
	}
	fund := fundAccountID()

	// ---------------------------------------------------------------
	// STEP 1: the flip must have latched (Fund-native consensus).
	// ---------------------------------------------------------------
	banner("STEP 1: require the list→Fund flip latched")
	waitFlipped(founder0, 60*time.Second)
	log.Printf("OK: consensus is Fund-native (flip latched)")

	// ---------------------------------------------------------------
	// STEP 2: val3 (non-roster, undialed) must converge on its own.
	// ---------------------------------------------------------------
	banner("STEP 2: non-roster val3 converges via behind-probe + verifying resync")
	waitHeadsMatch(extraURL, founder0, 240*time.Second)
	log.Printf("OK: val3 rebuilt the founders' heads without anyone dialing it")

	// ---------------------------------------------------------------
	// STEP 3: stake B3 with val3's REAL consensus key + endpoint.
	// ---------------------------------------------------------------
	banner("STEP 3: stake Banker B3 carrying val3's consensus key + endpoint")
	endpoint := hostPortOf(extraURL)
	const (
		bankerStake = uint64(60_000) * core.UnitsPerAnos
		grant       = uint64(80_000) * core.UnitsPerAnos
	)
	B3 := simkit.RandomAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING)
	fundAndOpen(c, genesis, B3, grant)
	bankerStakeSend(c, B3, fund, bankerStake, pb.StakeTimeDelay_STAKE_TIME_DELAY_ONE_MONTH, extraPub, endpoint)
	log.Printf("B3=%x staked banker with val3's key=%x endpoint=%s", B3.IDBytes()[:4], extraPub[:6], endpoint)

	// ---------------------------------------------------------------
	// STEP 4: every node (founders AND val3) lists B3; val3 keeps tracking.
	// ---------------------------------------------------------------
	banner("STEP 4: all nodes agree the Fund set includes B3; val3 tracks the tip")
	for _, u := range append(append([]string(nil), c.URLs...), extraURL) {
		waitBankerKey(u, B3.IDBytes(), extraPub, endpoint, "STEP 4 "+u, 120*time.Second)
	}
	// A post-join convergence check: val3 must match the founders' heads again (the join-era txs
	// reached it via Fund-native dialing — it is in nobody's static PEERS).
	waitHeadsMatch(extraURL, founder0, 240*time.Second)
	log.Printf("OK: val3 is a dialed, tracking member of the Fund-native set")

	banner("ALL CHECKS PASSED")
}

// --- flow helpers (the sim-banker-join pattern; sims are self-contained clients) ---

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

// --- read-API polling ---

func getJSON(u string, out any) error {
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func waitFlipped(base string, maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	for {
		var st struct {
			Flipped bool `json:"flipped"`
		}
		if err := getJSON(base+"/debug/consensus/flip", &st); err == nil && st.Flipped {
			return
		}
		if time.Now().After(deadline) {
			log.Fatalf("flip never latched on %s — run sim-list-fund-flip before this sim", base)
		}
		time.Sleep(1 * time.Second)
	}
}

// headsBody fetches the full heads dump; bbolt iterates key-sorted, so agreeing nodes return
// byte-identical JSON (the same property the harness's jq -S hashing relies on).
func headsBody(base string) (string, error) {
	resp, err := http.Get(base + "/debug/accounts/heads")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", err
	}
	return string(b), nil
}

func waitHeadsMatch(nodeURL, refURL string, maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	for {
		ref, err1 := headsBody(refURL)
		got, err2 := headsBody(nodeURL)
		if err1 == nil && err2 == nil && ref != "" && ref == got {
			return
		}
		if time.Now().After(deadline) {
			log.Fatalf("%s never converged to %s's heads within %s", nodeURL, refURL, maxWait)
		}
		time.Sleep(1 * time.Second)
	}
}

type bankerRow struct {
	Identity     string `json:"identity"`
	ConsensusKey string `json:"consensus_pubkey"`
	Endpoint     string `json:"endpoint"`
}

func waitBankerKey(base string, id, consensusKey []byte, endpoint, label string, maxWait time.Duration) {
	wantID := hex.EncodeToString(id)
	wantKey := hex.EncodeToString(consensusKey)
	deadline := time.Now().Add(maxWait)
	for {
		var rows []bankerRow
		if err := getJSON(base+"/debug/fund/bankers", &rows); err == nil {
			for _, r := range rows {
				if r.Identity == wantID && r.ConsensusKey == wantKey && r.Endpoint == endpoint {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			log.Fatalf("[%s] timed out waiting for banker %x key=%x endpoint=%s", label, id[:4], consensusKey[:6], endpoint)
		}
		time.Sleep(1 * time.Second)
	}
}

// --- misc ---

// hostPortOf extracts "host:port" from a base URL — the bare form banker endpoints register.
func hostPortOf(base string) string {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		log.Fatalf("EXTRA_VALIDATOR_URL %q is not a URL", base)
	}
	return u.Host
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
