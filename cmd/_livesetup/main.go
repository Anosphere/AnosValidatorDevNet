// Command _livesetup generates a fully self-contained 3-validator local test
// network config (fresh P-256 validator keys + a fresh hybrid genesis keypair) so
// the P1.2 live lifecycle + resync can run without touching the operator's real
// .env files. The dir is underscore-prefixed so `go build ./...` ignores it.
//
// Usage: go run ./cmd/_livesetup -dir <outdir>
// Writes <outdir>/val{0,1,2}.key and <outdir>/common.env, and prints a summary.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

func main() {
	dir := flag.String("dir", "", "output directory")
	flag.Parse()
	if *dir == "" {
		log.Fatal("-dir is required")
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatal(err)
	}

	// 3 fresh P-256 validator keys → key files + compressed-pubkey set.
	var pubs []string
	for i := 0; i < 3; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		var d [32]byte
		priv.D.FillBytes(d[:])
		keyPath := filepath.Join(*dir, fmt.Sprintf("val%d.key", i))
		if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(d[:])), 0o600); err != nil {
			log.Fatal(err)
		}
		comp := crypto.CompressP256PublicKey(&priv.PublicKey)
		pubs = append(pubs, hex.EncodeToString(comp[:]))
	}
	set := strings.Join(pubs, ",")

	// Fresh hybrid genesis keypair (seed-pinned).
	var seed [32]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		log.Fatal(err)
	}
	_, genPub := crypto.GenerateHybridKeyFromSeed(seed)
	genID := crypto.BaseAccountID(crypto.AccountTypeByteForClass(pb.AccountClass_ACCOUNT_CLASS_SPENDING), genPub.Encode())

	// Genesis a few seconds in the past so epoch numbering has already advanced.
	genesisUnixMs := time.Now().UnixMilli() - 10_000

	common := map[string]string{
		"EPOCH_MS":                "2000",
		"GENESIS_UNIX_MS":         fmt.Sprintf("%d", genesisUnixMs),
		"GENESIS_SUPPLY_UNITS":    "1000000000000000", // 1e9 Anos @ 1e6 units
		"FUND_ACCOUNT_HEX":        strings.Repeat("ff", 32),
		"TIMELOCKED_DELAY_EPOCHS": "6",
		// Small Guardian active window so the trailing-window denominator (spec-19 §6.2) is
		// exercisable in a short live run (production ~5–6 weeks). 20 epochs @2s ≈ 40s.
		"GUARDIAN_ACTIVE_WINDOW_EPOCHS": "20",
		// Small stake-lock tiers (P2.3b) so a returned stake's transfer chain unlocks within a
		// short live run. 1mo→4 epochs (≈8s), 1yr→8 epochs (≈16s).
		"STAKE_LOCK_1MO_EPOCHS": "4",
		"STAKE_LOCK_1YR_EPOCHS": "8",
		// Small GUARDED/VAULT transfer delays (P3.2) so a guarded/vault release unlocks within a
		// short live run (VAULT > GUARDED > TIMELOCKED=6). 8 epochs (≈16s) / 12 epochs (≈24s).
		"GUARDED_DELAY_EPOCHS": "8",
		"VAULT_DELAY_EPOCHS":   "12",
		// Flat M-of-N Fund Attestor quorum (P3.2): 2 attestors gate a guarded/vault release.
		"ATTESTOR_QUORUM_M": "2",
		// Small escrow attestation delay (P3.3) so an attested escrow's 1-of-2 → Fund trigger becomes
		// available within a short live run. 6 epochs (≈12s).
		"ESCROW_ATTESTATION_DELAY_EPOCHS": "6",
		// Small breakglass extra (fraud-challenge) window (P5.1) so a breakglass release unlocks within
		// a short live run. 5 epochs (≈10s); added on top of the source class's transfer delay.
		"BREAKGLASS_EXTRA_EPOCHS": "5",
		"VALIDATOR_SET_PUBKEYS":   set,
		"GENESIS_HEX":             hex.EncodeToString(genID[:]),
		"GENESIS_AUTH_PUBKEY_HEX": hex.EncodeToString(genPub.Encode()),
		"GENESIS_SEED_HEX":        hex.EncodeToString(seed[:]),
		"VALIDATOR_URL_LIST":      "http://127.0.0.1:9090,http://127.0.0.1:9091,http://127.0.0.1:9092",
	}

	var b strings.Builder
	// Deterministic-ish order for readability.
	order := []string{
		"EPOCH_MS", "GENESIS_UNIX_MS", "GENESIS_SUPPLY_UNITS", "FUND_ACCOUNT_HEX",
		"TIMELOCKED_DELAY_EPOCHS", "GUARDIAN_ACTIVE_WINDOW_EPOCHS",
		"STAKE_LOCK_1MO_EPOCHS", "STAKE_LOCK_1YR_EPOCHS",
		"GUARDED_DELAY_EPOCHS", "VAULT_DELAY_EPOCHS", "ATTESTOR_QUORUM_M",
		"ESCROW_ATTESTATION_DELAY_EPOCHS", "BREAKGLASS_EXTRA_EPOCHS",
		"VALIDATOR_SET_PUBKEYS",
		"GENESIS_HEX", "GENESIS_AUTH_PUBKEY_HEX", "GENESIS_SEED_HEX", "VALIDATOR_URL_LIST",
	}
	for _, k := range order {
		fmt.Fprintf(&b, "export %s=%s\n", k, common[k])
	}
	commonPath := filepath.Join(*dir, "common.env")
	if err := os.WriteFile(commonPath, []byte(b.String()), 0o644); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("wrote %s and val0/1/2.key\n", commonPath)
	fmt.Printf("GENESIS_HEX=%s\n", common["GENESIS_HEX"])
	fmt.Printf("ports: 9090(val0) 9091(val1) 9092(val2)\n")
}
