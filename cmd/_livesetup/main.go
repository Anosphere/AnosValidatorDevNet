// Command _livesetup generates a fully self-contained 3-validator local test network config
// (fresh P-256 validator keys + a fresh hybrid genesis keypair) so the live lifecycle + resync can
// run without touching the operator's real .env files. The dir is underscore-prefixed so
// `go build ./...` ignores it.
//
// P7.2: it writes a network MANIFEST (config/manifest.json shape) as the source of truth — the
// validators boot from it via `-manifest` (the only boot path now) — plus a common.env DERIVED from
// the same manifest struct that carries the SECRET genesis seed + the sim URL list for the
// simulators (which are external clients, not validators). Deriving common.env from the manifest
// keeps the two from drifting.
//
// Usage: go run ./cmd/_livesetup -dir <outdir>
// Writes <outdir>/val{0,1,2}.key, <outdir>/manifest.json, and <outdir>/common.env.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"anos/internal/config"
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

	// 3 fresh P-256 validator keys → key files + compressed-pubkey set — PLUS one EXTRA key
	// (val3) that is deliberately NOT in the roster/manifest: the P7.4 JOIN_LIVE stage boots it as
	// a non-founder and stakes it into the Fund, so Fund-native dialing is live-tested against a
	// genuinely non-roster validator.
	var pubs []string
	for i := 0; i < 4; i++ {
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
	extraPub := pubs[3]
	pubs = pubs[:3] // only the first 3 form the roster

	// Fresh hybrid genesis keypair (seed-pinned).
	var seed [32]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		log.Fatal(err)
	}
	_, genPub := crypto.GenerateHybridKeyFromSeed(seed)
	genID := crypto.BaseAccountID(crypto.AccountTypeByteForClass(pb.AccountClass_ACCOUNT_CLASS_SPENDING), genPub.Encode())

	// Genesis a few seconds in the past so epoch numbering has already advanced.
	genesisUnixMs := time.Now().UnixMilli() - 10_000
	urls := []string{"http://127.0.0.1:9090", "http://127.0.0.1:9091", "http://127.0.0.1:9092"}

	// The manifest is the SOURCE OF TRUTH. Timings are shrunk for a short live run; the economics +
	// consensus scalars are the canonical production values (matching config/testnet.json and the
	// core client-side consts, so a sim's ExpectedFee matches the validator's RequiredFee).
	mani := config.Manifest{
		Version:         config.SupportedVersion,
		ProtocolVersion: config.SupportedProtocolVersion,
		FundAccountHex:  strings.Repeat("ff", 32),
		Timing: config.Timing{
			EpochMs:                      2000,
			TimelockedDelayEpochs:        6,
			GuardianActiveWindowEpochs:   20,
			StakeLock1moEpochs:           4,
			StakeLock1yrEpochs:           8,
			GuardedDelayEpochs:           8,
			VaultDelayEpochs:             12,
			AttestorQuorumM:              2,
			EscrowAttestationDelayEpochs: 6,
			BreakglassExtraEpochs:        5,
		},
		Economics: config.Economics{
			MinFee:                           1_000,
			MaxFee:                           3_000_000,
			AttestedEscrowFee:                100_000,
			FeeBps:                           50,
			BankerStakeFloorAnos:             50_000,
			AttestorStakeFloorAnos:           5_000,
			GuardianDivisorAnos:              2_000,
			GuardianSendThresholdBps:         7_000,
			GuardianFundSendEpochSlackEpochs: 8,
		},
		Consensus: config.Consensus{
			QuorumPercent:             80,
			FinalizationQuorumPercent: 60,
			MaxCandidateScanPerSlot:   64,
		},
		Genesis: config.Genesis{
			Hex:           hex.EncodeToString(genID[:]),
			AuthPubkeyHex: hex.EncodeToString(genPub.Encode()),
			UnixMs:        genesisUnixMs,
			SupplyUnits:   1_000_000_000_000_000, // 1e9 Anos @ 1e6 units
		},
		Roster: []config.Node{
			{Pubkey: pubs[0], URL: urls[0]},
			{Pubkey: pubs[1], URL: urls[1]},
			{Pubkey: pubs[2], URL: urls[2]},
		},
	}
	// Fail fast if the harness config ever drifts out of the manifest's validity rules (the same
	// refuse-to-boot checks the validator runs). NetworkID is left empty — config.Load computes it, so
	// every validator derives the identical id.
	if err := mani.Validate(); err != nil {
		log.Fatalf("harness manifest is invalid: %v", err)
	}
	manifestPath := filepath.Join(*dir, "manifest.json")
	data, err := json.MarshalIndent(&mani, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
		log.Fatal(err)
	}

	// common.env is DERIVED from the manifest struct (no drift) + the SECRET genesis seed + the sim
	// URL list. The simulators source it (they are external clients that need the seed to sign genesis
	// SENDs and the delays to compute unlock epochs); the validators DO NOT use it — they boot from
	// -manifest.
	common := map[string]string{
		"EPOCH_MS":                        strconv.FormatInt(mani.Timing.EpochMs, 10),
		"GENESIS_UNIX_MS":                 strconv.FormatInt(mani.Genesis.UnixMs, 10),
		"GENESIS_SUPPLY_UNITS":            strconv.FormatUint(mani.Genesis.SupplyUnits, 10),
		"FUND_ACCOUNT_HEX":                mani.FundAccountHex,
		"TIMELOCKED_DELAY_EPOCHS":         strconv.FormatUint(mani.Timing.TimelockedDelayEpochs, 10),
		"GUARDIAN_ACTIVE_WINDOW_EPOCHS":   strconv.FormatUint(mani.Timing.GuardianActiveWindowEpochs, 10),
		"STAKE_LOCK_1MO_EPOCHS":           strconv.FormatUint(mani.Timing.StakeLock1moEpochs, 10),
		"STAKE_LOCK_1YR_EPOCHS":           strconv.FormatUint(mani.Timing.StakeLock1yrEpochs, 10),
		"GUARDED_DELAY_EPOCHS":            strconv.FormatUint(mani.Timing.GuardedDelayEpochs, 10),
		"VAULT_DELAY_EPOCHS":              strconv.FormatUint(mani.Timing.VaultDelayEpochs, 10),
		"ATTESTOR_QUORUM_M":               strconv.FormatUint(mani.Timing.AttestorQuorumM, 10),
		"ESCROW_ATTESTATION_DELAY_EPOCHS": strconv.FormatUint(mani.Timing.EscrowAttestationDelayEpochs, 10),
		"BREAKGLASS_EXTRA_EPOCHS":         strconv.FormatUint(mani.Timing.BreakglassExtraEpochs, 10),
		"VALIDATOR_SET_PUBKEYS":           mani.ValidatorSetCSV(),
		"GENESIS_HEX":                     mani.Genesis.Hex,
		"GENESIS_AUTH_PUBKEY_HEX":         mani.Genesis.AuthPubkeyHex,
		"GENESIS_SEED_HEX":                hex.EncodeToString(seed[:]),
		"VALIDATOR_URL_LIST":              strings.Join(urls, ","),
		// P7.4 JOIN_LIVE: the extra NON-roster validator (val3.key) the harness may start + stake.
		"EXTRA_VALIDATOR_PUBKEY_HEX": extraPub,
		"EXTRA_VALIDATOR_URL":        "http://127.0.0.1:9093",
	}

	var b strings.Builder
	order := []string{
		"EPOCH_MS", "GENESIS_UNIX_MS", "GENESIS_SUPPLY_UNITS", "FUND_ACCOUNT_HEX",
		"TIMELOCKED_DELAY_EPOCHS", "GUARDIAN_ACTIVE_WINDOW_EPOCHS",
		"STAKE_LOCK_1MO_EPOCHS", "STAKE_LOCK_1YR_EPOCHS",
		"GUARDED_DELAY_EPOCHS", "VAULT_DELAY_EPOCHS", "ATTESTOR_QUORUM_M",
		"ESCROW_ATTESTATION_DELAY_EPOCHS", "BREAKGLASS_EXTRA_EPOCHS",
		"VALIDATOR_SET_PUBKEYS",
		"GENESIS_HEX", "GENESIS_AUTH_PUBKEY_HEX", "GENESIS_SEED_HEX", "VALIDATOR_URL_LIST",
		"EXTRA_VALIDATOR_PUBKEY_HEX", "EXTRA_VALIDATOR_URL",
	}
	for _, k := range order {
		fmt.Fprintf(&b, "export %s=%s\n", k, common[k])
	}
	commonPath := filepath.Join(*dir, "common.env")
	if err := os.WriteFile(commonPath, []byte(b.String()), 0o644); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("wrote %s, %s and val0/1/2.key\n", manifestPath, commonPath)
	fmt.Printf("GENESIS_HEX=%s\n", mani.Genesis.Hex)
	fmt.Printf("ports: 9090(val0) 9091(val1) 9092(val2)\n")
}
