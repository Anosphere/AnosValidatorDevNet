// Command _gentestnet generates a complete, ready-to-run Anos TEST network from a set
// of endpoints: a fresh hybrid genesis keypair + one fresh P-256 consensus key per node,
// assembled into a committed public manifest (config/testnet.json) plus a secrets bundle
// (the private keys + genesis seed + a sim env) written OUTSIDE the repo.
//
// The dir is underscore-prefixed so `go build ./...` ignores it (like cmd/_livesetup).
//
// Usage (real 5-VM testnet, one shared port):
//
//	go run ./cmd/_gentestnet \
//	  -endpoints 35.234.70.37:30303,34.159.203.177:30303,34.107.74.229:30303,35.242.233.86:30303,35.234.117.219:30303 \
//	  -manifest-out config/testnet.json -secrets-dir ../deploy-bundles
//
// Usage (localhost identity test, distinct ports on one host):
//
//	go run ./cmd/_gentestnet -endpoints 127.0.0.1:30303,127.0.0.1:30304,127.0.0.1:30305 \
//	  -manifest-out /tmp/localnet.json -secrets-dir /tmp/localsecrets
//
// To REPRODUCE the same genesis on a later run, pass -genesis-seed <hex> and
// -genesis-unix-ms <ms> (both echoed to the secrets bundle on the first run). Genesis
// stays static: only THIS machine ever holds GENESIS_SEED_HEX; no VM receives it.
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
	"strings"
	"time"

	"anos/internal/config"
	"anos/internal/crypto"
	pb "anos/internal/proto"
)

func main() {
	endpoints := flag.String("endpoints", "", "comma-separated host:port list, one per validator (roster order)")
	manifestOut := flag.String("manifest-out", "config/testnet.json", "path to write the public manifest")
	secretsDir := flag.String("secrets-dir", "../deploy-bundles", "dir (OUTSIDE the repo) for private keys + genesis seed + sim env")
	keyPrefix := flag.String("key-prefix", "val", "filename prefix for the per-node key files")
	scheme := flag.String("scheme", "http", "URL scheme for roster URLs")
	genesisSeedHex := flag.String("genesis-seed", "", "optional 32-byte hex seed to reproduce a fixed genesis (default: fresh)")
	genesisUnixMs := flag.Int64("genesis-unix-ms", 0, "optional fixed genesis timestamp ms (default: now)")
	supply := flag.Uint64("supply-units", 1_000_000_000_000_000, "genesis supply units (1e9 Anos @ 1e6 units)")

	// Consensus timing/economics — defaults mirror the proven short TEST values. (network_id is
	// COMPUTED from the canonical manifest below, not a flag — P7.2.)
	epochMs := flag.Int64("epoch-ms", 2000, "epoch duration in ms")
	timelocked := flag.Uint64("timelocked-delay-epochs", 6, "")
	guardianWin := flag.Uint64("guardian-active-window-epochs", 20, "")
	lock1mo := flag.Uint64("stake-lock-1mo-epochs", 4, "")
	lock1yr := flag.Uint64("stake-lock-1yr-epochs", 8, "")
	guarded := flag.Uint64("guarded-delay-epochs", 8, "")
	vault := flag.Uint64("vault-delay-epochs", 12, "")
	attestorM := flag.Uint64("attestor-quorum-m", 2, "")
	escrowDelay := flag.Uint64("escrow-attestation-delay-epochs", 6, "")
	breakglass := flag.Uint64("breakglass-extra-epochs", 5, "")
	flag.Parse()

	eps := splitTrim(*endpoints)
	if len(eps) == 0 {
		log.Fatal("-endpoints is required (comma-separated host:port)")
	}
	if err := os.MkdirAll(*secretsDir, 0o700); err != nil {
		log.Fatal(err)
	}
	if dir := filepath.Dir(*manifestOut); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatal(err)
		}
	}

	// One fresh P-256 consensus key per node → key files (secret) + roster pubkeys (public).
	var roster []config.Node
	var mapping strings.Builder
	fmt.Fprintf(&mapping, "# key file -> endpoint -> consensus pubkey  (copy key N to the VM at endpoint N)\n")
	for i, ep := range eps {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		var d [32]byte
		priv.D.FillBytes(d[:])
		keyName := fmt.Sprintf("%s%d.key", *keyPrefix, i+1)
		keyPath := filepath.Join(*secretsDir, keyName)
		if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(d[:])), 0o600); err != nil {
			log.Fatal(err)
		}
		comp := crypto.CompressP256PublicKey(&priv.PublicKey)
		pubHex := hex.EncodeToString(comp[:])
		url := fmt.Sprintf("%s://%s", *scheme, ep)
		roster = append(roster, config.Node{Pubkey: pubHex, URL: url})
		fmt.Fprintf(&mapping, "%s\t%s\t%s\n", keyName, url, pubHex)
	}

	// Genesis hybrid keypair — fresh, or reproduced from a provided seed.
	var seed [32]byte
	if *genesisSeedHex != "" {
		b, err := hex.DecodeString(strings.TrimSpace(*genesisSeedHex))
		if err != nil || len(b) != 32 {
			log.Fatal("-genesis-seed must be 32-byte hex")
		}
		copy(seed[:], b)
	} else if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		log.Fatal(err)
	}
	_, genPub := crypto.GenerateHybridKeyFromSeed(seed)
	genID := crypto.BaseAccountID(crypto.AccountTypeByteForClass(pb.AccountClass_ACCOUNT_CLASS_SPENDING), genPub.Encode())

	unixMs := *genesisUnixMs
	if unixMs == 0 {
		unixMs = time.Now().UnixMilli()
	}

	fundHex := strings.Repeat("ff", 32)
	m := config.Manifest{
		Version:         config.SupportedVersion,
		ProtocolVersion: config.SupportedProtocolVersion,
		FundAccountHex:  fundHex,
		Timing: config.Timing{
			EpochMs:                      *epochMs,
			TimelockedDelayEpochs:        *timelocked,
			GuardianActiveWindowEpochs:   *guardianWin,
			StakeLock1moEpochs:           *lock1mo,
			StakeLock1yrEpochs:           *lock1yr,
			GuardedDelayEpochs:           *guarded,
			VaultDelayEpochs:             *vault,
			AttestorQuorumM:              *attestorM,
			EscrowAttestationDelayEpochs: *escrowDelay,
			BreakglassExtraEpochs:        *breakglass,
		},
		// Canonical production economics + consensus tuning (network-invariant; matches the core
		// client-side consts so a sim's fee matches a validator's).
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
			UnixMs:        unixMs,
			SupplyUnits:   *supply,
		},
		Roster: roster,
	}
	if err := m.Validate(); err != nil {
		log.Fatalf("generated manifest failed validation: %v", err)
	}
	// Content-address the manifest so the shipped config carries its network_id (a tripwire against a
	// later hand-edit that forgets to recompute it).
	id, err := config.ComputeNetworkID(&m)
	if err != nil {
		log.Fatalf("compute network_id: %v", err)
	}
	m.NetworkID = id

	out, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(*manifestOut, out, 0o644); err != nil {
		log.Fatal(err)
	}

	// Secrets bundle (OUTSIDE the repo): genesis seed + a self-contained sim env + the mapping.
	seedHex := hex.EncodeToString(seed[:])
	simEnv := buildSimEnv(&m, seedHex)
	writeSecret(filepath.Join(*secretsDir, "sim.env"), simEnv)
	writeSecret(filepath.Join(*secretsDir, "genesis-seed.hex"), seedHex+"\n")
	writeSecret(filepath.Join(*secretsDir, "MAPPING.txt"), mapping.String())

	fmt.Printf("wrote manifest: %s (%d validators)\n", *manifestOut, len(roster))
	fmt.Printf("wrote secrets:  %s/ (%s1..%d.key, sim.env, genesis-seed.hex, MAPPING.txt)\n", *secretsDir, *keyPrefix, len(roster))
	fmt.Printf("GENESIS_HEX=%s\n", m.Genesis.Hex)
	fmt.Printf("GENESIS_UNIX_MS=%d  (fixed — reproduce with -genesis-seed <hex> -genesis-unix-ms %d)\n", unixMs, unixMs)
}

func buildSimEnv(m *config.Manifest, seedHex string) string {
	kv := [][2]string{
		{"VALIDATOR_URL_LIST", m.URLList()},
		{"GENESIS_SEED_HEX", seedHex},
		{"GENESIS_HEX", m.Genesis.Hex},
		{"FUND_ACCOUNT_HEX", m.FundAccountHex},
		{"GENESIS_UNIX_MS", fmt.Sprintf("%d", m.Genesis.UnixMs)},
		{"GENESIS_SUPPLY_UNITS", fmt.Sprintf("%d", m.Genesis.SupplyUnits)},
		{"EPOCH_MS", fmt.Sprintf("%d", m.Timing.EpochMs)},
		{"TIMELOCKED_DELAY_EPOCHS", fmt.Sprintf("%d", m.Timing.TimelockedDelayEpochs)},
		{"GUARDIAN_ACTIVE_WINDOW_EPOCHS", fmt.Sprintf("%d", m.Timing.GuardianActiveWindowEpochs)},
		{"STAKE_LOCK_1MO_EPOCHS", fmt.Sprintf("%d", m.Timing.StakeLock1moEpochs)},
		{"STAKE_LOCK_1YR_EPOCHS", fmt.Sprintf("%d", m.Timing.StakeLock1yrEpochs)},
		{"GUARDED_DELAY_EPOCHS", fmt.Sprintf("%d", m.Timing.GuardedDelayEpochs)},
		{"VAULT_DELAY_EPOCHS", fmt.Sprintf("%d", m.Timing.VaultDelayEpochs)},
		{"ATTESTOR_QUORUM_M", fmt.Sprintf("%d", m.Timing.AttestorQuorumM)},
		{"ESCROW_ATTESTATION_DELAY_EPOCHS", fmt.Sprintf("%d", m.Timing.EscrowAttestationDelayEpochs)},
		{"BREAKGLASS_EXTRA_EPOCHS", fmt.Sprintf("%d", m.Timing.BreakglassExtraEpochs)},
	}
	var b strings.Builder
	b.WriteString("# Anos TEST sim env — SECRET (holds GENESIS_SEED_HEX). Never commit. Source before running sims:\n")
	b.WriteString("#   source sim.env && go run ./cmd/simulators/<sim>\n")
	for _, p := range kv {
		fmt.Fprintf(&b, "export %s=%s\n", p[0], p[1])
	}
	return b.String()
}

func writeSecret(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		log.Fatal(err)
	}
}

func splitTrim(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
