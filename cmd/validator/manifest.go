package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"anos/internal/config"
	"anos/internal/crypto"
)

// loadManifest reads, validates, and content-addresses a network manifest, populates the SAME
// environment variables main()'s (tested) env path already reads for the timing/genesis/fund/
// validator-set fields, and RETURNS the parsed manifest so main() can read the P7.2 scalars that
// are NOT on the env bridge (economics, quorum/scan-cap, network_id, protocol_version) directly off
// the typed struct. The env bridge keeps the downstream parsing byte-identical to a historical env
// boot; the struct is the single source of truth (network_id hashes it). Network-wide fields are
// authoritative (they overwrite any env of the same name — one source of truth, no fork on a
// forgotten var); per-node fields (PEERS, PORT) are DERIVED from the roster by locating this node
// via its consensus key. -manifest is MANDATORY (P7.2): a node with no manifest has no network_id
// and cannot participate.
func loadManifest(path string) (*config.Manifest, error) {
	m, err := config.Load(path)
	if err != nil {
		return nil, err
	}

	// Network-wide, consensus-critical — authoritative (overwrite env). Only the fields main()'s
	// env path parses are bridged here; the economics/consensus/identity scalars are read off the
	// returned struct.
	setenv := func(k, v string) { _ = os.Setenv(k, v) }
	setenv("EPOCH_MS", strconv.FormatInt(m.Timing.EpochMs, 10))
	setenv("GENESIS_UNIX_MS", strconv.FormatInt(m.Genesis.UnixMs, 10))
	setenv("GENESIS_SUPPLY_UNITS", strconv.FormatUint(m.Genesis.SupplyUnits, 10))
	setenv("FUND_ACCOUNT_HEX", strings.TrimSpace(m.FundAccountHex))
	setenv("TIMELOCKED_DELAY_EPOCHS", strconv.FormatUint(m.Timing.TimelockedDelayEpochs, 10))
	setenv("GUARDIAN_ACTIVE_WINDOW_EPOCHS", strconv.FormatUint(m.Timing.GuardianActiveWindowEpochs, 10))
	setenv("STAKE_LOCK_1MO_EPOCHS", strconv.FormatUint(m.Timing.StakeLock1moEpochs, 10))
	setenv("STAKE_LOCK_1YR_EPOCHS", strconv.FormatUint(m.Timing.StakeLock1yrEpochs, 10))
	setenv("GUARDED_DELAY_EPOCHS", strconv.FormatUint(m.Timing.GuardedDelayEpochs, 10))
	setenv("VAULT_DELAY_EPOCHS", strconv.FormatUint(m.Timing.VaultDelayEpochs, 10))
	setenv("ATTESTOR_QUORUM_M", strconv.FormatUint(m.Timing.AttestorQuorumM, 10))
	setenv("ESCROW_ATTESTATION_DELAY_EPOCHS", strconv.FormatUint(m.Timing.EscrowAttestationDelayEpochs, 10))
	setenv("BREAKGLASS_EXTRA_EPOCHS", strconv.FormatUint(m.Timing.BreakglassExtraEpochs, 10))
	setenv("GENESIS_HEX", strings.TrimSpace(m.Genesis.Hex))
	setenv("GENESIS_AUTH_PUBKEY_HEX", strings.TrimSpace(m.Genesis.AuthPubkeyHex))
	setenv("VALIDATOR_SET_PUBKEYS", m.ValidatorSetCSV())

	// Locate THIS node in the roster by its consensus key so PEERS/PORT can be derived.
	keyPath := strings.TrimSpace(os.Getenv("VALIDATOR_KEY_PATH"))
	if keyPath == "" {
		return nil, fmt.Errorf("VALIDATOR_KEY_PATH (or -key) is required to locate this node in the manifest roster")
	}
	priv, err := crypto.LoadP256PrivateKeyFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load validator key %q: %w", keyPath, err)
	}
	selfID := crypto.CompressP256PublicKey(&priv.PublicKey)
	selfHex := hex.EncodeToString(selfID[:])
	self, ok := m.Self(selfHex)

	// PEERS = every other roster URL (all of them for a non-roster node — PeersExcluding excludes
	// nothing then). Always derived (never trust a hand-set PEERS here).
	setenv("PEERS", strings.Join(m.PeersExcluding(selfHex), ","))

	if !ok {
		// P7.4 NON-FOUNDER boot — the open-net join path. A key outside the roster is no longer a
		// refusal: the node shares the identical manifest (same network_id), dials the full roster,
		// resyncs from it, and becomes a voting member the epoch the post-flip Fund banker set
		// includes its key (an operator stakes Banker carrying this consensus key + endpoint).
		// Pre-flip it can only observe. The roster gives it no URL, so the port must be explicit.
		if strings.TrimSpace(os.Getenv("PORT")) == "" {
			return nil, fmt.Errorf("consensus key %s is not in the manifest roster: booting as a "+
				"non-founder requires an explicit -port (the roster cannot derive one)", selfHex)
		}
		log.Printf("[boot] consensus key %s is NOT in the manifest roster — booting as a NON-FOUNDER "+
			"node: dialing the full roster, resync-follows, becomes a voting member once the post-flip "+
			"Fund banker set includes this key", selfHex)
		return m, nil
	}

	// PORT from this node's roster URL, unless an explicit PORT/-port already set it.
	if strings.TrimSpace(os.Getenv("PORT")) == "" {
		if p := config.PortFor(self); p != "" {
			setenv("PORT", p)
		}
	}

	// Optional post-flip Banker identity, if the roster pins one and env didn't override.
	if strings.TrimSpace(os.Getenv("VALIDATOR_IDENTITY_HEX")) == "" && strings.TrimSpace(self.Identity) != "" {
		setenv("VALIDATOR_IDENTITY_HEX", strings.TrimSpace(self.Identity))
	}
	return m, nil
}
