package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"anos/internal/config"
	"anos/internal/crypto"
)

// loadManifestIntoEnv reads a network manifest and populates the SAME environment
// variables main()'s (tested) env path already reads. It deliberately parses nothing
// itself beyond the manifest file: the downstream EngineConfig is therefore byte-identical
// to an env boot with the equivalent values. Network-wide fields are authoritative (they
// overwrite any env of the same name — that is the point: one source of truth, no
// fork-on-a-forgotten-var). Per-node fields (PEERS, PORT) are DERIVED from the roster by
// locating this node via its consensus key; an explicit PORT/-port still wins.
func loadManifestIntoEnv(path string) error {
	m, err := config.Load(path)
	if err != nil {
		return err
	}

	// Network-wide, consensus-critical — authoritative (overwrite env).
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
		return fmt.Errorf("VALIDATOR_KEY_PATH (or -key) is required to locate this node in the manifest roster")
	}
	priv, err := crypto.LoadP256PrivateKeyFromFile(keyPath)
	if err != nil {
		return fmt.Errorf("load validator key %q: %w", keyPath, err)
	}
	selfID := crypto.CompressP256PublicKey(&priv.PublicKey)
	selfHex := hex.EncodeToString(selfID[:])
	self, ok := m.Self(selfHex)
	if !ok {
		return fmt.Errorf("this node's consensus key (%s) is not in the manifest roster", selfHex)
	}

	// PEERS = every other roster URL. Always derived (never trust a hand-set PEERS here).
	setenv("PEERS", strings.Join(m.PeersExcluding(selfHex), ","))

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
	return nil
}
