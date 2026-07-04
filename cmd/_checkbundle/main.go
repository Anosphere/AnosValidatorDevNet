// Command _checkbundle cryptographically verifies the deploy bundle: every valN.key in the
// secrets dir must derive the compressed consensus pubkey of exactly one roster entry, and the
// roster must be fully covered. Underscore-prefixed so `go build ./...` ignores it. Throwaway.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"anos/internal/config"
	"anos/internal/crypto"
)

func main() {
	manifestPath := "config/testnet.json"
	secretsDir := "../deploy-bundles"
	if len(os.Args) > 1 {
		manifestPath = os.Args[1]
	}
	if len(os.Args) > 2 {
		secretsDir = os.Args[2]
	}
	m, err := config.Load(manifestPath)
	if err != nil {
		fmt.Println("MANIFEST LOAD FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("manifest:", manifestPath)
	fmt.Println("network_id (recomputed+validated):", m.NetworkID)
	fmt.Println("protocol_version:", m.ProtocolVersion, " schema version:", m.Version)
	fmt.Println("genesis.unix_ms:", m.Genesis.UnixMs)
	fmt.Println("roster size:", len(m.Roster))
	fmt.Println()

	// pubkey -> roster url
	rosterByPub := map[string]string{}
	for _, n := range m.Roster {
		rosterByPub[n.Pubkey] = n.URL
	}

	files, _ := filepath.Glob(filepath.Join(secretsDir, "val*.key"))
	sort.Strings(files)
	matched := map[string]bool{}
	allOK := true
	for _, f := range files {
		priv, err := crypto.LoadP256PrivateKeyFromFile(f)
		if err != nil {
			fmt.Printf("%-28s LOAD FAILED: %v\n", f, err)
			allOK = false
			continue
		}
		comp := crypto.CompressP256PublicKey(&priv.PublicKey)
		pub := hex.EncodeToString(comp[:])
		url, ok := rosterByPub[pub]
		if !ok {
			fmt.Printf("%-28s pub=%s  ** NOT IN ROSTER **\n", filepath.Base(f), pub)
			allOK = false
			continue
		}
		matched[pub] = true
		fmt.Printf("%-12s -> %-26s pub=%s  OK\n", filepath.Base(f), url, pub)
	}
	fmt.Println()
	for _, n := range m.Roster {
		if !matched[n.Pubkey] {
			fmt.Printf("roster entry %s (%s) has NO key file\n", n.URL, n.Pubkey)
			allOK = false
		}
	}
	if allOK && len(matched) == len(m.Roster) {
		fmt.Printf("RESULT: ALL %d ROSTER ENTRIES HAVE A MATCHING KEY. BUNDLE IS COMPLETE.\n", len(m.Roster))
	} else {
		fmt.Println("RESULT: BUNDLE PROBLEM (see above)")
		os.Exit(2)
	}
}
