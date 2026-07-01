// sim-print-keypairs generates hybrid (ML-DSA-87 + P-256) keypairs and prints the
// values needed to wire up the env files after the P1.2 post-quantum cutover.
//
// The model changed: an account is no longer "the ed25519 pubkey is the id". An
// account is a hybrid keypair pinned by a 32-byte SEED; its 32-byte account-id is
// HASH-DERIVED from the auth pubkey (keys-spec §6). So this tool prints, per
// account: the auth seed (the secret the sim signs with), the breakglass seed, the
// derived 32-byte account-id, and the 2625-byte auth pubkey hex (what validators
// cache to verify signatures).
//
// The headline use is the GENESIS account. Validators need GENESIS_HEX (the id) +
// GENESIS_AUTH_PUBKEY_HEX (the cached pubkey); the genesis-signing sim needs
// GENESIS_SEED_HEX. This tool emits all three as copy-paste env blocks.
//
// Flags:
//
//	-genesis-seed <hex>   reuse an existing 32-byte genesis seed (default: random)
//	-users <n>            also print N random user accounts (default 0)
package main

import (
	"encoding/hex"
	"flag"
	"fmt"

	"anos/internal/simkit"
	pb "anos/internal/proto"
)

func main() {
	genesisSeedHex := flag.String("genesis-seed", "", "32-byte hex genesis auth seed (default: random)")
	nUsers := flag.Int("users", 0, "number of random user accounts to also print")
	flag.Parse()

	var genSeed [32]byte
	if *genesisSeedHex != "" {
		genSeed = simkit.MustSeedFromHex(*genesisSeedHex)
	} else {
		genSeed = simkit.RandSeed()
	}
	// The genesis account is SPENDING (matches ensureGenesisOnBoot). Its breakglass
	// seed is irrelevant on-chain (genesis is seeded directly, never opens a block),
	// so we derive a deterministic one from the auth seed just to have a value.
	bgSeed := derive(genSeed, "ANOS-genesis-breakglass")
	genesis := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, genSeed, bgSeed)

	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println(" GENESIS ACCOUNT (hybrid)")
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("# --- add/replace in .env.a / .env.b / .env.c (validators) ---")
	fmt.Printf("GENESIS_HEX=%s\n", hex.EncodeToString(genesis.IDBytes()))
	fmt.Printf("GENESIS_AUTH_PUBKEY_HEX=%s\n", genesis.AuthPubKeyHex())
	fmt.Println()
	fmt.Println("# --- add/replace in .env.sim (genesis signer) ---")
	fmt.Printf("GENESIS_SEED_HEX=%s\n", hex.EncodeToString(genSeed[:]))
	fmt.Printf("GENESIS_HEX=%s\n", hex.EncodeToString(genesis.IDBytes()))
	fmt.Println()
	fmt.Println("# (FUND_ACCOUNT_HEX and all consensus params are unchanged.)")

	for i := 0; i < *nUsers; i++ {
		authSeed := simkit.RandSeed()
		ubg := simkit.RandSeed()
		u := simkit.NewAccount(pb.AccountClass_ACCOUNT_CLASS_SPENDING, authSeed, ubg)
		fmt.Println()
		fmt.Printf("──── USER %d (SPENDING) ────\n", i+1)
		fmt.Printf("AUTH_SEED       = %s\n", hex.EncodeToString(authSeed[:]))
		fmt.Printf("BREAKGLASS_SEED = %s\n", hex.EncodeToString(ubg[:]))
		fmt.Printf("ACCOUNT_ID      = %s\n", hex.EncodeToString(u.IDBytes()))
	}
}

// derive produces a deterministic secondary seed from a primary seed + a label.
func derive(seed [32]byte, label string) [32]byte {
	// Reuse simkit's seed→hybrid derivation indirectly is overkill; a labeled copy
	// is enough here since the genesis breakglass key is never used on-chain.
	var out [32]byte
	copy(out[:], seed[:])
	for i := 0; i < len(label) && i < len(out); i++ {
		out[i] ^= label[i]
	}
	return out
}
