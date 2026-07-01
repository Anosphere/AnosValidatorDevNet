# Anos validator — TEST network

> ## ⚠️ TEST NETWORK ONLY
> This repo ships a **throwaway test network**: short (seconds-long) epoch/unlock windows,
> unauthenticated debug/RPC endpoints, and validator keys generated for play. **Do not use
> it, its keys, or its genesis for anything with real value.** Production hardening (a
> content-addressed manifest that refuses to boot on mismatch, endpoint auth, cold-sync
> checkpoints) is the separate P7 track.

Anos is a post-quantum-hybrid (ML-DSA-87 + P-256) account chain with a Fund-based staking/role
registry. This README covers building it, standing up the 5-validator GCP test network from the
committed manifest, running the simulators against it, and inspecting live state.

---

## 1. What's here

```
config/testnet.json     # the network manifest — PUBLIC, identical on every node (see §3)
cmd/validator           # the validator binary (serves consensus + sync + RPC + debug on one port)
cmd/simulators/*        # ~25 traffic generators ("sims") you run from your workstation
cmd/_gentestnet         # generates config/testnet.json + the secrets bundle (see §7)
cmd/_livesetup          # the original localhost-3-node generator (used by run_livetest.sh)
scripts/run-validator.sh# one-command validator launcher for a VM
internal/…              # engine, crypto, proto, config, simkit
```

The validator reads **all** of its configuration from environment variables. A manifest
(`-manifest`) is simply a committed file that *populates those same variables* and derives each
node's peer list + port from the roster — so a manifest boot is byte-identical to an env boot,
and a single forgotten variable can't silently fork a node.

## 2. Prerequisites

- **Go ≥ 1.24** on each validator VM and on your workstation (`go version`). If Go isn't on
  `PATH`, pass `GO=/path/to/go` to the scripts.
- **Workstation tools for the sims / checks:** `jq`, `curl`, `shasum` (macOS) or `sha256sum`.
- **5 VMs** (this test net: Google Cloud Compute Engine) with a shared open TCP port between them
  and from your workstation (see §5).

## 3. The manifest (`config/testnet.json`)

One public file, identical on every node. Fields:

| Section | Field | Meaning |
|---|---|---|
| root | `version` | manifest schema version (`1`); a node refuses to boot on any other |
| root | `network_id` | empty here; **P7** fills it with a content hash and refuses to join a peer whose id differs |
| root | `fund_account_hex` | the reserved keyless Fund account id (`ff…ff`) |
| `timing` | `epoch_ms`, `*_epochs`, `attestor_quorum_m` | **consensus-critical** — must be byte-identical on every node; the manifest is what guarantees that |
| `genesis` | `hex`, `auth_pubkey_hex`, `unix_ms`, `supply_units` | the genesis account (seeded at boot), its hybrid auth pubkey, the fixed epoch anchor, and total supply |
| `roster[]` | `pubkey`, `url` | each validator's compressed P-256 consensus key + the base URL peers reach it at. `PEERS`, the validator set, and (per node) the listen port are all derived from this |

A node finds **itself** in the roster by matching its loaded private key's consensus pubkey to a
`roster[].pubkey`; it then serves on that entry's port and treats every other roster URL as a peer.
So every VM runs the same command apart from *which key file* it loads.

> **These are short TEST timings** (2 s epochs; unlock windows of seconds). They're the values
> proven by the live harness. Changing any `timing`/`genesis` value produces an *incompatible*
> network — every node must use the same manifest. To retune, edit the manifest (or regenerate,
> §7) and redeploy to all nodes.

## 4. Deploy a validator on a VM

1. **Get the code + manifest** onto the VM (the manifest is public, so it travels in git):
   ```sh
   git clone <this-repo> anos && cd anos
   ```
2. **Get this node's private key** onto the VM out-of-band — **never via git**. From your
   workstation, where the keys were generated (§7):
   ```sh
   scp deploy-bundles/val3.key   user@<vm3-ip>:~/anos.key   # val<N> → the Nth roster VM
   ```
   The key ↔ VM mapping is in `deploy-bundles/MAPPING.txt`.
3. **Run it:**
   ```sh
   ./scripts/run-validator.sh -k ~/anos.key
   # equivalently: go build -o bin/validator ./cmd/validator
   #               ./bin/validator -manifest config/testnet.json -key ~/anos.key -db ~/validator.db
   ```
   It prints `Validator Public Key: …` (must match this VM's roster entry) and begins producing
   epochs. Repeat on all 5 VMs.

**Keep it running (optional systemd unit):**
```ini
# /etc/systemd/system/anos-validator.service
[Unit]
Description=Anos test validator
After=network-online.target
[Service]
User=anos
WorkingDirectory=/home/anos/anos
ExecStart=/home/anos/anos/scripts/run-validator.sh -k /home/anos/anos.key -d /home/anos/validator.db
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

## 5. GCP firewall

The validator serves peer gossip + sync + RPC + debug on the **one** manifest port (this net:
`30303`). Open it **only** to the other validators and your workstation — the debug/RPC endpoints
are unauthenticated on a test net.

```sh
# allow the 5 validators + your workstation to reach tcp:30303
gcloud compute firewall-rules create anos-testnet \
  --direction=INGRESS --action=ALLOW --rules=tcp:30303 \
  --source-ranges=35.234.70.37/32,34.159.203.177/32,34.107.74.229/32,35.242.233.86/32,35.234.117.219/32,<YOUR_WORKSTATION_IP>/32
```
Roster URLs use each VM's **external** IP (that's how peers reach one another). The node binds
`0.0.0.0:30303` locally.

## 6. Run the sims (from your workstation)

Sims fund their own accounts from genesis, stake what they need, and self-pace on epochs. They
need the **secret** `sim.env` (holds `GENESIS_SEED_HEX` + `VALIDATOR_URL_LIST`) produced in §7:

```sh
source ../deploy-bundles/sim.env          # sets VALIDATOR_URL_LIST + genesis seed + timings
go run ./cmd/simulators/sim-timelocked-transfer
go run ./cmd/simulators/sim-escrow
go run ./cmd/simulators/sim-guarded-vault-release
go run ./cmd/simulators/sim-breakglass
```
Useful ones to start with: `sim-genesis-distribute`, `sim-fund-stakes`, `sim-fund-send`,
`sim-timelocked-transfer`, `sim-escrow`, `sim-guarded-vault-release`, `sim-breakglass`,
`sim-banker-join`, `sim-list-accounts`. (`ls cmd/simulators` for the full set.)

## 7. Regenerating the config (how `testnet.json` was made)

`cmd/_gentestnet` mints a fresh hybrid genesis + one P-256 key per node and writes the **public**
manifest into the repo plus a **secret** bundle *outside* the repo (`../deploy-bundles/`, which is
never a git directory):

```sh
go run ./cmd/_gentestnet \
  -endpoints 35.234.70.37:30303,34.159.203.177:30303,34.107.74.229:30303,35.242.233.86:30303,35.234.117.219:30303 \
  -manifest-out config/testnet.json \
  -secrets-dir ../deploy-bundles
```
Outputs: `config/testnet.json` (commit this) and, in `../deploy-bundles/` (**never commit**):
`val1..5.key` (one per VM), `sim.env`, `genesis-seed.hex`, `MAPPING.txt`.

**Genesis is static and this machine alone holds it.** No VM ever receives `GENESIS_SEED_HEX`.
To reproduce the *same* genesis on a later run (e.g. to change only IPs), pass the saved seed +
timestamp: `-genesis-seed $(cat ../deploy-bundles/genesis-seed.hex) -genesis-unix-ms <the value>`.

## 8. Inspecting live state (debug endpoints)

All JSON, all `GET`, on `http://<any-vm>:30303`:

| Endpoint | Shows |
|---|---|
| `/debug/accounts/heads` | every account head: balance, seq, class, transfer/escrow metadata |
| `/debug/fund/stakes` | the stake table: deposit txid, staker, amount, tier, status |
| `/debug/fund/roles` | per-identity `is_banker` / `is_attestor` / `guardian_weight` |
| `/debug/fund/guardians` | Guardian activity projection (Fund-SEND quorum denominator) |
| `/debug/fund/bankers` | Fund-derived validator set (identity → consensus key + endpoint) |
| `/debug/consensus/flip` | list→Fund flip status (`flip_epoch`, `flipped`, set sizes) |

Client RPC (protobuf `POST`): `/submit`, `/account`, `/receivables`. Peer/sync (internal):
`/peer/*`, `/sync/*`.

A quick health/agreement check across the fleet:
```sh
for ip in 35.234.70.37 34.159.203.177 34.107.74.229 35.242.233.86 35.234.117.219; do
  echo -n "$ip heads: "; curl -sf "http://$ip:30303/debug/accounts/heads" | jq -S . | shasum -a 256 | cut -d' ' -f1
done   # all five hashes should match
```

## 9. Resync

Consensus state is derived, not trusted. Stop a validator, delete its DB, and restart it — it
re-derives the entire chain from peers via a verifying walk (re-checking a quorum at every
validator-set change and the tip) and converges to byte-identical head hashes. That's exactly what
the local harness asserts:

```sh
./run_livetest.sh      # workspace-root: fresh localhost 3-node lifecycle + verifying resync
```
