# Anos validator — dev/test network

> ## ⚠️ DEV / TEST NETWORK
> This repo runs a **devnet**: short (seconds‑long) epoch/unlock windows, a fixed genesis, and admin
> endpoints that trust the local machine. The manifest is content‑addressed and nodes refuse to
> boot/peer on a mismatch, and the wire is hardened (P7), but cold‑sync checkpointing is still
> deferred. **Don't put real value on it, its keys, or its genesis.**

Anos is a post‑quantum‑hybrid (ML‑DSA‑87 + P‑256) account chain with a Fund‑based staking/role
registry. This README is the map; **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) is the full deploy,
release, and update guide.**

---

## 1. What's here

```
config/testnet.json        # the network manifest — PUBLIC, identical on every node (see §3)
cmd/validator              # the validator (serves consensus + sync + RPC + debug on one port)
cmd/simulators/*           # ~25 traffic generators ("sims") you run from your workstation
cmd/_gentestnet            # regenerates config/testnet.json + the secrets bundle (see §7)
cmd/_livesetup             # the localhost-3-node generator (used by run_livetest.sh)
scripts/run-validator.sh   # build-from-source launcher (dev convenience)
docs/DEPLOYMENT.md         # ★ how to publish releases, install, and update validators
.github/workflows/release.yml  # tag push -> cross-compiled release with binary + manifest + checksums
internal/…                 # engine, crypto, proto, config, simkit
```

## 2. Deploying a validator

Validators run a **prebuilt binary from a GitHub Release** — no toolchain, no build. The whole flow
(publishing a release, the operator install, firewall, verification, and updates) is in
**[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**. In brief, each operator:

```sh
mkdir -p ~/anos && cd ~/anos
curl -L -o validator    https://github.com/Anosphere/AnosValidatorDevNet/releases/download/v0.1.0/validator-linux-amd64
curl -L -o testnet.json https://github.com/Anosphere/AnosValidatorDevNet/releases/download/v0.1.0/testnet.json
chmod +x validator
# + drop in the private anos.key the maintainer sent you, then install as a systemd service
./validator -manifest testnet.json -key anos.key -db validator.db
```

The binary + manifest are public and come from the release; the **key is the only private hand‑off.**
Three things people miss (all covered in the guide): the VM's external IP must be **static**, the GCP
**firewall** must open tcp:30303 to the other validators, and `latest_epoch` stays **frozen until a
quorum is up** — that's normal, not a fault.

## 3. The manifest (`config/testnet.json`)

One public file, byte‑identical on every node. A node **refuses to boot** if it can't parse/validate
it, and **content‑addresses** it: `network_id` is a SHA‑256 over the whole manifest, carried on the
wire (`X-Anos-Network-Id`) so a peer on a different manifest is rejected (HTTP 421) rather than
silently forking.

| Section | Field | Meaning |
|---|---|---|
| root | `version` | manifest **schema** version (`2`); a node refuses to boot on any other |
| root | `protocol_version` | consensus **ruleset** version (`1`); a node refuses to boot/peer unless it matches |
| root | `network_id` | SHA‑256 over the manifest; recomputed on boot and refused if the file's value disagrees |
| root | `fund_account_hex` | the reserved keyless Fund account id (`ff…ff`) |
| `timing` | `epoch_ms`, `*_epochs`, `attestor_quorum_m` | **consensus‑critical** — the manifest guarantees they're byte‑identical everywhere |
| `economics` | fees, stake floors, guardian params | consensus‑critical scalars, read straight off the manifest |
| `consensus` | `quorum_percent`, `finalization_quorum_percent`, `max_candidate_scan_per_slot` | the quorum thresholds (80% / 60% here) |
| `genesis` | `hex`, `auth_pubkey_hex`, `unix_ms`, `supply_units` | the genesis account, its hybrid auth pubkey, the fixed epoch anchor, total supply |
| `roster[]` | `pubkey`, `url` | each validator's compressed P‑256 consensus key + base URL. `PEERS`, the validator set, and each node's port are derived from this |

A node finds **itself** in the roster by matching its loaded key's consensus pubkey to a
`roster[].pubkey`, then serves on that entry's port and treats the other URLs as peers — so every VM
runs the same command apart from *which key it loads*. Changing any `timing`/`economics`/`genesis`/
`roster` value changes `network_id` → a different, incompatible network (see the guide's *breaking
update* section).

## 4. Building & testing locally (from source)

You only need Go to **develop**; operators use the release binary. Requires **Go ≥ 1.24** (see
`go.mod`).

```sh
go build ./cmd/validator                 # or: GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ...
go test ./...
./run_livetest.sh                        # workspace-root: fresh localhost 3-node lifecycle + verifying resync
```

## 5. Cutting a release

Publishing (and updating) is a **one‑command tag push** — the Actions workflow cross‑compiles
amd64+arm64, attaches the manifest + `SHA256SUMS`, and creates the release:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

Full detail (including the manual `gh release create` alternative and the update workflow) is in
**[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) → Part A / Part C**.

## 6. Run the sims (from your workstation)

Sims fund their own accounts from genesis, stake what they need, and self‑pace on epochs. They need
the **secret** `sim.env` (holds `GENESIS_SEED_HEX` + `VALIDATOR_URL_LIST`) produced in §7:

```sh
source ../deploy-bundles/sim.env          # sets VALIDATOR_URL_LIST + genesis seed + timings
go run ./cmd/simulators/sim-timelocked-transfer
go run ./cmd/simulators/sim-escrow
go run ./cmd/simulators/sim-guarded-vault-release
go run ./cmd/simulators/sim-breakglass
```
Useful starters: `sim-genesis-distribute`, `sim-fund-stakes`, `sim-fund-send`,
`sim-timelocked-transfer`, `sim-escrow`, `sim-guarded-vault-release`, `sim-breakglass`,
`sim-banker-join`, `sim-list-accounts`. (`ls cmd/simulators` for the full set.)

## 7. Regenerating the config (how `testnet.json` was made)

`cmd/_gentestnet` mints a fresh hybrid genesis + one P‑256 key per node and writes the **public**
manifest into the repo plus a **secret** bundle *outside* it (`../deploy-bundles/`, never a git dir):

```sh
go run ./cmd/_gentestnet \
  -endpoints 35.234.70.37:30303,34.159.203.177:30303,34.107.74.229:30303,35.242.233.86:30303,35.234.117.219:30303 \
  -manifest-out config/testnet.json \
  -secrets-dir ../deploy-bundles
```
Outputs: `config/testnet.json` (commit this) and, in `../deploy-bundles/` (**never commit**):
`val1..5.key` (one per VM), `sim.env`, `genesis-seed.hex`, `MAPPING.txt`. **Genesis is static and this
machine alone holds the seed** — no VM ever receives `GENESIS_SEED_HEX`. Reproduce the same genesis
with `-genesis-seed $(cat ../deploy-bundles/genesis-seed.hex) -genesis-unix-ms <the value>`.

## 8. Inspecting live state (debug endpoints)

All JSON, all `GET`. **`/debug/*` is loopback‑only** — SSH into a VM and query `localhost`:

```sh
curl -s localhost:30303/debug/accounts/heads | jq .
```

| Endpoint | Shows |
|---|---|
| `/debug/accounts/heads` | every account head: balance, seq, class, transfer/escrow metadata |
| `/debug/fund/stakes` | the stake table: deposit txid, staker, amount, tier, status |
| `/debug/fund/roles` | per‑identity `is_banker` / `is_attestor` / `guardian_weight` |
| `/debug/fund/guardians` | Guardian activity projection (Fund‑SEND quorum denominator) |
| `/debug/fund/bankers` | Fund‑derived validator set (identity → consensus key + endpoint) |
| `/debug/consensus/flip` | list→Fund flip status (`flip_epoch`, `flipped`, set sizes) |

Public (any source, subject to firewall): `/health` (JSON liveness), and the client RPC `/submit`,
`/account`, `/receivables` (protobuf `POST`). Peer/sync (`/peer/*`, `/sync/*`) are internal and
firewalled to the roster. Fleet agreement check, run **on** a VM:
```sh
for ip in 127.0.0.1; do curl -sf "http://$ip:30303/debug/accounts/heads" | jq -S . | shasum -a 256; done
```
(compare the hash across all five VMs — they should match).

## 9. Resync

Consensus state is derived, not trusted. Stop a validator, delete its DB, restart — it re‑derives the
whole chain from peers via a verifying walk (re‑checking a quorum at every validator‑set change and the
tip) and converges to byte‑identical heads. That's what `./run_livetest.sh` asserts, and why a rolling
binary update (guide §C3) is safe.
