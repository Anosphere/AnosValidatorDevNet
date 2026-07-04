# Anos — Deployment & Release Guide

This guide explains how the Anos devnet/testnet is **published, installed, and updated**. It has two
audiences:

- **You, the maintainer** — you cut releases and hand operators their keys (Part A).
- **The operators** — the people running the 5 (later ~25) validator VMs. Part B is the copy‑paste
  they follow; Part C is how they take an update.

Everything is versioned by a **git tag**. One tag (`v0.1.0`) produces one GitHub Release, and that
release carries the binary *and* the manifest, so a node's code and its network config always match.

---

## The distribution model (read this first)

A running validator needs exactly three things. Two are public and come from GitHub; **only one is a
private hand‑off:**

| piece | what it is | where it comes from | secret? |
|---|---|---|---|
| `validator` | the node program (one static Linux binary) | **GitHub Release** asset | no |
| `testnet.json` | the network manifest (timings, genesis, roster) | **same GitHub Release** asset | no |
| `anos.key` | this VM's private validator key | **you send it privately** | **yes — never in git or a release** |

Because the binary and the manifest are attached to the *same tagged release*, an operator who
downloads `v0.1.0` gets a matched pair. The key is generated once (it already exists in
`deploy-bundles/valN.key`) and delivered out of band.

This is identical for devnet and testnet. The only devnet/testnet difference is who generates the
keys — for now **you** pre‑generate all of them and send each operator theirs.

---

# Part A — Maintainer: publishing a release

## A1. One‑time setup: add the release workflow

The repo ships a GitHub Actions workflow at `.github/workflows/release.yml`. Commit it once and make
sure **Actions is enabled** for the repo (GitHub → the repo → *Settings → Actions → General →* allow
actions). You never touch it again after that.

What it does, automatically, **every time you push a tag that starts with `v`:**

1. checks out the exact tagged commit,
2. cross‑compiles the validator for `linux/amd64` **and** `linux/arm64` (static, `CGO_ENABLED=0`),
3. copies `config/testnet.json` alongside them,
4. writes a `SHA256SUMS` file over all three,
5. creates the GitHub Release for that tag and attaches all four files.

The build runs on GitHub's own runners, so **you don't need Go or any credentials on your machine** —
you only need to be able to push a tag. That's the whole point of the Actions route: it works even
though your code‑push credentials and your Go toolchain live on different machines.

## A2. Cut a release

1. Make sure the branch you're tagging has the code **and** the `config/testnet.json` you want
   operators to run. (Push the P7 line and land it on the default branch first.)
2. Tag it and push the tag:
   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. Watch **Actions** run (~1–2 min). When it's green, the release is live at
   `https://github.com/Anosphere/AnosValidatorDevNet/releases/tag/v0.1.0` with four assets:
   `validator-linux-amd64`, `validator-linux-arm64`, `testnet.json`, `SHA256SUMS`.

That's it — publishing (and later, updating) is a **one‑command tag push**.

> **Manual alternative (no CI).** If you'd rather not use Actions, build and upload from a machine
> that has both Go and an authenticated `gh`:
> ```sh
> cd anosValidatorDevNet
> mkdir -p dist
> for a in amd64 arm64; do
>   GOOS=linux GOARCH=$a CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/validator-linux-$a ./cmd/validator
> done
> cp config/testnet.json dist/
> ( cd dist && sha256sum validator-linux-* testnet.json > SHA256SUMS )
> gh release create v0.1.0 dist/* --repo Anosphere/AnosValidatorDevNet \
>   --target <commit-or-branch> --title "Anos devnet v0.1.0" --notes "First devnet release."
> ```

## A3. Send each operator their key

The five keys already exist (generated once, in `deploy-bundles/valN.key`) and each is bound to one
VM. Send each operator **only their own key**, over a private channel (Signal, password manager,
encrypted email — never git, never the release). Which key goes to which VM:

| VM | operator's external IP | key file to send | this VM's consensus pubkey |
|---|---|---|---|
| 1 | `35.234.70.37`   | `deploy-bundles/val1.key` | `02530e653cffc20b82b946acd5235c8b8b4fa546a5b2df5003d041c813daeee3fd` |
| 2 | `34.159.203.177` | `deploy-bundles/val2.key` | `02650fcd9d5b5c741ec30152fe39b07c9a06c7b9ada2d16dc3e60a0d5c797f613b` |
| 3 | `34.107.74.229`  | `deploy-bundles/val3.key` | `03e5474db9b93eea7c194f6926dc03e3bd3d442c1d346c26f74027c816dbf9838d` |
| 4 | `35.242.233.86`  | `deploy-bundles/val4.key` | `03b2b28a04ceafa5ef4a5e4f2f80c47ff60b517f0b2ff68957738b231bacae5eb4` |
| 5 | `35.234.117.219` | `deploy-bundles/val5.key` | `03875c48e0f97875328822c8088191dcba1e030933e8054777730c160d15d89ca6` |

Tell each operator (a) which VM number they are, (b) their release download tag (`v0.1.0`),
(c) to save the key you sent them as `anos.key`, and (d) their VM's **consensus pubkey** (the last
column above, also in Part D) so they can complete verify step B4(a).

## A4. Coordinate the launch

The network only starts finalizing once a **quorum** is up — at least **3 of 5** at the same time for
epochs to advance, **4 of 5** for full conflict resolution. Agree a rough **launch window** so people
start together. Until the quorum is present, each node is healthy but "waiting" (see Part B, *Reading
`/health`*) — that is expected, not a fault.

---

# Part B — Operator: install and run a validator

You'll get from the maintainer: your **VM number**, the **release tag** (e.g. `v0.1.0`), and your
private **`anos.key`**. Do the steps in order. The network id for this network is
`82a4d3bd12d31fa2abb087710f524fc9f8b73e393480fc71cbd8066b53c339f7` — you'll confirm your node reports
exactly that.

## B0. Provision the VM correctly (do this first)

1. **x86‑64 machine + Linux image.** Create the VM with an **x86‑64 (amd64)** machine type (`e2-`,
   `n2-`, `n2d-`, `c3-` families) running **Debian or Ubuntu**. If you deliberately choose an **Arm /
   "Tau T2A" (`t2a-`)** type, download the `arm64` binary instead in B1 — but amd64 is the default and
   what these instructions assume.
2. **Make your external IP static by *promoting* it (not re‑reserving).** Your VM already has its
   assigned IP; make it *static* so a stop/start can't change it. Cloud Console → **VPC network → IP
   addresses → External IP addresses** → find the **row for THIS VM** (Type = *Ephemeral*) → change
   **that row** to **Static / Reserve**. Do **NOT** click the top "Reserve External Static IP Address"
   button — it gives you a *different* address and breaks your node.
3. **Leave the clock on NTP.** Epochs run on a shared wall‑clock; GCP syncs time automatically — don't
   disable it (you'll verify below).

## B1. Download the software  ← this is the core of the new workflow

Because the repo is **public**, the binary and manifest are plain public downloads — no login, no
tools beyond `curl`. A "GitHub Release" is just a page GitHub creates for a version tag, with files
("assets") attached to it. The URL of an asset is always:

```
https://github.com/Anosphere/AnosValidatorDevNet/releases/download/<TAG>/<FILENAME>
```

**Run these on the VM** (substitute the tag you were given for `v0.1.0`):

```sh
mkdir -p ~/anos && cd ~/anos
TAG=v0.1.0        # the release tag the maintainer gave you
BASE="https://github.com/Anosphere/AnosValidatorDevNet/releases/download/$TAG"

# 1) the binary — download under its OWN release name so the checksum can match it.
#    amd64 is the default; on an Arm VM use validator-linux-arm64 in BOTH this line and the mv below.
curl -L -O "$BASE/validator-linux-amd64"

# 2) the network manifest (attached to the SAME release, so it always matches the binary)
curl -L -o testnet.json "$BASE/testnet.json"

# 3) the checksums, then verify what you downloaded is intact
curl -L -O "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing      # must print:  validator-linux-amd64: OK   testnet.json: OK

# 4) ONLY after both say OK, install the binary under its short name
mv validator-linux-amd64 validator && chmod +x validator
```

Notes:
- `curl -L` follows redirects — GitHub sends release assets to a storage host, so `-L` is required;
  without it you'd save a tiny redirect page instead of the file.
- `curl -O` (capital O) keeps the release filename (`validator-linux-amd64`) so it matches the entry in
  `SHA256SUMS` — that's what makes the check actually cover the binary. `--ignore-missing` then just
  skips the *other* architecture's line (the one you didn't download); the two files you did download
  are fully verified. Rename to `validator` only **after** the check passes.
- There is also a **"latest" convenience URL** —
  `https://github.com/Anosphere/AnosValidatorDevNet/releases/latest/download/validator-linux-amd64` —
  which always points at the newest release. Handy day‑to‑day, but when the maintainer asks everyone to
  move to a *specific* version, use the explicit tag so nobody lands on the wrong one.

**Now place your private key.** Save the `anos.key` the maintainer sent you into `~/anos/anos.key`
(e.g. upload it via the Cloud Console SSH **⚙ gear → Upload file**, which drops it in your home
directory, then `mv ~/anos.key ~/anos/`).

## B2. Install as a service

```sh
sudo mkdir -p /opt/anos
sudo cp ~/anos/validator ~/anos/testnet.json ~/anos/anos.key /opt/anos/
sudo chmod +x /opt/anos/validator
sudo chmod 600 /opt/anos/anos.key
```

Create `/etc/systemd/system/anos-validator.service`:

```ini
[Unit]
Description=Anos validator
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/anos/validator -manifest /opt/anos/testnet.json -key /opt/anos/anos.key -db /opt/anos/validator.db
Restart=on-failure
RestartSec=5
User=root
WorkingDirectory=/opt/anos
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Then:
```sh
sudo systemctl daemon-reload
sudo systemctl enable --now anos-validator
```

The port (`30303`) and the peer list are derived automatically from the manifest — every VM runs the
identical command apart from which key it loads.

## B3. Open the firewall (once, in YOUR GCP project)

GCP **blocks all inbound traffic by default**, so this rule is required for peers to reach you. Don't
assume your network is named `default` — read your VM's actual network first (a rule on the wrong
network *succeeds silently and does nothing*):

```sh
NET=$(gcloud compute instances describe <INSTANCE_NAME> --zone <ZONE> \
      --format='value(networkInterfaces[0].network)')
gcloud compute firewall-rules create anos-p2p \
  --project=<YOUR_PROJECT_ID> --network="$NET" \
  --direction=INGRESS --action=ALLOW --rules=tcp:30303 \
  --source-ranges=<THE OTHER FOUR VALIDATOR IPs, comma-separated>
```

Your exact `--source-ranges` (the *other* four IPs) are in **Part D → Per‑VM firewall commands** —
copy the line for your VM number. Outbound is open by default, so no egress rule is needed. (If the
maintainer will run traffic simulators against your node, add their workstation IP too.)

## B4. Verify — two checks, both matter

**(a) You're up, on the right network, with the right key** (run on the VM):
```sh
curl -s localhost:30303/health
```
Expect `{"status":"ok","network_id":"82a4d3bd…c339f7","latest_epoch":N,"epoch_now":M,"resyncing":false,"panics_total":0}`.
- `network_id` **must equal** `82a4d3bd12d31fa2abb087710f524fc9f8b73e393480fc71cbd8066b53c339f7`. If it
  differs, your `testnet.json` is wrong — re‑download it (B1).
- Confirm your key is the founder key for your IP:
  ```sh
  journalctl -u anos-validator | grep 'Validator Public Key'   # must print YOUR pubkey from Part D
  ```
  > ⚠️ A node started with the wrong key still boots, syncs, and shows advancing epochs — but signs
  > nothing. **Advancing epochs alone don't prove you're one of the signers; the pubkey match does.**

**(b) Peers can actually reach you** — the check that catches firewall/IP mistakes. From **another
operator's VM** (its IP is allowed through your firewall), *not* localhost:
```sh
curl -m5 http://<YOUR_PUBLIC_IP>:30303/health   # must return the JSON above
```
If (a) works but (b) hangs/refuses, your firewall (B3) or static IP (B0.2) is wrong — your node looks
healthy locally but is invisible to peers. Do this as a mutual buddy‑check with another operator.

## Reading `/health` (so you don't "fix" a healthy node)

- `epoch_now` = current wall‑clock epoch; **climbs every ~2 s no matter what.** Climbing ⇒ the process
  is alive.
- `latest_epoch` = the last epoch you finalized **with peers.** It stays **frozen** until a quorum
  (≥3 of 5) is up together. **A frozen `latest_epoch` while `epoch_now` climbs = healthy, waiting for
  peers — NOT a fault.** Once peered, the gap `epoch_now − latest_epoch` should stay small (single
  digits) and `resyncing` should settle to `false`.
- ‼️ During the launch window do **NOT** edit `testnet.json` (it changes your `network_id` and
  permanently isolates you) and do **NOT** delete the database to "unstick" a frozen `latest_epoch`.
  Just wait for the quorum.

---

# Part C — Updating

## C1. How the maintainer publishes an update

Exactly like the first release — **one tag push:**
```sh
git tag v0.1.1
git push origin v0.1.1
```
Actions builds and publishes the `v0.1.1` release automatically. Then tell the operators the new tag
(and, per C2, whether it's a rolling or a coordinated update).

## C2. Two kinds of update — this is the important part

| | **Compatible update** | **Breaking update** |
|---|---|---|
| what changed | bug fix, performance, logging — no consensus‑rule change | `protocol_version` bumped, or the manifest changed (which changes `network_id`) |
| do old & new nodes talk? | **yes** — they interoperate | **no** — the P7 handshake rejects a mismatched `protocol_version`/`network_id` with HTTP 421 |
| how to roll it out | **rolling**, one node at a time, no coordination | **coordinated** — everyone in a window |
| network stays live? | yes | brief cutover; a manifest change is effectively a *new network* |

The release notes should say which kind it is. Rule of thumb: if the release did **not** ship a new
`testnet.json` and did **not** bump `protocol_version`, it's compatible → roll it. Otherwise it's
breaking → coordinate.

## C3. Applying a compatible (rolling) update — operator

Download → back up → swap → restart. ~4 lines, seconds of downtime:
```sh
cd /opt/anos
sudo curl -L -o validator.new https://github.com/Anosphere/AnosValidatorDevNet/releases/download/v0.1.1/validator-linux-amd64
# verify the new binary before trusting it
curl -sL https://github.com/Anosphere/AnosValidatorDevNet/releases/download/v0.1.1/SHA256SUMS | \
  grep validator-linux-amd64 | sed 's#validator-linux-amd64#validator.new#' | sha256sum -c -   # -> validator.new: OK
sudo cp validator validator.bak          # keep the current one for rollback
sudo mv validator.new validator && sudo chmod +x validator
sudo systemctl restart anos-validator
curl -s localhost:30303/health            # confirm it's back and latest_epoch resumes
```
Why this is safe: the database and manifest are untouched, so on restart the node continues from where
it was; if it drifted a few epochs behind while down, the verifying resync catches it up automatically.

**Across the fleet, update one node at a time** (wait for each to come back healthy before the next),
so you never drop below the ≥3‑of‑5 quorum and the network never stops.

## C4. Rollback

If a new version misbehaves, the previous binary is right there:
```sh
sudo systemctl stop anos-validator
sudo mv /opt/anos/validator.bak /opt/anos/validator
sudo systemctl start anos-validator
```

## C5. Applying a breaking (coordinated) update — operator

The maintainer names a **cutover window** and, for a manifest change, a new tag whose release includes
the new `testnet.json`. During the window each operator:
1. downloads the new `validator` **and** the new `testnet.json` (C3 steps, plus re‑download
   `testnet.json` into `/opt/anos/`),
2. `sudo systemctl restart anos-validator`.

Until enough operators have switched, old and new nodes won't peer (they reject each other's handshake
with 421) — that's expected during a cutover, not a bug. A manifest change means a *different*
`network_id`, i.e. effectively a new network, and typically a fresh genesis; the maintainer will say so
explicitly. This is the rare, ceremony‑heavy case that the "everyone on tag `vX.Y.Z` by <time>"
discipline exists for.

---

# Part D — Reference

## Per‑VM firewall commands

Each operator opens tcp:30303 to the *other four* validators. Copy the line for your VM number into
the B3 command's `--source-ranges` (fill in your own `<INSTANCE_NAME>`, `<ZONE>`, `<YOUR_PROJECT_ID>`):

| VM (IP) | `--source-ranges=` (the other four) |
|---|---|
| 1 (`35.234.70.37`)   | `34.159.203.177,34.107.74.229,35.242.233.86,35.234.117.219` |
| 2 (`34.159.203.177`) | `35.234.70.37,34.107.74.229,35.242.233.86,35.234.117.219` |
| 3 (`34.107.74.229`)  | `35.234.70.37,34.159.203.177,35.242.233.86,35.234.117.219` |
| 4 (`35.242.233.86`)  | `35.234.70.37,34.159.203.177,34.107.74.229,35.234.117.219` |
| 5 (`35.234.117.219`) | `35.234.70.37,34.159.203.177,34.107.74.229,35.242.233.86` |

## Per‑VM consensus pubkey (for verify step B4(a))

Your node logs `Validator Public Key: <hex>` at boot. Confirm it matches your VM's row — a value that
*doesn't* match means you're running the wrong key (a silent non‑signing observer). These are public.

| VM (IP) | consensus pubkey |
|---|---|
| 1 (`35.234.70.37`)   | `02530e653cffc20b82b946acd5235c8b8b4fa546a5b2df5003d041c813daeee3fd` |
| 2 (`34.159.203.177`) | `02650fcd9d5b5c741ec30152fe39b07c9a06c7b9ada2d16dc3e60a0d5c797f613b` |
| 3 (`34.107.74.229`)  | `03e5474db9b93eea7c194f6926dc03e3bd3d442c1d346c26f74027c816dbf9838d` |
| 4 (`35.242.233.86`)  | `03b2b28a04ceafa5ef4a5e4f2f80c47ff60b517f0b2ff68957738b231bacae5eb4` |
| 5 (`35.234.117.219`) | `03875c48e0f97875328822c8088191dcba1e030933e8054777730c160d15d89ca6` |

## Ports & endpoints

The node serves everything on **one** port, `30303`:
- **Public:** `/health` (ungated), `/submit`, `/account`, `/receivables` (client RPC).
- **Peer/consensus:** `/peer/*`, `/sync/*` — firewalled to the roster IPs (that's the B3 rule).
- **Admin/debug:** `/debug/*` — **loopback‑only** by design. To inspect, SSH into the VM and
  `curl localhost:30303/debug/accounts/heads` (also `/debug/fund/stakes`, `/debug/consensus/flip`, …).

## `/health` fields
`status` (always `ok` if up) · `network_id` · `latest_epoch` (last finalized) · `epoch_now` (wall‑clock)
· `resyncing` · `panics_total`.

## Troubleshooting

- `systemctl status anos-validator` → **`active (running)`** is good. **`activating (auto-restart)`** =
  crash‑looping; run `journalctl -u anos-validator -e` and look for a fatal line:
  - `exec format error` → you're on an **Arm** VM; download `validator-linux-arm64` (B1).
  - `manifest` / `network_id` / `parse` → `testnet.json` is corrupt/edited; re‑download it.
  - key / `permission denied` → `sudo chmod 600 /opt/anos/anos.key`.
- `active (running)`, local `/health` ok, but `latest_epoch` won't advance:
  1. Is a quorum (≥3) of operators actually up **right now**? If not, that's expected — wait.
  2. Run check B4(b) from another operator's VM. If your public `/health` is refused, fix the firewall
     (B3 — is the rule on your VM's *actual* network?) or the static IP (B0.2).
  3. `timedatectl` → if `System clock synchronized: no`, run `sudo timedatectl set-ntp true`.
