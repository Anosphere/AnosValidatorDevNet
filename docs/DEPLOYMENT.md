# Anos validator — deployment guide

Two roles use this doc:
- **Operators** run a validator VM → follow **§1** top to bottom, then **§2** for updates.
- **The maintainer** publishes releases and hands out keys → **§3**.

You download the program and the network config from GitHub. The maintainer sends you **one** private
file — your key — plus a short note with your specific values. Wherever a command says `<YOUR_…>`, use the
value from that note.

The network id for this net is `82a4d3bd12d31fa2abb087710f524fc9f8b73e393480fc71cbd8066b53c339f7`.

---

## §1 — Set up your validator (do these in order)

### 1. Create the VM
- Machine type: **x86‑64 (amd64)** — an `e2-`, `n2-`, or `c3-` family type. **Not** Arm / `t2a-`.
- Image: **Debian or Ubuntu**.
- Make its external IP **static** so a stop/start can't change it: Console → *VPC network → IP addresses →
  External IP addresses* → find the row for **this VM** (Type = *Ephemeral*) → set that row to **Static**.
  Do **not** use the top "Reserve External Static IP Address" button (that makes a *different* IP). Your IP
  must stay `<YOUR_IP>`.

### 2. Download and verify the software (run on the VM)
```sh
mkdir -p ~/anos && cd ~/anos
uname -m                                       # must print x86_64 (if aarch64 you made an Arm VM — recreate it)
TAG=<TAG>
BASE="https://github.com/Anosphere/AnosValidatorDevNet/releases/download/$TAG"

curl -L -O "$BASE/validator-linux-amd64"       # Arm VM: use validator-linux-arm64 here AND in the mv below
curl -L -o testnet.json "$BASE/testnet.json"
curl -L -O "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing       # must print:  validator-linux-amd64: OK   testnet.json: OK

mv validator-linux-amd64 validator && chmod +x validator
```
`-L` follows GitHub's redirect to the download host. Downloading under the release's own filename is what
lets the checksum actually verify the binary — rename it to `validator` only after both lines say `OK`.

### 3. Put your private key in place
The maintainer sent you `anos.key`. Upload it (Console SSH → **⚙ → Upload file** drops it in your home dir),
then:
```sh
mv ~/anos.key ~/anos/anos.key        # skip if it's already in ~/anos
```

### 4. Install it as a background service (run on the VM)
```sh
sudo mkdir -p /opt/anos
sudo cp ~/anos/validator ~/anos/testnet.json ~/anos/anos.key /opt/anos/
sudo chmod +x /opt/anos/validator && sudo chmod 600 /opt/anos/anos.key

sudo tee /etc/systemd/system/anos-validator.service >/dev/null <<'UNIT'
[Unit]
Description=Anos validator
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/opt/anos/validator -manifest /opt/anos/testnet.json -key /opt/anos/anos.key -db /opt/anos/validator.db
Restart=on-failure
RestartSec=5
WorkingDirectory=/opt/anos
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload && sudo systemctl enable --now anos-validator
```

### 5. Open the firewall (once, in your GCP project)
GCP blocks inbound traffic by default, so this rule is required. Target your VM's **actual** network — a
rule created on the wrong network silently does nothing:
```sh
NET=$(gcloud compute instances describe <INSTANCE_NAME> --zone <ZONE> \
      --format='value(networkInterfaces[0].network)')
gcloud compute firewall-rules create anos-p2p \
  --project=<YOUR_PROJECT_ID> --network="$NET" \
  --direction=INGRESS --action=ALLOW --rules=tcp:30303 \
  --source-ranges=<PEER_IPS>
```

### 6. Verify it's working
```sh
curl -s localhost:30303/health
```
- `network_id` must equal `82a4d3bd12d31fa2abb087710f524fc9f8b73e393480fc71cbd8066b53c339f7`. If it
  differs, your `testnet.json` is wrong — re‑download it (step 2).
- Your key is the right one if `journalctl -u anos-validator | grep 'Validator Public Key'` prints
  `<YOUR_PUBKEY>`. **A wrong key still boots and shows advancing epochs but signs nothing — the pubkey
  match is the real check.**
- **Peers can reach you:** from another operator's VM, `curl -m5 http://<YOUR_IP>:30303/health` must
  return the JSON. If your local check works but this doesn't, your firewall (step 5) or static IP (step 1)
  is wrong.

**About `latest_epoch`:** it stays **frozen** until at least **3 of the 5** validators are up at the same
time. A frozen `latest_epoch` while `epoch_now` keeps climbing = healthy, waiting for peers — **not** a
fault. Don't edit `testnet.json` or delete the database to "fix" it; just wait for the others.

---

## §2 — Update your validator

When the maintainer announces a new version tag `<NEW_TAG>` for a **plain update** (bug fix / no network
change), on the VM:
```sh
cd /opt/anos
sudo curl -L -o validator.new "https://github.com/Anosphere/AnosValidatorDevNet/releases/download/<NEW_TAG>/validator-linux-amd64"
curl -sL "https://github.com/Anosphere/AnosValidatorDevNet/releases/download/<NEW_TAG>/SHA256SUMS" \
  | grep validator-linux-amd64 | sed 's#validator-linux-amd64#validator.new#' | sha256sum -c -   # -> validator.new: OK
sudo cp validator validator.bak                 # keep the old one for rollback
sudo mv validator.new validator && sudo chmod +x validator
sudo systemctl restart anos-validator
curl -s localhost:30303/health                  # confirm it comes back and latest_epoch resumes
```
Downtime is seconds; the database is kept, so the node resumes where it left off. **Update one VM at a
time** across the fleet so a quorum stays up. Rollback if needed:
```sh
sudo systemctl stop anos-validator && sudo mv /opt/anos/validator.bak /opt/anos/validator && sudo systemctl start anos-validator
```
If the maintainer says the update is a **network change** (new `testnet.json`), also re‑download
`testnet.json` into `/opt/anos/` before the restart, and expect a brief window where old and new nodes
don't talk to each other — the maintainer will name a cutover time.

---

## §3 — Maintainer: publish a release

**One‑time:** repo → **Settings → Actions → General →** allow actions.

**Cut a release (entirely in the browser — no local push):**
1. Merge the code to `main` via a pull request.
2. Repo → **Releases → Draft a new release → Choose a tag →** type `v0.1.0` → **Create new tag: v0.1.0 on
   publish** → Target `main` → **Publish release**. Creating the tag triggers `release.yml`, which builds
   `validator-linux-{amd64,arm64}` + copies `testnet.json` + writes `SHA256SUMS` and attaches all four to
   the release. Watch the **Actions** tab (~1–2 min).

**Ship an update:** publish a new tag (`v0.1.1`) the same way. In the release notes say whether it's a
**plain update** (operators just swap the binary, §2) or a **network change** (new `testnet.json` /
`protocol_version` — operators also re‑download the manifest, and you coordinate a cutover window).

**Hand out keys:** send each operator **privately** only their `anos.key` and their personal note (VM
number, `<YOUR_IP>`, `<YOUR_PUBKEY>`, `<PEER_IPS>`, and the `<TAG>` to download). The binary and
`testnet.json` are public and come from the release — never send the key over anything public, and never
put it in git.

---

## Troubleshooting

- `systemctl status anos-validator` shows **`activating (auto-restart)`** = crash loop. Run
  `journalctl -u anos-validator -e` and read the fatal line:
  - `exec format error` → Arm VM; download `validator-linux-arm64` instead (step 2).
  - `manifest` / `network_id` / `parse` → `testnet.json` corrupt or edited; re‑download it.
  - `permission denied` on the key → `sudo chmod 600 /opt/anos/anos.key`.
- Node is `active (running)`, local `/health` is ok, but `latest_epoch` won't advance:
  1. Are at least 3 of the 5 operators up **right now**? If not, that's expected — wait for a quorum.
  2. Run the reachability check from another VM (§1 step 6). If refused, fix the firewall (§1 step 5 — is
     the rule on your VM's actual network?) or the static IP (§1 step 1).
  3. `timedatectl` → if `System clock synchronized: no`, run `sudo timedatectl set-ntp true`.

## Reference — the 5 VMs

| VM | external IP | consensus pubkey (`<YOUR_PUBKEY>`) | firewall peers (`<PEER_IPS>`) |
|---|---|---|---|
| 1 | `35.234.70.37`   | `02530e653cffc20b82b946acd5235c8b8b4fa546a5b2df5003d041c813daeee3fd` | `34.159.203.177,34.107.74.229,35.242.233.86,35.234.117.219` |
| 2 | `34.159.203.177` | `02650fcd9d5b5c741ec30152fe39b07c9a06c7b9ada2d16dc3e60a0d5c797f613b` | `35.234.70.37,34.107.74.229,35.242.233.86,35.234.117.219` |
| 3 | `34.107.74.229`  | `03e5474db9b93eea7c194f6926dc03e3bd3d442c1d346c26f74027c816dbf9838d` | `35.234.70.37,34.159.203.177,35.242.233.86,35.234.117.219` |
| 4 | `35.242.233.86`  | `03b2b28a04ceafa5ef4a5e4f2f80c47ff60b517f0b2ff68957738b231bacae5eb4` | `35.234.70.37,34.159.203.177,34.107.74.229,35.234.117.219` |
| 5 | `35.234.117.219` | `03875c48e0f97875328822c8088191dcba1e030933e8054777730c160d15d89ca6` | `35.234.70.37,34.159.203.177,34.107.74.229,35.242.233.86` |

The port is always `30303`. Admin endpoints (`/debug/*`) answer only on `localhost` — SSH in and
`curl localhost:30303/debug/accounts/heads` to inspect. This 5‑node roster is the network's **initial
banker/validator set**, defined in `config/testnet.json` in the repo (also attached to each release).
