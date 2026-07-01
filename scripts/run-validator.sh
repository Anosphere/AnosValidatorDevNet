#!/usr/bin/env bash
# run-validator.sh — build and launch one Anos validator on a VM from the shared manifest.
#
# The manifest (config/testnet.json) is public and identical on every node. This node's
# only unique inputs are its PRIVATE key file (copied to the VM out-of-band, never in git)
# and its DB path. PEERS and the listen PORT are derived from the manifest roster by
# matching this node's consensus key — so every VM runs the exact same command bar -k.
#
# Usage:
#   ./scripts/run-validator.sh -k /path/to/val.key            # typical
#   ./scripts/run-validator.sh -k ~/anos.key -d ~/validator.db -m config/testnet.json -p 30303
#
# Prereqs: Go (>=1.24) on PATH or set GO=/path/to/go. Run from the repo root.
set -euo pipefail

MANIFEST="config/testnet.json"
KEY=""
DB="validator.db"
PORT=""
GO="${GO:-go}"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -k|--key)      KEY="$2"; shift 2 ;;
    -d|--db)       DB="$2"; shift 2 ;;
    -m|--manifest) MANIFEST="$2"; shift 2 ;;
    -p|--port)     PORT="$2"; shift 2 ;;
    -h|--help)     usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 1 ;;
  esac
done

[ -n "$KEY" ] || { echo "error: -k/--key <path to this validator's private key> is required" >&2; usage 1; }
[ -f "$KEY" ] || { echo "error: key file not found: $KEY" >&2; exit 1; }
[ -f "$MANIFEST" ] || { echo "error: manifest not found: $MANIFEST (run from the repo root?)" >&2; exit 1; }

mkdir -p bin
echo "building validator ($($GO version))..."
$GO build -o bin/validator ./cmd/validator

args=(-manifest "$MANIFEST" -key "$KEY" -db "$DB")
[ -n "$PORT" ] && args+=(-port "$PORT")

echo "starting validator: bin/validator ${args[*]}"
exec ./bin/validator "${args[@]}"
