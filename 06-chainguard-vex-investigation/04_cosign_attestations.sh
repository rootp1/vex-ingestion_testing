#!/usr/bin/env bash
# Builds cosign from source and pulls the real, live OCI attestations attached
# to cgr.dev/chainguard/wolfi-base:latest, to check whether any of them is a
# VEX predicate.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="cgr.dev/chainguard/wolfi-base:latest"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "Cloning sigstore/cosign into $WORKDIR ..."
git clone --depth 1 https://github.com/sigstore/cosign "$WORKDIR/cosign"

echo "Building cosign binary (this pulls a lot of Go modules, be patient) ..."
( cd "$WORKDIR/cosign" && go build -o "$WORKDIR/cosign-bin" ./cmd/cosign )

"$WORKDIR/cosign-bin" version

echo
echo "=== cosign tree $IMAGE ==="
"$WORKDIR/cosign-bin" tree "$IMAGE" | tee samples/cosign_tree.log

echo
echo "=== cosign download attestation $IMAGE ==="
"$WORKDIR/cosign-bin" download attestation "$IMAGE" > samples/attestations_raw.jsonl
wc -l samples/attestations_raw.jsonl

echo
echo "=== decoding predicate types ==="
python3 - samples/attestations_raw.jsonl | tee samples/attestations_decoded.txt <<'PY'
import json, base64, sys
path = sys.argv[1]
with open(path) as f:
    for i, line in enumerate(f, 1):
        obj = json.loads(line)
        payload = base64.b64decode(obj["payload"])
        p = json.loads(payload)
        print(f"--- attestation {i} ---")
        print("payloadType:", obj.get("payloadType"))
        print("predicateType:", p.get("predicateType"))
        print("subject:", p.get("subject"))
        print()
PY

if grep -qi "vex" samples/attestations_decoded.txt; then
  echo "UNEXPECTED: a VEX-related predicate type was found -- inspect manually."
else
  echo "CONFIRMED: no VEX predicate type present among this image's attestations."
fi
