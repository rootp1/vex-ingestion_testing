#!/usr/bin/env bash
# Fetches Chainguard's own scanner-integration guide and confirms it
# recommends the OSV feed over the deprecated secdb for image scanning.
set -euo pipefail
cd "$(dirname "$0")"

curl -sL -o samples/chainguard_scanner-support_README.md \
  "https://raw.githubusercontent.com/chainguard-dev/vulnerability-scanner-support/main/README.md"

curl -sL -o samples/chainguard_scanning_implementation.md \
  "https://raw.githubusercontent.com/chainguard-dev/vulnerability-scanner-support/main/docs/scanning_implementation.md"

echo "=== relevant excerpt from docs/scanning_implementation.md ==="
grep -n -i -B2 -A5 "osv\|secdb\|deprecated\|security\.json" \
  samples/chainguard_scanning_implementation.md

echo
if grep -qi "RECOMMENDED.*OSV feed" samples/chainguard_scanning_implementation.md \
  && grep -qi "secdb format is deprecated" samples/chainguard_scanning_implementation.md; then
  echo "CONFIRMED: Chainguard's guide recommends the OSV feed and marks the"
  echo "secdb (including packages.wolfi.dev/os/security.json) as deprecated."
fi
