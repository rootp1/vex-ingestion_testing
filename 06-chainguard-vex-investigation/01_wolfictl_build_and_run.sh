#!/usr/bin/env bash
# Builds wolfictl from source and proves `wolfictl vex package` is a no-op
# against a real melange config (openssl.yaml from wolfi-dev/os).
set -euo pipefail
cd "$(dirname "$0")"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "Cloning wolfi-dev/wolfictl into $WORKDIR ..."
git clone --depth 50 https://github.com/wolfi-dev/wolfictl "$WORKDIR/wolfictl"

echo "Building wolfictl binary ..."
( cd "$WORKDIR/wolfictl" && go build -o "$WORKDIR/wolfictl-bin" ./ )

echo "Fetching real openssl.yaml from wolfi-dev/os ..."
curl -sL -o "$WORKDIR/openssl.yaml" \
  "https://raw.githubusercontent.com/wolfi-dev/os/main/openssl.yaml"
cp "$WORKDIR/openssl.yaml" "$(dirname "$0")/samples/wolfi_openssl.yaml"

echo
echo "=== wolfictl vex --help ==="
"$WORKDIR/wolfictl-bin" vex --help

echo
echo "=== running: wolfictl vex package --author=test@example.com openssl.yaml ==="
set +e
OUT="$("$WORKDIR/wolfictl-bin" vex package --author=test@example.com "$WORKDIR/openssl.yaml" 2>&1)"
EXIT=$?
set -e
echo "exit code: $EXIT"
echo "stdout+stderr bytes: ${#OUT}"
echo "stdout+stderr content: [${OUT}]"

if [ -z "$OUT" ] && [ "$EXIT" -eq 0 ]; then
  echo
  echo "CONFIRMED: 'wolfictl vex package' against a real melange config produces"
  echo "zero output and exit code 0 -- a genuine no-op, not merely deprecated."
fi
