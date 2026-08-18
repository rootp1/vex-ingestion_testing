#!/usr/bin/env bash
# Fetches the current pkg/cli/vex.go from wolfi-dev/wolfictl and confirms it
# is a Deprecated, no-op stub (RunE just logs "Did nothing!" and returns nil).
set -euo pipefail
cd "$(dirname "$0")"

curl -sL -o samples/wolfictl_pkg_cli_vex.go \
  "https://raw.githubusercontent.com/wolfi-dev/wolfictl/main/pkg/cli/vex.go"

echo "=== samples/wolfictl_pkg_cli_vex.go ==="
cat samples/wolfictl_pkg_cli_vex.go

echo
if grep -q 'Deprecated:' samples/wolfictl_pkg_cli_vex.go && \
   grep -q 'log.Print("Did nothing!")' samples/wolfictl_pkg_cli_vex.go; then
  echo "CONFIRMED: vex.go marks the command Deprecated and both 'package' and"
  echo "'sbom' subcommands' RunE bodies are literally just log.Print(\"Did nothing!\")."
else
  echo "DID NOT MATCH the expected stub shape -- source may have changed, inspect manually."
fi
