#!/usr/bin/env bash
# Confirms the real commit that dropped wolfictl's VEX generation, via the
# GitHub API (no full clone needed -- lighter than `git log --all`).
# Requires `gh` authenticated, or falls back to an unauthenticated curl.
set -euo pipefail
cd "$(dirname "$0")"

SHA="9364dfe924ac4c80484492f523008fab1eb634a1"

if command -v gh >/dev/null 2>&1; then
  gh api "repos/wolfi-dev/wolfictl/commits/$SHA" > samples/commit_9364dfe.json
else
  curl -sL "https://api.github.com/repos/wolfi-dev/wolfictl/commits/$SHA" \
    -o samples/commit_9364dfe.json
fi

python3 - <<PY
import json
d = json.load(open("samples/commit_9364dfe.json"))
print("sha:", d["sha"])
print("date:", d["commit"]["author"]["date"])
print("author:", d["commit"]["author"]["name"], "<" + d["commit"]["author"]["email"] + ">")
print("message:")
print(d["commit"]["message"])
print("html_url:", d["html_url"])
print("files changed:", [f["filename"] for f in d.get("files", [])])
PY

echo
echo "Confirm the commit is reachable from the default branch:"
if command -v gh >/dev/null 2>&1; then
  gh api "repos/wolfi-dev/wolfictl/compare/main...$SHA" --jq '.status' 2>/dev/null \
    && echo "(compare status above; 'identical'/'behind' means $SHA is an ancestor of main)" \
    || echo "(compare check skipped/failed -- commit still resolves individually above)"
fi
