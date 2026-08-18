#!/usr/bin/env bash
# Fetches the real, live Chainguard Libraries OpenVEX feed, pulls one real
# package document, and cross-checks a real CVE from it against OSV.dev's
# independent public API. Also confirms the Grype PR the Chainguard docs
# cite (anchore/grype#2886) is real and merged.
set -euo pipefail
cd "$(dirname "$0")"

echo "=== fetching index ==="
curl -sL -o samples/libraries_index.json \
  "https://libraries.cgr.dev/openvex/v1/index.json"

python3 - <<'PY'
import json
d = json.load(open("samples/libraries_index.json"))
pkgs = d["packages"]
print("package count today:", len(pkgs))
print("updated_at:", d.get("updated_at"))
print("has werkzeug:", any("werkzeug" in p["id"] for p in pkgs))
PY

echo
echo "=== fetching pypi/werkzeug.openvex.json ==="
curl -sL -o samples/werkzeug.openvex.json \
  "https://libraries.cgr.dev/openvex/v1/pypi/werkzeug.openvex.json"
python3 -m json.tool samples/werkzeug.openvex.json

echo
echo "=== cross-checking CVE-2024-34069 against OSV.dev ==="
curl -sL -o samples/osv_cve-2024-34069.json \
  "https://api.osv.dev/v1/vulns/CVE-2024-34069"
python3 - <<'PY'
import json
d = json.load(open("samples/osv_cve-2024-34069.json"))
print("OSV id:", d.get("id"))
print("OSV aliases:", d.get("aliases"))
print("OSV summary:", d.get("summary"))

w = json.load(open("samples/werkzeug.openvex.json"))
cg_aliases = set()
for s in w["statements"]:
    if "CVE-2024-34069" in s["vulnerability"].get("aliases", []):
        cg_aliases = set(s["vulnerability"]["aliases"]) | {s["vulnerability"]["name"]}

osv_aliases = set(d.get("aliases", [])) | {d.get("id")}
overlap = cg_aliases & osv_aliases
print("Chainguard-side aliases:", cg_aliases)
print("Overlap with OSV.dev:", overlap)
assert "GHSA-2g68-c3qc-8985" in overlap, "GHSA alias did not cross-check!"
print("CONFIRMED: GHSA alias matches between Chainguard's doc and OSV.dev.")
PY

echo
echo "=== confirming anchore/grype PR #2886 is real and merged ==="
if command -v gh >/dev/null 2>&1; then
  gh api repos/anchore/grype/pulls/2886 > samples/grype_pr_2886.json
else
  curl -sL "https://api.github.com/repos/anchore/grype/pulls/2886" -o samples/grype_pr_2886.json
fi
python3 - <<'PY'
import json
d = json.load(open("samples/grype_pr_2886.json"))
print("title:", d.get("title"))
print("state:", d.get("state"))
print("merged:", d.get("merged"))
print("merged_at:", d.get("merged_at"))
print("html_url:", d.get("html_url"))
PY
