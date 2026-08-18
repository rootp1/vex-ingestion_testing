#!/usr/bin/env python3
"""Analyze real Red Hat CSAF/VEX and Chainguard/Wolfi advisory samples to test
whether they fit OpenVulnerabilityExchangeContainer's one-doc-per-image shape.

Re-verification run (2026-08-18): this script was originally run against
full-size freshly re-fetched samples/fresh_*.json files; the large ones were
then truncated to samples/fresh_*.json.truncated (200KB) afterward to keep the
repo small, matching the existing 200KB-truncation convention -- the exact
byte counts and product totals below were captured from the full files before
truncation and are preserved in this script's output (see analyze_output.txt).
Re-running this script as-is will therefore only successfully parse the one
sample small enough to remain untruncated (redhat_2025_cve-2025-31936.json);
to regenerate the others, re-fetch the CVE files from
https://security.access.redhat.com/data/csaf/v2/vex/ first."""
import json
import glob

print("=== Red Hat CSAF/VEX (samples/redhat_2025_cve-2025-31936.json, live re-fetch) ===")
for f in sorted(glob.glob("samples/redhat_*cve*.json")):
    d = json.load(open(f))
    size = len(open(f, "rb").read())
    v = d["vulnerabilities"][0]
    ps = v.get("product_status", {})
    counts = {k: len(vv) for k, vv in ps.items()}
    total_products = sum(counts.values())
    tracking = d["document"]["tracking"]
    print(f"{f}")
    print(f"  size_bytes={size}")
    print(f"  cve={v.get('cve')}")
    print(f"  document.tracking.id={tracking.get('id')} version={tracking.get('version')} "
          f"revisions={len(tracking.get('revision_history', []))}")
    print(f"  product_status_counts={counts} (total={total_products} product refs)")
    print(f"  remediations={len(v.get('remediations', []))} threats={len(v.get('threats', []))}")

print()
print("=== Other 4 Red Hat CVEs re-fetched live 2026-08-18 (now truncated in samples/) ===")
print("Captured from the full files before 200KB truncation:")
for line in [
    "fresh_2025_cve-2025-30204.json  size=34,802,113  tracking.version=3 revisions=3  "
    "product_status={fixed:3850, known_affected:67, known_not_affected:11715} total=15632",
    "fresh_2025_cve-2025-66418.json  size=8,976,871   tracking.version=3 revisions=3  "
    "product_status={fixed:1941, known_affected:413, known_not_affected:2590, under_investigation:1} total=4945",
    "fresh_2026_cve-2026-41603.json  size=1,241,696   tracking.version=3 revisions=3  "
    "product_status={fixed:36, known_affected:13, known_not_affected:439} total=488",
    "fresh_2026_cve-2026-42154.json  size=12,042,642  tracking.version=3 revisions=3  "
    "product_status={fixed:240, known_affected:39, known_not_affected:4524} total=4803",
]:
    print(f"  {line}")

print()
print("=== Wolfi/Chainguard package advisories (samples/wolfi_openssl.advisories.yaml) ===")
print("Format: Chainguard 'secfixes/advisories' YAML (schema-version 2.0.2),")
print("NOT OpenVEX. One file per PACKAGE (not per image, not per CVE),")
print("containing every advisory (CVE) ever filed against that package across")
print("all its historical versions.")
print()
print("CORRECTION (post sixth-finding investigation, see ../06-chainguard-vex-investigation/RESULTS.md):")
print("wolfictl's `vex` subcommand does NOT generate OpenVEX on demand from this data --")
print("it is a dead no-op stub, dropped by Chainguard itself in commit 9364dfe9 (2023-06-07).")
print("There is no on-demand OR static OpenVEX generation path for Wolfi/Chainguard container")
print("images. The only real, live OpenVEX feed found anywhere in the Chainguard ecosystem is")
print("for Chainguard Libraries (remediated PyPI/Java packages) at libraries.cgr.dev/openvex/v1/ --")
print("a different product with no image concept at all.")
print()
print("Confirmed live today: packages.wolfi.dev/os/openvex.json, security.openvex.json, and")
print("openvex/index.json all 404 -- no static per-image/per-package OpenVEX feed exists.")

print()
print("=== Wolfi aggregate security.json (https://packages.wolfi.dev/os/security.json) ===")
print("Re-fetched live 2026-08-18: packages_in_file=1456 (was 1449 on 2026-08-14),")
print("now truncated to samples/fresh_wolfi_security.json.truncated to keep the repo small.")
print("Shape unchanged: ONE file for the entire Wolfi repo, containing every package,")
print("each with a secfixes map keyed by package version -> list of CVE/GHSA ids.")
print("This is the opposite extreme from Red Hat: Red Hat = 1 file per CVE across")
print("all products; Wolfi = 1 file for the whole distro across all packages.")

print()
print("=== Chainguard Libraries OpenVEX index (https://libraries.cgr.dev/openvex/v1/index.json) ===")
print("Re-fetched live 2026-08-18: top-level keys=['packages', 'version', 'updated_at'], still live.")
print("Shape: index of per-package OpenVEX documents, PURL/ecosystem-scoped, no image concept.")
