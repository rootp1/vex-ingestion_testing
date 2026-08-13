#!/usr/bin/env python3
"""Analyze real Red Hat CSAF/VEX and Chainguard/Wolfi advisory samples to test
whether they fit OpenVulnerabilityExchangeContainer's one-doc-per-image shape."""
import json
import glob

print("=== Red Hat CSAF/VEX (samples/redhat_*.json) ===")
for f in sorted(glob.glob("samples/redhat_*.json")):
    d = json.load(open(f))
    size = len(open(f).read())
    pt = d.get("product_tree", {})
    fpn = pt.get("full_product_names", [])
    v = d["vulnerabilities"][0]
    ps = v.get("product_status", {})
    counts = {k: len(vv) for k, vv in ps.items()}
    total_products = sum(counts.values())
    print(f"{f}")
    print(f"  size_bytes={size}")
    print(f"  cve={v.get('cve')}")
    print(f"  product_status_counts={counts} (total={total_products} product refs)")
    print(f"  remediations={len(v.get('remediations', []))} threats={len(v.get('threats', []))}")

print()
print("=== Wolfi/Chainguard package advisories (samples/wolfi_openssl.advisories.yaml) ===")
print("Format: Chainguard 'secfixes/advisories' YAML (schema-version 2.0.2),")
print("NOT raw OpenVEX. One file per PACKAGE (not per image, not per CVE),")
print("containing every advisory (CVE) ever filed against that package across")
print("all its historical versions. OpenVEX is generated on-demand from this")
print("data by `wolfictl advisory` tooling -- it is not published as a static")
print("OpenVEX feed.")

print()
print("=== Wolfi aggregate security.json (samples/wolfi_security.json) ===")
d = json.load(open("samples/wolfi_security.json"))
print(f"packages_in_file={len(d['packages'])}")
print("Shape: ONE file for the entire Wolfi repo, containing every package,")
print("each with a secfixes map keyed by package version -> list of CVE/GHSA ids.")
print("This is the opposite extreme from Red Hat: Red Hat = 1 file per CVE across")
print("all products; Wolfi = 1 file for the whole distro across all packages.")
