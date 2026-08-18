#!/usr/bin/env python3
"""Extract candidate dedup-key fields from real CSAF/VEX samples in samples/."""
import json
import glob

print(f"{'file':<22}{'doc_id':<16}{'version':<8}{'revisions':<10}{'#vulns':<8}{'has_stmt_id':<12}{'has_purl':<10}{'#prods':<8}{'#purl'}")
for path in sorted(glob.glob("samples/cve-*.json")):
    d = json.load(open(path))
    t = d["document"]["tracking"]
    vulns = d.get("vulnerabilities", [])
    stmt_id_present = any("id" in v for v in vulns)
    pt = d.get("product_tree", {})

    def walk(b):
        out = []
        for item in b:
            if "product" in item:
                out.append(item["product"])
            if "branches" in item:
                out += walk(item["branches"])
        return out

    prods = walk(pt.get("branches", []))
    purl_count = sum(1 for p in prods if "purl" in p.get("product_identification_helper", {}))
    has_purl = purl_count > 0
    print(f"{path:<22}{t.get('id'):<16}{t.get('version'):<8}"
          f"{len(t.get('revision_history', [])):<10}{len(vulns):<8}"
          f"{str(stmt_id_present):<12}{str(has_purl):<10}{len(prods):<8}{purl_count}")

print()
print("--- Chainguard Libraries OpenVEX (real, live fetch) ---")
cg = json.load(open("samples/chainguard_werkzeug.openvex.json"))
print("document @id:", cg.get("@id"))
print("document version:", cg.get("version"))
print("has document-level revision_history field:", "revision_history" in cg)
for s in cg["statements"]:
    has_stmt_id = "id" in s
    print(f"statement vuln={s['vulnerability']['name']:<20} status={s['status']:<10} "
          f"has_id_field={has_stmt_id} keys={sorted(s.keys())}")
