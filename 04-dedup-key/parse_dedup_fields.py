#!/usr/bin/env python3
"""Extract candidate dedup-key fields from real CSAF/VEX samples in samples/."""
import json
import glob

print(f"{'file':<22}{'doc_id':<16}{'version':<8}{'revisions':<10}{'#vulns':<8}{'has_stmt_id':<12}{'has_purl'}")
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
    has_purl = any("purl" in p.get("product_identification_helper", {}) for p in prods)
    print(f"{path:<22}{t.get('id'):<16}{t.get('version'):<8}"
          f"{len(t.get('revision_history', [])):<10}{len(vulns):<8}"
          f"{str(stmt_id_present):<12}{has_purl}")
