#!/usr/bin/env python3
"""Compare image-glob-only matching vs PURL/digest matching against a real
Red Hat CSAF/VEX document (samples/cve-2024-6119.json).

Reverified 2026-08-18: re-fetch the live document and diff it against this
sample before trusting these numbers -- see RESULTS.md for how to do that.
"""
import json
import fnmatch
import re
import sys

DOC = "samples/cve-2024-6119.json"


def load():
    with open(DOC) as f:
        return json.load(f)


def repo_of(product_id):
    """Extract the bare repo name from a product_id like
    '9Base-RHOSE-4.16:openshift4/foo@sha256:abcd..._amd64'."""
    m = re.search(r":([^@]+)@", product_id)
    return m.group(1) if m else None


def main():
    d = load()
    tracking = d["document"]["tracking"]
    print(f"document.tracking.id: {tracking['id']}")
    print(f"document.tracking.version: {tracking['version']}")
    print(f"document.tracking.status: {tracking['status']}")
    print(f"revision_history entries: {len(tracking['revision_history'])}")
    print(f"last revision: {tracking['revision_history'][-1]}")
    print()

    vuln = d["vulnerabilities"][0]
    ps = vuln["product_status"]

    patterns = ["registry.redhat.io/*", "registry.access.redhat.com/*"]

    known_affected = ps.get("known_affected", [])
    known_not_affected = ps.get("known_not_affected", [])
    fixed = ps.get("fixed", [])

    print(f"known_affected total: {len(known_affected)}")
    print(f"known_not_affected total: {len(known_not_affected)}")
    print(f"fixed total: {len(fixed)}")
    print(f"sum: {len(known_affected) + len(known_not_affected) + len(fixed)}")
    print()

    def registry_products(bucket):
        return [p for p in bucket if "@sha256:" in p]

    na_images = registry_products(known_not_affected)
    fixed_images = registry_products(fixed)
    aff_images = registry_products(known_affected)

    print(f"known_not_affected digest-qualified image entries: {len(na_images)}")
    print(f"fixed digest-qualified image entries: {len(fixed_images)}")
    print(f"known_affected digest-qualified image entries: {len(aff_images)}")
    print(
        "known_affected has ANY digest-qualified (container image) entry for "
        f"this CVE: {bool(aff_images)}"
    )
    print()

    # Cross-bucket collision check: does any repo name appear in more than
    # one status bucket for this CVE?
    repo_to_buckets = {}
    for bucket_name, items in [
        ("known_affected", known_affected),
        ("known_not_affected", known_not_affected),
        ("fixed", fixed),
    ]:
        for pid in items:
            r = repo_of(pid)
            if r:
                repo_to_buckets.setdefault(r, set()).add(bucket_name)
    cross_bucket = {r: b for r, b in repo_to_buckets.items() if len(b) > 1}
    print(f"repo names appearing in >1 status bucket: {len(cross_bucket)}")
    print()

    # Within-bucket digest multiplicity: same repo, multiple digests, one bucket.
    na_repo_counts = {}
    for pid in na_images:
        r = repo_of(pid)
        na_repo_counts.setdefault(r, []).append(pid)
    multi_digest = {r: v for r, v in na_repo_counts.items() if len(v) > 1}
    print(
        f"repo names with >1 digest within known_not_affected alone: "
        f"{len(multi_digest)}"
    )
    if multi_digest:
        example_repo, example_entries = next(iter(multi_digest.items()))
        print(f"\nExample -- repo '{example_repo}' at {len(example_entries)} digests:")
        for e in example_entries:
            print(" ", e)

    print(
        "\nAll of the above product_ids would match glob pattern "
        f"{patterns} indiscriminately -- glob matching cannot see which "
        "specific digest a status bucket actually covers, only the repo "
        "name. Digest/PURL matching against the statement's own listed "
        "products is required to know whether a given scanned image's "
        "exact digest is actually covered, or simply absent from the "
        "document entirely."
    )


if __name__ == "__main__":
    sys.exit(main())
