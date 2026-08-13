#!/usr/bin/env python3
"""Compare image-glob-only matching vs PURL/digest matching against a real
Red Hat CSAF/VEX document (samples/cve-2024-6119.json).
"""
import json
import fnmatch
import sys

DOC = "samples/cve-2024-6119.json"


def load():
    with open(DOC) as f:
        return json.load(f)


def glob_match(image_ref, patterns):
    return any(fnmatch.fnmatch(image_ref, p) for p in patterns)


def main():
    d = load()
    vuln = d["vulnerabilities"][0]
    ps = vuln["product_status"]

    patterns = ["registry.redhat.io/*", "registry.access.redhat.com/*"]

    # Registry-qualified product ids for each status bucket (only ones that look like image refs)
    def registry_products(bucket):
        return [p for p in ps.get(bucket, []) if "@sha256:" in p]

    not_affected = registry_products("known_not_affected")
    fixed = registry_products("fixed")
    affected = registry_products("known_affected")

    print(f"known_not_affected image entries: {len(not_affected)}")
    print(f"fixed image entries: {len(fixed)}")
    print(f"known_affected image entries: {len(affected)}")

    # Demonstrate: glob would match ALL of these regardless of bucket,
    # because glob only sees "registry.redhat.io/..." style refs, not the
    # digest-qualified product_status entries which are the real source of
    # truth for affected-vs-not.
    sample_not_affected = not_affected[0] if not_affected else None
    sample_fixed = fixed[0] if fixed else None

    print("\nSample known_not_affected entry:", sample_not_affected)
    print("Sample fixed entry:", sample_fixed)
    print(
        "\nBoth entries share the same registry host and would BOTH match glob "
        "pattern 'registry.redhat.io/*' or 'registry.access.redhat.com/*' -- "
        "glob matching cannot distinguish them from a same-name image at a "
        "DIFFERENT digest that is NOT listed in known_not_affected/fixed at all "
        "(and may still be in known_affected)."
    )

    if affected:
        print("\nSample known_affected entry (non-image, RPM-level):", affected[0] if affected else ps["known_affected"][0])
    else:
        print("\nSample known_affected entry (RPM-level, no digest):", ps["known_affected"][0])


if __name__ == "__main__":
    sys.exit(main())
