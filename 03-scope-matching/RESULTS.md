# Scope matching: image-glob vs PURL/product-id — empirical test

Source: real Red Hat CSAF/VEX document for CVE-2024-6119, fetched live from
`https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-6119.json`
(saved in `samples/cve-2024-6119.json`, 1.98 MB).

**Correction found during reverification:** the proposal text states "909
product-tree entries" for this CVE. The actual, directly counted sum of
`known_affected` (18) + `known_not_affected` (799) + `fixed` (111) is
**928**, not 909 — confirmed as the exact count of distinct product IDs
across all three status buckets combined (`len(set of all product ids) ==
928`, no duplicates). This appears to be a pre-existing arithmetic/transcription
slip in the proposal (18+799+111=928), not a change in the live data — the
per-bucket counts (18/799/111) it also cites are themselves correct and
unchanged. The proposal's total count should be corrected to 928.

**Reverified 2026-08-18.** Re-fetched the document live and diffed it
byte-for-byte against the original 2026-08-14 sample: **identical**
(`document.tracking.version: 3`, `revision_history` still 3 entries, last
dated `2026-08-08T17:12:20Z`, sha256 content hash unchanged). Red Hat has not
revised this document since the original test. All counts and conclusions
below are re-derived from the live re-fetch via `python3 analyze.py`, not
carried over from the prior run.

## What the real statement actually contains

`vulnerabilities[0].product_status` has three buckets for this single CVE,
909 entries total:

- `known_affected`: **18 entries**, e.g. `red_hat_enterprise_linux_6:openssl`,
  `red_hat_enterprise_linux_6:openssl-devel`,
  `red_hat_3scale_api_management_platform_2:3scale-amp-backend-container`.
  **Correction from the original write-up:** none of these 18 carry a
  `@sha256:...` digest — for this CVE, every `known_affected` entry is an
  RPM/product-name-level identifier, not a digest-qualified container image.
  Verified directly: `any('@sha256:' in p for p in known_affected)` → `False`.
- `known_not_affected`: **799 entries**, of which 773 are digest-qualified
  container/RHCOS builds (`@sha256:...`), e.g.
  `9Base-RHOSE-4.16:openshift4/aws-kms-encryption-provider-rhel9@sha256:1d914e9e...`.
- `fixed`: **111 entries**, of which 50 are digest-qualified container builds.

Product tree PURLs use `pkg:oci/...?repository_url=registry.redhat.io/...` for
containers and RPM NEVRA for packages — not a bare image-reference glob.

## Key finding: glob matching cannot distinguish which specific build a status applies to

All three status buckets contain products whose registry host is
`registry.redhat.io` or `registry.access.redhat.com`. A glob like
`registry.redhat.io/*` (the default suggested in the proposal's `imageMatch`
examples) matches **all** of them indiscriminately — it has no way to know
which digest a given status actually covers, because the distinguishing key
is the digest embedded in the product_id, not the image repo name.

**This document does not contain a literal same-repo-name `known_affected`
vs. `known_not_affected` pair** (checked directly: zero repo names appear in
more than one status bucket in this CVE's document — `known_affected` here
has no image-level entries to collide with). The original write-up implied
such a same-repo cross-bucket example; that specific framing was not
supported by this document and has been corrected here.

The real, directly observed evidence for "digest granularity is required" is
instead **within-bucket repetition**: the same repo name recurs across many
different digests inside a single status bucket — e.g.
`openshift4/aws-kms-encryption-provider-rhel9` appears **4 times** in
`known_not_affected` alone, once per architecture, each at a different
digest:

```
9Base-RHOSE-4.16:openshift4/aws-kms-encryption-provider-rhel9@sha256:1d914e9e28bb05d936c22d20f021d31cf806285d5e4ae0e47c47b50c90c7e8de_ppc64le
9Base-RHOSE-4.16:openshift4/aws-kms-encryption-provider-rhel9@sha256:7460081ddaf409891100dad0bbf264e09a2ed75a5daab332610837c6091ca6ce_amd64
9Base-RHOSE-4.16:openshift4/aws-kms-encryption-provider-rhel9@sha256:a016229598f9b0d366d745218b71c543e7f9593270d2cd84c33f867d12ebb567_s390x
9Base-RHOSE-4.16:openshift4/aws-kms-encryption-provider-rhel9@sha256:a0de020a0ccd742c5e9f8d2d84f4b6d4db25556c10eca46a2ac0bc4993aff352_arm64
```

179 repo names in `known_not_affected` alone have more than one digest listed
this way. This proves the document's own data model treats "which digest" as
load-bearing, not incidental: Red Hat itself never asserts a status at the
repo-name level, only at the exact-digest level. A glob that stops at the
repo name is therefore structurally unable to reproduce what the document
actually asserts — it can only ever say "this repo, in general," when the
source data says "this exact digest, specifically."

The practical risk this creates: if a scanned image's actual digest is not
one of the digests explicitly listed under `known_not_affected`/`fixed` for
its repo (e.g. an older build, a digest for an architecture not covered, or a
build predating this document's revision), glob-only matching on
`registry.redhat.io/*` would still suppress the CVE for it — silently
treating "not explicitly covered by any listed digest" the same as
"confirmed not_affected." Digest/PURL matching against the statement's actual
listed products is what closes that gap, because it can tell "this digest is
in the not_affected list" apart from "this digest doesn't appear in this
document at all."

## Conclusion

Image-reference glob matching is **safe as a coarse pre-filter** (it correctly
excludes non-Red-Hat images like Debian/Alpine from Red Hat statements) but
**is not sufficient as the sole matching mechanism** for Red Hat's own CSAF
feed: the document's own product tree only makes affected/not-affected/fixed
determinations at the digest level (confirmed: 179 repo names recur across
multiple digests within a single status bucket in this one document), never
at the registry/repo-name level. A v1 that matches only on `imageMatch` globs
risks suppressing findings on images whose digest was never actually covered
by the `known_not_affected`/`fixed` entries it's matching against.

**This core finding still holds after reverification against the live,
unrevised document.** Digest or PURL matching against the statement's actual
listed products remains a correctness requirement for Red Hat's
container-image statements, not just a future enhancement — this reverify
pass corrected one illustrative example (no same-repo cross-bucket collision
exists in this particular CVE's data) without weakening the underlying
conclusion, which is now backed by stronger, directly-observed evidence
(within-bucket digest multiplicity) than the original write-up cited.

Recommendation unchanged: treat `imageMatch` as a cheap first-pass scope
filter (do we even need to consider this source for this image family), but
require a digest or PURL match against the specific `product_status` entry
before actually suppressing.

## Note on SBOM step

A live SBOM-vs-Debian/Alpine comparison was not generated — no `syft` binary
was used for this specific test and fetching a public SBOM fixture was out of
scope. The finding above is fully supported by the real CSAF document's own
product_status structure without needing a second SBOM, since the
digest-level granularity requirement already exists *within* the same
document.
