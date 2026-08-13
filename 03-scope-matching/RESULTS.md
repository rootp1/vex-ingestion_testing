# Scope matching: image-glob vs PURL/product-id — empirical test

Source: real Red Hat CSAF/VEX document for CVE-2024-6119, fetched live from
`https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-6119.json`
(saved in `samples/cve-2024-6119.json`, 1.98 MB, 909 product_tree entries).

## What the real statement actually contains

`vulnerabilities[0].product_status` has three buckets for this single CVE:

- `known_affected`: 18 entries, e.g. `red_hat_enterprise_linux_6:openssl`,
  `red_hat_enterprise_linux_6:openssl-devel`,
  `red_hat_3scale_api_management_platform_2:3scale-amp-backend-container`
- `known_not_affected`: 799 entries, almost all **container images identified
  by exact digest**, e.g.
  `9Base-RHOSE-4.16:openshift4/aws-kms-encryption-provider-rhel9@sha256:1d914e9e...`
- `fixed`: 111 entries, also digest-qualified container/RHCOS builds.

Product tree PURLs use `pkg:oci/...?repository_url=registry.redhat.io/...` for
containers and RPM NEVRA for packages — not a bare image-reference glob.

## Key finding: glob matching cannot distinguish affected from not-affected variants of the *same* image family

All three status buckets (`known_affected`, `known_not_affected`, `fixed`)
contain products whose registry host is `registry.redhat.io` or
`registry.access.redhat.com`. A glob like `registry.redhat.io/*` (the
default suggested in the proposal's `imageMatch` examples) matches **all**
of them indiscriminately — it cannot tell an `openshift4/...@sha256:1d91...`
image that is `known_not_affected` from a sibling build of the same
component name that is `known_affected` at a different digest, because the
distinguishing key is the digest embedded in the product_id, not the image
repo name.

Concretely: `red_hat_enterprise_linux_6:openssl` (affected RPM package) and
`registry.redhat.io/.../aws-kms-encryption-provider-rhel9@sha256:...`
(not_affected container using a different/patched openssl build) can both
match the same `registry.redhat.io/*` glob. Glob-only matching would either:
- suppress correctly for the not_affected majority (799 entries) — fine, **or**
- if applied to an `openshift4/...` image at a *different* digest not listed
  in `known_not_affected`/`fixed` (e.g. an older, still-affected build),
  glob-only matching has no way to know the difference, since it never looks
  at the digest/PURL at all — it would suppress by name/registry match alone,
  producing a false `not_affected` suppression on an actually-affected image.

PURL/digest-based matching, by contrast, uses exactly the identifier Red Hat
itself uses to make the distinction (`@sha256:...`), so it cannot conflate
an affected and not-affected build of visually-identical image names.

## Conclusion

Image-reference glob matching is **safe as a coarse pre-filter** (it correctly
excludes non-Red-Hat images like Debian/Alpine from Red Hat statements) but
**is not sufficient as the sole matching mechanism** for Red Hat's own CSAF
feed: real-world statements differentiate affected vs not-affected at the
image-digest / PURL level, not at the registry/repo-name level. A v1 that
matches only on `imageMatch` globs risks suppressing findings on images whose
digest was never actually covered by the `known_not_affected`/`fixed` entries
it's matching against.

Recommendation: treat `imageMatch` as a cheap first-pass scope filter (do we
even need to consider this source for this image family), but require a
digest or PURL match against the specific `product_status` entry before
actually suppressing — this is a correctness requirement, not just a future
enhancement, at least for Red Hat's container-image statements.

## Note on SBOM step

A live SBOM-vs-Debian/Alpine comparison (step 2) was not generated — no
`syft` binary was available in this environment and fetching a public SBOM
fixture was out of scope for the time available. The finding above is fully
supported by the real CSAF document's own product_status structure without
needing a second SBOM, since the affected/not-affected distinction already
exists *within* the same document at the digest level.
