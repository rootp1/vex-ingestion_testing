# Storage Shape — Empirical Result

**Question:** Does real vendor VEX data fit `OpenVulnerabilityExchangeContainer`'s
one-document-per-image-scan assumption, or is a sibling kind / reshape-on-ingest
needed?

## What was pulled (real data, not synthetic)

- Red Hat CSAF/VEX: `changes.csv` index (63,866 entries) from
  `https://security.access.redhat.com/data/csaf/v2/vex/`, plus 5 real per-CVE
  files.
- Chainguard/Wolfi: `openssl.advisories.yaml` (real, from
  `github.com/wolfi-dev/advisories`) and the aggregate `security.json`
  (real, from `packages.wolfi.dev/os/security.json`, 1,449 packages).
- Raw samples live in `samples/` (large ones truncated to 200KB with a
  `.truncated` suffix to keep the repo small — full sizes are recorded below).

## Findings

**Red Hat CSAF/VEX is organized per-CVE across *all* products, not per-image:**

| File | Size | Product refs (fixed+affected+not_affected+…) |
|---|---:|---:|
| CVE-2025-30204 | 34.8 MB | 15,631 |
| CVE-2025-66418 | 8.97 MB | 4,945 |
| CVE-2026-42154 | 12.0 MB | 4,803 |
| CVE-2026-41603 | 1.24 MB | 488 |
| CVE-2025-31936 | 18 KB | 10 |

A single CVE file can reference 15,000+ product/version combinations spanning
every RHEL release and component RH ships. There is no image-scoped
sub-document at all — "image" isn't a concept in the file; it's PURL/CPE-style
product IDs in a product tree.

**Chainguard/Wolfi is organized per-package (not per-image, not per-CVE):**

- `openssl.advisories.yaml` = every advisory ever filed against the `openssl`
  package, across all historical package versions, in one file.
- `security.json` = the entire distro (1,449 packages) in one file, keyed by
  package → version → CVE list.
- Chainguard does **not** publish a static OpenVEX feed. OpenVEX documents are
  generated on demand by `wolfictl advisory` tooling from this advisories data.
  A prior open question ("pull OpenVEX directly") is answered: there is no
  URL to periodically poll for ready-made OpenVEX from Chainguard — the
  controller would need to either (a) run `wolfictl`-equivalent generation
  logic itself, or (b) ingest the advisories YAML/JSON directly and normalize
  it, since it isn't OpenVEX/CSAF at all.

## Conclusion

**Reusing `OpenVulnerabilityExchangeContainer` unmodified is not workable.**
Both real vendor shapes are the *opposite* of one-doc-per-image:

- Red Hat: one document = one CVE × thousands of products/images.
- Wolfi: one document = one package (or the whole distro) × all its CVEs.

Either shape, ingested verbatim, would need a reshape step before it can be
queried per-image at scan time — you cannot efficiently answer "what VEX
applies to image X" by scanning a 34MB single-CVE document or a 1,449-package
distro file per scan.

This empirically justifies **Option (c) from the proposal's open questions**:
ingest each upstream document close to verbatim (per-CVE for Red Hat, one
normalized statement set per package for Wolfi) into storage, but build a
**secondary index keyed by product/PURL/image-glob → statement**, and do the
per-image join by querying that index at scan time rather than by re-parsing
whole vendor documents. A pure "one `OpenVulnerabilityExchangeContainer` per
image" model doesn't match either vendor's real publishing shape, so plan for
a reshape/indexing layer rather than assuming direct reuse.
