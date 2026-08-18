# Storage Shape — Empirical Result

**Question:** Does real vendor VEX data fit `OpenVulnerabilityExchangeContainer`'s
one-document-per-image-scan assumption, or is a sibling kind / reshape-on-ingest
needed?

**Re-verified live 2026-08-18** (original test: 2026-08-14). Every figure below
was re-measured against the live feeds today; reproduce with `python3 analyze.py`
after re-running the `curl` commands in the script's docstring for the large files.

## What was pulled (real data, not synthetic)

- Red Hat CSAF/VEX: `changes.csv` index from
  `https://security.access.redhat.com/data/csaf/v2/vex/`, plus the same 5 real
  per-CVE files re-fetched live today.
- Chainguard/Wolfi: `openssl.advisories.yaml` (real, from
  `github.com/wolfi-dev/advisories`) and the aggregate `security.json`
  (real, from `packages.wolfi.dev/os/security.json`), re-fetched live today.
- Chainguard Libraries OpenVEX index (`libraries.cgr.dev/openvex/v1/index.json`),
  re-fetched live today.
- Raw samples live in `samples/` (large ones truncated to 200KB with a
  `.truncated` suffix to keep the repo small — full sizes are recorded below
  and in `analyze_output.txt`).

## Findings

**`changes.csv` total document count grew from 63,866 (2026-08-14) to 64,242
(2026-08-18)** — a net +376 over 4 days, consistent with the ~0.9%/6h,
~1.5%/24h change rate measured separately in `../05-feed-volume/RESULTS.md`.

**Red Hat CSAF/VEX is still organized per-CVE across *all* products, not per-image:**

| File | Size (2026-08-14) | Size (2026-08-18) | Product refs (2026-08-18) |
|---|---:|---:|---:|
| CVE-2025-30204 | 34.8 MB | 34.80 MB | 15,632 |
| CVE-2025-66418 | 8.97 MB | 8.98 MB | 4,945 |
| CVE-2026-42154 | 12.0 MB | 12.04 MB | 4,803 |
| CVE-2026-41603 | 1.24 MB | 1.24 MB | 488 |
| CVE-2025-31936 | 18 KB | 18.2 KB | 10 |

All 5 documents show `document.tracking.version=3` with 3 entries in
`revision_history` today — same revision count as the original test, i.e. no
new revision landed on any of these 5 specific CVEs in the intervening 4 days,
but the mechanism (revised in place, not reissued) is unchanged. A single CVE
file can still reference 15,000+ product/version combinations spanning every
RHEL release and component RH ships. There is no image-scoped sub-document at
all — "image" isn't a concept in the file; it's PURL/CPE-style product IDs in
a product tree.

**Chainguard/Wolfi is organized per-package (not per-image, not per-CVE):**

- `openssl.advisories.yaml` = every advisory ever filed against the `openssl`
  package, across all historical package versions, in one file.
- `security.json` = the entire distro in one file, keyed by package → version
  → CVE list. Package count grew from 1,449 (2026-08-14) to 1,456 (2026-08-18).
- Confirmed live today: `packages.wolfi.dev/os/openvex.json`,
  `.../security.openvex.json`, and `.../openvex/index.json` all return **404**
  — there is no static per-image or per-package OpenVEX feed for Wolfi/Chainguard
  container images.

**Correction from the original 2026-08-14 write-up of this test:** this
document previously said Chainguard "does not publish a static OpenVEX feed
[because] OpenVEX documents are generated on demand by `wolfictl advisory`
tooling from this advisories data." **That on-demand-generation claim is
wrong** — it was superseded by the proposal's later, deeper "sixth finding"
investigation (see `../06-chainguard-vex-investigation/RESULTS.md`), which
built `wolfictl` from source and found its `vex` subcommand is a **dead no-op
stub**, dropped by Chainguard itself in commit `9364dfe9` ("Drop wolfictl
vex", 2023-06-07) — it does not generate OpenVEX on demand or in any other
way. There is no on-demand *or* static OpenVEX path for Wolfi/Chainguard
**container images**. The only real, live OpenVEX feed anywhere in the
Chainguard ecosystem is for **Chainguard Libraries** (remediated PyPI/Java
packages) at `libraries.cgr.dev/openvex/v1/` — re-confirmed live today
(`top-level keys=['packages', 'version', 'updated_at']`) — and that product has
no image concept at all.

## Conclusion

**Reusing `OpenVulnerabilityExchangeContainer` unmodified is still not
workable, re-confirmed with today's live data.** Both real vendor shapes are
the *opposite* of one-doc-per-image:

- Red Hat: one document = one CVE × thousands of products/images.
- Wolfi: one document = one package (or the whole distro) × all its CVEs.
- Chainguard Libraries (the only real Chainguard OpenVEX source that exists):
  one document = one language-ecosystem package, no image concept at all.

Either shape, ingested verbatim, would need a reshape step before it can be
queried per-image at scan time — you cannot efficiently answer "what VEX
applies to image X" by scanning a 34MB single-CVE document or a
1,456-package distro file per scan.

This empirically justifies the proposal's chosen default: reuse the
`OpenVulnerabilityExchangeContainer` *kind* (clientsets, CRD, VEX type tree)
for the *external label/annotation shape*, but reshape-on-ingest into
per-image/per-product records rather than storing vendor documents verbatim.
A pure "one `OpenVulnerabilityExchangeContainer` per image" model doesn't
match either vendor's real publishing shape, so plan for a reshape/indexing
layer rather than assuming direct reuse.
