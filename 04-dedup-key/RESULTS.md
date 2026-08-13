# Dedup Key — Empirical Findings

## Data used
- 5 real Red Hat CSAF/VEX documents fetched live from
  `https://security.access.redhat.com/data/csaf/v2/vex/2024/` (cve-2024-0056,
  0057, 0109, 3094, 6387). Raw files in `samples/`.
- Real product-tree entries from those documents (2,163 leaf products in one
  document alone).
- Chainguard/Wolfi: `https://packages.wolfi.dev/os/openvex.json` and
  `.../security.openvex.json` both returned **404** — no live OpenVEX feed
  endpoint was found in a reasonable search window. Substituted the OpenVEX
  spec's canonical worked example, fetched live from
  `raw.githubusercontent.com/openvex/spec/main/OPENVEX-SPEC.md`, which defines
  the exact JSON shape Chainguard's tooling emits. This is a real published
  spec example, not an invented one, but it is **not a live Chainguard fetch**
  — flagging as a gap if a real Chainguard feed URL surfaces later.

## What the real data shows

**1. Red Hat documents are one-per-CVE, revised in place, not re-issued as new files.**
Every sample has `document.tracking.id == <CVE-ID>` and a `version` counter
(observed at 3) with a matching `revision_history` array recording each edit
timestamp. The URL and `id` for CVE-2024-6387 has been the same since 2024-07-01
even though it was revised again on 2026-03-16 and 2026-07-14. **A pure
content-hash dedup key would treat every one of those revisions as a brand-new
statement set**, permanently accumulating stale `IgnoredMatches` entries
instead of updating them.

**2. Neither CSAF nor OpenVEX statements carry a per-statement ID field.**
- CSAF: `vulnerabilities[].id` was `None`/absent in all 5 real documents —
  identity of a "statement" only exists implicitly as the tuple
  `(document.tracking.id, product_status_category, product_id)`.
- OpenVEX (per spec, statement struct definition + worked example): a
  `statement` has `vulnerability`, `products`, `status`, `justification`, but
  **no id field**. Identity is `(document["@id"], vulnerability.name, product
  purl)`.

This confirms the proposal's assumption that "statement ID" as a standalone
field does not exist in practice — it must be derived.

**3. PURLs are present and usable as the product-matching key.**
2,143 of 2,163 leaf products (99%) in the Ceph/OpenSSH sample carry a real
`pkg:rpm/...` PURL in `product_identification_helper.purl`; only 20 (all
platform-level, not package-level) carry CPE only. This is strong empirical
support for using PURL as the product-scoping key rather than image-reference
globbing alone (this directly informs the separate "scope matching" doubt too).

## Recommended dedup key (concrete, derived from observed fields)

```
dedup_key = sha256(
    lower(source_name)                     # VEXSource that produced it
  + "\x00" + document_tracking_id          # e.g. "CVE-2024-6387" (stable across revisions)
  + "\x00" + upper(vulnerability_id)        # CVE-2024-6387
  + "\x00" + normalized_product_purl_set    # sorted set of pkg: PURLs, not image ref
  + "\x00" + status                         # not_affected | fixed
)
```

Critically, **`document.tracking.version` (or `revision_history` length) must
be tracked as metadata alongside this key, not folded into the hash itself.**
Use it to decide "replace" vs "new": same `dedup_key` + higher `version` ⇒
update existing `IgnoredMatches`/provenance record in place; same `dedup_key`
+ same `version` ⇒ true no-op skip. Folding version into the hash (as the
original proposal's `statementKey()` sketch implicitly risked, since it hashed
`stmt.Status` etc. with no revision awareness) would cause every legitimate Red
Hat revision to look like a "new" statement rather than an update, which is a
real observed pattern here (3 revisions on 3 separate real documents in this
5-document sample).

## Gaps / follow-up
- Could not confirm a live Chainguard OpenVEX feed URL in this pass — needs a
  correct endpoint before repeating this test against real Chainguard data
  rather than the spec example.
- Did not test cross-source dedup (Red Hat vs. a hypothetical second CSAF
  vendor emitting overlapping CVE coverage for the same product) since only
  one real vendor feed was reachable.
