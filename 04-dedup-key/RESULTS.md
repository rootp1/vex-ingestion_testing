# Dedup Key — Empirical Findings

**Re-verified live on 2026-08-18** (original test: 2026-08-14). Reproduce with
the commands at the bottom of this file, then `python3 parse_dedup_fields.py`.

## Data used
- 5 real Red Hat CSAF/VEX documents fetched live from
  `https://security.access.redhat.com/data/csaf/v2/vex/2024/` (cve-2024-0056,
  0057, 0109, 3094, 6387). Raw files in `samples/`. **Byte-for-byte identical**
  to the 2026-08-14 fetch — Red Hat has not revised any of these 5 documents
  again in the 4 days since the original test, consistent with the low
  change-rate finding in `../05-feed-volume/`.
- Real Chainguard Libraries OpenVEX feed, fetched live from
  `https://libraries.cgr.dev/openvex/v1/index.json` (207 packages) and one
  real package document, `pypi/werkzeug.openvex.json`. This replaces the
  earlier draft of this test, which could not find a live Chainguard OpenVEX
  endpoint and substituted the OpenVEX spec's abstract worked example instead
  — that gap is now closed by the "sixth finding" investigation (see
  `../06-chainguard-vex-investigation/`), which located this real feed.

## What the real data shows

**1. Red Hat documents are one-per-CVE, revised in place, not re-issued as new files.**
Every sample has `document.tracking.id == <CVE-ID>` and a `version` counter
(observed at 3 in all 5 samples, unchanged from the 2026-08-14 test) with a
matching `revision_history` array of length 3 recording each edit timestamp.
`CVE-2024-3094`'s most recent revision timestamp is `2026-08-04T07:05:53Z` —
after the original test date — confirming Red Hat does actively revise these
documents over time, in place, under the same `document.tracking.id`, exactly
as the dedup key design assumes. **A pure content-hash dedup key would treat
every one of those revisions as a brand-new statement set.**

**2. Neither CSAF nor real Chainguard OpenVEX statements carry a per-statement ID field.**
- CSAF: `vulnerabilities[].id` was absent (`has_stmt_id: False`) in all 5 real
  documents — identity of a "statement" only exists implicitly as the tuple
  `(document.tracking.id, product_status_category, product_id)`.
- OpenVEX, confirmed against a **real Chainguard Libraries statement** (not
  the spec's abstract example, as the earlier draft used): the two real
  statements in `pypi/werkzeug.openvex.json` have exactly the keys
  `{vulnerability, products, status, timestamp, last_updated}` — no `id`
  field. Identity is `(document["@id"], vulnerability.name, product purl)`.
  The Chainguard document itself also carries a `version` counter (`1`) and
  `timestamp`/`last_updated` fields, but **no `revision_history` array** the
  way CSAF does — so revision tracking for Chainguard documents would need to
  key off `last_updated` changing, not a structured history list.

This confirms the proposal's assumption that "statement ID" as a standalone
field does not exist in practice, now checked against two independent real
vendor feeds (Red Hat CSAF and Chainguard Libraries OpenVEX) rather than one
real feed plus a spec example.

**3. PURLs are present and usable as the product-matching key — percentage unchanged.**
2,143 of 2,163 leaf products (**99.08%**, unchanged from the 2026-08-14
result since the source file is byte-identical) in the CVE-2024-6387 sample
carry a real `pkg:rpm/...` PURL in `product_identification_helper.purl`; the
remaining 20 are platform-level entries with CPE only. This remains strong
empirical support for using PURL as the product-scoping key rather than
image-reference globbing alone (see the `03-scope-matching` test).

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
`stmt.Status` etc. with no revision awareness) would cause every legitimate
revision to look like a "new" statement rather than an update — a real,
observed pattern (all 5 real documents here carry 3 revisions each, and
`CVE-2024-3094` revised again just two weeks before this re-verification).

For Chainguard Libraries documents specifically, since there's no
`revision_history` array, use `last_updated` (document-level) as the
"did this change" signal instead of a revision count.

## Gaps / follow-up
- Did not test cross-source dedup (Red Hat vs. a hypothetical second CSAF
  vendor emitting overlapping CVE coverage for the same product) since only
  one real CSAF vendor feed was reachable in this pass.
- The Chainguard `revision_history`-vs-`last_updated` distinction above is a
  new observation from this re-verification pass, not present in the
  2026-08-14 draft — worth folding into the proposal's Format Normalization /
  Dedup Key sections if a maintainer wants Chainguard-specific staleness
  tracking beyond the generic `staleAfter` TTL.

## Reproduce

```bash
BASE="https://security.access.redhat.com/data/csaf/v2/vex/2024"
for cve in cve-2024-0056 cve-2024-0057 cve-2024-0109 cve-2024-3094 cve-2024-6387; do
  curl -sL -o "samples/${cve}.json" "$BASE/${cve}.json"
done
curl -sL -o samples/chainguard_libraries_index.json "https://libraries.cgr.dev/openvex/v1/index.json"
curl -sL -o samples/chainguard_werkzeug.openvex.json "https://libraries.cgr.dev/openvex/v1/pypi/werkzeug.openvex.json"
python3 parse_dedup_fields.py
```
