# Feed Volume — Empirical Results

Tested against the live feed at `https://security.access.redhat.com/data/csaf/v2/vex/`
on 2026-08-14. Reproduce with `./measure.sh`.

## Findings

1. **`changes.csv` exists and is exactly the incremental cursor the proposal
   speculated about.** It lists every document path with a per-file
   last-modified timestamp, one row per CVE, going back to CVE IDs from 2001.
   Total documents currently tracked: **63,867**.

2. **Document size is highly skewed, not uniform.** A naive sample of the
   *most recently changed* documents (top of `changes.csv`) averaged ~5.1 MB,
   with outliers up to 34.8 MB — these are CVEs affecting huge numbers of RHEL
   product/version combinations (one file had 3,850 `fixed` + 66
   `known_affected` + 11,715 `known_not_affected` product entries for a
   *single* CVE). A random sample across all years is more representative:
   **avg ~321 KB/doc**.

3. **Estimated full-feed size: ~21 GB** (63,867 docs × ~321 KB avg).
   Fetching that in full on every refresh cycle (the proposal's example is
   every 6h) is not reasonable for an in-cluster controller.

4. **Change rate is tiny relative to feed size:**
   - Last 6h: **575** docs changed (0.9% of the feed)
   - Last 24h: **929** docs (1.5%)
   - Last 7 days: **2,849** docs (4.5%)
   - Last 30 days: **10,904** docs (17%)

## Conclusion

**Incremental fetch is empirically necessary, not a nice-to-have.** Full
re-sync per cycle means pulling ~21 GB of JSON every 6 hours indefinitely,
while `changes.csv` already gives the controller a ready-made cursor: sort by
the second column (timestamp), remember the last-processed timestamp/row, and
only fetch documents newer than that. At a 6h refresh interval this reduces
each sync from ~21 GB / 63,867 docs down to ~575 docs (~185 MB by the random-
sample average, though actual bytes will skew higher since actively-changing
CVEs tend to be the large multi-product ones).

Recommendation for the proposal: drop "full sync + content hash no-op" as the
v1 default fetch strategy for Red Hat CSAF specifically, and instead consume
`changes.csv` directly as the sync cursor from day one — it requires no extra
design work since Red Hat already publishes it at a stable, well-known path.

## Caveats

- Sizes were measured via `curl` `%{size_download}` (i.e. full GET, not HEAD —
  Red Hat's CSAF endpoint did not appear to support cheap HEAD-based size
  probing reliably, so full downloads were used for the 30-doc random sample).
- The "most recent" sample (15 docs, not included in final numbers) skewed
  the average up by ~16x vs. the random sample — recency-biased sampling is
  not representative of the whole feed and should be avoided when estimating
  aggregate storage/bandwidth needs.
- This measured Red Hat CSAF only. Chainguard's OpenVEX feed was out of scope
  for this specific test (see the *storage-shape* test folder for OpenVEX
  data), but Chainguard's feed is known to be far smaller (per-image, not
  per-product-matrix), so it is unlikely to need the same incremental
  treatment as urgently.
