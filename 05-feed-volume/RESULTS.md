# Feed Volume — Empirical Results

Originally tested against the live feed at `https://security.access.redhat.com/data/csaf/v2/vex/`
on 2026-08-14. **Re-verified live on 2026-08-18** by re-running `./measure.sh`
(script unchanged — no fixes needed, ran cleanly against today's live feed).
Reproduce with `./measure.sh`.

## Findings (2026-08-18 re-run)

1. **`changes.csv` still exists and is still exactly the incremental cursor
   the proposal relies on.** Total documents currently tracked: **64,243**
   (up from 63,867 on 2026-08-14 — a net increase of ~376 documents in 4 days,
   consistent with a live, continuously-updated vendor feed rather than a
   static snapshot; growth direction and rough rate match expectations from
   the original measurement).

2. **Document size is still highly skewed, not uniform.** Fresh random
   sample of 30 documents across all years: sizes ranged from 4.2 KB to
   1.54 MB. **avg ~234.6 KB/doc** (vs. ~321 KB/doc on 2026-08-14 — same order
   of magnitude; the difference is sampling noise from a 30-document random
   draw against a heavy-tailed size distribution, not a change in the feed's
   underlying shape).

3. **Estimated full-feed size: ~15.4 GB** (64,243 docs × ~234.6 KB avg) —
   same order of magnitude as the original ~21 GB estimate; both estimates
   depend heavily on which large outlier documents happen to land in a
   30-document random sample, but both agree the feed is in the low tens of
   GB, not MB.

4. **Change rate is still tiny relative to feed size:**
   - Last 6h: **292** docs (0.45% of feed) — vs. 575 (0.9%) on 2026-08-14
   - Last 24h: **913** docs (1.42%) — vs. 929 (1.5%)
   - Last 7 days: **2,702** docs (4.21%) — vs. 2,849 (4.5%)
   - Last 30 days: **11,229** docs (17.48%) — vs. 10,904 (17%)

   The 24h/7d/30d figures are nearly identical to the 2026-08-14 run (within
   ~1 percentage point); the 6h figure is lower this time, which is expected
   variance for a short window sampled at a different point in Red Hat's
   publishing cadence (e.g. whether a batch of revisions happened to land
   just before or just after the snapshot instant), not a contradiction of
   the original finding.

## Conclusion (reaffirmed)

**Incremental fetch is still empirically necessary, not a nice-to-have.**
Four days apart, two independent live measurements agree on every material
point: the feed is tens of thousands of documents totaling low-tens-of-GB,
and only ~0.4-1.5% of it changes in any 6-24h window. Full re-sync per cycle
still means pulling multiple GB of JSON every 6 hours indefinitely, while
`changes.csv` still gives the controller a ready-made cursor: sort by the
second column (timestamp), remember the last-processed timestamp/row, and
only fetch documents newer than that.

Recommendation for the proposal is unchanged: consume `changes.csv` directly
as the sync cursor from day one — it requires no extra design work since Red
Hat already publishes it at a stable, well-known path, and this re-verification
confirms that path and its shape are stable over time, not a one-off fluke of
the original test.

## Caveats

- Sizes were measured via `curl` `%{size_download}` (i.e. full GET, not HEAD —
  Red Hat's CSAF endpoint did not appear to support cheap HEAD-based size
  probing reliably, so full downloads were used for the 30-doc random sample),
  same methodology as the original run.
- A 30-document random sample is small relative to a 64k-document, heavy-tailed
  feed, so the ~15.4 GB vs ~21 GB estimates should be read as "low tens of GB,
  order of magnitude confirmed twice" rather than a precise figure — this
  variance between two independent runs is itself useful evidence that a
  single point estimate shouldn't be over-trusted, but the qualitative
  conclusion (full sync is expensive, incremental via `changes.csv` is cheap)
  is robust to it.
- This measured Red Hat CSAF only, same scope as the original test.
- Raw artifacts from this re-run overwrote the originals in this directory
  (`changes.csv`, `all_paths.txt`, `random_paths.txt`, `head_sizes.txt`) —
  the script always re-fetches fresh data on each run, which is the point of
  re-running it as a reverification rather than reusing cached output.
