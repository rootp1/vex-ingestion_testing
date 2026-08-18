# vex-ingestion_testing

Empirical scratch-testing for open doubts in the "External VEX Ingestion for
Kubescape Vulnerability Scanning" proposal (see .vscode/proposal_kv.md in the
main repo). Each subdirectory tests one doubt against real vendor feed data
rather than deciding it by discussion alone.

| Dir | Doubt being tested |
|---|---|
| 01-storage-shape | Does real Red Hat CSAF / Chainguard OpenVEX data fit `OpenVulnerabilityExchangeContainer`'s one-doc-per-image assumption? |
| 02-grype-version | Does the currently pinned Grype version correctly ingest real CSAF/OpenVEX via `--vex`? |
| 03-scope-matching | Does image-reference globbing alone cause false suppressions vs PURL matching? |
| 04-dedup-key | What statement/document identifiers are actually stable across real overlapping feed data? |
| 05-feed-volume | How large is the real Red Hat CSAF feed, and is incremental fetch actually necessary? |
| 06-chainguard-vex-investigation | Does a live OpenVEX feed exist for Chainguard/Wolfi *container images* (the mentorship listing's own assumption)? |
| 07-vexprocessor-behavior | Is Grype's `VexProcessor` file-based only, and is its API/behavior stable between the pinned v0.99.1 and v0.104.1 (the Option A fallback trigger)? |
