# Doubt: Grype version — is a Grype upgrade required for CSAF/OpenVEX ingestion?

## Answer: No upgrade required. Empirically re-verified on 2026-08-18 (originally tested 2026-08-14).

## What was tested (reproduced live, today)

1. **Pinned version check**: `kubevuln`'s `go.mod` (checked directly at
   `/Users/rootp1/Documents/repos/kubevuln/go.mod`, line 11) still pins
   `github.com/anchore/grype v0.99.1` — unchanged since the original test.
2. **Built the exact pinned binary**: `go install github.com/anchore/grype/cmd/grype@v0.99.1`
   succeeded. Verified via `go version -m $(go env GOPATH)/bin/grype` that the
   binary's `mod` line reports exactly
   `github.com/anchore/grype v0.99.1 h1:C2Ylg32IRqCt07e9MKqTUed6gOa8C5TZ51W5RYSaPT4=`.
3. **Real scan**: ran `grype alpine:3.18 -o json` (pulled the real public image,
   no mocks) → **14 vulnerability matches**, identical set to the original
   2026-08-14 run: `CVE-2025-60876` (busybox / busybox-binsh / ssl_client),
   `CVE-2026-40200` (musl / musl-utils), plus `CVE-2026-27171` (zlib),
   `CVE-2026-6042` (musl / musl-utils), `CVE-2025-46394` and `CVE-2024-58251`
   (busybox family). See `scan_alpine.json`. Image resolved to
   `index.docker.io/library/alpine@sha256:de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f`
   (grype's DB was flagged `WARN ... database is invalid ... built 5 days ago`
   but still ran and produced results — not a blocker for this test).
4. **OpenVEX suppression test** (`test.openvex.json`): built a real OpenVEX
   0.2.0 document marking `CVE-2025-60876` `not_affected` for the exact
   product identifier grype expects — the image's **RepoDigest string itself**
   (`index.docker.io/library/alpine@sha256:de0eb0...`), with `subcomponents`
   being the exact package PURLs grype reported today. Re-ran:
   `grype alpine:3.18 --vex test.openvex.json -o json`
   → matches dropped from 14 to 11, and the 3 busybox-family matches moved to
   `ignoredMatches` with `appliedIgnoreRules: [{namespace: vex, vex-status: not_affected}]`.
   See `scan_alpine_vex.json`.
5. **CSAF suppression test** (`test.csaf.json`): built a CSAF 2.0 VEX document
   (product_tree + `known_not_affected` status) targeting the real
   `CVE-2026-40200` / musl PURL from today's scan. Re-ran with
   `--vex test.csaf.json` → matches dropped from 14 to 13, `musl` moved to
   `ignoredMatches` with the same `vex-status: not_affected` rule.
   See `scan_alpine_csaf.json`.

## Key implementation detail discovered (important for the proposal's kubevuln integration)

Re-inspected `grype/vex/openvex/implementation.go` in the pinned `v0.99.1`
module source (`~/go/pkg/mod/github.com/anchore/grype@v0.99.1/`) directly
today — the finding below is unchanged from the original test:

- OpenVEX product matching in Grype v0.99.1 is **not** purl-of-the-image-based;
  `productIdentifiersFromContext` builds a list of identifiers from the
  image's **tags and RepoDigests** (`identifiersFromTags` /
  `identifiersFromDigests`) read off `pkg.Context.Source.Metadata` (a
  `source.ImageMetadata`). The simplest reliable product `@id` to emit from an
  external VEX source is the image's RepoDigest string verbatim
  (`registry/repo@sha256:...`), not a synthesized `pkg:oci/...` purl —
  although `identifiersFromDigests` also derives and appends an equivalent
  `pkg:oci/<name>@sha256:<digest>?repository_url=...`-style purl as an
  alternate identifier when the digest reference parses.
- Subcomponent matching is exact-string match against `match.Package.PURL`,
  so the external VEX ingestion pipeline's normalizer must reproduce package
  PURLs in the identical qualifier format grype/syft generates (arch, distro,
  upstream qualifiers all matter — confirmed again today: `arch=aarch64`,
  `distro=alpine-3.18.12`, `upstream=busybox` all had to match exactly for the
  suppression to fire).
- CSAF matching is purl-only (no image-level wrapper needed) — it resolves a
  `product_id` to a purl via `product_identification_helper.purl`, then
  matches CVE + purl directly. This is simpler to normalize than OpenVEX's
  image+subcomponent shape.
- Both statuses cleanly produced `ignoredMatches` with populated
  `appliedIgnoreRules` again today, confirming the proposal's assumption that
  Grype-native `--vex` consumption (Option A / the "prefer Grype-native VEX
  consumption" default in the proposal) is viable on the currently pinned
  version — no Grype upgrade is required to unblock this project.

## Conclusion for the proposal's "Grype version" doubt

**No upgrade needed — reconfirmed.** v0.99.1 (still the pinned version as of
2026-08-18) fully supports both OpenVEX and CSAF `--vex` ingestion and
correctly produces provenance-bearing `ignoredMatches`, with results
consistent with the original 2026-08-14 test run (same 14 baseline matches,
same suppression counts). This can be marked resolved in the proposal without
needing a maintainer decision — it was project risk, not a preference, and
remains empirically closed.

## Artifacts in this directory

- `test.openvex.json`, `test.csaf.json` — hand-built VEX documents targeting
  real CVEs/packages from today's actual `alpine:3.18` scan.
- `scan_alpine.json` / `scan_alpine.log` — baseline scan, no VEX.
- `scan_alpine_vex.json` / `scan_alpine_vex.log` — scan with OpenVEX suppression applied.
- `scan_alpine_csaf.json` / `scan_alpine_csaf.log` — scan with CSAF suppression applied.
- `install.log` — `go install` output for the pinned grype version.

Reproduce with:
```bash
go install github.com/anchore/grype/cmd/grype@v0.99.1
export PATH="$PATH:$(go env GOPATH)/bin"
grype alpine:3.18 -o json > scan_alpine.json
grype alpine:3.18 --vex test.openvex.json -o json > scan_alpine_vex.json
grype alpine:3.18 --vex test.csaf.json -o json > scan_alpine_csaf.json
```
