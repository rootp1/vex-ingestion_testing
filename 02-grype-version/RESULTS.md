# Doubt: Grype version — is a Grype upgrade required for CSAF/OpenVEX ingestion?

## Answer: No upgrade required. Empirically verified working on the currently pinned version.

## What was tested

1. **Pinned version check**: `kubevuln`'s `go.mod` (main branch) pins
   `github.com/anchore/grype v0.99.1`.
2. **Built the exact pinned binary**: `go install github.com/anchore/grype/cmd/grype@v0.99.1`
   succeeded in this sandbox (network + go toolchain available). Verified via
   `go version -m $(go env GOPATH)/bin/grype` that the binary's `mod` line
   reports exactly `v0.99.1`.
3. **Real scan**: ran `grype alpine:3.18 -o json` (pulled the real public image,
   no mocks) → 14 vulnerability matches, including `CVE-2025-60876` (busybox /
   busybox-binsh / ssl_client) and `CVE-2026-40200` (musl / musl-utils).
   See `scan_alpine.json`.
4. **OpenVEX suppression test** (`test.openvex.json`): built a real OpenVEX
   0.2.0 document marking `CVE-2025-60876` `not_affected` for the exact
   product identifier grype expects — the image's **RepoDigest string itself**
   (`index.docker.io/library/alpine@sha256:...`), with `subcomponents` being
   the exact package PURLs grype reported. Re-ran:
   `grype alpine:3.18 --vex test.openvex.json -o json`
   → matches dropped from 14 to 11, and the 3 busybox-family matches moved to
   `ignoredMatches` with `appliedIgnoreRules: [{namespace: vex, vex-status: not_affected}]`.
   See `scan_alpine_vex.json`.
5. **CSAF suppression test** (`test.csaf.json`): built a CSAF 2.0 VEX document
   (product_tree + `known_not_affected` status) targeting the real
   `CVE-2026-40200` / musl PURL from the same scan. Re-ran with
   `--vex test.csaf.json` → matches dropped from 14 to 13, `musl` moved to
   `ignoredMatches` with the same `vex-status: not_affected` rule.
   See `scan_alpine_csaf.json`.

## Key implementation detail discovered (important for the proposal's kubevuln integration)

- OpenVEX product matching in Grype v0.99.1 is **not** purl-of-the-image-based;
  it matches against a list of identifiers built from the image's **tags and
  RepoDigests** (`grype/vex/openvex/implementation.go` →
  `productIdentifiersFromContext` / `identifiersFromDigests`). The simplest
  reliable product `@id` to emit from an external VEX source is the image's
  RepoDigest string verbatim (`registry/repo@sha256:...`), not a synthesized
  `pkg:oci/...` purl — although grype also derives and accepts an equivalent
  `pkg:oci/<name>@sha256:<digest>?repository_url=...` purl and the bare hex
  digest as alternates.
- Subcomponent matching is exact-string match against `match.Package.PURL`,
  so the external VEX ingestion pipeline's normalizer must reproduce package
  PURLs in the identical qualifier format grype/syft generates
  (arch, distro, upstream qualifiers all matter).
- CSAF matching is purl-only (no image-level wrapper needed) — it walks the
  advisory's `product_tree` to resolve a `product_id` to a purl via
  `product_identification_helper.purl`, then matches CVE + purl directly.
  This is simpler to normalize than OpenVEX's image+subcomponent shape.
- Both statuses cleanly produced `ignoredMatches` with populated
  `appliedIgnoreRules`, confirming the proposal's assumption that Grype-native
  `--vex` consumption (Option A / the "prefer Grype-native VEX consumption"
  default in the proposal) is viable on the currently pinned version — no
  Grype upgrade is required to unblock this project.

## Conclusion for the proposal's "Grype version" doubt

**No upgrade needed.** v0.99.1 (already pinned) fully supports both OpenVEX
and CSAF `--vex` ingestion and correctly produces provenance-bearing
`ignoredMatches`. This can be marked resolved in the proposal without needing
a maintainer decision — it was project risk, not a preference, and is now
empirically closed.

## Artifacts in this directory

- `test.openvex.json`, `test.csaf.json` — hand-built VEX documents targeting
  real CVEs/packages from an actual `alpine:3.18` scan.
- `scan_alpine.json` — baseline scan, no VEX.
- `scan_alpine_vex.json` — scan with OpenVEX suppression applied.
- `scan_alpine_csaf.json` — scan with CSAF suppression applied.
- `install.log` — `go install` output for the pinned grype version.
