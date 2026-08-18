# Grype `VexProcessor` behavior — reverification of the "seventh finding"

Reproduces (2026-08-18) the proposal's `Empirical Verification` "seventh finding": the
spike test aimed at closing the Option A (Grype-native VEX) fallback trigger —
whether `vex.NewProcessor` has an in-memory API, and whether its API/behavior
is stable between kubevuln's pinned `github.com/anchore/grype v0.99.1` and
the newer `v0.104.1`. Run with `go test -v ./...` against both versions
already present in the local module cache (`~/go/pkg/mod/github.com/anchore/grype@v0.99.1`
and `@v0.104.1`) — no network needed for the module itself, though `go mod
tidy` pulled the full transitive dependency graph from the public Go module
proxy (see "Dependency footprint" below).

Reproduce with: `go mod tidy && go test -v ./...` in this directory.

## 1. No in-memory API — confirmed, matches original finding

```
vex.NewProcessor(vex.ProcessorOptions{Documents: []string{"/nonexistent/path.json"}})
→ unable to create VEX processor: VEX document "/nonexistent/path.json" not found
```

`getVexImplementation` (`grype/vex/processor.go`) calls `os.Stat` on
`Documents[0]` before anything else. There is no byte-slice/reader
constructor anywhere in `vex.ProcessorOptions` — `Documents` must be real
file paths. **Confirmed, unchanged from the original finding.**

## 2. A single valid document — confirmed

A real, previously-verified OpenVEX fixture (copied from
`../02-grype-version/test.openvex.json`, the same document empirically
confirmed in finding 2 to correctly suppress a real `alpine:3.18` match)
constructs a working processor and runs `ApplyVEX` without error. **Confirmed.**

## 3. Mixed CSAF + OpenVEX in one `Documents` list — corrected, not what the original finding claimed

This is where reverification diverges from the original write-up. The
original finding stated flatly: *"a `Documents` list mixing an OpenVEX file
with a non-OpenVEX file ... fails at `ApplyVEX` time with `unable to detect
document format`."* That is **not accurate** as a general statement — the
actual behavior depends on which format is listed first, and the quoted
error string doesn't appear anywhere in grype's own source in either
version (confirmed via `grep -rn "unable to detect document format"` against
both `~/go/pkg/mod/github.com/anchore/grype@v0.99.1` and `@v0.104.1` — zero
matches in grype itself; it lives one dependency layer down, in
`github.com/openvex/go-vex`'s `Open()`).

Using two real, previously-verified fixtures
(`../02-grype-version/test.openvex.json` and `test.csaf.json`, copied here
as `valid_openvex_fixture.json` / `valid_csaf_fixture.json`):

| Ordering | Result | Actual error |
|---|---|---|
| `[csaf, openvex]` | **Fails** | `parsing vex document: error loading VEX CSAF document: 'document' is missing` |
| `[openvex, csaf]` | **Succeeds, no error** | — |

Why the asymmetry, traced through the real source in both versions:

- `getVexImplementation` picks an implementation based on **`Documents[0]`
  only** (`csaf.IsCSAF` checked before `openvex.IsOpenVex`), then hands the
  **entire** `Documents` list to that one implementation's
  `ReadVexDocuments`.
- **CSAF-first:** `csaf.Processor.ReadVexDocuments` calls
  `csaf.LoadAdvisory` (from `github.com/gocsaf/csaf/v3`) on every path in the
  list, including the OpenVEX one. `LoadAdvisory` does strict JSON parsing
  plus full CSAF schema `Validate()`. The OpenVEX document has no top-level
  `document` object, so validation fails immediately with `'document' is
  missing` — a real, hard failure, just not the string the original finding
  quoted.
- **OpenVEX-first:** `openvex.Processor.ReadVexDocuments` calls
  `openvex.MergeFiles(docs)` (from `github.com/openvex/go-vex`), which opens
  **each file independently** via its own `Open()` function — not grype's
  `getVexImplementation`. That `Open()` first checks for an OpenVEX
  `@context` locator; if that's absent, it falls back to checking whether
  the raw bytes contain the literal substring `"csaf_version"`, and if so
  calls `OpenCSAF()`, which walks the CSAF product tree and **silently
  converts it into OpenVEX `Statement`s** inline. So a trailing CSAF file
  in an OpenVEX-first list isn't rejected — it's transparently absorbed
  through a second, independent CSAF-to-OpenVEX conversion path that lives
  in the `go-vex` dependency, not in grype's own `csaf` package.

This directly affects the proposal's `applyExternalVEXByFormat` design (see
`proposal_kv.md`, Scan Pipeline Join): grouping documents by format before
constructing a `vex.Processor` is still the correct, predictable thing to
do — relying on ordering-dependent, partially-undocumented cross-format
absorption behavior in a transitive dependency would be fragile and, in the
CSAF-first case, an outright bug (the whole batch fails, not just the
malformed member). But the *reason* to group by format is subtly different
from what the original finding said: it's not "mixing formats reliably
fails with a clear error" — it's "mixing formats fails unpredictably
(hard error one way, silent reinterpretation through a different code path
the other way), and neither behavior is one an integrator should rely on."

The literal string `"unable to detect document format"` **does** exist for
real, but only fires when a file is neither valid-context-tagged OpenVEX nor
contains a `csaf_version` marker at all — i.e., not a VEX document of any
supported kind, not "a document in the *other* supported format":

```
vex.NewProcessor(Documents: [validOpenVEX, garbageJSON]) → ApplyVEX
→ parsing vex document: merging vex documents: opening garbage_fixture.json:
  unable to detect document format reading garbage_fixture.json
```

## 4. Version stability, v0.99.1 → v0.104.1 — corrected, real drift found

The original finding claimed the `VexProcessor`/`VulnerabilityMatcher` API
"is byte-for-byte identical across that range — no version-compatibility
drift found." Reverified today with a direct file diff between the two
locally-cached module source trees:

| File | Result |
|---|---|
| `grype/vex/processor.go` | **Identical** (`processor_diff.txt` is empty) |
| `grype/vex/csaf/implementation.go` | **Identical** (`csaf_implementation_diff.txt` is empty) |
| `grype/vex/openvex/implementation.go` | **Changed**, 44-line diff (`openvex_implementation_diff.txt`) |
| `grype/vulnerability_matcher.go` (`VulnerabilityMatcher`) | **Changed**, 51-line diff (`matcher_diff.txt`) |

The `processor.go` public surface this project actually calls
(`NewProcessor`, `ProcessorOptions`, `ApplyVEX`) is unchanged — that part of
the original claim holds. But two files this project's design directly
depends on are **not** identical:

- **`openvex/implementation.go`**: v0.104.1 adds a fallback so
  `productIdentifiersFromContext` no longer immediately errors
  (`"source type not supported for VEX"`) for a non-image source with a
  name+version — it now emits a synthetic `pkg:generic/<name>@<version>`
  identifier. It also adds `productIdentifierFromVEX`, which falls back to
  reading product `@id`s straight out of the VEX document itself when
  context-derived identifiers come back empty. Both changes are additive
  and backward-compatible (existing image-based matching is untouched), but
  they are real behavior changes an integrator pinned to v0.99.1 does not
  get — relevant if kubevuln's `ScanOptions.ExternalVEX` sources ever
  include non-image (`purlMatch`-only) statements, since that's exactly the
  code path this change touches.
- **`vulnerability_matcher.go`**: v0.104.1 reworks internal ignore-rule
  indexing (`ignoreRulesByLocation` → `ignoreRulesByIndex`) to also index by
  package name, not just file location, plus unrelated `//nolint` comments
  on deprecated-API calls. This is internal to match/ignore-rule filtering,
  not the public VEX API surface, but it is a real code change between the
  two versions, not a no-op diff.

**Conclusion for finding 4:** "no version-compatibility drift" is not
accurate as an unqualified statement. The specific public functions this
project's design sketch (`buildGrypeVEXProcessor`, `applyExternalVEXByFormat`)
calls are stable, but the surrounding VEX-matching internals have moved in
ways that would matter for the `purlMatch`-only / non-image source case the
proposal itself introduces (Chainguard Libraries). This doesn't block v1
(kubevuln stays pinned to v0.99.1, per the existing recommendation), but the
proposal's Risk Management row for a "future Grype major-version break"
should be read as covering minor/patch releases too, not just majors — real
drift was found within `v0.99.x`→`v0.104.x`, a minor-version range.

## Conclusion for the proposal's Option A fallback trigger

- **Input format (no in-memory API):** confirmed, unchanged.
- **Mixing CSAF and OpenVEX in one processor:** real problem confirmed, but
  the mechanism and error message in the original finding were wrong for the
  OpenVEX-first case (silent absorption, not a raised error) and imprecise
  for the CSAF-first case (a schema-validation error, not "unable to detect
  document format"). The design recommendation to group by format before
  constructing a processor stands, now for a more precise reason: not just
  "it fails," but "it fails one way and silently reinterprets the other way,
  and neither is safe to depend on."
- **Version compatibility:** **not** closed the way the original finding
  claimed. Two files this design depends on changed between v0.99.1 and
  v0.104.1. Nothing here blocks shipping Option A against the currently
  pinned v0.99.1, but "closed, no drift" should be corrected to "stable for
  the specific functions called, but the surrounding implementation has
  measurably changed within a minor-version range" in the proposal text.

## Dependency footprint (side observation)

`go mod tidy` for a module that imports only `github.com/anchore/grype/grype/vex`,
`.../grype/match`, and `.../grype/pkg` still resolved a ~14,000-line `go.mod`
with the full grype transitive dependency graph (cloud SDKs, container
runtimes, license/SBOM tooling, etc.) — grype does not appear to offer a
lighter-weight import path for just the VEX subpackage. Not a blocker (kubevuln
already depends on all of `grype` today), but worth knowing before assuming a
narrow `vex`-only import keeps kubevuln's own dependency tree small.

## Files in this directory

- `processor_test.go` — the 4 reproduced test cases, using `go.mod` pinned to
  `github.com/anchore/grype v0.99.1` (matching kubevuln's own pin).
- `valid_openvex_fixture.json`, `valid_csaf_fixture.json` — copied verbatim
  from `../02-grype-version/` (already empirically verified fixtures), reused
  here rather than re-authoring new ones, so a fixture-authoring mistake
  can't be mistaken for a grype behavior finding.
- `garbage_fixture.json` — deliberately not a VEX document in any format.
- `test_output.txt` — captured `go test -v ./...` output.
- `processor_diff.txt`, `csaf_implementation_diff.txt` — empty (no diff) between v0.99.1 and v0.104.1.
- `openvex_implementation_diff.txt`, `matcher_diff.txt` — real diffs found between v0.99.1 and v0.104.1.
