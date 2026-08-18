# Chainguard/Wolfi VEX Investigation — Empirical Result

**Question:** Does a live OpenVEX feed exist for Chainguard/Wolfi *container
images*, as the mentorship listing's own scope originally assumed?

**Answer: No.** Re-run live on 2026-08-18. Every one of the six steps below
reproduced exactly as the proposal's "sixth finding" describes, with the
scripts in this folder as the reproducible evidence (previously this finding
was prose-only in the proposal).

## Method, reproduced step by step

### 1. `wolfictl vex package` against a real melange config (`01_wolfictl_build_and_run.sh`)

Built `wolfictl` from source (`go build ./` against a fresh clone of
`wolfi-dev/wolfictl`), fetched the real, current `openssl.yaml` from
`wolfi-dev/os`, and ran `wolfictl vex package --author=... openssl.yaml`
against it.

**Result:** exit code `0`, **zero bytes of output** — not even the
`"Did nothing!"` log line the source code below would suggest (it appears to
be swallowed by wolfictl's root logger setup at the default `WARN` log
level). This is a stronger no-op than the original finding described: the
command is not just functionally inert, it's silent too.

### 2. Reading the stub source (`02_inspect_vex_stub_source.sh`)

Fetched the current `pkg/cli/vex.go` from `wolfi-dev/wolfictl` (saved at
`samples/wolfictl_pkg_cli_vex.go`). Confirmed both `vex package` and
`vex sbom` are marked `Deprecated: "This command does nothing, and will be
removed in a future version."` and their `RunE` bodies are literally:

```go
RunE: func(_ *cobra.Command, _ []string) error {
    log.Print("Did nothing!")
    return nil
},
```

Unchanged from the original finding.

### 3. The commit that dropped VEX support (`03_git_history_drop_commit.sh`)

Queried the GitHub API directly for commit `9364dfe924ac4c80484492f523008fab1eb634a1`
(saved at `samples/commit_9364dfe.json`) rather than doing a full history
clone. Confirmed real:

- **Date:** 2023-06-07T16:19:16Z
- **Author:** Jon Johnson \<jon.johnson@chainguard.dev\>
- **Message:** *"Drop wolfictl vex — The vex command depends on things
  within melange that have been removed, and we no longer use the vex
  command ourselves, so we have to drop it in order to bump melange."*
- **Files changed:** `pkg/cli/vex.go` and the entire `pkg/vex/` package
  (generator + its testdata) — this was a real removal of working code, not
  a stub that was always empty.
- Confirmed reachable from `main` (`compare/main...9364dfe...` → `behind`,
  i.e. an ancestor of the current default branch).

### 4. Live OCI attestations on a real Chainguard image (`04_cosign_attestations.sh`)

Built `cosign` v2.6.0 from source (no `cosign` binary was preinstalled) and
ran `cosign tree` / `cosign download attestation` against the real, live
public registry for `cgr.dev/chainguard/wolfi-base:latest`.

**Result:** exactly 3 attestations, decoded (`samples/attestations_decoded.txt`,
raw at `samples/attestations_raw.jsonl`):

| # | `predicateType` |
|---|---|
| 1 | `https://slsa.dev/provenance/v1` |
| 2 | `https://spdx.dev/Document` |
| 3 | `https://apko.dev/image-configuration` |

No VEX predicate type present. Identical to the original finding.

### 5. Chainguard's own scanner-integration guidance (`05_chainguard_scanner_guide.sh`)

Fetched `docs/scanning_implementation.md` from
`chainguard-dev/vulnerability-scanner-support` directly (the top-level
`README.md` alone doesn't contain this detail — it just links out to the
`docs/` and `libraries/` subdirectories, which is worth noting since the
original finding didn't call this out). Confirmed today's text:

> **✅ RECOMMENDED**: New scanner integrations must use the OSV feed...
>
> **⚠️ DEPRECATED**: The secdb format is deprecated for new scanner
> integrations. Use the OSV feed instead.

The Wolfi secdb it names as deprecated is `https://packages.wolfi.dev/os/security.json`
— exactly the endpoint the original finding cited.

### 6. The real Chainguard Libraries OpenVEX feed, cross-checked (`06_libraries_openvex_crosscheck.sh`)

Fetched `https://libraries.cgr.dev/openvex/v1/index.json` live.

**Result:** **207 packages** listed — identical count to the original
2026-08-14 finding. Fetched `pypi/werkzeug.openvex.json`
(`samples/werkzeug.openvex.json`): valid OpenVEX 0.2.0, real PURLs
(`pkg:pypi/werkzeug@...+cgr.1`), and a statement for `CVE-2024-34069` with
alias `GHSA-2g68-c3qc-8985` and Chainguard's internal ID `CGA-7vmq-pmg8-4rqv`.

Cross-checked `CVE-2024-34069` against OSV.dev's public API
(`samples/osv_cve-2024-34069.json`): OSV's own alias list is
`['GHSA-2g68-c3qc-8985', 'PYSEC-2026-2043']` — the GHSA alias matches
Chainguard's document exactly, an independent confirmation the statement is
real and correctly cross-referenced.

Also confirmed the Grype PR Chainguard's ecosystem cites,
`anchore/grype#2886` (`samples/grype_pr_2886.json`): real, `state: closed`,
`merged: true`, merged 2025-09-08.

## Conclusion

No OpenVEX artifact exists anywhere in the Chainguard container-image/Wolfi
ecosystem — not in a hosted feed, not in `wolfictl` (functionally removed in
2023, now a silent no-op), not as an OCI attestation on a real image. A real,
live OpenVEX feed does exist, but it is scoped to **Chainguard Libraries**
(remediated PyPI/Java packages), a different product than container images.
Every part of this finding reproduced identically today (2026-08-18) to the
original 2026-08-14 pass, with one refinement: `wolfictl vex package`'s
no-op is even more silent in practice than the source code alone suggests
(no visible log line), and the top-level `vulnerability-scanner-support`
README doesn't itself contain the OSV-vs-secdb guidance — that's one level
deeper, in `docs/scanning_implementation.md`.

This directly supports the proposal's decision to make **Red Hat CSAF** the
mandatory e2e feed and to re-scope the Chainguard example to
`libraries.cgr.dev` (PURL/library-scoped), not container images — see
`proposal_kv.md`'s "Supported feeds" doubt and "Example: Chainguard OpenVEX".

## Artifacts in this directory

- `01_wolfictl_build_and_run.sh` … `06_libraries_openvex_crosscheck.sh` —
  runnable scripts reproducing each step above from a clean checkout (each
  clones/builds into a `mktemp -d` scratch dir, not into this repo).
- `samples/` — captured real outputs from the 2026-08-18 run: the wolfictl
  stub source, the commit metadata, cosign's decoded attestations, both
  Chainguard doc pages, the Libraries OpenVEX index + werkzeug document, the
  OSV.dev cross-check response, and the Grype PR metadata.
