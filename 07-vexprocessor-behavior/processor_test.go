package main

import (
	"strings"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/syft/syft/source"
)

// validOpenVEXFixture / validCSAFFixture are copied verbatim from
// ../02-grype-version/{test.openvex.json,test.csaf.json} -- documents
// already empirically confirmed (finding 2) to be accepted by grype v0.99.1
// and to correctly move real alpine:3.18 matches into ignoredMatches. Using
// them here (rather than freshly hand-rolled fixtures) avoids conflating
// "my fixture is invalid" with "grype's mixed-format behavior is X".
const validOpenVEXFixturePath = "valid_openvex_fixture.json"
const validCSAFFixturePath = "valid_csaf_fixture.json"

// garbageFixture is neither OpenVEX (no matching @context) nor CSAF (no
// "csaf_version" marker) -- used to exercise the real
// "unable to detect document format" error path, which (per source reading,
// see RESULTS.md) lives in github.com/openvex/go-vex's Open(), not in grype
// itself.
const garbageFixturePath = "garbage_fixture.json"

func newTestPkgContext() *pkg.Context {
	return &pkg.Context{
		Source: &source.Description{
			Name: "alpine",
			Metadata: source.ImageMetadata{
				UserInput:   "alpine:3.18",
				Tags:        []string{"alpine:3.18"},
				RepoDigests: []string{"index.docker.io/library/alpine@sha256:de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f"},
			},
		},
	}
}

// 1. NewProcessor with a nonexistent path must fail immediately -- confirms
// VexProcessor has no in-memory/byte-content API; Documents must be real
// file paths, resolved via os.Stat inside getVexImplementation.
func TestNewProcessor_NonexistentPath_Fails(t *testing.T) {
	_, err := vex.NewProcessor(vex.ProcessorOptions{
		Documents: []string{"/nonexistent/path.json"},
	})
	if err == nil {
		t.Fatal("expected an error constructing a VEX processor for a nonexistent path, got nil")
	}
	t.Logf("actual error: %v", err)
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected error to mention the document was not found, got: %v", err)
	}
}

// 2. A single real, valid OpenVEX document on disk must succeed and be
// usable end-to-end via ApplyVEX.
func TestNewProcessor_ValidOpenVEX_Succeeds(t *testing.T) {
	proc, err := vex.NewProcessor(vex.ProcessorOptions{Documents: []string{validOpenVEXFixturePath}})
	if err != nil {
		t.Fatalf("expected NewProcessor to succeed for a valid OpenVEX doc, got error: %v", err)
	}
	if proc == nil {
		t.Fatal("expected a non-nil processor")
	}

	matches := match.NewMatches()
	_, _, err = proc.ApplyVEX(newTestPkgContext(), &matches, nil)
	if err != nil {
		t.Fatalf("ApplyVEX on a lone valid OpenVEX doc should not error, got: %v", err)
	}
}

// 3a. Documents[0] = OpenVEX (real, valid), Documents[1] = CSAF (real, valid).
// getVexImplementation picks the OpenVEX implementation from Documents[0].
// Its ReadVexDocuments delegates to go-vex's MergeFiles -> Open(), which
// independently auto-detects EACH file's format (OpenVEX via @context,
// CSAF via a "csaf_version" substring check) and silently converts a
// trailing CSAF file into OpenVEX statements internally via OpenCSAF().
// Empirically this SUCCEEDS with no error -- it does not raise
// "unable to detect document format" the way the original finding claimed.
func TestApplyVEX_MixedFormats_OpenVEXFirst_Succeeds(t *testing.T) {
	proc, err := vex.NewProcessor(vex.ProcessorOptions{
		Documents: []string{validOpenVEXFixturePath, validCSAFFixturePath},
	})
	if err != nil {
		t.Fatalf("NewProcessor failed constructing implementation from Documents[0] (openvex): %v", err)
	}

	matches := match.NewMatches()
	_, _, err = proc.ApplyVEX(newTestPkgContext(), &matches, nil)
	if err != nil {
		t.Fatalf("expected ApplyVEX to SUCCEED with OpenVEX-first mixed real documents (go-vex silently absorbs the trailing CSAF file), got error: %v", err)
	}
	t.Log("ApplyVEX with [openvex, csaf] succeeded with no error -- go-vex's Open() auto-converted the CSAF file rather than failing")
}

// 3b. Documents[0] = CSAF (real, valid), Documents[1] = OpenVEX (real, valid).
// getVexImplementation picks the CSAF implementation. Its ReadVexDocuments
// calls csaf.LoadAdvisory on every doc in the list, including the OpenVEX
// one, which is not a valid CSAF advisory (no top-level "document" object)
// and fails strict-mode validation. This ordering DOES fail, but the error
// is "error loading VEX CSAF document: 'document' is missing" (schema
// validation), not the "unable to detect document format" string the
// original finding attributed to this case.
func TestApplyVEX_MixedFormats_CSAFFirst_Fails(t *testing.T) {
	proc, err := vex.NewProcessor(vex.ProcessorOptions{
		Documents: []string{validCSAFFixturePath, validOpenVEXFixturePath},
	})
	if err != nil {
		t.Fatalf("NewProcessor failed constructing implementation from Documents[0] (csaf): %v", err)
	}

	matches := match.NewMatches()
	_, _, err = proc.ApplyVEX(newTestPkgContext(), &matches, nil)
	if err == nil {
		t.Fatal("expected ApplyVEX to fail with CSAF-first mixed documents (csaf.LoadAdvisory rejects the OpenVEX file as an invalid CSAF advisory)")
	}
	t.Logf("actual error: %v", err)
	if strings.Contains(err.Error(), "unable to detect document format") {
		t.Error(`got "unable to detect document format" -- this string does NOT appear anywhere in the CSAF loading path; the original finding's quoted error message is not accurate for this ordering`)
	}
	if !strings.Contains(err.Error(), "document") {
		t.Errorf("expected a schema-validation-shaped error mentioning the missing 'document' object, got: %v", err)
	}
}

// 3c. The literal "unable to detect document format" string DOES exist in
// grype's dependency chain (github.com/openvex/go-vex's Open()), but only
// fires for a file that is neither OpenVEX-context-tagged NOR contains a
// "csaf_version" marker at all -- i.e. not-a-VEX-document-of-any-kind, not
// "a second, different VEX format". Confirms exactly where that message
// actually lives and what triggers it.
func TestApplyVEX_OpenVEXFirst_WithGarbageSecondDoc_DetectsFormatFailure(t *testing.T) {
	proc, err := vex.NewProcessor(vex.ProcessorOptions{
		Documents: []string{validOpenVEXFixturePath, garbageFixturePath},
	})
	if err != nil {
		t.Fatalf("NewProcessor failed: %v", err)
	}

	matches := match.NewMatches()
	_, _, err = proc.ApplyVEX(newTestPkgContext(), &matches, nil)
	if err == nil {
		t.Fatal("expected ApplyVEX to fail when the second document is neither OpenVEX nor CSAF at all")
	}
	t.Logf("actual error: %v", err)
	if !strings.Contains(err.Error(), "unable to detect document format") {
		t.Errorf(`expected error to contain "unable to detect document format", got: %v`, err)
	}
}
