package auditvex_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gautamtalksdev/lading/internal/auditvex"
	"github.com/gautamtalksdev/lading/internal/purl"
)

func fixtureDir(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "auditvex", name)
}

// TestAudit_GrypeInert reproduces the Grype failure mode:
// a VEX statement whose product PURL disagrees in type with the SBOM
// component (pkg:generic/... vs pkg:maven/...) so tools that require
// Exact identity silently ignore the statement — it is inert.
func TestAudit_GrypeInert(t *testing.T) {
	dir := fixtureDir(t, "grype_inert")
	rep, err := auditvex.Audit(
		filepath.Join(dir, "sbom.cdx.json"),
		[]string{filepath.Join(dir, "vex.openvex.json")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("results=%d", len(rep.Results))
	}
	r := rep.Results[0]
	if r.Status != auditvex.StatusInert {
		t.Fatalf("status=%s detail=%s best=%s matches=%v", r.Status, r.Detail, r.Best, r.Matches)
	}
	// Cross-type name+version still grades NameVersionOnly — never Exact.
	if r.Best != purl.NameVersionOnly {
		t.Fatalf("best=%s want name_version_only (Grype would still miss Exact)", r.Best)
	}
	if !rep.HasFailures() {
		t.Fatal("expected HasFailures")
	}
}

// TestAudit_TrivyOverbroad reproduces the Trivy failure mode:
// a VEX statement Exact-matches a shared subcomponent (openssl) that is
// depended on by multiple root products. Applying it would suppress
// findings across unrelated products — it is over-broad.
func TestAudit_TrivyOverbroad(t *testing.T) {
	dir := fixtureDir(t, "trivy_overbroad")
	rep, err := auditvex.Audit(
		filepath.Join(dir, "sbom.cdx.json"),
		[]string{filepath.Join(dir, "vex.openvex.json")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("results=%d", len(rep.Results))
	}
	r := rep.Results[0]
	if r.Status != auditvex.StatusOverbroad {
		t.Fatalf("status=%s detail=%s best=%s matches=%v", r.Status, r.Detail, r.Best, r.Matches)
	}
	if r.Best != purl.Exact {
		t.Fatalf("best=%s want exact (matched the shared subcomponent)", r.Best)
	}
	sawSub := false
	for _, m := range r.Matches {
		if !m.Component.IsRoot && m.Quality == purl.Exact {
			sawSub = true
		}
	}
	if !sawSub {
		t.Fatal("expected Exact match on non-root subcomponent")
	}
}
