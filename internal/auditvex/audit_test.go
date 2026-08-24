package auditvex_test

import (
	"path/filepath"
	"runtime"
	"strings"
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

// TestAudit_RedHatCSAF_Expat exercises real Red Hat CSAF shapes: composite
// product IDs via relationships, product_status keys, and versionless PURLs.
func TestAudit_RedHatCSAF_Expat(t *testing.T) {
	dir := fixtureDir(t, "redhat_csaf_expat")
	rep, err := auditvex.Audit(
		filepath.Join(dir, "sbom.cdx.json"),
		[]string{filepath.Join(dir, "vex.csaf.json")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 3 {
		t.Fatalf("results=%d want 3 (2 known_not_affected + 1 fixed)", len(rep.Results))
	}

	var notAffected, fixed int
	var versionless *auditvex.StatementResult
	for i := range rep.Results {
		r := rep.Results[i]
		switch r.VEXStatus {
		case "known_not_affected":
			notAffected++
			if r.ProductIDs[0] != "red_hat_enterprise_linux_6:expat" &&
				r.ProductIDs[0] != "red_hat_enterprise_linux_7:expat" {
				t.Fatalf("unexpected composite product_id %q", r.ProductIDs[0])
			}
			if r.Products[0] != "pkg:rpm/redhat/expat" {
				t.Fatalf("composite %q resolved to %q want pkg:rpm/redhat/expat", r.ProductIDs[0], r.Products[0])
			}
			if r.Justification != "vulnerable_code_not_present" {
				t.Fatalf("justification=%q want vulnerable_code_not_present", r.Justification)
			}
			if r.Status == auditvex.StatusVersionless {
				copy := r
				versionless = &copy
			}
		case "fixed":
			fixed++
			if r.Products[0] != "pkg:rpm/redhat/expat@2.5.0-2.el9_4?arch=x86_64" {
				t.Fatalf("fixed resolved to %q", r.Products[0])
			}
			if r.Status != auditvex.StatusOK {
				t.Fatalf("fixed statement status=%s want ok (must not be overbroad)", r.Status)
			}
		default:
			t.Fatalf("unexpected vex_status=%q", r.VEXStatus)
		}
	}
	if notAffected != 2 || fixed != 1 {
		t.Fatalf("known_not_affected=%d fixed=%d", notAffected, fixed)
	}
	if versionless == nil {
		t.Fatal("expected VERSIONLESS on bare pkg:rpm/redhat/expat known_not_affected")
	}
	if !strings.Contains(versionless.Detail, "red_hat_enterprise_linux_6") &&
		!strings.Contains(versionless.Detail, "red_hat_enterprise_linux_7") {
		t.Fatalf("versionless detail missing platform: %s", versionless.Detail)
	}
	if !rep.HasFailures() {
		t.Fatal("expected HasFailures for versionless statements")
	}
}
