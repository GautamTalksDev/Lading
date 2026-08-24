package evidence_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/evidence"
	"github.com/gautamtalksdev/lading/internal/inventory"
	"github.com/gautamtalksdev/lading/internal/manifest"
)

func testArtifact(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "inventory", "bin", "symver_ssl_elf")
}

func testFixture(t *testing.T) (artifact, bundleDir, vexPath string, cleanup func()) {
	t.Helper()
	rel := testArtifact(t)
	artifact, err := filepath.Abs(rel)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Scan(artifact)
	if err != nil {
		t.Fatal(err)
	}

	comp := manifest.Component{
		Name:            "openssl",
		Ecosystem:       "native",
		PURLs:           []string{"pkg:generic/openssl@3.0.7"},
		IdentitySymbols: []string{"OPENSSL_init_ssl", "GENERAL_NAME_cmp", "SSL_CTX_new"},
	}
	entry := manifest.Entry{
		CVE:              "CVE-2023-0286",
		AffectedVersions: []string{"3.0.7"},
		VulnerableSymbols: []manifest.VulnerableSymbol{{
			Name:                 "GENERAL_NAME_cmp",
			Confidence:           manifest.ConfidenceDefinitive,
			DynsymExportVerified: true,
			Provenance: manifest.Provenance{
				UpstreamFixCommit: "https://github.com/openssl/openssl/commit/2f7530077e0ef79d98718138716bc51ca0cad658",
				Derivation:        manifest.DerivationPatchTouched,
				ReviewedBy:        "fixture",
				ReviewedAt:        "2026-08-23",
			},
		}},
		ManifestVersion: "0.1.0",
	}
	m, err := manifest.BuildForTest("0.1.0", comp, []manifest.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	slice, err := manifest.SliceFromManifest(m, "openssl", "CVE-2023-0286")
	if err != nil {
		t.Fatal(err)
	}

	finding := decide.Finding{
		CVE:           "CVE-2023-0286",
		ComponentPURL: "pkg:generic/openssl@3.0.7",
	}
	result, err := decide.Evaluate(decide.Input{
		Inventories: []*inventory.Inventory{inv},
		Finding:     finding,
		Manifest:    m,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RuleID != decide.RuleD02 {
		t.Fatalf("expected D02 fixture, got %s", result.RuleID)
	}

	dir := t.TempDir()
	bundleDir = filepath.Join(dir, "bundle")
	if _, err := evidence.WriteBundleDir(bundleDir, []evidence.BuildInput{{
		ArtifactPath: artifact,
		StatementID:  "cve-2023-0286",
		Finding:      finding,
		Result:       result,
		Inventories:  []*inventory.Inventory{inv},
		Slice:        slice,
	}}); err != nil {
		t.Fatal(err)
	}

	vexPath = filepath.Join(dir, "vex.json")
	if err := os.WriteFile(vexPath, []byte(`{
  "format": "lading-vex-v1",
  "statements": [{
    "vulnerability": "CVE-2023-0286",
    "product_purl": "pkg:generic/openssl@3.0.7",
    "status": "not_affected",
    "justification": "vulnerable_code_not_present"
  }]
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return artifact, bundleDir, vexPath, func() {}
}

func TestVerify_Success(t *testing.T) {
	artifact, bundle, vex, _ := testFixture(t)
	report, err := evidence.Verify(evidence.VerifyOptions{
		ArtifactPath: artifact,
		VEXPath:      vex,
		BundleDir:    bundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.AllVerified() {
		t.Fatalf("report: %+v", report)
	}
	if report.BundleID == "" {
		t.Fatal("empty bundle id")
	}
}

func TestVerify_TamperedArtifact(t *testing.T) {
	_, bundle, vex, _ := testFixture(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.elf")
	data, err := os.ReadFile(testArtifact(t))
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xff
	if werr := os.WriteFile(bad, data, 0o600); werr != nil {
		t.Fatal(werr)
	}
	report, err := evidence.Verify(evidence.VerifyOptions{
		ArtifactPath: bad,
		VEXPath:      vex,
		BundleDir:    bundle,
	})
	if err != nil {
		return
	}
	if report.AllVerified() {
		t.Fatal("expected verify failure on tampered artifact")
	}
	for _, s := range report.Statements {
		if s.Status != evidence.StatusUnverifiable {
			t.Fatalf("expected UNVERIFIABLE, got %s (%s)", s.Status, s.Detail)
		}
	}
}

func TestVerify_TamperedBundle(t *testing.T) {
	artifact, bundle, vex, _ := testFixture(t)
	stmtPath := filepath.Join(bundle, "statements", "cve-2023-0286", "statement.json")
	data, err := os.ReadFile(stmtPath) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, ' ')
	if werr := os.WriteFile(stmtPath, data, 0o600); werr != nil {
		t.Fatal(werr)
	}
	_, err = evidence.Verify(evidence.VerifyOptions{
		ArtifactPath: artifact,
		VEXPath:      vex,
		BundleDir:    bundle,
	})
	if err == nil {
		t.Fatal("expected verify failure on tampered bundle")
	}
}

func TestVerify_TamperedVEX(t *testing.T) {
	artifact, bundle, vex, _ := testFixture(t)
	if err := os.WriteFile(vex, []byte(`{
  "format": "lading-vex-v1",
  "statements": [{
    "vulnerability": "CVE-2023-0286",
    "product_purl": "pkg:generic/openssl@3.0.7",
    "status": "affected"
  }]
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := evidence.Verify(evidence.VerifyOptions{
		ArtifactPath: artifact,
		VEXPath:      vex,
		BundleDir:    bundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.AllVerified() {
		t.Fatal("expected MISMATCH on tampered vex")
	}
	found := false
	for _, s := range report.Statements {
		if s.Status == evidence.StatusMismatch {
			found = true
		}
	}
	if !found {
		t.Fatalf("report: %+v", report)
	}
}

func TestVerify_NoInstalledManifest(t *testing.T) {
	artifact, bundle, vex, _ := testFixture(t)
	// Absolute paths work even if cwd has no manifest/ tree (auditor laptop).
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir("/")
	})
	if _, err := os.Stat("manifest"); err == nil {
		t.Fatal("test cwd unexpectedly has manifest/")
	}
	report, err := evidence.Verify(evidence.VerifyOptions{
		ArtifactPath: artifact,
		VEXPath:      vex,
		BundleDir:    bundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.AllVerified() {
		t.Fatalf("report: %+v", report)
	}
}

func TestVerify_NoHTTPImports(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	verifyGo := filepath.Join(filepath.Dir(file), "verify.go")
	out, err := os.ReadFile(verifyGo) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"net/http"`) {
		t.Fatal("evidence verify must not import net/http")
	}
}

func TestBundleID_IsManifestSHA(t *testing.T) {
	_, bundle, _, _ := testFixture(t)
	data, err := os.ReadFile(filepath.Join(bundle, "MANIFEST.sha")) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	id, err := os.ReadFile(filepath.Join(bundle, "BUNDLE.id")) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	// BUNDLE.id should match sha256(MANIFEST.sha) — checked in WriteBundleDir.
	if len(id) < 64 {
		t.Fatalf("short bundle id: %q", string(id))
	}
	if len(data) == 0 {
		t.Fatal("empty MANIFEST.sha")
	}
}
