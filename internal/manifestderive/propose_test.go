package manifestderive_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/manifestderive"
)

func setupProposeManifest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("0.2.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	compDir := filepath.Join(dir, "components", "native")
	if err := os.MkdirAll(compDir, 0o750); err != nil {
		t.Fatal(err)
	}
	zlib := filepath.Join(compDir, "zlib.yaml")
	if err := os.WriteFile(zlib, []byte(`
component:
  name: zlib
  ecosystem: native
  purls: ["pkg:generic/zlib"]
  identity_symbols: ["inflate", "deflate"]
entries:
  - cve: CVE-2022-37434
    affected_versions: ["1.2.12"]
    vulnerable_symbols:
      - name: inflate
        confidence: definitive
        provenance:
          upstream_fix_commit: https://github.com/madler/zlib/commit/eff308af425b67093bab25f80f1ae950166bece1
          derivation: patch-touched-function
          reviewed_by: maintainer
          reviewed_at: "2026-08-22"
    manifest_version: "0.2.0"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPropose_WritesProbableOnlyCandidateAndPRTemplate(t *testing.T) {
	manDir := setupProposeManifest(t)
	proposalRoot := t.TempDir()

	res, err := manifestderive.Propose(manifestderive.ProposeInput{
		Component:          "zlib",
		CVE:                "CVE-2018-25032",
		FixCommit:          "https://github.com/madler/zlib/commit/21767c0dbc5b3b221bc1996d9a496d3aada545eb",
		Symbols:            []string{"deflate"},
		EnclosingFunctions: []string{"deflate", "deflate_fast"},
		AffectedVersions:   []string{"1.2.11"},
		Verification:       "nm testdata/manifest-fixtures/zlib-1.2.11.so | grep deflate",
		FixturePath:        "testdata/manifest-fixtures/zlib-1.2.11.so",
		ContributorGitHub:  "contributor-example",
		Notes:              "Example contributor proposal for CP-13 golden path.",
	}, manifestderive.ProposeOptions{
		ManifestDir:  manDir,
		ProposalRoot: proposalRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(res.CandidatePath) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if strings.Contains(body, "confidence: definitive") {
		t.Fatal("propose must never write definitive")
	}
	if !strings.Contains(body, "confidence: probable") {
		t.Fatal("expected probable confidence")
	}
	if !strings.Contains(body, "CVE-2018-25032") {
		t.Fatal("missing CVE in candidate")
	}

	pr, err := os.ReadFile(res.PRTemplatePath) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	prBody := string(pr)
	for _, needle := range []string{
		"Upstream fix commit",
		"How I verified",
		"Test fixture",
		"@contributor-example",
		"deflate_fast",
	} {
		if !strings.Contains(prBody, needle) {
			t.Fatalf("PR template missing %q", needle)
		}
	}
}

func TestPropose_RequiresVerificationAndFixture(t *testing.T) {
	manDir := setupProposeManifest(t)
	_, err := manifestderive.Propose(manifestderive.ProposeInput{
		Component:        "zlib",
		CVE:              "CVE-2099-0001",
		FixCommit:        "https://github.com/madler/zlib/commit/abc",
		Symbols:          []string{"inflate"},
		AffectedVersions: []string{"1.0.0"},
	}, manifestderive.ProposeOptions{
		ManifestDir:  manDir,
		ProposalRoot: t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected error without verification/fixture")
	}
}
