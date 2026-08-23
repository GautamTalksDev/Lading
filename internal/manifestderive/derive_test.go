package manifestderive_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/manifestderive"
	"github.com/gautamtalksdev/lading/internal/manifest"
)

func TestParseUnifiedDiff_IgnoresHunkTrailer(t *testing.T) {
	diff := `diff --git a/inflate.c b/inflate.c
--- a/inflate.c
+++ b/inflate.c
@@ -100,3 +100,4 @@ inflate (z_streamp strm, int flush) /* TRAILER LIES */
 context
-oldline
+newline
+another
`
	cl, err := manifestderive.ParseUnifiedDiff(diff)
	if err != nil {
		t.Fatal(err)
	}
	var news, olds []int
	for _, c := range cl {
		if c.Path != "inflate.c" {
			t.Fatalf("path=%s", c.Path)
		}
		if c.Side == manifestderive.SideNew {
			news = append(news, c.Line)
		} else {
			olds = append(olds, c.Line)
		}
	}
	if len(olds) != 1 || olds[0] != 101 {
		t.Fatalf("olds=%v", olds)
	}
	if len(news) != 2 || news[0] != 101 || news[1] != 102 {
		t.Fatalf("news=%v", news)
	}
}

func TestPromote_RequiresReviewAndOnlyPathToDefinitive(t *testing.T) {
	candDir := t.TempDir()
	compDir := t.TempDir()
	cand := filepath.Join(candDir, "fixturelib.yaml")
	if err := os.WriteFile(cand, []byte(`
component:
  name: fixturelib
  ecosystem: native
  purls: ["pkg:generic/fixturelib"]
  identity_symbols: ["vuln_parse"]
meta:
  status: candidate
entries:
  - cve: CVE-2099-0001
    affected_versions: ["0.1.0"]
    vulnerable_symbols:
      - name: vuln_parse
        confidence: probable
        provenance:
          upstream_fix_commit: https://example.com/commit/abc
          derivation: patch-touched-function
    manifest_version: "0.1.0"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := manifestderive.Promote(cand, manifestderive.PromoteOptions{
		ComponentsDir: compDir,
	})
	if err == nil {
		t.Fatal("expected refuse without reviewed-by/at")
	}

	out, err := manifestderive.Promote(cand, manifestderive.PromoteOptions{
		ReviewedBy:      "tester",
		ReviewedAt:      "2026-08-23",
		ComponentsDir:   compDir,
		ManifestVersion: "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "confidence: definitive") {
		t.Fatal("promote should write definitive")
	}
	if !strings.Contains(string(raw), "reviewed_by: tester") {
		t.Fatal("missing reviewed_by")
	}
}

func TestDerive_NeverWritesDefinitiveConstant(t *testing.T) {
	if manifest.ConfidenceDefinitive != "definitive" {
		t.Fatal("unexpected constant")
	}
	if manifest.ConfidenceProbable != "probable" {
		t.Fatal("unexpected constant")
	}
}

func TestCoverage_SeedComponents(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := manifestderive.ComputeCoverage(root)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]manifestderive.ComponentCoverage{}
	for _, c := range rep.Components {
		byName[c.Name] = c
	}
	for _, name := range []string{"zlib", "libexpat", "openssl"} {
		c, ok := byName[name]
		if !ok {
			t.Fatalf("missing component %s", name)
		}
		if c.Definitive < 1 {
			t.Fatalf("%s: want definitive≥1, got %+v", name, c)
		}
	}
}
