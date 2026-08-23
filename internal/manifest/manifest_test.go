package manifest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/inventory"
	"github.com/gautamtalksdev/lading/internal/manifest"
)

func manifestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLoad_SeedEntries(t *testing.T) {
	m, err := manifest.Load(manifestRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Components()) != 3 {
		t.Fatalf("components=%d want 3", len(m.Components()))
	}
	for _, cve := range []string{"CVE-2022-37434", "CVE-2022-25315", "CVE-2023-0286"} {
		ents, ok := m.LookupCVE(cve)
		if !ok || len(ents) == 0 {
			t.Fatalf("missing %s", cve)
		}
		for _, e := range ents {
			if !e.AllowsNotAffected() {
				t.Fatalf("%s should allow not_affected (definitive only)", cve)
			}
			for _, vs := range e.VulnerableSymbols {
				if vs.Provenance.UpstreamFixCommit == "" {
					t.Fatalf("%s missing provenance URL", cve)
				}
				if !strings.HasPrefix(vs.Provenance.UpstreamFixCommit, "https://") {
					t.Fatalf("%s provenance not https: %s", cve, vs.Provenance.UpstreamFixCommit)
				}
			}
		}
	}
	v := m.Version()
	if !strings.HasPrefix(v, "0.1.0+") || len(v) < 20 {
		t.Fatalf("Version()=%q", v)
	}
}

func TestLoad_RejectsMissingProvenance(t *testing.T) {
	dir := t.TempDir()
	writeMinimalManifestTree(t, dir, `
component:
  name: bad
  ecosystem: native
  purls: ["pkg:generic/bad"]
  identity_symbols: ["bad_sym"]
entries:
  - cve: CVE-2024-0001
    affected_versions: ["1.0.0"]
    vulnerable_symbols:
      - name: bad_sym
        confidence: definitive
        provenance:
          upstream_fix_commit: ""
          derivation: manual
          reviewed_by: tester
          reviewed_at: "2026-08-22"
    manifest_version: "0.1.0"
`)
	_, err := manifest.Load(dir)
	if err == nil {
		t.Fatal("expected schema failure for missing provenance URL")
	}
	if !strings.Contains(err.Error(), "upstream_fix_commit") {
		t.Fatalf("error should mention upstream_fix_commit: %v", err)
	}
}

func TestLoad_RejectsMissingProvenanceKey(t *testing.T) {
	dir := t.TempDir()
	writeMinimalManifestTree(t, dir, `
component:
  name: bad
  ecosystem: native
  purls: ["pkg:generic/bad"]
  identity_symbols: ["bad_sym"]
entries:
  - cve: CVE-2024-0002
    affected_versions: ["1.0.0"]
    vulnerable_symbols:
      - name: bad_sym
        confidence: definitive
        provenance:
          derivation: manual
          reviewed_by: tester
          reviewed_at: "2026-08-22"
    manifest_version: "0.1.0"
`)
	_, err := manifest.Load(dir)
	if err == nil {
		t.Fatal("expected failure when provenance.upstream_fix_commit key is absent")
	}
}

func TestVersion_ChangesWhenDataChanges(t *testing.T) {
	dir := t.TempDir()
	body := `
component:
  name: demo
  ecosystem: native
  purls: ["pkg:generic/demo"]
  identity_symbols: ["demo_sym"]
entries:
  - cve: CVE-2024-1000
    affected_versions: ["1.0.0"]
    vulnerable_symbols:
      - name: demo_sym
        confidence: definitive
        provenance:
          upstream_fix_commit: https://example.com/commit/1
          derivation: manual
          reviewed_by: tester
          reviewed_at: "2026-08-22"
    manifest_version: "0.1.0"
`
	writeMinimalManifestTree(t, dir, body)
	m1, err := manifest.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	v1 := m1.Version()

	// Mutate notes → content hash must change.
	path := filepath.Join(dir, "components", "native", "demo.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, []byte("\n# touch\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	m2, err := manifest.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Version() == v1 {
		t.Fatalf("Version() unchanged after data edit: %s", v1)
	}
	if m2.Semver() != m1.Semver() {
		t.Fatalf("semver should stay %s, got %s", m1.Semver(), m2.Semver())
	}
}

func TestIdentifyComponent(t *testing.T) {
	m, err := manifest.Load(manifestRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Inventory{
		DynSyms: []inventory.Symbol{
			{Raw: "inflate", Normalized: "inflate"},
			{Raw: "deflate", Normalized: "deflate"},
		},
	}
	hits := m.IdentifyComponent(inv)
	found := false
	for _, h := range hits {
		if h.Component.Name == "zlib" {
			found = true
			if !strings.HasPrefix(h.Reason, "symbol:") {
				t.Fatalf("reason=%s", h.Reason)
			}
		}
	}
	if !found {
		t.Fatalf("expected zlib match, got %#v", hits)
	}
}

func TestEntry_ProbableDisallowsNotAffected(t *testing.T) {
	e := manifest.Entry{
		VulnerableSymbols: []manifest.VulnerableSymbol{
			{Name: "foo", Confidence: manifest.ConfidenceProbable},
		},
	}
	if e.AllowsNotAffected() {
		t.Fatal("probable must not allow not_affected")
	}
}

func writeMinimalManifestTree(t *testing.T, dir, yamlBody string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("0.1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	schemaSrc := filepath.Join(manifestRoot(t), "schema", "entry.schema.json")
	schemaDir := filepath.Join(dir, "schema")
	if err := os.MkdirAll(schemaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(schemaSrc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(schemaDir, "entry.schema.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	compDir := filepath.Join(dir, "components", "native")
	if err := os.MkdirAll(compDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(compDir, "demo.yaml"), []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}
}
