package scan_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gautamtalksdev/lading/internal/scan"
)

func TestDiscoverBinaries_InventoryFixture(t *testing.T) {
	root := inventoryBinDir(t)
	invs, err := scan.DiscoverBinaries(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(invs) == 0 {
		t.Fatal("expected binaries")
	}
}

func TestLoadFindings_GrypeShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grype.json")
	data := `{
	  "matches": [
	    {"vulnerability":{"id":"CVE-2023-0286"},"artifact":{"purl":"pkg:generic/openssl@3.0.7"}}
	  ]
	}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := scan.LoadFindings(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].CVE != "CVE-2023-0286" {
		t.Fatalf("got %+v", findings)
	}
}

func inventoryBinDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "inventory", "bin")
}
