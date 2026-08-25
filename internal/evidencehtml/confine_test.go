package evidencehtml

import (
	"path/filepath"
	"testing"
)

func TestConfinedDir(t *testing.T) {
	root := t.TempDir()
	got, err := confinedDir(root, "cve-2026-14456")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "cve-2026-14456" {
		t.Fatalf("got %s", got)
	}
	for _, bad := range []string{"../etc", "a/b", "..", "", ".", "cve/../x"} {
		if _, err := confinedDir(root, bad); err == nil {
			t.Fatalf("expected reject %q", bad)
		}
	}
}
