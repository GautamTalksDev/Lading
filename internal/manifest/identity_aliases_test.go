package manifest_test

import (
	"testing"

	"github.com/gautamtalksdev/lading/internal/manifest"
)

func TestLoadIdentityAliases_EmbeddedSeed(t *testing.T) {
	t.Parallel()

	ia, err := manifest.LoadIdentityAliases("")
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"curl", "expat", "glibc", "openssl", "util-linux"}
	got := ia.SourceNames()
	if len(got) != len(want) {
		t.Fatalf("count=%d want %d: %v", len(got), len(want), got)
	}
	for i, name := range want {
		if got[i] != name {
			t.Fatalf("names=%v want %v", got, want)
		}
	}

	a, ok := ia.Lookup("expat")
	if !ok {
		t.Fatal("missing expat alias")
	}
	if a.Status != manifest.AliasStatusProbable {
		t.Fatalf("status=%q want probable", a.Status)
	}
	if a.Component != "pkg:generic/libexpat" {
		t.Fatalf("component=%q", a.Component)
	}
}
