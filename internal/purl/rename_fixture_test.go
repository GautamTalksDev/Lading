package purl_test

import (
	"testing"

	"github.com/gautamtalksdev/lading/internal/purl"
)

func TestRenameFixturePURLQuality(t *testing.T) {
	f, err := purl.Canonicalize("pkg:deb/debian/zlib@1.2.12")
	if err != nil {
		t.Fatal(err)
	}
	m, err := purl.Canonicalize("pkg:generic/zlib@1.2.12")
	if err != nil {
		t.Fatal(err)
	}
	q := purl.Equivalent(f, m)
	t.Logf("quality=%s", q)
	if q != purl.NameVersionOnly {
		t.Fatalf("want name_version_only, got %s", q)
	}
}
