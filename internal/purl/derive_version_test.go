package purl_test

import (
	"testing"

	"github.com/gautamtalksdev/lading/internal/purl"
)

func TestDeriveUpstreamVersion_Debian(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"2.5.0-1+deb12u2", "2.5.0", true},
		{"1:3.0.19-1~deb12u2", "3.0.19", true},
		{"1.2.13.dfsg-1", "1.2.13", true},
		{"", "", false},
	}
	for _, tc := range cases {
		p, err := purl.Canonicalize("pkg:deb/debian/libexpat1@" + tc.raw + "?upstream=expat")
		if err != nil {
			t.Fatalf("canonicalize %q: %v", tc.raw, err)
		}
		// Version is on the PURL, not only in raw string after @ encoding.
		p.Version = tc.raw
		got, ok := purl.DeriveUpstreamVersion(p)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("%q: got (%q,%v) want (%q,%v)", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDeriveUpstreamVersion_Alpine(t *testing.T) {
	t.Parallel()
	p, err := purl.Canonicalize("pkg:apk/alpine/zlib@1.3.1-r0")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := purl.DeriveUpstreamVersion(p)
	if !ok || got != "1.3.1" {
		t.Fatalf("got (%q,%v) want (1.3.1,true)", got, ok)
	}
}

func TestDeriveUpstreamVersion_RPM(t *testing.T) {
	t.Parallel()
	p, err := purl.Canonicalize("pkg:rpm/fedora/openssl-libs@3.2.2-3.fc40")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := purl.DeriveUpstreamVersion(p)
	if !ok || got != "3.2.2" {
		t.Fatalf("got (%q,%v) want (3.2.2,true)", got, ok)
	}
}
